"""Traffic file ingestion and privacy-preserving packet metadata extraction."""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Timer, current_thread
from typing import Any, Iterable
import ipaddress
import math
import re
import socket
import time
from urllib.parse import urlsplit
from uuid import uuid4

import pandas as pd

BASE_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes",
    "app_category",
    "user",
]

ACTIVITY_COLUMNS = [
    "hostname",
    "url",
    "tls_sni",
    "dns_query",
    "download_name",
    "content_type",
    "process_name",
    "process_id",
    "activity",
    "activity_target",
]

CANONICAL_COLUMNS = BASE_COLUMNS + ACTIVITY_COLUMNS

_COLUMN_ALIASES = {
    "timestamp": (
        "timestamp", "time", "datetime", "date_time", "frame_time",
        "frame.time", "frame.time_epoch", "_ws.col.time", "time_epoch",
    ),
    "src_ip": ("src_ip", "source_ip", "src", "source", "ip_src", "ip.src"),
    "dst_ip": ("dst_ip", "destination_ip", "dst", "destination", "ip_dst", "ip.dst"),
    "src_port": ("src_port", "source_port", "sport", "tcp_srcport", "udp_srcport", "tcp.srcport", "udp.srcport"),
    "dst_port": ("dst_port", "destination_port", "dport", "tcp_dstport", "udp_dstport", "tcp.dstport", "udp.dstport"),
    "protocol": ("protocol", "proto", "frame_protocols", "_ws.col.protocol", "ip_proto"),
    "bytes": ("bytes", "length", "len", "size", "packet_length", "frame_len", "frame.len"),
    "app_category": ("app_category", "category", "application", "app", "service"),
    "user": ("user", "username", "client", "device", "host", "source_user"),
    "hostname": ("hostname", "host", "domain", "server_name"),
    "url": ("url", "uri", "request_url", "http_url"),
    "tls_sni": ("tls_sni", "sni", "server_name_indication"),
    "dns_query": ("dns_query", "dns_name", "query_name"),
    "download_name": ("download_name", "filename", "content_disposition_filename"),
    "content_type": ("content_type", "mime_type"),
    "process_name": ("process_name", "application_name", "process"),
    "process_id": ("process_id", "pid"),
    "activity": ("activity", "event", "event_type"),
    "activity_target": ("activity_target", "target", "resource"),
}

SUPPORTED_EXTENSIONS = {"csv", "pcap", "pcapng", "cap"}


class TrafficImportError(ValueError):
    """A traffic source cannot be read into the common analysis schema."""


class CaptureDependencyError(RuntimeError):
    """Scapy or its platform capture backend is unavailable."""


def _normalise_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _column_lookup(columns: Iterable[object]) -> dict[str, object]:
    normalised = {_normalise_name(column): column for column in columns}
    result: dict[str, object] = {}
    for canonical, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            source = normalised.get(_normalise_name(alias))
            if source is not None:
                result[canonical] = source
                break
    return result


def _to_port(value: object) -> int:
    try:
        port = int(float(value))
        return port if 0 <= port <= 65535 else 0
    except (TypeError, ValueError):
        return 0


def _to_bytes(value: object) -> int:
    try:
        amount = int(float(value))
        return max(amount, 0)
    except (TypeError, ValueError):
        return 0


def _is_private_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def _display_user(src_ip: str, dst_ip: str) -> str:
    if _is_private_address(src_ip):
        return src_ip
    if _is_private_address(dst_ip):
        return dst_ip
    return src_ip if src_ip and src_ip != "unknown" else dst_ip


def categorise_traffic(protocol: str, src_port: int, dst_port: int) -> str:
    """Classify traffic from protocol and ports."""
    ports = {src_port, dst_port}
    protocol = str(protocol or "OTHER").upper()
    if 53 in ports:
        return "DNS"
    if 1900 in ports:
        return "Device Discovery"
    if ports & {5353, 5355}:
        return "Local Name Resolution"
    if ports & {67, 68, 546, 547}:
        return "DHCP"
    if ports & {123}:
        return "NTP"
    if ports & {80, 8080, 8000, 8888}:
        return "Web"
    if ports & {443, 784, 885, 993, 995} and protocol == "UDP":
        return "QUIC / Encrypted Web"
    if ports & {443, 8443}:
        return "Encrypted Web"
    if ports & {22, 3389}:
        return "Remote Access"
    if ports & {25, 110, 143, 465, 587, 993, 995}:
        return "Email"
    if ports & {3478, 3479, 5349}:
        return "Realtime Media"
    if protocol in {"ICMP", "ICMPV6"}:
        return "Network Control"
    return "Other"


def _parse_timestamp(value: object) -> pd.Timestamp:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return pd.to_datetime(value, unit="s", errors="coerce")
    text = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return pd.to_datetime(float(text), unit="s", errors="coerce")
    return pd.to_datetime(text, errors="coerce")


def canonicalise_dataframe(raw_df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Map CSV variants to the application's canonical packet metadata schema."""
    if raw_df.empty:
        raise TrafficImportError("文件没有可分析的数据行。")

    mapping = _column_lookup(raw_df.columns)
    if not mapping.get("src_ip") or not mapping.get("dst_ip"):
        raise TrafficImportError("CSV 至少需要源 IP 和目的 IP 字段。")

    result = pd.DataFrame(index=raw_df.index)
    timestamp_source = mapping.get("timestamp")
    result["timestamp"] = (
        raw_df[timestamp_source].map(_parse_timestamp)
        if timestamp_source is not None
        else pd.Timestamp.now()
    )
    result["timestamp"] = result["timestamp"].fillna(pd.Timestamp.now()).dt.tz_localize(None)
    result["src_ip"] = raw_df[mapping["src_ip"]].fillna("unknown").astype(str).str.strip()
    result["dst_ip"] = raw_df[mapping["dst_ip"]].fillna("unknown").astype(str).str.strip()
    result["src_port"] = raw_df[mapping["src_port"]].map(_to_port) if mapping.get("src_port") else 0
    result["dst_port"] = raw_df[mapping["dst_port"]].map(_to_port) if mapping.get("dst_port") else 0
    result["protocol"] = (
        raw_df[mapping["protocol"]].fillna("OTHER").astype(str).str.upper()
        if mapping.get("protocol") else "OTHER"
    )
    result["bytes"] = raw_df[mapping["bytes"]].map(_to_bytes) if mapping.get("bytes") else 0
    result["app_category"] = (
        raw_df[mapping["app_category"]].fillna("").astype(str).str.strip()
        if mapping.get("app_category") else ""
    )
    missing_category = result["app_category"].eq("")
    result.loc[missing_category, "app_category"] = result[missing_category].apply(
        lambda row: categorise_traffic(row["protocol"], row["src_port"], row["dst_port"]), axis=1
    )
    result["user"] = (
        raw_df[mapping["user"]].fillna("").astype(str).str.strip()
        if mapping.get("user") else ""
    )
    missing_user = result["user"].eq("")
    result.loc[missing_user, "user"] = result[missing_user].apply(
        lambda row: _display_user(row["src_ip"], row["dst_ip"]), axis=1
    )
    for field in ACTIVITY_COLUMNS:
        if field == "process_id":
            result[field] = raw_df[mapping[field]].map(_to_port) if mapping.get(field) else 0
        else:
            result[field] = (
                raw_df[mapping[field]].fillna("").astype(str).str.strip()
                if mapping.get(field) else ""
            )
    missing_target = result["activity_target"].eq("")
    result.loc[missing_target, "activity_target"] = result.loc[missing_target, "url"]
    missing_target = result["activity_target"].eq("")
    result.loc[missing_target, "activity_target"] = result.loc[missing_target, "hostname"]

    warnings = []
    absent = [field for field in ("timestamp", "src_port", "dst_port", "protocol", "bytes") if field not in mapping]
    if absent:
        warnings.append("已补充缺失字段：" + "、".join(absent))
    return result[CANONICAL_COLUMNS], warnings


def read_csv_traffic(path: Path) -> tuple[pd.DataFrame, list[str]]:
    encodings = ("utf-8-sig", "utf-8", "gb18030", "latin-1")
    last_error: Exception | None = None
    for encoding in encodings:
        try:
            raw_df = pd.read_csv(path, encoding=encoding)
            return canonicalise_dataframe(raw_df)
        except UnicodeDecodeError as error:
            last_error = error
        except (pd.errors.ParserError, OSError, ValueError) as error:
            raise TrafficImportError(f"CSV 读取失败：{error}") from error
    raise TrafficImportError(f"CSV 编码无法识别：{last_error}")


def _require_scapy() -> dict[str, Any]:
    try:
        from scapy.all import AsyncSniffer, DNS, IP, IPv6, PcapReader, PcapWriter, Raw, TCP, UDP, get_if_list
        return {
            "AsyncSniffer": AsyncSniffer, "IP": IP, "IPv6": IPv6, "PcapReader": PcapReader,
            "TCP": TCP, "UDP": UDP, "DNS": DNS, "Raw": Raw, "PcapWriter": PcapWriter,
            "get_if_list": get_if_list,
        }
    except ImportError as error:
        raise CaptureDependencyError("缺少 Scapy。请先安装 requirements.txt 中的依赖。") from error


def _empty_activity() -> dict[str, object]:
    return {
        "hostname": "",
        "url": "",
        "tls_sni": "",
        "dns_query": "",
        "download_name": "",
        "content_type": "",
        "process_name": "",
        "process_id": 0,
        "activity": "",
        "activity_target": "",
    }


def _clean_text(value: object, limit: int = 240) -> str:
    text = str(value or "").replace("\r", "").replace("\n", "").strip()
    return text[:limit]


def _redact_path(value: str) -> str:
    """Keep a page path but omit query-string values that may contain secrets."""
    try:
        parts = urlsplit(value)
        path = parts.path or "/"
        if parts.query:
            names = [item.split("=", 1)[0] for item in parts.query.split("&") if item]
            return f"{path}?{'&'.join(names[:8])}" if names else f"{path}?…"
        return path
    except ValueError:
        return "/"


def _http_headers(payload: bytes) -> tuple[str, dict[str, str]]:
    if not payload:
        return "", {}
    header_block = payload[:16_384].split(b"\r\n\r\n", 1)[0]
    try:
        lines = header_block.decode("iso-8859-1", errors="ignore").split("\r\n")
    except UnicodeDecodeError:
        return "", {}
    if not lines:
        return "", {}
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = _clean_text(value, 512)
    return _clean_text(lines[0], 512), headers


def _extract_download_name(content_disposition: str) -> str:
    match = re.search(r"filename\*?=(?:UTF-8''|\"|')?([^;\"']+)", content_disposition, re.I)
    return _clean_text(match.group(1).strip(), 160) if match else ""


def _extract_tls_sni(payload: bytes) -> str:
    """Read a hostname from a complete TLS ClientHello record when present."""
    try:
        if len(payload) < 52 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        position = 9  # TLS record (5) + handshake header (4)
        position += 2 + 32  # legacy version + random
        session_length = payload[position]
        position += 1 + session_length
        cipher_length = int.from_bytes(payload[position:position + 2], "big")
        position += 2 + cipher_length
        compression_length = payload[position]
        position += 1 + compression_length
        extensions_length = int.from_bytes(payload[position:position + 2], "big")
        position += 2
        extension_end = min(position + extensions_length, len(payload))
        while position + 4 <= extension_end:
            extension_type = int.from_bytes(payload[position:position + 2], "big")
            extension_length = int.from_bytes(payload[position + 2:position + 4], "big")
            extension_data = payload[position + 4:position + 4 + extension_length]
            position += 4 + extension_length
            if extension_type != 0 or len(extension_data) < 5:
                continue
            name_length = int.from_bytes(extension_data[3:5], "big")
            if extension_data[2] != 0 or 5 + name_length > len(extension_data):
                continue
            return _clean_text(extension_data[5:5 + name_length].decode("idna", errors="ignore"), 253)
    except (IndexError, UnicodeError, ValueError):
        return ""
    return ""


def _packet_payload(packet: Any, raw_layer: Any) -> bytes:
    raw = packet.getlayer(raw_layer)
    return bytes(getattr(raw, "load", b""))[:16_384] if raw is not None else b""


def _extract_activity_metadata(
    packet: Any,
    scapy: dict[str, Any],
    src_port: int,
    dst_port: int,
) -> dict[str, object]:
    """Parse display-only indicators and immediately discard packet payload bytes."""
    metadata = _empty_activity()
    dns = packet.getlayer(scapy["DNS"])
    if dns is not None and getattr(dns, "qd", None) is not None:
        query = _clean_text(getattr(dns.qd, "qname", b"").decode(errors="ignore").rstrip("."), 253)
        if query:
            metadata.update(
                hostname=query,
                dns_query=query,
                activity="DNS 查询" if int(getattr(dns, "qr", 0)) == 0 else "DNS 响应",
                activity_target=query,
            )
            return metadata

    payload = _packet_payload(packet, scapy["Raw"])
    if not payload:
        return metadata
    ports = {src_port, dst_port}
    first_line, headers = _http_headers(payload)
    is_http = first_line.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/"))
    if is_http and ports & {80, 8080, 8000, 8888}:
        hostname = _clean_text(headers.get("host", ""), 253)
        content_type = _clean_text(headers.get("content-type", ""), 120)
        if first_line.startswith("HTTP/"):
            filename = _extract_download_name(headers.get("content-disposition", ""))
            metadata.update(
                download_name=filename,
                content_type=content_type,
                activity="文件下载" if filename else "HTTP 响应",
                activity_target=filename or content_type or first_line.split(" ", 2)[1],
            )
        else:
            method, request_target, *_ = first_line.split(" ", 2)
            path = _redact_path(request_target)
            url = f"http://{hostname}{path}" if hostname else path
            metadata.update(
                hostname=hostname,
                url=url,
                content_type=content_type,
                activity="网页访问",
                activity_target=url,
            )
        return metadata

    sni = _extract_tls_sni(payload)
    if sni:
        metadata.update(
            hostname=sni,
            tls_sni=sni,
            url=f"https://{sni}/",
            activity="加密站点访问",
            activity_target=sni,
        )
    return metadata


class ProcessResolver:
    """Best-effort local process correlation using the operating system connection table."""

    def __init__(self, refresh_seconds: float = 2.0) -> None:
        self.refresh_seconds = refresh_seconds
        self._refreshed_at = 0.0
        self._exact: dict[tuple[str, int, str, int, str], tuple[str, int]] = {}
        self._local: dict[tuple[str, int, str], tuple[str, int]] = {}

    @staticmethod
    def _address(value: object) -> tuple[str, int]:
        if not value:
            return "", 0
        try:
            return str(getattr(value, "ip", value[0])), int(getattr(value, "port", value[1]))
        except (IndexError, TypeError, ValueError):
            return "", 0

    def _refresh(self) -> None:
        if time.monotonic() - self._refreshed_at < self.refresh_seconds:
            return
        self._refreshed_at = time.monotonic()
        self._exact.clear()
        self._local.clear()
        try:
            import psutil
            for connection in psutil.net_connections(kind="inet"):
                if not connection.pid or not connection.laddr:
                    continue
                local_ip, local_port = self._address(connection.laddr)
                remote_ip, remote_port = self._address(connection.raddr)
                protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
                try:
                    process_name = psutil.Process(connection.pid).name()
                except (psutil.Error, OSError):
                    continue
                process = (_clean_text(process_name, 120), int(connection.pid))
                self._local[(local_ip, local_port, protocol)] = process
                if remote_ip:
                    self._exact[(local_ip, local_port, remote_ip, remote_port, protocol)] = process
        except ImportError:
            return
        except (OSError, PermissionError):
            return

    def resolve(self, record: dict[str, object]) -> tuple[str, int]:
        protocol = str(record["protocol"])
        if protocol not in {"TCP", "UDP"}:
            return "", 0
        self._refresh()
        src_ip, dst_ip = str(record["src_ip"]), str(record["dst_ip"])
        src_port, dst_port = int(record["src_port"]), int(record["dst_port"])
        process = (
            self._exact.get((src_ip, src_port, dst_ip, dst_port, protocol))
            or self._exact.get((dst_ip, dst_port, src_ip, src_port, protocol))
            or self._local.get((src_ip, src_port, protocol))
            or self._local.get((dst_ip, dst_port, protocol))
        )
        return process or ("", 0)


def packet_to_record(packet: Any, process_resolver: ProcessResolver | None = None) -> dict[str, object] | None:
    """Extract analysis fields and selected protocol metadata from an IP packet."""
    scapy = _require_scapy()
    ip_layer = packet.getlayer(scapy["IP"]) or packet.getlayer(scapy["IPv6"])
    if ip_layer is None:
        return None

    tcp_layer = packet.getlayer(scapy["TCP"])
    udp_layer = packet.getlayer(scapy["UDP"])
    src_port = int(tcp_layer.sport if tcp_layer else udp_layer.sport if udp_layer else 0)
    dst_port = int(tcp_layer.dport if tcp_layer else udp_layer.dport if udp_layer else 0)
    protocol = "TCP" if tcp_layer else "UDP" if udp_layer else str(getattr(ip_layer, "nh", getattr(ip_layer, "proto", "OTHER")))
    if protocol == "1":
        protocol = "ICMP"
    elif protocol == "58":
        protocol = "ICMPV6"
    timestamp = pd.to_datetime(float(getattr(packet, "time", datetime.now(timezone.utc).timestamp())), unit="s")
    src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
    record: dict[str, object] = {
        "timestamp": timestamp.tz_localize(None),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes": max(len(packet), 0),
        "app_category": categorise_traffic(protocol, src_port, dst_port),
        "user": _display_user(src_ip, dst_ip),
    }
    record.update(_extract_activity_metadata(packet, scapy, src_port, dst_port))
    if process_resolver is not None:
        process_name, process_id = process_resolver.resolve(record)
        record["process_name"] = process_name
        record["process_id"] = process_id
    return record


def read_packet_capture(path: Path) -> tuple[pd.DataFrame, list[str]]:
    scapy = _require_scapy()
    records: list[dict[str, object]] = []
    skipped = 0
    try:
        with scapy["PcapReader"](str(path)) as capture:
            for packet in capture:
                record = packet_to_record(packet)
                if record is None:
                    skipped += 1
                else:
                    records.append(record)
    except Exception as error:
        raise TrafficImportError(f"流量包读取失败：{error}") from error
    if not records:
        raise TrafficImportError("流量包中没有 IPv4/IPv6 数据包。")
    warnings = [f"已跳过 {skipped} 个非 IP 数据包。"] if skipped else []
    return pd.DataFrame(records, columns=CANONICAL_COLUMNS), warnings


def load_traffic_file(path: Path) -> tuple[pd.DataFrame, dict[str, object]]:
    suffix = path.suffix.lower().lstrip(".")
    if suffix not in SUPPORTED_EXTENSIONS:
        raise TrafficImportError("仅支持 CSV、PCAP、PCAPNG 和 CAP 文件。")
    dataframe, warnings = read_csv_traffic(path) if suffix == "csv" else read_packet_capture(path)
    return dataframe, {
        "name": path.name,
        "type": suffix.upper(),
        "records": int(len(dataframe)),
        "warnings": warnings,
    }


def save_canonical_csv(dataframe: pd.DataFrame, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    dataframe[CANONICAL_COLUMNS].to_csv(destination, index=False, encoding="utf-8-sig")
    return destination


class LiveCaptureService:
    """Owns one bounded live capture session and its evidence files."""

    def __init__(self, output_path: Path, evidence_dir: Path | None = None, max_records: int = 100_000) -> None:
        self.output_path = output_path
        self.evidence_dir = evidence_dir or output_path.parent / "captures"
        self.max_records = max_records
        self._records: deque[dict[str, object]] = deque(maxlen=max_records)
        self._lock = Lock()
        self._sniffer: Any | None = None
        self._pcap_writer: Any | None = None
        self._auto_stop_timer: Timer | None = None
        self._started_at: datetime | None = None
        self._duration_seconds = 0
        self._retention_days = 3
        self._capture_id = ""
        self._pcap_path: Path | None = None
        self._metadata_path: Path | None = None
        self._auto_stopped = False
        self._interface = ""
        self._bpf_filter = ""
        self._dropped = 0
        self._errors: deque[str] = deque(maxlen=5)
        self._process_resolver = ProcessResolver()
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.cleanup_expired(self._retention_days)

    def available_interfaces(self) -> list[str]:
        return [str(interface) for interface in _require_scapy()["get_if_list"]()]

    @property
    def retention_days(self) -> int:
        return self._retention_days

    def start(
        self,
        interface: str = "",
        bpf_filter: str = "",
        duration_seconds: int = 0,
        retention_days: int = 3,
        evidence_dir: Path | None = None,
    ) -> None:
        scapy = _require_scapy()
        with self._lock:
            if self.is_running:
                raise TrafficImportError("实时采集正在运行。")
            if duration_seconds < 0 or duration_seconds > 86_400:
                raise TrafficImportError("保存时长必须是 0 到 86400 秒，0 表示手动停止。")
            if retention_days < 1 or retention_days > 365:
                raise TrafficImportError("自动删除时间必须是 1 到 365 天。")
            if evidence_dir is not None:
                evidence_dir = Path(evidence_dir).expanduser()
                if evidence_dir.exists() and not evidence_dir.is_dir():
                    raise TrafficImportError("证据保存路径不是目录。")
                self.evidence_dir = evidence_dir
                self.evidence_dir.mkdir(parents=True, exist_ok=True)
            self.cleanup_expired(retention_days)
            self._records.clear()
            self._dropped = 0
            self._errors.clear()
            self._duration_seconds = duration_seconds
            self._retention_days = retention_days
            self._auto_stopped = False
            self._capture_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]
            self._pcap_path = self.evidence_dir / f"capture_{self._capture_id}.pcap"
            self._metadata_path = self.evidence_dir / f"capture_{self._capture_id}_metadata.csv"
            self._interface = interface
            self._bpf_filter = bpf_filter.strip()
            self._started_at = datetime.now()
            options: dict[str, object] = {"prn": self._on_packet, "store": False}
            if interface:
                options["iface"] = interface
            if self._bpf_filter:
                options["filter"] = self._bpf_filter
            try:
                self._pcap_writer = scapy["PcapWriter"](str(self._pcap_path), append=False, sync=True)
                self._sniffer = scapy["AsyncSniffer"](**options)
                self._sniffer.start()
                if duration_seconds:
                    self._auto_stop_timer = Timer(duration_seconds, self._auto_stop)
                    self._auto_stop_timer.daemon = True
                    self._auto_stop_timer.start()
            except Exception as error:
                self._sniffer = None
                if self._pcap_writer is not None:
                    self._pcap_writer.close()
                self._pcap_writer = None
                self._started_at = None
                raise TrafficImportError(f"实时抓包启动失败：{error}") from error

    def _auto_stop(self) -> None:
        try:
            self.stop(auto=True)
        except Exception as error:
            with self._lock:
                self._errors.append(f"自动停止失败：{error}")

    @property
    def is_running(self) -> bool:
        return self._sniffer is not None and bool(getattr(self._sniffer, "running", False))

    def _on_packet(self, packet: Any) -> None:
        try:
            with self._lock:
                if self._pcap_writer is not None:
                    self._pcap_writer.write(packet)
            record = packet_to_record(packet, self._process_resolver)
            if record is None:
                return
            with self._lock:
                if len(self._records) == self.max_records:
                    self._dropped += 1
                self._records.append(record)
        except Exception as error:
            with self._lock:
                self._errors.append(str(error))

    def stop(self, auto: bool = False) -> int:
        timer = None
        with self._lock:
            sniffer = self._sniffer
            self._sniffer = None
            timer = self._auto_stop_timer
            self._auto_stop_timer = None
            if auto:
                self._auto_stopped = True
        if timer is not None and timer is not current_thread():
            timer.cancel()
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as error:
                with self._lock:
                    self._errors.append(str(error))
        with self._lock:
            writer = self._pcap_writer
            self._pcap_writer = None
        if writer is not None:
            try:
                writer.close()
            except Exception as error:
                with self._lock:
                    self._errors.append(str(error))
        return self.persist()

    def persist(self) -> int:
        with self._lock:
            snapshot = list(self._records)
        if not snapshot:
            if self._metadata_path is not None:
                save_canonical_csv(pd.DataFrame(columns=CANONICAL_COLUMNS), self._metadata_path)
            return 0
        dataframe = pd.DataFrame(snapshot, columns=CANONICAL_COLUMNS)
        save_canonical_csv(dataframe, self.output_path)
        if self._metadata_path is not None:
            save_canonical_csv(dataframe, self._metadata_path)
        return len(snapshot)

    def cleanup_expired(self, retention_days: int | None = None) -> int:
        """Delete only files generated by this service after the configured retention period."""
        days = retention_days or self._retention_days
        cutoff = time.time() - days * 86_400
        deleted = 0
        if not self.evidence_dir.exists():
            return deleted
        for path in self.evidence_dir.glob("capture_*"):
            if path.suffix.lower() not in {".pcap", ".pcapng", ".cap", ".csv"}:
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    deleted += 1
            except OSError:
                continue
        return deleted

    def list_evidence(self) -> list[dict[str, object]]:
        files: list[dict[str, object]] = []
        if not self.evidence_dir.exists():
            return files
        for path in sorted(self.evidence_dir.glob("capture_*"), key=lambda item: item.stat().st_mtime, reverse=True):
            if path.suffix.lower() not in {".pcap", ".pcapng", ".cap", ".csv"}:
                continue
            try:
                stat = path.stat()
                files.append({
                    "name": path.name,
                    "path": str(path),
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                })
            except OSError:
                continue
        return files

    def status(self) -> dict[str, object]:
        with self._lock:
            rows = list(self._records)
            category_counts = Counter(row["app_category"] for row in rows)
            activity_counts = Counter(str(row.get("activity") or "未识别") for row in rows)
            hostname_counts = Counter(str(row.get("hostname") or row.get("dns_query") or row.get("tls_sni") or "") for row in rows)
            process_counts = Counter(str(row.get("process_name") or "") for row in rows)
            download_rows = [row for row in rows if row.get("download_name")]
            total_bytes = sum(int(row["bytes"]) for row in rows)
            unique_ips = {str(row["src_ip"]) for row in rows} | {str(row["dst_ip"]) for row in rows}
            duration = (datetime.now() - self._started_at).total_seconds() if self._started_at else 0
            self.cleanup_expired(self._retention_days)
            return {
                "running": self.is_running,
                "interface": self._interface,
                "filter": self._bpf_filter,
                "started_at": self._started_at.isoformat(timespec="seconds") if self._started_at else None,
                "duration_seconds": max(math.floor(duration), 0),
                "duration_limit_seconds": self._duration_seconds,
                "retention_days": self._retention_days,
                "evidence_dir": str(self.evidence_dir),
                "pcap_path": str(self._pcap_path) if self._pcap_path else None,
                "metadata_path": str(self._metadata_path) if self._metadata_path else None,
                "auto_stopped": self._auto_stopped,
                "total_packets": len(rows),
                "total_bytes": total_bytes,
                "unique_ips": len(unique_ips),
                "dropped_packets": self._dropped,
                "categories": [{"category": key, "packets": value} for key, value in category_counts.most_common()],
                "activities": [
                    {"activity": key, "packets": value}
                    for key, value in activity_counts.most_common()
                    if key != "未识别" or value
                ],
                "top_hosts": [
                    {"host": key, "packets": value}
                    for key, value in hostname_counts.most_common(10)
                    if key
                ],
                "top_processes": [
                    {"process": key, "packets": value}
                    for key, value in process_counts.most_common(10)
                    if key
                ],
                "downloads": [
                    {
                        "time": str(row["timestamp"]),
                        "name": row.get("download_name", ""),
                        "source": row.get("hostname", "") or row.get("src_ip", ""),
                        "content_type": row.get("content_type", ""),
                        "bytes": row.get("bytes", 0),
                    }
                    for row in download_rows[-10:][::-1]
                ],
                "recent_packets": [
                    {
                        **record,
                        "timestamp": str(record["timestamp"]),
                    }
                    for record in rows[-20:][::-1]
                ],
                "errors": list(self._errors),
            }
