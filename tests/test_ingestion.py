from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import os
import time
import unittest

import pandas as pd
from scapy.all import DNS, DNSQR, Ether, IP, PcapNgWriter, PcapReader, PcapWriter, Raw, TCP, UDP, wrpcap

from utils.ingestion import (
    CANONICAL_COLUMNS,
    canonicalise_dataframe,
    load_traffic_file,
    packet_to_record,
    LiveCaptureService,
)


class TrafficIngestionTests(unittest.TestCase):
    def test_wireshark_style_csv_is_normalised(self) -> None:
        source = pd.DataFrame(
            {
                "frame.time_epoch": [1_704_067_200.0],
                "ip.src": ["192.168.43.10"],
                "ip.dst": ["8.8.8.8"],
                "udp.srcport": [51234],
                "udp.dstport": [53],
                "_ws.col.protocol": ["UDP"],
                "frame.len": [88],
            }
        )
        dataframe, warnings = canonicalise_dataframe(source)
        self.assertEqual(list(dataframe.columns), CANONICAL_COLUMNS)
        self.assertEqual(dataframe.iloc[0]["app_category"], "DNS")
        self.assertEqual(dataframe.iloc[0]["user"], "192.168.43.10")
        self.assertEqual(int(dataframe.iloc[0]["bytes"]), 88)
        self.assertEqual(warnings, [])

    def test_pcap_is_converted_to_common_schema(self) -> None:
        with TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "sample.pcap"
            wrpcap(
                str(capture_path),
                [
                    Ether(dst="00:11:22:33:44:55") / IP(src="192.168.43.10", dst="1.1.1.1") / UDP(sport=50000, dport=53),
                    Ether(dst="00:11:22:33:44:55") / IP(src="192.168.43.10", dst="93.184.216.34") / TCP(sport=50001, dport=443),
                ],
            )
            dataframe, metadata = load_traffic_file(capture_path)
        self.assertEqual(len(dataframe), 2)
        self.assertEqual(metadata["type"], "PCAP")
        self.assertEqual(dataframe.iloc[0]["app_category"], "DNS")
        self.assertEqual(dataframe.iloc[1]["app_category"], "Encrypted Web")

    def test_packet_metadata_does_not_include_payload(self) -> None:
        packet = Ether(dst="00:11:22:33:44:55") / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=23456, dport=443) / b"not-retained"
        record = packet_to_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(set(record), set(CANONICAL_COLUMNS))
        self.assertEqual(record["app_category"], "Encrypted Web")
        self.assertNotIn("not-retained", str(record))

    def test_http_page_url_redacts_query_values(self) -> None:
        packet = (
            Ether(dst="00:11:22:33:44:55")
            / IP(src="192.168.43.10", dst="93.184.216.34")
            / TCP(sport=50001, dport=80)
            / Raw(b"GET /course?id=42&token=secret HTTP/1.1\r\nHost: campus.example.edu\r\n\r\n")
        )
        record = packet_to_record(packet)
        self.assertEqual(record["activity"], "网页访问")
        self.assertEqual(record["hostname"], "campus.example.edu")
        self.assertEqual(record["url"], "http://campus.example.edu/course?id&token")
        self.assertNotIn("secret", str(record))

    def test_dns_and_http_download_metadata_are_extracted(self) -> None:
        dns_packet = Ether(dst="00:11:22:33:44:55") / IP(src="192.168.43.10", dst="8.8.8.8") / UDP(sport=50002, dport=53) / DNS(rd=1, qd=DNSQR(qname="download.example.edu"))
        dns_record = packet_to_record(dns_packet)
        self.assertEqual(dns_record["dns_query"], "download.example.edu")
        self.assertEqual(dns_record["activity"], "DNS 查询")

        response_packet = (
            Ether(dst="00:11:22:33:44:55")
            / IP(src="93.184.216.34", dst="192.168.43.10")
            / TCP(sport=80, dport=50001)
            / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=guide.pdf\r\n\r\n")
        )
        response_record = packet_to_record(response_packet)
        self.assertEqual(response_record["activity"], "文件下载")
        self.assertEqual(response_record["download_name"], "guide.pdf")
        self.assertEqual(response_record["content_type"], "application/pdf")

    def test_pcapng_is_converted_to_common_schema(self) -> None:
        with TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "sample.pcapng"
            writer = PcapNgWriter(str(capture_path))
            writer.write(Ether(dst="00:11:22:33:44:55") / IP(src="192.168.43.10", dst="8.8.4.4") / UDP(sport=50002, dport=53))
            writer.close()
            dataframe, metadata = load_traffic_file(capture_path)
        self.assertEqual(len(dataframe), 1)
        self.assertEqual(metadata["type"], "PCAPNG")
        self.assertEqual(dataframe.iloc[0]["app_category"], "DNS")

    def test_evidence_writes_raw_packets_and_metadata_and_cleans_old_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metadata_path = root / "live.csv"
            evidence_dir = root / "captures"
            service = LiveCaptureService(metadata_path, evidence_dir=evidence_dir)
            packet_path = evidence_dir / "capture_test.pcap"
            service._pcap_path = packet_path
            service._metadata_path = evidence_dir / "capture_test_metadata.csv"
            service._pcap_writer = PcapWriter(str(packet_path), sync=True)
            packet = Ether(dst="00:11:22:33:44:55") / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=50000, dport=53)
            service._on_packet(packet)
            service._pcap_writer.close()
            service._pcap_writer = None
            self.assertEqual(service.persist(), 1)

            with PcapReader(str(packet_path)) as reader:
                self.assertEqual(sum(1 for _ in reader), 1)
            self.assertTrue(service._metadata_path.exists())
            self.assertIn("10.0.0.2", service._metadata_path.read_text(encoding="utf-8-sig"))

            old_file = evidence_dir / "capture_old.pcap"
            old_file.write_bytes(b"old")
            old_time = time.time() - 4 * 86_400
            os.utime(old_file, (old_time, old_time))
            self.assertEqual(service.cleanup_expired(3), 1)
            self.assertFalse(old_file.exists())


if __name__ == "__main__":
    unittest.main()
