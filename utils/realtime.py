"""Traffic replay and real-time event bus for campus network monitoring."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)


from utils.constants import (
    SUSPICIOUS_PORTS,
    REALTIME_WINDOW_SIZE as WINDOW_SIZE,
    REALTIME_TRAFFIC_BUCKETS as TRAFFIC_BUCKETS,
    REALTIME_BUCKET_SECONDS as BUCKET_SECONDS,
    REALTIME_PORT_SCAN_THRESHOLD as PORT_SCAN_THRESHOLD,
    REALTIME_PORT_SCAN_WINDOW as PORT_SCAN_WINDOW,
    REALTIME_LARGE_FLOW_BYTES as LARGE_FLOW_BYTES,
)


@dataclass
class ReplayMetrics:
    """Cumulative real-time metrics collected during replay."""
    sent_events: int = 0
    total_bytes: int = 0
    unique_users: set = field(default_factory=set)
    unique_src_ips: set = field(default_factory=set)
    alerts_triggered: int = 0
    started_at: Optional[float] = None
    last_event_at: Optional[float] = None

    def snapshot(self) -> Dict[str, Any]:
        """Return a snapshot of current metrics as a dictionary."""
        return {
            "sent_events": self.sent_events,
            "total_bytes": int(self.total_bytes),
            "unique_users": len(self.unique_users),
            "unique_src_ips": len(self.unique_src_ips),
            "alerts_triggered": self.alerts_triggered,
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
        }


class ReplayEngine:
    """Thread-safe traffic replay engine with singleton pattern."""

    _instance: Optional["ReplayEngine"] = None
    _instance_lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        """Initialize the replay engine with default state."""
        self._lock: threading.RLock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop_flag: threading.Event = threading.Event()
        self._subscribers: List[queue.Queue] = []
        self._df: Optional[pd.DataFrame] = None
        self._rate: float = 5.0
        self._loop: bool = True
        self._metrics: ReplayMetrics = ReplayMetrics()
        self._recent_events: Deque[Dict[str, Any]] = deque(maxlen=WINDOW_SIZE)
        self._traffic_buckets: Deque[Dict[str, Any]] = deque(maxlen=TRAFFIC_BUCKETS)
        self._port_seen: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=64))
        self._alert_history: Deque[Dict[str, Any]] = deque(maxlen=500)

    @classmethod
    def instance(cls) -> "ReplayEngine":
        """Return the singleton ReplayEngine instance."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # ----- 控制接口 ----------------------------------------------------

    def start(self, df: pd.DataFrame, rate: float = 5.0, loop: bool = True) -> Dict[str, Any]:
        """Start the replay engine with the given DataFrame."""
        with self._lock:
            if self.is_running():
                return {"status": "already_running", "message": "回放线程已在运行。"}
            if df is None or df.empty:
                return {"status": "error", "message": "数据为空，无法启动回放。"}

            self._df = self._prepare(df)
            self._rate = max(0.5, float(rate))
            self._loop = bool(loop)
            self._stop_flag.clear()
            self._reset_state()
            self._metrics.started_at = time.time()

            self._thread = threading.Thread(target=self._run, name="replay-engine", daemon=True)
            self._thread.start()
            logger.info("流量回放已启动: rate=%.1f loop=%s rows=%d", self._rate, self._loop, len(self._df))
            return {"status": "started", "rate": self._rate, "loop": self._loop, "rows": len(self._df)}

    def stop(self) -> Dict[str, Any]:
        """Stop the replay engine."""
        with self._lock:
            if not self.is_running():
                return {"status": "not_running"}
            self._stop_flag.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("流量回放已停止")
        return {"status": "stopped"}

    def set_rate(self, rate: float) -> Dict[str, Any]:
        """Change the replay rate on the fly without restarting."""
        with self._lock:
            self._rate = max(0.5, float(rate))
        logger.info("回放速率已调整: %.1f/s", self._rate)
        return {"status": "ok", "rate": self._rate}

    def is_running(self) -> bool:
        """Check if the replay engine is currently running."""
        return self._thread is not None and self._thread.is_alive() and not self._stop_flag.is_set()

    def status(self) -> Dict[str, Any]:
        """Return the current status and metrics of the replay engine."""
        with self._lock:
            return {
                "running": self.is_running(),
                "rate": self._rate,
                "loop": self._loop,
                "subscribers": len(self._subscribers),
                "metrics": self._metrics.snapshot(),
                "recent_events": list(self._recent_events)[-20:],
                "traffic_buckets": list(self._traffic_buckets),
            }

    def get_alert_history(self) -> List[Dict[str, Any]]:
        """Return all alerts with timestamps from the alert history."""
        with self._lock:
            return list(self._alert_history)

    # ----- 订阅接口 ----------------------------------------------------

    def subscribe(self) -> queue.Queue:
        """Subscribe a new queue to receive replay events."""
        q: queue.Queue = queue.Queue(maxsize=512)
        with self._lock:
            self._subscribers.append(q)
            # 新订阅者先收到一份"快照"，避免大屏空白
            try:
                q.put_nowait({"type": "snapshot", "payload": self.status()})
            except queue.Full:
                pass
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Unsubscribe a queue from receiving replay events."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    # ----- 内部实现 ----------------------------------------------------

    def _prepare(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare and normalize the DataFrame for replay."""
        df = df.copy()
        for col in ["bytes", "src_port", "dst_port"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        for col in ["user", "src_ip", "dst_ip", "protocol", "app_category"]:
            if col not in df.columns:
                df[col] = "unknown"
            else:
                df[col] = df[col].fillna("unknown").astype(str)
        return df.reset_index(drop=True)

    def _reset_state(self) -> None:
        """Reset engine state while preserving start time."""
        self._metrics = ReplayMetrics(started_at=self._metrics.started_at)
        self._recent_events.clear()
        self._traffic_buckets.clear()
        self._port_seen.clear()
        self._alert_history.clear()

    def _run(self) -> None:
        """Main replay loop that broadcasts events to subscribers."""
        assert self._df is not None
        try:
            while not self._stop_flag.is_set():
                for _, row in self._df.iterrows():
                    if self._stop_flag.is_set():
                        break
                    event = self._build_event(row)
                    self._update_state(event)
                    self._broadcast({"type": "event", "payload": event})
                    self._broadcast({"type": "metrics", "payload": self.status()})
                    # 每次循环重新读取 rate，运行中改速率才能即时生效
                    interval = 1.0 / max(0.5, self._rate)
                    time.sleep(interval)
                if not self._loop:
                    break
        except Exception:
            logger.exception("回放线程异常退出")
        finally:
            self._broadcast({"type": "finished", "payload": self._metrics.snapshot()})

    def _build_event(self, row: pd.Series) -> Dict[str, Any]:
        """Build an event dictionary from a DataFrame row."""
        bytes_val = int(row.get("bytes", 0))
        return {
            "ts": time.time(),
            "user": str(row.get("user", "unknown")),
            "src_ip": str(row.get("src_ip", "unknown")),
            "dst_ip": str(row.get("dst_ip", "unknown")),
            "src_port": int(row.get("src_port", 0)),
            "dst_port": int(row.get("dst_port", 0)),
            "protocol": str(row.get("protocol", "unknown")),
            "bytes": bytes_val,
            "app_category": str(row.get("app_category", "unknown")),
        }

    def _update_state(self, event: Dict[str, Any]) -> None:
        """Update engine metrics and state from a new event."""
        with self._lock:
            self._metrics.sent_events += 1
            self._metrics.total_bytes += event["bytes"]
            self._metrics.unique_users.add(event["user"])
            self._metrics.unique_src_ips.add(event["src_ip"])
            self._metrics.last_event_at = event["ts"]
            self._recent_events.append(event)

            self._update_buckets(event)
            alerts = self._check_alerts(event)
            for alert in alerts:
                self._metrics.alerts_triggered += 1
                self._alert_history.append(alert)
                self._broadcast({"type": "alert", "payload": alert})

    def _update_buckets(self, event: Dict[str, Any]) -> None:
        """Update traffic time buckets with a new event's data."""
        bucket_ts = int(event["ts"] // BUCKET_SECONDS) * BUCKET_SECONDS
        if not self._traffic_buckets:
            self._traffic_buckets.append({"ts": bucket_ts, "bytes": 0, "events": 0})
        last_ts = self._traffic_buckets[-1]["ts"]
        if bucket_ts > last_ts:
            next_ts = last_ts + BUCKET_SECONDS
            while next_ts < bucket_ts:
                self._traffic_buckets.append({"ts": next_ts, "bytes": 0, "events": 0})
                next_ts += BUCKET_SECONDS
            self._traffic_buckets.append({"ts": bucket_ts, "bytes": 0, "events": 0})
        cur = self._traffic_buckets[-1]
        cur["bytes"] += event["bytes"]
        cur["events"] += 1

    def _check_alerts(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check a new event for port scan, large flow, and sensitive port alerts."""
        alerts: List[Dict[str, Any]] = []
        now = event["ts"]

        # 端口扫描：同一源 IP 在窗口期内访问超过阈值数量的不同端口
        seen = self._port_seen[event["src_ip"]]
        seen.append((now, event["dst_port"]))
        recent = [(ts, p) for ts, p in seen if now - ts <= PORT_SCAN_WINDOW]
        unique_ports = {p for _, p in recent}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "ts": now,
                "level": "high",
                "title": "实时端口扫描",
                "entity": event["src_ip"],
                "detail": f"30 秒内访问 {len(unique_ports)} 个不同端口",
            })
            seen.clear()  # 触发后清空，避免连环刷屏

        # 单条大流量
        if event["bytes"] >= LARGE_FLOW_BYTES:
            alerts.append({
                "ts": now,
                "level": "medium",
                "title": "大流量突发",
                "entity": event["user"],
                "detail": f"单条 {event['bytes']} 字节，目标 {event['dst_ip']}:{event['dst_port']}",
            })

        # 敏感端口访问
        if event["dst_port"] in SUSPICIOUS_PORTS:
            alerts.append({
                "ts": now,
                "level": "medium",
                "title": "敏感端口访问",
                "entity": f"{event['user']} / {event['src_ip']}",
                "detail": f"目标端口 {event['dst_port']}",
            })

        return alerts

    def _broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all active subscriber queues."""
        with self._lock:
            dead: List[queue.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(message)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)


def sse_format(message: Dict[str, Any]) -> str:
    """Serialize a message dictionary into SSE format."""
    return f"event: {message.get('type', 'message')}\ndata: {json.dumps(message.get('payload'), ensure_ascii=False)}\n\n"


def stream_events(stop_event: threading.Event, heartbeat_interval: float = 15.0) -> Iterable[str]:
    """Subscribe to the replay engine and yield SSE-formatted event strings."""
    engine = ReplayEngine.instance()
    q = engine.subscribe()
    try:
        last_heartbeat = time.time()
        while not stop_event.is_set():
            try:
                msg = q.get(timeout=1.0)
                yield sse_format(msg)
            except queue.Empty:
                pass

            now = time.time()
            if now - last_heartbeat >= heartbeat_interval:
                yield ": heartbeat\n\n"
                last_heartbeat = now
    finally:
        engine.unsubscribe(q)
