"""Prometheus-style metrics for the campus network application."""

import time
from typing import Dict


class MetricsRegistry:
    """Simple in-memory Prometheus-style metrics registry."""

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, list] = {}

    def increment(self, name: str, labels: Dict[str, str] = None, value: int = 1) -> None:
        key = self._format_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def gauge(self, name: str, value: float, labels: Dict[str, str] = None) -> None:
        key = self._format_key(name, labels)
        self._gauges[key] = value

    def observe(self, name: str, value: float, labels: Dict[str, str] = None) -> None:
        key = self._format_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)

    def _format_key(self, name: str, labels: Dict[str, str] = None) -> str:
        if not labels:
            return name
        parts = [name]
        for k, v in sorted(labels.items()):
            parts.append(f'{k}="{v}"')
        return '{' + ','.join(parts) + '}'

    def dump(self) -> str:
        lines = []
        now = time.time()
        for key, val in sorted(self._counters.items()):
            lines.append(f'# HELP {key} Counter metric')
            lines.append(f'# TYPE {key} counter')
            lines.append(f'{key} {val} {int(now * 1000)}')
        for key, val in sorted(self._gauges.items()):
            lines.append(f'# HELP {key} Gauge metric')
            lines.append(f'# TYPE {key} gauge')
            lines.append(f'{key} {val} {int(now * 1000)}')
        for key, vals in sorted(self._histograms.items()):
            lines.append(f'# HELP {key} Histogram metric')
            lines.append(f'# TYPE {key} histogram')
            for v in vals:
                lines.append(f'{key}_bucket{{le="+Inf"}} {v} {int(now * 1000)}')
            lines.append(f'{key}_count {len(vals)} {int(now * 1000)}')
            lines.append(f'{key}_sum {sum(vals)} {int(now * 1000)}')
        return '\n'.join(lines)


registry = MetricsRegistry()

requests_total = lambda labels=None: registry.increment('requests_total', labels)
bytes_processed = lambda n, labels=None: registry.increment('bytes_processed_total', labels, value=n)
alerts_total = lambda labels=None: registry.increment('alerts_total', labels)
request_duration = lambda sec, labels=None: registry.observe('request_duration_seconds', sec, labels)
