"""Test the Prometheus-style metrics registry."""

import pytest
from utils.metrics import MetricsRegistry


@pytest.fixture
def registry():
    return MetricsRegistry()


class TestCounter:
    def test_increment_default(self, registry):
        registry.increment("requests_total")
        output = registry.dump()
        assert "requests_total" in output
        assert "counter" in output

    def test_increment_with_value(self, registry):
        registry.increment("bytes_total", value=4096)
        assert "4096" in registry.dump()

    def test_increment_with_labels(self, registry):
        registry.increment("requests_total", labels={"method": "GET", "endpoint": "/api/test"})
        dump = registry.dump()
        assert "method=\"GET\"" in dump
        assert "endpoint=\"/api/test\"" in dump

    def test_multiple_increments(self, registry):
        for _ in range(5):
            registry.increment("hits")
        dump = registry.dump()
        assert "hits" in dump

    def test_label_sorting_stable(self, registry):
        registry.increment("m", labels={"z": "1", "a": "2"})
        dump = registry.dump()
        assert "a=\"2\"" in dump
        assert "z=\"1\"" in dump


class TestGauge:
    def test_gauge_set(self, registry):
        registry.gauge("temperature", 36.5)
        dump = registry.dump()
        assert "temperature" in dump
        assert "gauge" in dump

    def test_gauge_overwrite(self, registry):
        registry.gauge("temperature", 36.5)
        registry.gauge("temperature", 37.0)
        assert "37.0" in registry.dump()

    def test_gauge_with_labels(self, registry):
        registry.gauge("cpu_usage", 0.85, labels={"core": "0"})
        dump = registry.dump()
        assert "cpu_usage" in dump
        assert "core=\"0\"" in dump


class TestHistogram:
    def test_observe_single(self, registry):
        registry.observe("request_duration", 0.042)
        dump = registry.dump()
        assert "histogram" in dump
        assert "_count" in dump
        assert "_sum" in dump

    def test_observe_multiple(self, registry):
        for v in [0.1, 0.2, 0.3]:
            registry.observe("latency", v)
        dump = registry.dump()
        assert "latency_count" in dump

    def test_histogram_with_labels(self, registry):
        registry.observe("latency", 0.05, labels={"endpoint": "/api"})
        dump = registry.dump()
        assert "endpoint=\"/api\"" in dump


class TestDumpFormat:
    def test_dump_is_string(self, registry):
        registry.increment("test")
        assert isinstance(registry.dump(), str)

    def test_dump_multiple_metric_types(self, registry):
        registry.increment("counter_1")
        registry.gauge("gauge_1", 1.0)
        registry.observe("hist_1", 0.5)
        dump = registry.dump()
        assert "counter" in dump
        assert "gauge" in dump
        assert "histogram" in dump
        assert dump.count("\n") >= 6

    def test_dump_empty_registry(self, registry):
        dump = registry.dump()
        assert dump == ""


class TestEdgeCases:
    def test_increment_large_value(self, registry):
        registry.increment("big", value=2**31 - 1)
        assert str(2**31 - 1) in registry.dump()

    def test_multiple_label_values(self, registry):
        registry.increment("req", labels={"a": "1", "b": "2", "c": "3"})
        dump = registry.dump()
        for k in ("a", "b", "c"):
            assert f"{k}=\"" in dump

    def test_metric_names_with_underscores(self, registry):
        registry.increment("my_custom_metric_total")
        assert "my_custom_metric_total" in registry.dump()
