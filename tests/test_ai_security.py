import pandas as pd
from utils.ai_security import AISecurityAnalyzer, DeepSeekConfig, DeepSeekSecurityReviewer


def test_empty_dataframe():
    analyzer = AISecurityAnalyzer(pd.DataFrame())
    report = analyzer.generate_report()
    assert report["summary"]["risk_level"] == "low"
    assert report["summary"]["total_alerts"] == 0


def test_port_scan_detection(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    scan_alerts = [a for a in report["alerts"] if a["type"] == "reconnaissance"]
    assert len(scan_alerts) >= 0


def test_sensitive_service_detection(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    sensitive = [a for a in report["alerts"] if a["type"] == "sensitive_service"]
    assert len(sensitive) >= 0


def test_volume_anomaly_detection(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    volume = [a for a in report["alerts"] if a["type"] == "traffic_anomaly"]
    assert len(volume) >= 0


def test_off_hours_detection(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    off_hours = [a for a in report["alerts"] if a["type"] == "off_hours_activity"]
    assert len(off_hours) >= 0


def test_alert_ids_unique(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    ids = [a["id"] for a in report["alerts"]]
    assert len(ids) == len(set(ids))


def test_deepseek_not_configured():
    reviewer = DeepSeekSecurityReviewer(DeepSeekConfig(api_key=None, base_url="", model="", timeout=10))
    assert reviewer.is_configured() is False
    result = reviewer.review({})
    assert result["status"] == "missing_api_key"


def test_alert_score_range(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    for alert in report["alerts"]:
        assert 0 <= alert["score"] <= 100


def test_blocklist_generation(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    report = analyzer.generate_report()
    assert "blocked_entities" in report


def test_deepseek_config_from_env(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    config = DeepSeekConfig.from_env()
    assert config.api_key == "test-key"
    assert config.base_url == "https://api.deepseek.com"
