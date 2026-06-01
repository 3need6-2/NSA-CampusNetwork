import pandas as pd
from utils.ml_anomaly import MLAnomalyDetector, AnomalyConfig


def test_empty_dataframe():
    detector = MLAnomalyDetector(pd.DataFrame())
    result = detector.detect()
    assert result["status"] == "skipped"


def test_missing_user_column():
    df = pd.DataFrame({"bytes": [100, 200]})
    detector = MLAnomalyDetector(df)
    result = detector.detect()
    assert result["status"] == "skipped"


def test_fewer_users_than_minimum(sample_df):
    config = AnomalyConfig(min_users=100, contamination=0.1)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect()
    assert result["status"] == "skipped"
    assert "少于" in result["message"]


def test_anomaly_detection_with_data(sample_df):
    config = AnomalyConfig(contamination=0.3, top_n=10)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect()
    if result["status"] == "ok":
        assert result["model"] == "IsolationForest"
        assert "summary" in result
        assert result["summary"]["total_users"] > 0
        assert "anomalies" in result
        for anomaly in result["anomalies"]:
            assert "user" in anomaly
            assert "anomaly_score" in anomaly
            assert "severity" in anomaly


def test_feature_extraction(sample_df):
    detector = MLAnomalyDetector(sample_df)
    features = detector._build_features()
    assert len(features) > 0
    expected = [
        "total_bytes", "total_packets", "unique_dst_ips",
        "unique_dst_ports", "suspicious_port_hits", "night_byte_ratio",
        "dns_query_count", "max_hour_bytes", "active_hour_count",
        "avg_bytes_per_packet",
    ]
    for col in expected:
        assert col in features.columns


def test_empty_report_format():
    detector = MLAnomalyDetector(pd.DataFrame())
    result = detector.detect()
    assert "summary" in result
    assert "anomalies" in result
    assert result["summary"]["total_users"] == 0


def test_severity_from_score():
    from utils.ml_anomaly import _severity_from_score
    assert _severity_from_score(90) == "critical"
    assert _severity_from_score(75) == "high"
    assert _severity_from_score(60) == "medium"
    assert _severity_from_score(30) == "low"
