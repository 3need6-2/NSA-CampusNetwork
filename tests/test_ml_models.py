import pandas as pd
from utils.ml_anomaly import MLAnomalyDetector, AnomalyConfig


def test_lof_empty_dataframe():
    detector = MLAnomalyDetector(pd.DataFrame())
    result = detector.detect_lof()
    assert result["status"] == "skipped"


def test_lof_fewer_users_than_minimum(sample_df):
    config = AnomalyConfig(min_users=100, contamination=0.1)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_lof()
    assert result["status"] == "skipped"


def test_lof_with_data(sample_df):
    config = AnomalyConfig(contamination=0.3, top_n=10)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_lof()
    if result["status"] == "ok":
        assert result["model"] == "LocalOutlierFactor"
        assert "summary" in result
        assert result["summary"]["total_users"] > 0
        for anomaly in result["anomalies"]:
            assert "user" in anomaly
            assert "anomaly_score" in anomaly


def test_svm_empty_dataframe():
    detector = MLAnomalyDetector(pd.DataFrame())
    result = detector.detect_svm()
    assert result["status"] == "skipped"


def test_svm_fewer_users_than_minimum(sample_df):
    config = AnomalyConfig(min_users=100, contamination=0.1)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_svm()
    assert result["status"] == "skipped"


def test_svm_with_data(sample_df):
    config = AnomalyConfig(contamination=0.3, top_n=10)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_svm()
    if result["status"] == "ok":
        assert result["model"] == "OneClassSVM"
        assert "summary" in result
        assert result["summary"]["total_users"] > 0
        for anomaly in result["anomalies"]:
            assert "user" in anomaly
            assert "severity" in anomaly


def test_ensemble_empty_dataframe():
    detector = MLAnomalyDetector(pd.DataFrame())
    result = detector.detect_ensemble()
    assert result["status"] == "skipped"


def test_ensemble_fewer_users_than_minimum(sample_df):
    config = AnomalyConfig(min_users=100, contamination=0.1)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_ensemble()
    assert result["status"] == "skipped"


def test_ensemble_with_data(sample_df):
    config = AnomalyConfig(contamination=0.3, top_n=10)
    detector = MLAnomalyDetector(sample_df, config)
    result = detector.detect_ensemble()
    if result["status"] == "ok":
        assert result["model"] == "Ensemble"
        assert "config" in result
        assert "models" in result["config"]
        for anomaly in result["anomalies"]:
            assert "voting_models" in anomaly
            assert len(anomaly["voting_models"]) >= 2


def test_lof_feature_extraction(sample_df):
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
