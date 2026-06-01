from utils.ai_security import AISecurityAnalyzer


def test_detect_dns_tunneling(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    analyzer._prepare_data()
    analyzer._detect_dns_tunneling()
    dns_alerts = [a for a in analyzer.alerts if a["type"] == "dns_tunneling"]
    assert isinstance(dns_alerts, list)
    for alert in dns_alerts:
        assert "score" in alert
        assert 0 <= alert["score"] <= 100
        assert "entity" in alert
        assert "evidence" in alert


def test_detect_data_exfiltration(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    analyzer._prepare_data()
    analyzer._detect_data_exfiltration()
    exfil_alerts = [a for a in analyzer.alerts if a["type"] == "data_exfiltration"]
    assert isinstance(exfil_alerts, list)
    for alert in exfil_alerts:
        assert "score" in alert
        assert 0 <= alert["score"] <= 100
        assert "block_target" in alert


def test_detect_brute_force(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    analyzer._prepare_data()
    analyzer._detect_brute_force()
    bf_alerts = [a for a in analyzer.alerts if a["type"] == "brute_force"]
    assert isinstance(bf_alerts, list)
    for alert in bf_alerts:
        assert "score" in alert
        assert "title" in alert
        assert "端口" in alert["title"]


def test_detect_beaconing(sample_df):
    analyzer = AISecurityAnalyzer(sample_df)
    analyzer._prepare_data()
    analyzer._detect_beaconing()
    beacon_alerts = [a for a in analyzer.alerts if a["type"] == "beaconing"]
    assert isinstance(beacon_alerts, list)
    for alert in beacon_alerts:
        assert "score" in alert
        assert alert["score"] >= 0
        assert "evidence" in alert


def test_dns_tunneling_empty_dataframe():
    import pandas as pd
    analyzer = AISecurityAnalyzer(pd.DataFrame())
    analyzer._prepare_data()
    analyzer._detect_dns_tunneling()
    assert analyzer.alerts == []


def test_data_exfiltration_empty_dataframe():
    import pandas as pd
    analyzer = AISecurityAnalyzer(pd.DataFrame())
    analyzer._prepare_data()
    analyzer._detect_data_exfiltration()
    assert analyzer.alerts == []


def test_brute_force_empty_dataframe():
    import pandas as pd
    analyzer = AISecurityAnalyzer(pd.DataFrame())
    analyzer._prepare_data()
    analyzer._detect_brute_force()
    assert analyzer.alerts == []


def test_beaconing_empty_dataframe():
    import pandas as pd
    analyzer = AISecurityAnalyzer(pd.DataFrame())
    analyzer._prepare_data()
    analyzer._detect_beaconing()
    assert analyzer.alerts == []
