from utils.analysis import TrafficAnalyzer


def test_get_protocol_distribution(sample_df):
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = sample_df
    result = analyzer.get_protocol_distribution()
    assert isinstance(result, dict)
    assert len(result) > 0
    for proto, byte_val in result.items():
        assert isinstance(proto, str)
        assert isinstance(byte_val, int)
        assert byte_val >= 0


def test_get_protocol_distribution_empty():
    import pandas as pd
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = pd.DataFrame()
    assert analyzer.get_protocol_distribution() == {}


def test_get_top_talkers(sample_df):
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = sample_df
    result = analyzer.get_top_talkers(top_n=5)
    assert isinstance(result, list)
    assert len(result) <= 5
    assert len(result) > 0
    for entry in result:
        assert "src_ip" in entry
        assert "bytes" in entry
    assert result[0]["bytes"] >= result[-1]["bytes"]


def test_get_top_talkers_empty():
    import pandas as pd
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = pd.DataFrame()
    assert analyzer.get_top_talkers() == []


def test_get_hourly_averages(sample_df):
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = sample_df
    result = analyzer.get_hourly_averages()
    assert isinstance(result, list)
    assert len(result) > 0
    for entry in result:
        assert "hour" in entry
        assert "avg_bytes" in entry
        assert isinstance(entry["avg_bytes"], float)


def test_get_hourly_averages_empty():
    import pandas as pd
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = pd.DataFrame()
    assert analyzer.get_hourly_averages() == []


def test_get_daily_stats(sample_df):
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = sample_df
    result = analyzer.get_daily_stats()
    assert isinstance(result, list)
    assert len(result) > 0
    for entry in result:
        assert "date" in entry
        assert "total_bytes" in entry
        assert "total_packets" in entry
        assert isinstance(entry["date"], str)


def test_get_daily_stats_empty():
    import pandas as pd
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = pd.DataFrame()
    assert analyzer.get_daily_stats() == []


def test_get_concurrent_users(sample_df):
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = sample_df
    result = analyzer.get_concurrent_users()
    assert isinstance(result, list)
    assert len(result) > 0
    for entry in result:
        assert "date" in entry
        assert "hour" in entry
        assert "active_users" in entry
        assert isinstance(entry["active_users"], int)
        assert entry["active_users"] >= 0


def test_get_concurrent_users_empty():
    import pandas as pd
    analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
    analyzer.df = pd.DataFrame()
    assert analyzer.get_concurrent_users() == []
