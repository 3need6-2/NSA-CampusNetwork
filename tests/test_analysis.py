from utils.analysis import TrafficAnalyzer


def test_load_data(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    assert analyzer.df is not None
    assert len(analyzer.df) > 0


def test_get_total_traffic(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    stats = analyzer.get_total_traffic()
    assert stats["total_bytes"] > 0
    assert stats["total_packets"] > 0
    assert stats["unique_users"] > 0


def test_get_total_traffic_empty():
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user\n")
        tmp = f.name
    try:
        analyzer = TrafficAnalyzer(tmp)
        stats = analyzer.get_total_traffic()
        assert stats["total_bytes"] == 0
        assert stats["unique_users"] == 0
    finally:
        os.unlink(tmp)


def test_get_user_traffic_ranking(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    ranking = analyzer.get_user_traffic_ranking(top_n=5)
    assert len(ranking) <= 5
    assert len(ranking) > 0
    assert all("user" in r and "bytes" in r for r in ranking)
    assert ranking[0]["bytes"] >= ranking[-1]["bytes"]


def test_get_app_category_traffic(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    categories = analyzer.get_app_category_traffic()
    assert len(categories) > 0
    assert all("category" in c and "bytes" in c for c in categories)


def test_get_traffic_trend(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    trend = analyzer.get_traffic_trend(unit="hour")
    assert len(trend) > 0
    assert all("time" in t and "bytes" in t for t in trend)


def test_get_active_hours(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    hours = analyzer.get_active_hours()
    assert len(hours) > 0
    assert all("hour" in h and "active_users" in h for h in hours)


def test_get_user_app_distribution(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    dist = analyzer.get_user_app_distribution("student_001")
    assert len(dist) > 0
    assert all("category" in d and "bytes" in d for d in dist)


def test_get_user_app_distribution_nonexistent(sample_csv_path):
    analyzer = TrafficAnalyzer(sample_csv_path)
    dist = analyzer.get_user_app_distribution("nonexistent_user")
    assert dist == []
