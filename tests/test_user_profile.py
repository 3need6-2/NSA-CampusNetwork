from utils.user_profile import UserProfileAnalyzer


def test_load_data(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    assert analyzer.df is not None
    assert len(analyzer.df) > 0


def test_get_user_list(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    users = analyzer.get_user_list()
    assert len(users) > 0
    assert "student_001" in users


def test_get_app_category_pct(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    pct = analyzer.get_app_category_pct("student_001")
    assert isinstance(pct, dict)
    assert len(pct) > 0
    assert all(isinstance(v, float) for v in pct.values())


def test_get_active_hours(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    hours = analyzer.get_active_hours("student_001")
    assert isinstance(hours, dict)
    assert len(hours) > 0
    for h, info in hours.items():
        assert isinstance(h, int)
        assert "bytes" in info
        assert "count" in info


def test_get_protocol_ratio(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    ratio = analyzer.get_protocol_ratio("student_001")
    assert isinstance(ratio, dict)
    assert len(ratio) > 0
    total = sum(ratio.values())
    assert abs(total - 100.0) < 0.01


def test_get_port_stats(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    stats = analyzer.get_port_stats("student_001")
    assert isinstance(stats, dict)
    assert 53 in stats


def test_get_dns_stats(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    stats = analyzer.get_dns_stats("student_001")
    assert "dns_queries" in stats
    assert "dns_bytes" in stats
    assert stats["dns_queries"] > 0


def test_get_daily_bytes(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    daily = analyzer.get_daily_bytes("student_001")
    assert isinstance(daily, dict)
    assert len(daily) > 0


def test_generate_tags(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    tags = analyzer.generate_tags("student_001")
    assert isinstance(tags, list)


def test_analyze_all_users(sample_csv_path):
    analyzer = UserProfileAnalyzer(sample_csv_path)
    profiles = analyzer.analyze_all_users()
    assert len(profiles) > 0
    for uid, profile in profiles.items():
        assert "tags" in profile
        assert "category_pct" in profile
        assert "active_hours" in profile


def test_save_profiles(sample_csv_path):
    import tempfile, os, json
    analyzer = UserProfileAnalyzer(sample_csv_path)
    analyzer.analyze_all_users()
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
        out = f.name
    try:
        result = analyzer.save_profiles(out)
        assert result is True
        with open(out) as f:
            data = json.load(f)
        assert len(data) > 0
    finally:
        os.unlink(out)


def test_load_profiles(sample_csv_path):
    import tempfile, os, json
    analyzer1 = UserProfileAnalyzer(sample_csv_path)
    profiles = analyzer1.analyze_all_users()
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
        json.dump(profiles, f)
        out = f.name
    try:
        analyzer2 = UserProfileAnalyzer(sample_csv_path)
        result = analyzer2.load_profiles(out)
        assert result is True
        assert len(analyzer2.user_profiles) > 0
    finally:
        os.unlink(out)
