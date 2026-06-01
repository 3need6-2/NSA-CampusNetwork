"""Extended tests for UserProfileAnalyzer tags and methods."""

import pytest
import pandas as pd
import tempfile
import os
from io import StringIO

from utils.user_profile import UserProfileAnalyzer


@pytest.fixture
def csv_path_all_tags():
    """CSV data designed to trigger all existing and new tags."""
    lines = ["timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user"]
    # big_user: high traffic outlier for 大流量用户 tag
    for i in range(200):
        h = 8 + i // 60
        m = i % 60
        lines.append(f"2025-12-01 {h:02d}:{m:02d}:00,10.0.0.1,8.8.8.8,{10001+i},53,UDP,500,DNS,big_user")
    # second user for variance
    for i in range(5):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.x,8.8.4.4,{20001+i},53,UDP,50,DNS,small_user")
    # gamer: game > 30%
    for i in range(10):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.2,142.251.41.14,{30001+i},443,TCP,2000,Game,gamer")
    # streamer: video > 40%
    for i in range(10):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.3,13.226.123.45,{40001+i},80,TCP,5000,Video Streaming,streamer")
    # social_user: social + chat > 30%
    for i in range(10):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.4,151.101.1.140,{50001+i},443,TCP,300,Social Media,social_user")
    # learner: edu > 20%
    for i in range(5):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.5,172.217.164.46,{60001+i},443,TCP,200,Education,learner")
    # tech_user: 3+ suspicious ports, 20+ total hits
    for i in range(10):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.6,185.89.218.42,{70001+i},22,TCP,500,SSH,tech_user")
    for i in range(8):
        lines.append(f"2025-12-01 09:{i:02d}:00,10.0.0.6,185.89.218.43,{71001+i},3389,TCP,1000,RDP,tech_user")
    for i in range(5):
        lines.append(f"2025-12-01 10:{i:02d}:00,10.0.0.6,185.89.218.44,{72001+i},3306,TCP,200,MySQL,tech_user")
    # night_user: 60%+ at night, 50+ DNS queries
    for i in range(55):
        m = i % 60
        lines.append(f"2025-12-01 23:{m:02d}:00,10.0.0.7,8.8.4.4,{80001+i},53,UDP,100,DNS,night_user")
    for i in range(5):
        lines.append(f"2025-12-02 01:{i:02d}:00,10.0.0.7,8.8.4.4,{81001+i},53,UDP,100,DNS,night_user")
    for i in range(3):
        lines.append(f"2025-12-02 02:{i:02d}:00,10.0.0.7,8.8.4.4,{82001+i},53,UDP,100,DNS,night_user")
    for i in range(3):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.7,8.8.4.4,{83001+i},80,TCP,200,Web,night_user")
    # morning_user: 30%+ in morning
    for i in range(10):
        lines.append(f"2025-12-01 06:{i:02d}:00,10.0.0.8,8.8.4.4,{90001+i},53,UDP,100,DNS,morning_user")
    for i in range(3):
        lines.append(f"2025-12-01 12:{i:02d}:00,10.0.0.8,8.8.4.4,{91001+i},53,UDP,100,DNS,morning_user")
    # vpn_user: 443+UDP ratio > 20%
    for i in range(5):
        lines.append(f"2025-12-01 22:{i:02d}:00,10.0.0.9,203.0.113.1,{100001+i},443,UDP,500,Web,vpn_user")
    lines.append("2025-12-01 22:05:00,10.0.0.9,203.0.113.2,100006,80,TCP,100,Web,vpn_user")
    # downloader: avg_bytes > 1000
    for i in range(3):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.10,203.0.113.3,{110001+i},443,TCP,2000,CDN,downloader")
    # light_user: total bytes < 10000
    for i in range(3):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.11,203.0.113.4,{120001+i},80,TCP,50,DNS,light_user")
    # vpn_user_tcp: no vpn tag (all TCP)
    for i in range(5):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.12,203.0.113.5,{130001+i},443,TCP,500,Web,vpn_user_tcp")
    # small_packet_user: avg_bytes < 1000
    for i in range(10):
        lines.append(f"2025-12-01 08:{i:02d}:00,10.0.0.13,203.0.113.6,{140001+i},53,UDP,100,DNS,small_packet_user")

    data = "\n".join(lines)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(data)
        tmp_path = f.name
    yield tmp_path
    os.unlink(tmp_path)


class TestNewTags:
    """Test the three newly added tags."""

    def test_vpn_user_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("vpn_user")
        assert "VPN用户" in tags

    def test_downloader_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("downloader")
        assert "下载大户" in tags

    def test_light_user_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("light_user")
        assert "轻度用户" in tags

    def test_vpn_user_not_triggered_for_tcp_only(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("vpn_user_tcp")
        assert "VPN用户" not in tags

    def test_downloader_not_triggered_for_small_packets(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("small_packet_user")
        assert "下载大户" not in tags

    def test_light_user_not_triggered_for_high_traffic(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("big_user")
        assert "轻度用户" not in tags


class TestExistingTags:
    """Verify existing tags still trigger correctly."""

    def test_big_traffic_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("big_user")
        assert "大流量用户" in tags

    def test_tech_user_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("tech_user")
        assert "技术用户" in tags

    def test_night_owl_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("night_user")
        assert "夜猫子" in tags

    def test_morning_person_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("morning_user")
        assert "早起族" in tags

    def test_suspicious_scan_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("tech_user")
        assert "可疑扫描" in tags

    def test_dns_suspicious_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("night_user")
        assert "可疑DNS" in tags

    def test_abnormal_active_time_tag(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        tags = analyzer.generate_tags("night_user")
        assert "异常活跃时间" in tags


class TestGetUserSummary:
    """Test the get_user_summary method."""

    def test_get_user_summary_returns_string(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        summary = analyzer.get_user_summary("big_user")
        assert isinstance(summary, str)
        assert "big_user" in summary

    def test_get_user_summary_includes_tags(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        summary = analyzer.get_user_summary("vpn_user")
        assert "VPN用户" in summary

    def test_get_user_summary_no_data(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        summary = analyzer.get_user_summary("nonexistent_user")
        assert "无数据" in summary


class TestGetUserSummaryIntegration:
    """Integration test for all new tags via summarize method."""

    def test_summary_includes_new_tags(self, csv_path_all_tags):
        analyzer = UserProfileAnalyzer(csv_path_all_tags)
        summary = analyzer.get_user_summary("vpn_user")
        assert "VPN用户" in summary
        summary2 = analyzer.get_user_summary("downloader")
        assert "下载大户" in summary2
        summary3 = analyzer.get_user_summary("light_user")
        assert "轻度用户" in summary3
