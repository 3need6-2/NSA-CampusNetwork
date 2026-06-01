"""Comprehensive tests for user profile tag generation."""
import tempfile
import os
import pandas as pd
from utils.user_profile import UserProfileAnalyzer


HIGH_PACKET_CSV = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:00,192.168.1.100,8.8.8.8,52341,53,UDP,256,DNS,high_packet_user
2025-12-01 08:01:00,192.168.1.100,8.8.8.8,52342,53,UDP,256,DNS,high_packet_user
2025-12-01 08:02:00,192.168.1.100,8.8.8.8,52343,53,UDP,256,DNS,high_packet_user
2025-12-01 08:03:00,192.168.1.100,8.8.8.8,52344,53,UDP,256,DNS,high_packet_user
2025-12-01 08:04:00,192.168.1.100,8.8.8.8,52345,53,UDP,256,DNS,high_packet_user
2025-12-01 08:05:00,192.168.1.100,8.8.8.8,52346,53,UDP,256,DNS,high_packet_user
2025-12-01 08:06:00,192.168.1.100,8.8.8.8,52347,53,UDP,256,DNS,high_packet_user
2025-12-01 08:07:00,192.168.1.100,8.8.8.8,52348,53,UDP,256,DNS,high_packet_user
2025-12-01 08:08:00,192.168.1.100,8.8.8.8,52349,53,UDP,256,DNS,high_packet_user
2025-12-01 08:09:00,192.168.1.100,8.8.8.8,52350,53,UDP,256,DNS,high_packet_user
2025-12-01 08:10:00,192.168.1.100,8.8.8.8,52351,53,UDP,256,DNS,high_packet_user
2025-12-01 08:11:00,192.168.1.100,8.8.8.8,52352,53,UDP,256,DNS,high_packet_user
2025-12-01 08:12:00,192.168.1.100,8.8.8.8,52353,53,UDP,256,DNS,high_packet_user
2025-12-01 08:13:00,192.168.1.100,8.8.8.8,52354,53,UDP,256,DNS,high_packet_user
2025-12-01 08:14:00,192.168.1.100,8.8.8.8,52355,53,UDP,256,DNS,high_packet_user
2025-12-01 08:15:00,192.168.1.100,8.8.8.8,52356,53,UDP,256,DNS,high_packet_user
2025-12-01 08:16:00,192.168.1.100,8.8.8.8,52357,53,UDP,256,DNS,high_packet_user
2025-12-01 08:17:00,192.168.1.100,8.8.8.8,52358,53,UDP,256,DNS,high_packet_user
2025-12-01 08:18:00,192.168.1.100,8.8.8.8,52359,53,UDP,256,DNS,high_packet_user
2025-12-01 08:19:00,192.168.1.100,8.8.8.8,52360,53,UDP,256,DNS,high_packet_user
2025-12-01 08:20:00,192.168.1.100,8.8.8.8,52361,53,UDP,256,DNS,high_packet_user
2025-12-01 08:21:00,192.168.1.100,8.8.8.8,52362,53,UDP,256,DNS,high_packet_user
2025-12-01 08:22:00,192.168.1.100,8.8.8.8,52363,53,UDP,256,DNS,high_packet_user
2025-12-01 08:23:00,192.168.1.100,8.8.8.8,52364,53,UDP,256,DNS,high_packet_user
2025-12-01 08:24:00,192.168.1.100,8.8.8.8,52365,53,UDP,256,DNS,high_packet_user
2025-12-01 08:25:00,192.168.1.100,8.8.8.8,52366,53,UDP,256,DNS,high_packet_user
2025-12-01 08:26:00,192.168.1.100,8.8.8.8,52367,53,UDP,256,DNS,high_packet_user
2025-12-01 08:27:00,192.168.1.100,8.8.8.8,52368,53,UDP,256,DNS,high_packet_user
2025-12-01 08:28:00,192.168.1.100,8.8.8.8,52369,53,UDP,256,DNS,high_packet_user
2025-12-01 08:29:00,192.168.1.100,8.8.8.8,52370,53,UDP,256,DNS,high_packet_user
2025-12-01 08:30:00,192.168.1.100,8.8.8.8,52371,53,UDP,256,DNS,high_packet_user
2025-12-01 08:31:00,192.168.1.100,8.8.8.8,52372,53,UDP,256,DNS,high_packet_user
2025-12-01 08:32:00,192.168.1.100,8.8.8.8,52373,53,UDP,256,DNS,high_packet_user
2025-12-01 08:33:00,192.168.1.100,8.8.8.8,52374,53,UDP,256,DNS,high_packet_user
2025-12-01 08:34:00,192.168.1.100,8.8.8.8,52375,53,UDP,256,DNS,high_packet_user
2025-12-01 08:35:00,192.168.1.100,8.8.8.8,52376,53,UDP,256,DNS,high_packet_user
2025-12-01 08:36:00,192.168.1.100,8.8.8.8,52377,53,UDP,256,DNS,high_packet_user
2025-12-01 08:37:00,192.168.1.100,8.8.8.8,52378,53,UDP,256,DNS,high_packet_user
2025-12-01 08:38:00,192.168.1.100,8.8.8.8,52379,53,UDP,256,DNS,high_packet_user
2025-12-01 08:39:00,192.168.1.100,8.8.8.8,52380,53,UDP,256,DNS,high_packet_user
2025-12-01 08:40:00,192.168.1.100,8.8.8.8,52381,53,UDP,256,DNS,high_packet_user
2025-12-01 08:41:00,192.168.1.100,8.8.8.8,52382,53,UDP,256,DNS,high_packet_user
2025-12-01 08:42:00,192.168.1.100,8.8.8.8,52383,53,UDP,256,DNS,high_packet_user
2025-12-01 08:43:00,192.168.1.100,8.8.8.8,52384,53,UDP,256,DNS,high_packet_user
2025-12-01 08:44:00,192.168.1.100,8.8.8.8,52385,53,UDP,256,DNS,high_packet_user
2025-12-01 08:45:00,192.168.1.100,8.8.8.8,52386,53,UDP,256,DNS,high_packet_user
2025-12-01 08:46:00,192.168.1.100,8.8.8.8,52387,53,UDP,256,DNS,high_packet_user
2025-12-01 08:47:00,192.168.1.100,8.8.8.8,52388,53,UDP,256,DNS,high_packet_user
2025-12-01 08:48:00,192.168.1.100,8.8.8.8,52389,53,UDP,256,DNS,high_packet_user
2025-12-01 08:49:00,192.168.1.100,8.8.8.8,52390,53,UDP,256,DNS,high_packet_user
2025-12-01 08:50:00,192.168.1.100,8.8.8.8,52391,53,UDP,256,DNS,high_packet_user
2025-12-01 08:51:00,192.168.1.100,8.8.8.8,52392,53,UDP,256,DNS,high_packet_user
2025-12-01 08:52:00,192.168.1.100,8.8.8.8,52393,53,UDP,256,DNS,high_packet_user
2025-12-01 08:53:00,192.168.1.100,8.8.8.8,52394,53,UDP,256,DNS,high_packet_user
2025-12-01 08:54:00,192.168.1.100,8.8.8.8,52395,53,UDP,256,DNS,high_packet_user
2025-12-01 08:55:00,192.168.1.100,8.8.8.8,52396,53,UDP,256,DNS,high_packet_user
2025-12-01 08:56:00,192.168.1.100,8.8.8.8,52397,53,UDP,256,DNS,high_packet_user
2025-12-01 08:57:00,192.168.1.100,8.8.8.8,52398,53,UDP,256,DNS,high_packet_user
2025-12-01 08:58:00,192.168.1.100,8.8.8.8,52399,53,UDP,256,DNS,high_packet_user
2025-12-01 08:59:00,192.168.1.100,8.8.8.8,52400,53,UDP,256,DNS,high_packet_user
2025-12-01 09:00:00,192.168.1.100,8.8.8.8,52401,53,UDP,256,DNS,high_packet_user
"""

PRIVATE_IP_CSV = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:00,192.168.1.100,10.0.0.1,52341,443,TCP,1024,Web,private_user
2025-12-01 08:05:00,10.0.0.55,192.168.1.1,52456,80,TCP,2048,Web,private_user
"""

PUBLIC_IP_CSV = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:00,8.8.8.8,142.251.41.14,52341,443,TCP,4096,Web,public_user
2025-12-01 08:05:00,1.1.1.1,13.226.123.45,52456,80,TCP,2048,Web,public_user
"""

BALANCED_CSV = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:00,192.168.1.100,8.8.8.8,52341,53,UDP,256,DNS,balanced_user
2025-12-01 08:05:00,192.168.1.100,142.251.41.14,52456,443,TCP,300,Web,balanced_user
2025-12-01 08:10:00,192.168.1.100,13.226.123.45,52789,80,TCP,350,Video,balanced_user
2025-12-01 08:15:00,192.168.1.100,151.101.1.140,53012,443,TCP,280,Chat,balanced_user
2025-12-01 08:20:00,192.168.1.100,172.217.164.46,53234,443,TCP,320,Social,balanced_user
"""

WEEKEND_CSV = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-06 08:00:00,192.168.1.100,8.8.8.8,52341,53,UDP,5000,DNS,weekend_user
2025-12-06 09:00:00,192.168.1.100,8.8.8.8,52342,53,UDP,6000,DNS,weekend_user
2025-12-07 08:00:00,192.168.1.100,8.8.8.8,52343,53,UDP,7000,DNS,weekend_user
2025-12-01 08:00:00,192.168.1.100,8.8.8.8,52344,53,UDP,100,DNS,weekend_user
2025-12-02 08:00:00,192.168.1.100,8.8.8.8,52345,53,UDP,100,DNS,weekend_user
"""


def _make_analyzer(csv_content):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(csv_content)
        tmp_path = f.name
    analyzer = UserProfileAnalyzer(tmp_path)
    os.unlink(tmp_path)
    return analyzer


def test_tag_数据采集者():
    analyzer = _make_analyzer(HIGH_PACKET_CSV)
    tags = analyzer.generate_tags('high_packet_user')
    assert '数据采集者' in tags


def test_tag_内网用户():
    analyzer = _make_analyzer(PRIVATE_IP_CSV)
    tags = analyzer.generate_tags('private_user')
    assert '内网用户' in tags


def test_tag_外网用户():
    analyzer = _make_analyzer(PUBLIC_IP_CSV)
    tags = analyzer.generate_tags('public_user')
    assert '外网用户' in tags


def test_tag_平衡用户():
    analyzer = _make_analyzer(BALANCED_CSV)
    tags = analyzer.generate_tags('balanced_user')
    assert '平衡用户' in tags


def test_tag_周末活跃():
    analyzer = _make_analyzer(WEEKEND_CSV)
    tags = analyzer.generate_tags('weekend_user')
    assert '周末活跃' in tags


def test_all_tags_unique():
    analyzer = _make_analyzer(HIGH_PACKET_CSV)
    tags = analyzer.generate_tags('high_packet_user')
    assert len(tags) == len(set(tags))


def test_empty_data_no_tags():
    from io import StringIO
    empty_csv = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user\n"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(empty_csv)
        tmp_path = f.name
    analyzer = UserProfileAnalyzer(tmp_path)
    os.unlink(tmp_path)
    tags = analyzer.generate_tags('nonexistent')
    assert isinstance(tags, list)
    assert len(tags) == 0
