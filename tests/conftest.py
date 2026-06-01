import pytest
import pandas as pd
import tempfile
import os


SAMPLE_CSV_CONTENT = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:15,192.168.1.100,8.8.8.8,52341,53,UDP,256,DNS,student_001
2025-12-01 08:00:32,192.168.1.101,142.251.41.14,52456,443,TCP,4096,Social Media,student_002
2025-12-01 08:01:05,192.168.1.102,13.226.123.45,52789,80,TCP,2048,Video Streaming,student_003
2025-12-01 08:01:45,192.168.1.100,8.8.8.8,52342,53,UDP,256,DNS,student_001
2025-12-01 08:02:12,192.168.1.103,151.101.1.140,53012,443,TCP,8192,CDN,student_004
2025-12-01 08:02:58,192.168.1.104,172.217.164.46,53234,443,TCP,6144,Web Search,student_005
2025-12-01 08:03:25,192.168.1.101,142.251.41.14,52457,443,TCP,5120,Social Media,student_002
2025-12-01 08:04:10,192.168.1.105,185.89.218.42,53456,443,TCP,10240,P2P,student_006
2025-12-01 08:05:00,192.168.1.100,8.8.8.8,52343,53,UDP,256,DNS,student_001
2025-12-01 08:05:30,192.168.1.106,10.0.0.1,53512,22,TCP,512,SSH,student_007
2025-12-01 08:06:00,192.168.1.107,10.0.0.2,53678,443,TCP,20480,Video Streaming,student_008
2025-12-01 22:10:00,192.168.1.108,8.8.4.4,54001,53,UDP,128,DNS,student_009
2025-12-01 22:15:00,192.168.1.108,8.8.4.4,54002,53,UDP,128,DNS,student_009
2025-12-01 22:20:00,192.168.1.108,8.8.4.4,54003,53,UDP,128,DNS,student_009
2025-12-01 23:00:00,192.168.1.108,8.8.4.4,54004,53,UDP,128,DNS,student_009
2025-12-01 23:30:00,192.168.1.108,8.8.4.4,54005,53,UDP,128,DNS,student_009
2025-12-02 00:00:00,192.168.1.108,8.8.4.4,54006,53,UDP,128,DNS,student_009
2025-12-02 00:30:00,192.168.1.108,8.8.4.4,54007,53,UDP,128,DNS,student_009
2025-12-01 09:00:00,192.168.1.200,10.0.0.100,60001,3389,TCP,50000,RDP,student_010
2025-12-01 09:15:00,192.168.1.200,10.0.0.100,60002,3389,TCP,30000,RDP,student_010
2025-12-01 09:30:00,192.168.1.200,10.0.0.100,60003,3389,TCP,40000,RDP,student_010
"""


@pytest.fixture
def sample_csv_path():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(SAMPLE_CSV_CONTENT)
        tmp_path = f.name
    yield tmp_path
    os.unlink(tmp_path)


@pytest.fixture
def sample_df():
    from io import StringIO
    df = pd.read_csv(StringIO(SAMPLE_CSV_CONTENT))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['date'] = df['timestamp'].dt.date
    return df
