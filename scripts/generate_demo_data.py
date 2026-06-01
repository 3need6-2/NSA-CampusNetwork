"""Generate a large demo CSV for testing the campus network analysis pipeline."""

import csv
import random
import uuid
from datetime import datetime, timedelta


USERS = [f'user_{i:04d}' for i in range(1, 56)]
APPS = ['Web', 'Streaming', 'Gaming', 'VoIP', 'FileTransfer', 'Email', 'Cloud', 'Social']
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
SRC_IPS = [f'10.0.{random.randint(0, 255)}.{random.randint(1, 254)}' for _ in range(30)]
DST_IPS = [f'192.168.{random.randint(0, 255)}.{random.randint(1, 254)}' for _ in range(50)]
PORTS = [22, 53, 80, 443, 3306, 3389, 6379, 8080, 8443, 25, 110, 143, 993, 995]


def generate_csv(path: str, num_records: int = 500) -> None:
    """Generate a CSV with random traffic data."""
    base = datetime.now() - timedelta(days=30)
    fieldnames = ['timestamp', 'bytes', 'user', 'src_ip', 'dst_ip', 'dst_port', 'app_category', 'protocol']

    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(num_records):
            ts = base + timedelta(
                days=random.randint(0, 29),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            writer.writerow({
                'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
                'bytes': random.randint(64, 1_000_000),
                'user': random.choice(USERS),
                'src_ip': random.choice(SRC_IPS),
                'dst_ip': random.choice(DST_IPS),
                'dst_port': random.choice(PORTS),
                'app_category': random.choice(APPS),
                'protocol': random.choice(PROTOCOLS),
            })

    print(f'Generated {num_records} records to {path}')
    print(f'  Users: {len(USERS)}')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate demo traffic CSV')
    parser.add_argument('--output', default='data/traffic.csv', help='Output CSV path')
    parser.add_argument('--records', type=int, default=500, help='Number of records')
    args = parser.parse_args()
    generate_csv(args.output, args.records)
