"""CLI script to run all analysis from command line and print summary."""

import sys
from pathlib import Path


def analyze(csv_path: str) -> None:
    """Run the full analysis and print a summary to stdout."""
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from utils.analysis import TrafficAnalyzer, generate_all_charts
    from utils.user_profile import UserProfileAnalyzer
    from utils.ai_security import AISecurityAnalyzer
    from utils.ml_anomaly import detect_anomalies

    print(f'Loading CSV: {csv_path}')
    analyzer = TrafficAnalyzer(csv_path)
    if analyzer.df is None or len(analyzer.df) == 0:
        print('ERROR: No data loaded.')
        sys.exit(1)

    traffic = analyzer.get_total_traffic()
    user_ranking = analyzer.get_user_traffic_ranking(top_n=10)
    app_category = analyzer.get_app_category_traffic()
    active_hours = analyzer.get_active_hours()

    print(f'\nTotal Traffic:')
    print(f'  Bytes:     {traffic["total_bytes"]:,}')
    print(f'  Packets:   {traffic["total_packets"]:,}')
    print(f'  Users:     {traffic["unique_users"]}')
    print(f'  Unique IPs: {traffic["unique_ips"]}')

    print(f'\nTop 10 Users (by bytes):')
    for i, u in enumerate(user_ranking, 1):
        print(f'  {i:2d}. {u["user"]:15s} {u["bytes"]:>12,} bytes')

    print(f'\nApp Category Traffic:')
    for cat in app_category:
        print(f'  {cat["category"]:15s} {cat["bytes"]:>12,} bytes')

    print(f'\nActive Hours (peak):')
    active_hours.sort(key=lambda x: x['total_bytes'], reverse=True)
    for h in active_hours[:5]:
        print(f'  Hour {h["hour"]:5s}: {h["active_users"]:3d} users, {h["total_bytes"]:>12,} bytes')

    print(f'\nGenerating charts...')
    charts = generate_all_charts(analyzer)
    print(f'  {len(charts)} charts generated')

    print(f'\nAnalyzing user profiles...')
    ua = UserProfileAnalyzer(csv_path)
    profiles = ua.analyze_all_users()
    print(f'  {len(profiles)} user profiles built')

    print(f'\nRunning AI security analysis...')
    security = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
    threats = security.get('threats', [])
    blocked = security.get('blocked_entities', [])
    print(f'  Threats: {len(threats)}, Blocked: {len(blocked)}')

    print(f'\nRunning ML anomaly detection...')
    ml = detect_anomalies(analyzer.df)
    anomalies = ml.get('anomalies', [])
    anomaly_users = ml.get('summary', {}).get('anomaly_users', 0)
    print(f'  Anomalies: {len(anomalies)}')

    print(f'\n{"=" * 50}')
    print(f'Analysis complete: {len(analyzer.df)} records, {traffic["unique_users"]} users')
    print(f'{"=" * 50}')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run traffic analysis from CLI')
    parser.add_argument('csv', nargs='?', default='data/traffic.csv', help='CSV file to analyze')
    args = parser.parse_args()
    analyze(args.csv)
