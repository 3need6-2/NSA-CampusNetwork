"""Benchmark the analysis pipeline: load CSV, run all analysis, measure time."""

import time
import sys
from pathlib import Path


def benchmark(csv_path: str) -> dict:
    """Run the full analysis pipeline and return timing results."""
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from utils.analysis import TrafficAnalyzer, generate_all_charts
    from utils.user_profile import UserProfileAnalyzer
    from utils.ai_security import AISecurityAnalyzer
    from utils.ml_anomaly import detect_anomalies

    times = {}

    t0 = time.perf_counter()
    analyzer = TrafficAnalyzer(csv_path)
    times['load_csv'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    _ = analyzer.get_total_traffic()
    _ = analyzer.get_user_traffic_ranking()
    _ = analyzer.get_app_category_traffic()
    _ = analyzer.get_active_hours()
    times['basic_analysis'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    charts = generate_all_charts(analyzer)
    times['charts'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    ua = UserProfileAnalyzer(csv_path)
    profiles = ua.analyze_all_users()
    times['user_profiles'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    security = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
    times['ai_security'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    ml = detect_anomalies(analyzer.df)
    times['ml_anomaly'] = time.perf_counter() - t0

    times['total'] = sum(times.values())

    return {
        'times': times,
        'record_count': len(analyzer.df),
        'user_count': int(analyzer.df['user'].nunique()),
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Benchmark the analysis pipeline')
    parser.add_argument('csv', nargs='?', default='data/traffic.csv', help='CSV file to analyze')
    args = parser.parse_args()

    result = benchmark(args.csv)

    print('=== Benchmark Results ===')
    print(f'  Records:         {result["record_count"]}')
    print(f'  Users:           {result["user_count"]}')
    print(f'  Load CSV:        {result["times"]["load_csv"]:.3f}s')
    print(f'  Basic Analysis:  {result["times"]["basic_analysis"]:.3f}s')
    print(f'  Charts:          {result["times"]["charts"]:.3f}s')
    print(f'  User Profiles:   {result["times"]["user_profiles"]:.3f}s')
    print(f'  AI Security:     {result["times"]["ai_security"]:.3f}s')
    print(f'  ML Anomaly:      {result["times"]["ml_anomaly"]:.3f}s')
    print(f'  ─────────────────────────')
    print(f'  Total:           {result["times"]["total"]:.3f}s')
