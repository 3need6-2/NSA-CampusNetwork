"""CLI script to export full analysis as HTML report."""

import sys
import json
from pathlib import Path


def export_report(csv_path: str, output_path: str) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from utils.analysis import TrafficAnalyzer, generate_all_charts
    from utils.user_profile import UserProfileAnalyzer
    from utils.ai_security import AISecurityAnalyzer
    from utils.ml_anomaly import detect_anomalies

    print(f"Loading CSV: {csv_path}")
    analyzer = TrafficAnalyzer(csv_path)
    if analyzer.df is None or len(analyzer.df) == 0:
        print("ERROR: No data loaded.")
        sys.exit(1)

    traffic = analyzer.get_total_traffic()
    user_ranking = analyzer.get_user_traffic_ranking(top_n=10)
    app_category = analyzer.get_app_category_traffic()
    active_hours = analyzer.get_active_hours()

    charts = generate_all_charts(analyzer)
    ua = UserProfileAnalyzer(csv_path)
    profiles = ua.analyze_all_users()
    security = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
    ml = detect_anomalies(analyzer.df)

    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Traffic Analysis Report</title>",
        "<style>body{font-family:sans-serif;margin:40px;background:#f5f5f5}",
        ".card{background:#fff;border-radius:8px;padding:20px;margin:20px 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}",
        "table{width:100%;border-collapse:collapse}",
        "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd}",
        "h2{color:#333}</style></head><body>",
        "<h1>Traffic Analysis Report</h1>",
        f"<p>Generated from: {csv_path} | Records: {traffic['total_packets']:,} | Users: {traffic['unique_users']}</p>",
        "<div class='card'><h2>Total Traffic</h2>",
        f"<p>Bytes: {traffic['total_bytes']:,}<br>Packets: {traffic['total_packets']:,}<br>Users: {traffic['unique_users']}<br>Unique IPs: {traffic['unique_ips']}</p></div>",
        "<div class='card'><h2>Top Users</h2><table><tr><th>#</th><th>User</th><th>Bytes</th></tr>",
    ]
    for i, u in enumerate(user_ranking, 1):
        html_parts.append(f"<tr><td>{i}</td><td>{u['user']}</td><td>{u['bytes']:,}</td></tr>")
    html_parts.append("</table></div>")

    html_parts.append("<div class='card'><h2>App Category</h2><table><tr><th>Category</th><th>Bytes</th></tr>")
    for cat in app_category:
        html_parts.append(f"<tr><td>{cat['category']}</td><td>{cat['bytes']:,}</td></tr>")
    html_parts.append("</table></div>")

    html_parts.append(f"<div class='card'><h2>Charts Generated</h2><p>{len(charts)} charts</p></div>")
    html_parts.append(f"<div class='card'><h2>User Profiles</h2><p>{len(profiles)} profiles</p></div>")
    html_parts.append(f"<div class='card'><h2>Security</h2><p>Threats: {len(security.get('threats', []))}<br>Blocked: {len(security.get('blocked_entities', []))}</p></div>")
    html_parts.append(f"<div class='card'><h2>ML Anomalies</h2><p>Anomalies: {len(ml.get('anomalies', []))}</p></div>")
    html_parts.append("</body></html>")

    Path(output_path).write_text("".join(html_parts), encoding="utf-8")
    print(f"Report exported to: {output_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export full analysis as HTML report")
    parser.add_argument("csv", nargs="?", default="data/traffic.csv", help="CSV file to analyze")
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML file")
    args = parser.parse_args()
    export_report(args.csv, args.output)
