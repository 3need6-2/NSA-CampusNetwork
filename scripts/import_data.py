"""CLI script to import data from CSV to database."""

import sys
import os
from pathlib import Path


def import_data(csv_path: str) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from utils.database import save_report
    from utils.analysis import TrafficAnalyzer

    csv_path = os.path.abspath(csv_path)
    if not os.path.exists(csv_path):
        print(f"ERROR: File not found: {csv_path}")
        sys.exit(1)

    print(f"Importing: {csv_path}")
    analyzer = TrafficAnalyzer(csv_path)
    if analyzer.df is None or len(analyzer.df) == 0:
        print("ERROR: No data loaded from CSV.")
        sys.exit(1)

    filename = os.path.basename(csv_path)
    report_id = save_report(filename, {
        "total_records": len(analyzer.df),
        "total_bytes": int(analyzer.df["bytes"].sum()),
        "unique_users": int(analyzer.df["user"].nunique()),
        "columns": list(analyzer.df.columns),
    })
    print(f"Imported {len(analyzer.df)} records as report id={report_id}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Import CSV data to database")
    parser.add_argument("csv", help="CSV file to import")
    args = parser.parse_args()
    import_data(args.csv)
