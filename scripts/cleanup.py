"""CLI script to clean old data and logs."""

import sys
import os
import shutil
from pathlib import Path


def cleanup(days: int = 30, dry_run: bool = False) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from utils.database import cleanup_old_reports

    base = Path(__file__).parent.parent
    deleted_count = 0

    old_reports = cleanup_old_reports(days)
    deleted_count += old_reports
    if dry_run:
        print(f"[DRY-RUN] Would delete {old_reports} old reports from database")
    else:
        print(f"Deleted {old_reports} old reports from database")

    data_dir = base / "data"
    if data_dir.exists():
        for f in data_dir.glob("*.csv"):
            if f.name != "traffic.csv":
                if dry_run:
                    print(f"[DRY-RUN] Would delete: {f}")
                else:
                    f.unlink()
                    deleted_count += 1
                    print(f"Deleted: {f}")

    logs_dir = base / "logs"
    if logs_dir.exists():
        for f in logs_dir.glob("*"):
            if f.is_file():
                if dry_run:
                    print(f"[DRY-RUN] Would delete: {f}")
                else:
                    f.unlink()
                    deleted_count += 1
                    print(f"Deleted: {f}")

    cache_dir = base / "__pycache__"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        print(f"Removed: {cache_dir}")

    print(f"Cleanup complete. {deleted_count} items removed.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Clean old data, logs, and cache files")
    parser.add_argument("--days", type=int, default=30, help="Delete records older than N days")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without deleting")
    args = parser.parse_args()
    cleanup(args.days, args.dry_run)
