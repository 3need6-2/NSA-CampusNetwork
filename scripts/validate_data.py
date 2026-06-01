"""Validate a CSV data file for required columns and data types."""

import csv
import sys
from pathlib import Path

REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port",
    "dst_port", "protocol", "bytes", "app_category", "user",
]


def validate_csv(filepath: str) -> dict:
    errors = []
    path = Path(filepath)
    if not path.exists():
        return {"valid": False, "errors": [f"File not found: {filepath}"]}

    with open(path, newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return {"valid": False, "errors": ["Empty file"]}

        header_stripped = [h.strip() for h in header]
        for col in REQUIRED_COLUMNS:
            if col not in header_stripped:
                errors.append(f"Missing required column: {col}")

        if errors:
            return {"valid": False, "errors": errors}

        col_index = {h: i for i, h in enumerate(header_stripped)}
        row_count = 0
        for row_num, row in enumerate(reader, start=2):
            row_count += 1
            if len(row) != len(REQUIRED_COLUMNS):
                errors.append(f"Row {row_num}: expected {len(REQUIRED_COLUMNS)} columns, got {len(row)}")
                continue
            try:
                bytes_val = int(row[col_index["bytes"]])
                if bytes_val < 0:
                    errors.append(f"Row {row_num}: negative bytes value")
            except ValueError:
                errors.append(f"Row {row_num}: invalid bytes value: {row[col_index['bytes']]}")

    return {"valid": len(errors) == 0, "errors": errors, "rows": row_count}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python validate_data.py <csv_path>")
        sys.exit(1)
    result = validate_csv(sys.argv[1])
    if result["valid"]:
        print(f"Valid: {result['rows']} rows")
    else:
        print(f"Invalid: {len(result['errors'])} errors")
        for e in result["errors"]:
            print(f"  - {e}")
        sys.exit(1)
