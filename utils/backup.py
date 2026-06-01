"""Backup utility for the data directory."""

import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parent.parent / "data"
BACKUP_DIR = Path(__file__).parent.parent / "backups"


def backup_data(output_path: Optional[Path] = None) -> Path:
    """Create a timestamped ZIP backup of the data/ directory.

    Returns the path to the created backup file.
    """
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Data directory not found: {DATA_DIR}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = BACKUP_DIR / f"data_backup_{timestamp}.zip"

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in DATA_DIR.rglob("*"):
            if item.is_file():
                arcname = str(item.relative_to(DATA_DIR.parent))
                zf.write(item, arcname)

    return output_path


if __name__ == "__main__":
    path = backup_data()
    print(f"Backup created: {path}")
