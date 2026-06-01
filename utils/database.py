"""SQLite persistence for analysis results."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).parent.parent / "data" / "analysis.db"


def _get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_db() -> None:
    conn = _get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            created_at TEXT NOT NULL,
            data TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_report(filename: str, data: Dict[str, Any]) -> int:
    """Save an analysis report and return its row id."""
    _init_db()
    conn = _get_connection()
    cursor = conn.execute(
        "INSERT INTO reports (filename, created_at, data) VALUES (?, ?, ?)",
        (filename, datetime.utcnow().isoformat(), json.dumps(data, ensure_ascii=False)),
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id


def load_report(report_id: int) -> Optional[Dict[str, Any]]:
    """Load a single report by its id, or None if not found."""
    _init_db()
    conn = _get_connection()
    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row["id"],
        "filename": row["filename"],
        "created_at": row["created_at"],
        "data": json.loads(row["data"]),
    }


def list_reports(limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    """List saved reports, newest first."""
    _init_db()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT id, filename, created_at FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
