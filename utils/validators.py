"""Input validation utilities for the campus network application."""

import re
from typing import Any, Dict, List, Optional, Tuple, Union


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 address string."""
    if not isinstance(ip, str):
        return False
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    m = re.match(pattern, ip)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def validate_port(port: Union[int, str]) -> bool:
    """Validate a network port number (1-65535)."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


def validate_csv_columns(columns: List[str]) -> Tuple[bool, List[str]]:
    """Validate that required CSV columns are present."""
    required = {"timestamp", "bytes", "user", "src_ip", "dst_ip", "dst_port", "app_category", "protocol"}
    col_set = set(columns)
    missing = [c for c in sorted(required) if c not in col_set]
    return (len(missing) == 0, missing)


def validate_rate(rate: Any) -> Tuple[bool, Optional[str]]:
    """Validate a replay rate value."""
    try:
        r = float(rate)
    except (TypeError, ValueError):
        return False, "速率必须为数值"
    if r <= 0:
        return False, "速率必须大于 0"
    if r > 1000:
        return False, "速率不能超过 1000"
    return True, None


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    cleaned = re.sub(r"[^\w\.\-]", "_", filename)
    cleaned = cleaned.strip("._")
    return cleaned or "unnamed"


def validate_email(email: str) -> bool:
    """Basic email format validation."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))
