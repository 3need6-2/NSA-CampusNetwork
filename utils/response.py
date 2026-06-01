"""Standardized API response helpers."""

from typing import Any, Dict
import time


def api_response(data: Any, status: int = 200) -> Dict[str, Any]:
    """Return a standardized API response envelope."""
    return {
        'success': status < 400,
        'data': data,
        'timestamp': time.time(),
    }
