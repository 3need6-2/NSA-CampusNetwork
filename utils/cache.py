"""Simple time-based in-memory cache."""

import time
from typing import Any, Dict, Optional, Tuple


class TimeBasedCache:
    """A simple TTL-based in-memory cache."""

    def __init__(self, default_ttl: int = 300) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        if key not in self._store:
            return None
        value, expiry = self._store[key]
        if time.time() > expiry:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        self._store[key] = (value, time.time() + (ttl or self.default_ttl))

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def invalidate_prefix(self, prefix: str) -> None:
        self._store = {k: v for k, v in self._store.items() if not k.startswith(prefix)}


cache = TimeBasedCache()
