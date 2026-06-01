"""Test the time-based in-memory cache utility."""

import time
import pytest
from utils.cache import TimeBasedCache


@pytest.fixture
def cache():
    return TimeBasedCache(default_ttl=300)


class TestCacheSetGet:
    def test_set_and_get(self, cache):
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key(self, cache):
        assert cache.get("nonexistent") is None

    def test_get_expired_key(self, cache):
        cache.set("expires_soon", "data", ttl=-1)
        assert cache.get("expires_soon") is None

    def test_overwrite_existing(self, cache):
        cache.set("k", "old")
        cache.set("k", "new")
        assert cache.get("k") == "new"

    def test_custom_ttl(self, cache):
        cache.set("k", "v", ttl=60)
        val = cache.get("k")
        assert val == "v"

    def test_none_value(self, cache):
        cache.set("null_key", None)
        assert cache.get("null_key") is None

    def test_dict_value(self, cache):
        d = {"a": 1, "b": [2, 3]}
        cache.set("dict_key", d)
        assert cache.get("dict_key") == d


class TestCacheDelete:
    def test_delete_existing(self, cache):
        cache.set("k", "v")
        cache.delete("k")
        assert cache.get("k") is None

    def test_delete_missing(self, cache):
        cache.delete("nonexistent")

    def test_delete_then_set(self, cache):
        cache.set("k", "v1")
        cache.delete("k")
        cache.set("k", "v2")
        assert cache.get("k") == "v2"


class TestCacheClear:
    def test_clear_empty(self, cache):
        cache.clear()

    def test_clear_removes_all(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None
        assert cache.get("c") is None

    def test_clear_then_set(self, cache):
        cache.set("k", "v")
        cache.clear()
        cache.set("k", "new_v")
        assert cache.get("k") == "new_v"


class TestCacheInvalidatePrefix:
    def test_invalidate_prefix(self, cache):
        cache.set("user:alice", 1)
        cache.set("user:bob", 2)
        cache.set("config:app", 3)
        cache.invalidate_prefix("user:")
        assert cache.get("user:alice") is None
        assert cache.get("user:bob") is None
        assert cache.get("config:app") == 3

    def test_invalidate_prefix_no_match(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        cache.invalidate_prefix("z:")
        assert cache.get("a") == 1
        assert cache.get("b") == 2

    def test_invalidate_prefix_empty_cache(self, cache):
        cache.invalidate_prefix("x")


class TestCacheEdgeCases:
    def test_large_value(self, cache):
        big = list(range(10000))
        cache.set("big", big)
        assert cache.get("big") == big

    def test_special_chars_in_key(self, cache):
        cache.set("key with spaces", "val")
        assert cache.get("key with spaces") == "val"

    def test_empty_string_key(self, cache):
        cache.set("", "empty_key")
        assert cache.get("") == "empty_key"

    def test_default_ttl_property(self, cache):
        assert cache.default_ttl == 300

    def test_custom_default_ttl(self):
        c = TimeBasedCache(default_ttl=60)
        assert c.default_ttl == 60
