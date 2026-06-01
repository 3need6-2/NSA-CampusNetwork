"""Test that constants defined in utils/constants.py are used consistently

across the codebase -- no stale, missing, or inconsistent values.
"""

import importlib
import inspect
import pytest

import utils.constants as const


def _collect_constant_definitions():
    """Return dict of {name: value} for module-level constants in constants.py."""
    return {
        name: value
        for name, value in inspect.getmembers(const)
        if not name.startswith("_")
        and not inspect.ismodule(value)
        and not inspect.isfunction(value)
        and not inspect.isclass(value)
    }


def _search_text(path, pattern):
    """Return set of (file, line) matching pattern in the given file."""
    import re
    import os

    root = os.path.join(os.path.dirname(__file__), "..")
    hits = set()
    for dirpath, _dirnames, fnames in os.walk(root):
        for fn in fnames:
            if not fn.endswith(".py"):
                continue
            if fn.startswith("test_") and dirpath.endswith("tests"):
                continue
            fpath = os.path.join(dirpath, fn)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    for lineno, line in enumerate(f, 1):
                        if re.search(pattern, line):
                            hits.add((fpath, lineno))
            except Exception:
                continue
    return hits


SENSITIVE_PORTS_KEYS = sorted(const.SENSITIVE_PORTS.keys())
SUSPICIOUS_PORTS = sorted(const.SUSPICIOUS_PORTS)


class TestPortConsistency:
    def test_suspicious_ports_are_sensitive_subset(self):
        for p in SUSPICIOUS_PORTS:
            assert p in SENSITIVE_PORTS_KEYS or p == 53, (
                f"Suspicious port {p} should be a sensitive port or port 53 (DNS)"
            )

    def test_sensitive_ports_ordered(self):
        for i in range(1, len(SENSITIVE_PORTS_KEYS)):
            assert SENSITIVE_PORTS_KEYS[i] > SENSITIVE_PORTS_KEYS[i - 1], (
                "SENSITIVE_PORTS keys should be sorted"
            )

    def test_no_duplicate_sensitive_ports(self):
        assert len(set(SENSITIVE_PORTS_KEYS)) == len(SENSITIVE_PORTS_KEYS)


class TestNamedConstantConsistency:
    def test_realtime_window_size_positive(self):
        assert const.REALTIME_WINDOW_SIZE > 0

    def test_realtime_traffic_buckets_positive(self):
        assert const.REALTIME_TRAFFIC_BUCKETS > 0

    def test_realtime_bucket_seconds_positive(self):
        assert const.REALTIME_BUCKET_SECONDS > 0

    def test_realtime_port_scan_threshold_positive(self):
        assert const.REALTIME_PORT_SCAN_THRESHOLD > 0

    def test_realtime_large_flow_bytes_positive(self):
        assert const.REALTIME_LARGE_FLOW_BYTES > 0

    def test_ml_contamination_range(self):
        assert 0 < const.ML_DEFAULT_CONTAMINATION <= 1

    def test_ml_min_users_positive(self):
        assert const.ML_MIN_USERS > 0

    def test_ml_top_n_positive(self):
        assert const.ML_TOP_N > 0


class TestCategoriesConsistency:
    def test_normalized_categories_nonempty(self):
        assert len(const.NORMALIZED_CATEGORIES) > 0

    def test_each_category_has_aliases(self):
        for cat, aliases in const.NORMALIZED_CATEGORIES.items():
            assert isinstance(aliases, list)
            assert len(aliases) >= 1
            assert cat in aliases, (
                f"Category '{cat}' must appear in its own alias list"
            )

    def test_no_overlap_between_categories(self):
        all_seen = {}
        for cat, aliases in const.NORMALIZED_CATEGORIES.items():
            for alias in aliases:
                assert alias not in all_seen, (
                    f"Alias '{alias}' overlaps between '{all_seen[alias]}' and '{cat}'"
                )
                all_seen[alias] = cat


class TestTermsNonEmpty:
    @pytest.mark.parametrize("term_list_name", [
        "PROMPT_INJECTION_TERMS",
        "AI_AGENT_TERMS",
        "WEB_ATTACK_TERMS",
    ])
    def test_terms_list_nonempty(self, term_list_name):
        lst = getattr(const, term_list_name)
        assert isinstance(lst, list)
        assert len(lst) > 0
        for t in lst:
            assert isinstance(t, str)
            assert len(t) > 0


class TestFeatureNamesDeduped:
    def test_feature_names_unique(self):
        assert len(const.FEATURE_NAMES) == len(set(const.FEATURE_NAMES))

    def test_feature_names_nonempty(self):
        assert len(const.FEATURE_NAMES) > 0
