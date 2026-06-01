"""Test that all modules can be imported without errors."""

import importlib
import pkgutil
import pytest

UTILS_MODULES = [
    "utils.analysis",
    "utils.ai_security",
    "utils.backup",
    "utils.cache",
    "utils.constants",
    "utils.database",
    "utils.logging_config",
    "utils.metrics",
    "utils.ml_anomaly",
    "utils.realtime",
    "utils.response",
    "utils.user_profile",
    "utils.validators",
]

APP_MODULES = ["app"]


@pytest.mark.parametrize("module_name", UTILS_MODULES + APP_MODULES)
def test_module_import(module_name):
    """Verify each module can be imported without raising ImportError."""
    importlib.import_module(module_name)


def test_all_utils_modules_discovered():
    """Ensure that every .py file in utils/ is covered by this test."""
    import utils
    actual = {m.name for m in pkgutil.iter_modules(utils.__path__)}
    tested = set()
    for m in UTILS_MODULES:
        tested.add(m.split(".", 1)[1])
    uncovered = actual - tested
    assert not uncovered, f"Untested utility modules: {uncovered}"


def test_import_with_sys_path():
    """Test import works when running from project root via sys.path manipulation."""
    import sys
    import os

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if root not in sys.path:
        sys.path.insert(0, root)
    importlib.reload(importlib.import_module("utils.constants"))
    importlib.reload(importlib.import_module("utils.cache"))
    importlib.reload(importlib.import_module("utils.metrics"))


def test_dunder_main_backup():
    """Verify utils/backup.py __main__ block runs without error (doesn't crash on import)."""
    module = importlib.import_module("utils.backup")
    assert hasattr(module, "backup_data")
    assert callable(module.backup_data)
