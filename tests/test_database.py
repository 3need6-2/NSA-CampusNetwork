"""Test SQLite database operations in utils/database.py."""

import json
import os
import tempfile
import pytest
from unittest.mock import patch

import utils.database as db


@pytest.fixture(autouse=True)
def isolate_db_path(tmp_path):
    """Redirect DB_PATH to a temp directory for each test."""
    original_path = db.DB_PATH
    test_db = tmp_path / "data" / "analysis.db"
    test_db.parent.mkdir(parents=True, exist_ok=True)
    db.DB_PATH = test_db
    yield
    db.DB_PATH = original_path


class TestSaveReport:
    def test_save_report_returns_int_id(self):
        rid = db.save_report("test.csv", {"key": "value"})
        assert isinstance(rid, int)
        assert rid > 0

    def test_save_report_increments_id(self):
        r1 = db.save_report("a.csv", {"x": 1})
        r2 = db.save_report("b.csv", {"y": 2})
        assert r2 > r1

    def test_save_report_with_unicode(self):
        rid = db.save_report("测试.csv", {"message": "你好"})
        report = db.load_report(rid)
        assert report is not None
        assert report["data"]["message"] == "你好"

    def test_save_report_empty_data(self):
        rid = db.save_report("empty.csv", {})
        report = db.load_report(rid)
        assert report is not None
        assert report["data"] == {}


class TestLoadReport:
    def test_load_existing_report(self):
        rid = db.save_report("existing.csv", {"val": 42})
        report = db.load_report(rid)
        assert report is not None
        assert report["id"] == rid
        assert report["filename"] == "existing.csv"
        assert report["data"]["val"] == 42

    def test_load_nonexistent_report(self):
        report = db.load_report(99999)
        assert report is None

    def test_load_report_has_timestamp(self):
        rid = db.save_report("ts.csv", {})
        report = db.load_report(rid)
        assert "created_at" in report
        assert isinstance(report["created_at"], str)
        assert len(report["created_at"]) > 0

    def test_load_returns_dict_with_integrity(self):
        data = {"users": ["alice", "bob"], "count": 2}
        rid = db.save_report("integrity.csv", data)
        report = db.load_report(rid)
        assert report["filename"] == "integrity.csv"
        assert report["data"]["users"] == ["alice", "bob"]


class TestListReports:
    def test_list_reports_empty(self):
        reports = db.list_reports()
        assert reports == []
        assert isinstance(reports, list)

    def test_list_reports_newest_first(self):
        db.save_report("first.csv", {"n": 1})
        db.save_report("second.csv", {"n": 2})
        db.save_report("third.csv", {"n": 3})
        reports = db.list_reports()
        assert len(reports) == 3
        assert reports[0]["filename"] == "third.csv"
        assert reports[-1]["filename"] == "first.csv"

    def test_list_reports_with_limit(self):
        for i in range(5):
            db.save_report(f"file_{i}.csv", {"i": i})
        reports = db.list_reports(limit=2)
        assert len(reports) == 2

    def test_list_reports_with_offset(self):
        for i in range(3):
            db.save_report(f"f_{i}.csv", {"i": i})
        reports = db.list_reports(limit=1, offset=1)
        assert len(reports) == 1

    def test_list_reports_returns_dicts(self):
        db.save_report("r.csv", {})
        reports = db.list_reports()
        report = reports[0]
        assert isinstance(report, dict)
        assert "id" in report
        assert "filename" in report
        assert "created_at" in report
        assert "data" not in report


class TestConcurrentCalls:
    def test_multiple_save_and_list(self):
        ids = [db.save_report(f"concurrent_{i}.csv", {"i": i}) for i in range(10)]
        for rid in ids:
            report = db.load_report(rid)
            assert report is not None
        assert len(db.list_reports()) == 10


class TestEdgeCases:
    def test_filename_with_spaces(self):
        rid = db.save_report("my report.csv", {"val": 1})
        report = db.load_report(rid)
        assert report["filename"] == "my report.csv"

    def test_nested_json_data(self):
        data = {"deep": {"nested": [1, {"two": 2}]}}
        rid = db.save_report("nested.csv", data)
        report = db.load_report(rid)
        assert report["data"]["deep"]["nested"][1]["two"] == 2
