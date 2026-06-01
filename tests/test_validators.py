"""Test the input validators in utils/validators.py."""

import pytest
from utils.validators import (
    validate_ip,
    validate_port,
    validate_csv_columns,
    validate_rate,
    sanitize_filename,
    validate_email,
)


class TestValidateIP:
    @pytest.mark.parametrize("ip", [
        "192.168.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "1.2.3.4",
        "10.0.0.1",
    ])
    def test_valid_ips(self, ip):
        assert validate_ip(ip) is True

    @pytest.mark.parametrize("bad_ip", [
        "256.1.2.3",
        "1.2.3.256",
        "abc.def.ghi.jkl",
        "192.168.1",
        "192.168.1.1.1",
        " 192.168.1.1",
        "",
        "300.300.300.300",
        "-1.0.0.0",
    ])
    def test_invalid_ips(self, bad_ip):
        assert validate_ip(bad_ip) is False

    def test_non_string_ip(self):
        assert validate_ip(12345) is False


class TestValidatePort:
    @pytest.mark.parametrize("port", [1, 80, 443, 3306, 65535, "80", "443", 1024])
    def test_valid_ports(self, port):
        assert validate_port(port) is True

    @pytest.mark.parametrize("bad_port", [0, -1, 65536, 99999, "abc", "", None])
    def test_invalid_ports(self, bad_port):
        assert validate_port(bad_port) is False


class TestValidateCSVColumns:
    def test_all_columns_present(self):
        cols = ["timestamp", "bytes", "user", "src_ip", "dst_ip", "dst_port", "app_category", "protocol"]
        ok, missing = validate_csv_columns(cols)
        assert ok is True
        assert missing == []

    def test_missing_columns(self):
        cols = ["timestamp", "bytes"]
        ok, missing = validate_csv_columns(cols)
        assert ok is False
        assert "user" in missing
        assert "src_ip" in missing

    def test_extra_columns_ignored(self):
        cols = ["timestamp", "bytes", "user", "src_ip", "dst_ip", "dst_port", "app_category", "protocol", "extra_col"]
        ok, missing = validate_csv_columns(cols)
        assert ok is True

    def test_empty_list(self):
        ok, missing = validate_csv_columns([])
        assert ok is False
        assert len(missing) == 8


class TestValidateRate:
    @pytest.mark.parametrize("rate", [1, 5.0, 0.5, 100, 1000])
    def test_valid_rates(self, rate):
        ok, msg = validate_rate(rate)
        assert ok is True
        assert msg is None

    @pytest.mark.parametrize("bad_rate", [0, -1, 1001, "abc", None, "one"])
    def test_invalid_rates(self, bad_rate):
        ok, msg = validate_rate(bad_rate)
        assert ok is False
        assert isinstance(msg, str)
        assert len(msg) > 0


class TestSanitizeFilename:
    def test_clean_filename(self):
        assert sanitize_filename("report.csv") == "report.csv"

    def test_path_traversal_removed(self):
        result = sanitize_filename("../../../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_special_chars_replaced(self):
        result = sanitize_filename("file<name>.csv")
        assert "<" not in result

    def test_empty_string_returns_default(self):
        assert sanitize_filename("") == "unnamed"

    def test_only_special_chars(self):
        result = sanitize_filename("<>:\"/\\|?*")
        assert result == "unnamed"


class TestValidateEmail:
    @pytest.mark.parametrize("email", [
        "user@example.com",
        "test.user@domain.co.uk",
        "user+tag@example.org",
        "a@b.cd",
    ])
    def test_valid_emails(self, email):
        assert validate_email(email) is True

    @pytest.mark.parametrize("bad_email", [
        "",
        "not-an-email",
        "@example.com",
        "user@",
        "user@.com",
        "user@example",
    ])
    def test_invalid_emails(self, bad_email):
        assert validate_email(bad_email) is False
