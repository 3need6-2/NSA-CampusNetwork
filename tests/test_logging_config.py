"""Test logging configuration including JSON formatter."""

import json
import io
import logging
import re
import pytest
from utils.logging_config import JSONFormatter, setup_logger, setup_json_logger


class TestJSONFormatter:
    def test_format_basic_record(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/path/to/module.py",
            lineno=42,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        record.funcName = ""
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test_logger"
        assert parsed["message"] == "hello world"
        assert parsed["module"] == "module"
        assert parsed["function"] == ""
        assert parsed["line"] == 42
        assert "timestamp" in parsed
        assert "exception" not in parsed

    def test_format_with_exception(self):
        formatter = JSONFormatter()
        import traceback
        try:
            raise ValueError("test error")
        except ValueError:
            exc_type, exc_value, exc_tb = __import__("sys").exc_info()
            record = logging.LogRecord(
                name="err", level=logging.ERROR,
                pathname="/f.py", lineno=10,
                msg="error occurred", args=(),
                exc_info=(exc_type, exc_value, exc_tb),
            )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "ERROR"
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]
        assert "test error" in parsed["exception"]

    def test_format_with_extra(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="ext", level=logging.WARNING,
            pathname="/f.py", lineno=5,
            msg="with extra", args=(), exc_info=None,
        )
        record.extra = {"user_id": 123, "request_id": "abc"}
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["extra"]["user_id"] == 123
        assert parsed["extra"]["request_id"] == "abc"

    def test_format_output_is_valid_json(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="json_test", level=logging.DEBUG,
            pathname="/t.py", lineno=1,
            msg="valid json", args=(), exc_info=None,
        )
        output = formatter.format(record)
        json.loads(output)

    def test_unicode_message(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="uni", level=logging.INFO,
            pathname="/u.py", lineno=1,
            msg="你好世界", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "你好世界"


class TestSetupLogger:
    def test_setup_logger_returns_logger(self):
        logger = setup_logger("test_std")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_std"

    def test_setup_logger_level(self):
        logger = setup_logger("test_level", level=logging.DEBUG)
        assert logger.level == logging.DEBUG

    def test_setup_logger_default_level(self):
        logger = setup_logger("test_default")
        assert logger.level == logging.INFO

    def test_setup_logger_has_console_handler(self):
        logger = setup_logger("test_console")
        assert len(logger.handlers) >= 1
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

    def test_called_twice_reuses_handlers(self):
        logger1 = setup_logger("test_reuse")
        n1 = len(logger1.handlers)
        logger2 = setup_logger("test_reuse")
        assert len(logger2.handlers) == n1


class TestSetupJSONLogger:
    def test_setup_json_logger_returns_logger(self):
        logger = setup_json_logger("test_json")
        assert isinstance(logger, logging.Logger)

    def test_setup_json_logger_uses_json_formatter(self):
        logger = setup_json_logger("test_fmt")
        for h in logger.handlers:
            assert isinstance(h, logging.StreamHandler)
            assert isinstance(h.formatter, JSONFormatter)

    def test_json_logger_output_format(self):
        logger = setup_json_logger("test_out")
        stream = io.StringIO()
        for h in logger.handlers:
            h.stream = stream
        logger.info("json log test")
        output = stream.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["message"] == "json log test"
        assert parsed["logger"] == "test_out"
        assert parsed["level"] == "INFO"


class TestIntegration:
    def test_std_logger_to_json_conversion(self):
        logger = setup_logger("integ_std")
        stream = io.StringIO()
        for h in logger.handlers:
            h.stream = stream
        logger.info("integration test")
        output = stream.getvalue()
        assert "integration test" in output
        assert "INFO" in output
        assert "integ_std" in output

    def test_logger_name_none(self):
        logger = setup_logger()
        assert logger.name is not None
        assert len(logger.name) > 0
