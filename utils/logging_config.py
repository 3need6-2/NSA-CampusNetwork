import logging
import sys
import json
import datetime
from pathlib import Path
from typing import Any, Dict, Optional

LOG_DIR = Path(__file__).parent.parent / "logs"
DEFAULT_LEVEL = logging.INFO
DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs JSON-formatted log records."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            log_entry["extra"] = record.extra
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logger(
    name: str = None,
    level: int = DEFAULT_LEVEL,
    log_file: str = None,
) -> logging.Logger:
    logger = logging.getLogger(name or __name__)
    logger.setLevel(level)

    formatter = logging.Formatter(DEFAULT_FORMAT)

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_file:
            LOG_DIR.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(LOG_DIR / log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def setup_json_logger(
    name: Optional[str] = None,
    level: int = DEFAULT_LEVEL,
    log_file: Optional[str] = None,
) -> logging.Logger:
    logger = logging.getLogger(name or __name__)
    logger.setLevel(level)

    json_formatter = JSONFormatter()

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(json_formatter)
        logger.addHandler(console_handler)

        if log_file:
            LOG_DIR.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(LOG_DIR / log_file, encoding="utf-8")
            file_handler.setFormatter(json_formatter)
            logger.addHandler(file_handler)

    return logger
