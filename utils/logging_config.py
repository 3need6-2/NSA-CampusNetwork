import logging
import sys
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
DEFAULT_LEVEL = logging.INFO
DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


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
