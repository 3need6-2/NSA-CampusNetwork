import pytest
import yaml
from pathlib import Path


CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


@pytest.fixture
def config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def test_config_exists():
    assert CONFIG_PATH.exists()


def test_config_server_host(config):
    assert "server" in config
    assert "host" in config["server"]


def test_config_server_port(config):
    assert isinstance(config["server"]["port"], int)


def test_config_upload_allowed_extensions(config):
    assert "upload" in config
    assert "allowed_extensions" in config["upload"]


def test_config_upload_max_size(config):
    assert isinstance(config["upload"]["max_size_mb"], int)


def test_config_deepseek_api_url(config):
    assert "deepseek" in config
    assert "api_url" in config["deepseek"]


def test_config_deepseek_model(config):
    assert isinstance(config["deepseek"]["model"], str)


def test_config_logging_level(config):
    assert config["logging"]["level"] in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def test_config_analysis_default_top_n(config):
    assert "analysis" in config
    assert config["analysis"]["default_top_n"] == 10


def test_config_analysis_default_contamination(config):
    assert config["analysis"]["default_contamination"] == 0.1
