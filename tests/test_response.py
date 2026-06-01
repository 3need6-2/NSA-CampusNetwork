import time
from utils.response import api_response


def test_api_response_success():
    result = api_response({"key": "value"}, status=200)
    assert result["success"] is True
    assert result["data"] == {"key": "value"}
    assert "timestamp" in result
    assert isinstance(result["timestamp"], float)


def test_api_response_error():
    result = api_response({"error": "not found"}, status=404)
    assert result["success"] is False
    assert result["data"] == {"error": "not found"}


def test_api_response_status_range():
    for status in [200, 201, 400, 404, 500]:
        result = api_response(None, status=status)
        expected_success = status < 400
        assert result["success"] is expected_success


def test_api_response_timestamp():
    before = time.time()
    result = api_response("ok")
    after = time.time()
    assert before <= result["timestamp"] <= after


def test_api_response_none_data():
    result = api_response(None)
    assert result["success"] is True
    assert result["data"] is None
