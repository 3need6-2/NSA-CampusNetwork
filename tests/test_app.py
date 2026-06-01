import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_homepage(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"NSA" in resp.data or b"校园" in resp.data


def test_dashboard(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200


def test_realtime(client):
    resp = client.get("/realtime")
    assert resp.status_code == 200


def test_api_stats(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_dashboard_data(client):
    resp = client.get("/api/dashboard_data")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_user_profiles(client):
    resp = client.get("/api/user_profiles")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_ai_security(client):
    resp = client.get("/api/ai_security")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_ml_anomaly(client):
    resp = client.get("/api/ml_anomaly")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_realtime_status(client):
    resp = client.get("/api/realtime/status")
    assert resp.status_code == 200
    assert resp.is_json


def test_upload_no_file(client):
    resp = client.post("/upload")
    assert resp.status_code == 302


def test_api_ml_anomaly_refresh(client):
    resp = client.post("/api/ml_anomaly/refresh")
    assert resp.status_code == 200
    assert resp.is_json
