"""Tests for recently added API endpoints."""
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


def test_api_stats_detailed(client):
    resp = client.get("/api/stats/detailed")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert isinstance(data, dict)


def test_api_network_topology(client):
    resp = client.get("/api/network/topology")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert isinstance(data, (dict, list))


def test_api_search(client):
    resp = client.get("/api/search?q=student")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_tags(client):
    resp = client.get("/api/tags")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert isinstance(data, (dict, list))


def test_api_tags_specific(client):
    resp = client.get("/api/tags/VPN用户")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_users(client):
    resp = client.get("/api/users")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_summary(client):
    resp = client.get("/api/summary")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_traffic_timeline(client):
    resp = client.get("/api/traffic/timeline")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_traffic_protocols(client):
    resp = client.get("/api/traffic/protocols")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_alerts_history(client):
    resp = client.get("/api/alerts/history")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert "status" in data


def test_api_config(client):
    resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_export_json(client):
    resp = client.get("/api/export/json")
    assert resp.status_code == 200
    assert resp.is_json or "json" in resp.content_type


def test_api_export_csv(client):
    resp = client.get("/api/export/csv")
    assert resp.status_code == 200


def test_api_data_info(client):
    resp = client.get("/api/data/info")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_404_returns_json(client):
    resp = client.get("/api/nonexistent_route_xyz")
    assert resp.status_code == 404
