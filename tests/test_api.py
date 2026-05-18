from fastapi.testclient import TestClient

from backend.api.main import app


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_stats_endpoint_contains_mvp_keys():
    with TestClient(app) as client:
        response = client.get("/stats")
    assert response.status_code == 200
    payload = response.json()
    assert {"packets", "devices", "alerts", "protocols"} <= set(payload)
