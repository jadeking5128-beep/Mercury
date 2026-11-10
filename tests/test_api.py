from fastapi.testclient import TestClient

import mercury.storage as storage
from mercury.api import app


def make_client(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "mercury-test.db")
    monkeypatch.setenv("MERCURY_API_TOKEN", "test-token-" + ("x" * 48))
    return TestClient(app)


def test_api_requires_bearer_token(monkeypatch, tmp_path):
    with make_client(monkeypatch, tmp_path) as client:
        assert client.get("/api/v1/health").status_code == 401
        response = client.get("/api/v1/health",
                              headers={"Authorization": "Bearer " + "test-token-" + ("x" * 48)})
        assert response.status_code == 200
        assert response.json()["service"] == "mercury-api"


def test_target_registration_and_unverified_scan_rejection(monkeypatch, tmp_path):
    token = "test-token-" + ("x" * 48)
    headers = {"Authorization": "Bearer " + token}
    with make_client(monkeypatch, tmp_path) as client:
        created = client.post("/api/v1/targets", json={"hostname": "example.com"},
                              headers=headers)
        assert created.status_code == 200
        target_id = created.json()["id"]
        assert created.json()["record_name"] == "_mercury-challenge.example.com"
        scan = client.post("/api/v1/scans",
                           json={"target_id": target_id, "modules": ["dns"]},
                           headers=headers)
        assert scan.status_code == 403


def test_api_rejects_raw_ip_target(monkeypatch, tmp_path):
    headers = {"Authorization": "Bearer " + "test-token-" + ("x" * 48)}
    with make_client(monkeypatch, tmp_path) as client:
        response = client.post("/api/v1/targets", json={"hostname": "127.0.0.1"},
                               headers=headers)
        assert response.status_code == 422
