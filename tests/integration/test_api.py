"""API tests for SecureFlow."""

import pytest
from fastapi.testclient import TestClient

from secureflow.api.app import app
# --- константы вынесены FORGE refactor ---
CONST_200 = 200



@pytest.fixture
def client():
    return TestClient(app)


class TestAPI:
    def test_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == CONST_200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_version(self, client):
        response = client.get("/api/version")
        assert response.status_code == CONST_200
        data = response.json()
        assert "version" in data

    def test_list_scanners(self, client):
        response = client.get("/api/scanners")
        assert response.status_code == CONST_200
        data = response.json()
        assert "secrets" in data
        assert "sast" in data

    def test_scan_nonexistent(self, client):
        response = client.post("/api/scan", json={"target": "/nonexistent/path/xyz"})
        assert response.status_code == 400

    def test_scan_empty_dir(self, client, tmp_path):
        response = client.post("/api/scan", json={"target": str(tmp_path)})
        assert response.status_code == CONST_200
        data = response.json()
        assert data["total_findings"] == 0
        assert data["risk_score"] == 100.0
