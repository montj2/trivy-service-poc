import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_readyz():
    # This might fail if trivy is not installed locally where tests run
    # So we might need to mock get_trivy_version, but for now let's see.
    # If strictly local dev, trivy might not be there.
    # We should mock it.
    from unittest.mock import patch
    with patch("app.api.routes.get_trivy_version", return_value="0.44.0"):
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "trivy_version": "0.44.0"}
