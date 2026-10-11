from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint_returns_api_information() -> None:
    response = client.get("/")

    assert response.status_code == 200

    body = response.json()
    assert body["name"] == "VulnGuard API"
    assert body["version"] == "0.1.0"
    assert body["status"] == "running"
    assert body["health_endpoint"] == "/api/v1/health"


def test_health_endpoint_returns_ok() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "VulnGuard API",
        "version": "0.1.0",
    }


def test_health_endpoint_uses_get_method() -> None:
    response = client.post("/api/v1/health")

    assert response.status_code == 405


def test_unknown_endpoint_returns_404() -> None:
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404


def test_openapi_schema_is_available() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()
    assert schema["info"]["title"] == "VulnGuard API"
    assert "/api/v1/health" in schema["paths"]
