import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import Finding, Repository, Scan, User  # noqa: F401


PASSWORD = "A-Strong-Test-Password-2026!"


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def create_account(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 201, response.text

    response = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_repository(client: TestClient, token: str) -> int:
    response = client.post(
        "/api/v1/repositories",
        headers=auth_header(token),
        json={
            "clone_url": "https://github.com/example/project.git",
            "default_branch": "main",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def create_queued_scan(
    client: TestClient,
    token: str,
    repository_id: int,
) -> dict:
    response = client.post(
        "/api/v1/scans",
        headers=auth_header(token),
        json={
            "repository_id": repository_id,
            "scanners": ["semgrep", "gitleaks"],
        },
    )
    assert response.status_code == 202, response.text
    return response.json()


def prepare_scan_environment(monkeypatch, tmp_path):
    submitted = []
    cancellation_requests = []

    monkeypatch.setattr(
        "app.api.v1.scans.get_repository_workspace",
        lambda owner_id, repository_id: tmp_path,
    )

    def fake_submit(**kwargs):
        submitted.append(kwargs)

    monkeypatch.setattr(
        "app.api.v1.scans.scan_worker.submit",
        fake_submit,
    )
    monkeypatch.setattr(
        "app.api.v1.scans.scan_worker.request_cancel",
        lambda scan_id: cancellation_requests.append(scan_id),
    )

    return submitted, cancellation_requests


def test_scan_submission_returns_accepted_and_queues_job(
    client, monkeypatch, tmp_path
):
    submitted, _ = prepare_scan_environment(monkeypatch, tmp_path)
    token = create_account(client, "scan-owner@example.com")
    repository_id = create_repository(client, token)

    scan = create_queued_scan(client, token, repository_id)

    assert scan["status"] == "queued"
    assert scan["repository_id"] == repository_id
    assert scan["progress_percent"] == 0
    assert scan["cancel_requested"] is False
    assert len(submitted) == 1
    assert submitted[0]["owner_id"] > 0
    assert submitted[0]["repository_id"] == repository_id
    assert submitted[0]["scanner_names"] == ["semgrep", "gitleaks"]


def test_user_cannot_read_or_cancel_another_users_scan(
    client, monkeypatch, tmp_path
):
    prepare_scan_environment(monkeypatch, tmp_path)

    owner_token = create_account(client, "scan-owner2@example.com")
    other_token = create_account(client, "scan-other@example.com")
    repository_id = create_repository(client, owner_token)
    scan = create_queued_scan(client, owner_token, repository_id)
    scan_id = scan["id"]

    headers = auth_header(other_token)

    read_response = client.get(
        f"/api/v1/scans/{scan_id}",
        headers=headers,
    )
    cancel_response = client.post(
        f"/api/v1/scans/{scan_id}/cancel",
        headers=headers,
    )

    assert read_response.status_code == 404
    assert cancel_response.status_code == 404


def test_owner_can_request_scan_cancellation(
    client, monkeypatch, tmp_path
):
    _, cancellation_requests = prepare_scan_environment(
        monkeypatch, tmp_path
    )
    token = create_account(client, "scan-cancel@example.com")
    repository_id = create_repository(client, token)
    scan = create_queued_scan(client, token, repository_id)

    response = client.post(
        f"/api/v1/scans/{scan['id']}/cancel",
        headers=auth_header(token),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["cancel_requested"] is True
    assert body["id"] == scan["id"]
    assert cancellation_requests == [scan["id"]]


def test_scan_creation_requires_authentication(client):
    response = client.post(
        "/api/v1/scans",
        json={"repository_id": 1, "scanners": ["semgrep"]},
    )
    assert response.status_code == 401
