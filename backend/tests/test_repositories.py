
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
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestSessionLocal = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    Base.metadata.create_all(bind=test_engine)

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
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


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


def register_repository(
    client: TestClient,
    token: str,
    url: str = "https://github.com/example/project.git",
):
    return client.post(
        "/api/v1/repositories",
        headers=auth_header(token),
        json={"clone_url": url, "default_branch": "main"},
    )


def test_repository_endpoint_requires_authentication(client):
    response = client.get("/api/v1/repositories")
    assert response.status_code == 401


def test_register_and_list_repository(client):
    token = create_account(client, "owner@example.com")

    response = register_repository(client, token)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["provider"] == "github"
    assert body["full_name"] == "example/project"
    assert body["name"] == "project"
    assert body["default_branch"] == "main"
    assert "owner_id" in body

    listing = client.get(
        "/api/v1/repositories",
        headers=auth_header(token),
    )

    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert listing.json()[0]["id"] == body["id"]


def test_duplicate_repository_returns_conflict(client):
    token = create_account(client, "duplicate@example.com")

    first = register_repository(client, token)
    second = register_repository(client, token)

    assert first.status_code == 201
    assert second.status_code == 409


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/project",
        "https://evil.example/example/project",
        "https://user:password@github.com/example/project",
        "https://github.com/example/project?token=secret",
        "https://github.com/example",
    ],
)
def test_invalid_repository_url_is_rejected(client, url):
    token = create_account(client, "validation@example.com")

    response = register_repository(client, token, url)

    assert response.status_code == 422


def test_users_cannot_access_another_users_repository(client):
    owner_token = create_account(client, "first@example.com")
    other_token = create_account(client, "second@example.com")

    created = register_repository(client, owner_token)
    assert created.status_code == 201
    repository_id = created.json()["id"]

    detail = client.get(
        f"/api/v1/repositories/{repository_id}",
        headers=auth_header(other_token),
    )
    assert detail.status_code == 404

    deletion = client.delete(
        f"/api/v1/repositories/{repository_id}",
        headers=auth_header(other_token),
    )
    assert deletion.status_code == 404

    # The original owner still has access.
    owner_detail = client.get(
        f"/api/v1/repositories/{repository_id}",
        headers=auth_header(owner_token),
    )
    assert owner_detail.status_code == 200


def test_owner_can_delete_repository(client):
    token = create_account(client, "delete@example.com")
    created = register_repository(client, token)
    assert created.status_code == 201

    repository_id = created.json()["id"]

    deleted = client.delete(
        f"/api/v1/repositories/{repository_id}",
        headers=auth_header(token),
    )
    assert deleted.status_code == 204

    detail = client.get(
        f"/api/v1/repositories/{repository_id}",
        headers=auth_header(token),
    )
    assert detail.status_code == 404


def test_repository_list_is_scoped_to_current_user(client):
    first_token = create_account(client, "first-owner@example.com")
    second_token = create_account(client, "second-owner@example.com")

    first = register_repository(
        client,
        first_token,
        "https://github.com/first-owner/alpha.git",
    )
    second = register_repository(
        client,
        second_token,
        "https://gitlab.com/second-owner/beta.git",
    )

    assert first.status_code == 201
    assert second.status_code == 201

    first_list = client.get(
        "/api/v1/repositories",
        headers=auth_header(first_token),
    )
    second_list = client.get(
        "/api/v1/repositories",
        headers=auth_header(second_token),
    )

    assert [r["full_name"] for r in first_list.json()] == [
        "first-owner/alpha"
    ]
    assert [r["full_name"] for r in second_list.json()] == [
        "second-owner/beta"
    ]
