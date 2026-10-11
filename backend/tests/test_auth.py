
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import Finding, Repository, Scan, User  # noqa: F401


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


def register(client: TestClient, email="tester@example.com"):
    return client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "A-Strong-Test-Password-2026!",
        },
    )


def login(client: TestClient, email="tester@example.com"):
    return client.post(
        "/api/v1/auth/login",
        data={
            "username": email,
            "password": "A-Strong-Test-Password-2026!",
        },
    )


def test_register_user(client):
    response = register(client)

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "tester@example.com"
    assert body["is_active"] is True
    assert "password_hash" not in body
    assert "password" not in body


def test_duplicate_registration_returns_conflict(client):
    assert register(client).status_code == 201

    response = register(client)

    assert response.status_code == 409


def test_login_returns_access_token(client):
    assert register(client).status_code == 201

    response = login(client)

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str)
    assert len(body["access_token"]) > 20


def test_wrong_password_is_rejected(client):
    assert register(client).status_code == 201

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "tester@example.com",
            "password": "Wrong-password-2026!",
        },
    )

    assert response.status_code == 401


def test_profile_requires_authentication(client):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_authenticated_user_can_view_profile(client):
    assert register(client).status_code == 201
    token_response = login(client)
    assert token_response.status_code == 200

    token = token_response.json()["access_token"]
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["email"] == "tester@example.com"


def test_invalid_token_is_rejected(client):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401
