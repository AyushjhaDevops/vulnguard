from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models import Finding, Repository, Scan, User  # noqa: F401
from app.workers import scan_worker as worker_module


@pytest.fixture
def worker_database(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)

    db = Session()
    user = User(
        email="worker-test@example.com",
        password_hash="test-hash",
    )
    db.add(user)
    db.flush()

    repository = Repository(
        owner_id=user.id,
        name="project",
        full_name="example/project",
        provider="github",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
    )
    db.add(repository)
    db.flush()

    scan = Scan(repository_id=repository.id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    monkeypatch.setattr(worker_module, "SessionLocal", Session)

    yield db, user, repository, scan

    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_worker_checks_out_repository_persists_commit_and_cleans_up(
    worker_database, monkeypatch, tmp_path
):
    db, user, repository, scan = worker_database
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    calls = {}
    cleaned = []

    def fake_checkout(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(
            workspace=workspace,
            commit_sha="a" * 40,
        )

    def fake_execute(db, *, scan, target, scanner_names, **kwargs):
        assert target == workspace
        assert scanner_names == ["semgrep"]
        scan.status = "completed"
        scan.progress_percent = 100
        db.add(scan)
        db.commit()
        return scan

    monkeypatch.setattr(
        worker_module, "checkout_repository", fake_checkout
    )
    monkeypatch.setattr(
        worker_module, "execute_scan", fake_execute
    )
    monkeypatch.setattr(
        worker_module,
        "cleanup_checkout",
        lambda path: cleaned.append(path),
    )

    worker_module.ScanWorkerManager._run_scan(
        scan.id,
        user.id,
        repository.id,
        ["semgrep"],
        __import__("threading").Event(),
    )

    db.refresh(scan)

    assert calls["clone_url"] == repository.clone_url
    assert calls["branch"] == "main"
    assert calls["scan_id"] == scan.id
    assert scan.commit_sha == "a" * 40
    assert scan.status == "completed"
    assert cleaned == [workspace]


def test_worker_marks_checkout_failure_without_leaking_git_output(
    worker_database, monkeypatch, tmp_path
):
    db, user, repository, scan = worker_database
    cleaned = []

    def failed_checkout(**kwargs):
        raise worker_module.GitCheckoutError(
            "Repository checkout failed. Verify repository access and branch."
        )

    monkeypatch.setattr(
        worker_module, "checkout_repository", failed_checkout
    )
    monkeypatch.setattr(
        worker_module,
        "cleanup_checkout",
        lambda path: cleaned.append(path),
    )

    import threading

    worker_module.ScanWorkerManager._run_scan(
        scan.id,
        user.id,
        repository.id,
        ["semgrep"],
        threading.Event(),
    )

    db.refresh(scan)

    assert scan.status == "failed"
    assert scan.error_message is not None
    assert "private details" not in scan.error_message
    assert scan.commit_sha is None
    assert cleaned == []
