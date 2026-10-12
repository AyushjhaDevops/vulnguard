from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models import Finding, Repository, Scan, User  # noqa: F401
from app.services.scans import execute_scan


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)
    db = Session()

    try:
        user = User(
            email="service-test@example.com",
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

        yield db, scan
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def fake_finding(
    *,
    scanner="semgrep",
    title="Potential security issue",
    severity="high",
):
    return SimpleNamespace(
        scanner=scanner,
        title=title,
        description="Test finding",
        severity=severity,
        file_path="app.py",
        line_number=10,
        evidence={"rule_id": "test-rule"},
    )


def fake_result(*findings):
    return SimpleNamespace(findings=list(findings))


def test_successful_scan_persists_findings_and_progress(
    db_session, monkeypatch, tmp_path
):
    db, scan = db_session
    progress_updates = []

    fake_scanner = SimpleNamespace(
        scan=lambda target: fake_result(fake_finding())
    )
    monkeypatch.setattr(
        "app.services.scans.get_scanner",
        lambda name: fake_scanner,
    )

    result = execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep"],
        progress_callback=lambda name, percent: progress_updates.append(
            (name, percent)
        ),
    )

    findings = list(
        db.scalars(
            select(Finding).where(Finding.scan_id == scan.id)
        ).all()
    )

    assert result.status == "completed"
    assert result.progress_percent == 100
    assert result.current_scanner is None
    assert result.finished_at is not None
    assert len(findings) == 1
    assert findings[0].title == "Potential security issue"
    assert findings[0].severity == "high"
    assert progress_updates


def test_duplicate_findings_are_deduplicated(
    db_session, monkeypatch, tmp_path
):
    db, scan = db_session
    finding = fake_finding()

    fake_scanner = SimpleNamespace(
        scan=lambda target: fake_result(finding, finding)
    )
    monkeypatch.setattr(
        "app.services.scans.get_scanner",
        lambda name: fake_scanner,
    )

    execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep"],
    )

    findings = list(
        db.scalars(
            select(Finding).where(Finding.scan_id == scan.id)
        ).all()
    )
    assert len(findings) == 1


def test_scanner_failure_marks_scan_failed(
    db_session, monkeypatch, tmp_path
):
    db, scan = db_session

    def fail_scan(target):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(
        "app.services.scans.get_scanner",
        lambda name: SimpleNamespace(scan=fail_scan),
    )

    result = execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep"],
    )

    assert result.status == "failed"
    assert result.finished_at is not None
    assert result.current_scanner is None
    assert "synthetic failure" in result.error_message


def test_cancellation_between_scanners_preserves_findings(
    db_session, monkeypatch, tmp_path
):
    db, scan = db_session
    cancellation_checks = iter([False, True])
    first_scanner = SimpleNamespace(
        scan=lambda target: fake_result(fake_finding())
    )

    monkeypatch.setattr(
        "app.services.scans.get_scanner",
        lambda name: first_scanner,
    )

    result = execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep", "gitleaks"],
        cancel_check=lambda: next(cancellation_checks),
    )

    findings = list(
        db.scalars(
            select(Finding).where(Finding.scan_id == scan.id)
        ).all()
    )

    assert result.status == "cancelled"
    assert result.finished_at is not None
    assert result.current_scanner is None
    assert result.progress_percent < 100
    assert len(findings) == 1


def test_scanner_failure_does_not_discard_prior_findings(
    db_session, monkeypatch, tmp_path
):
    db, scan = db_session

    def get_fake_scanner(name):
        if name == "semgrep":
            return SimpleNamespace(
                scan=lambda target: fake_result(fake_finding())
            )

        def fail_scan(target):
            raise RuntimeError("second scanner failed")

        return SimpleNamespace(scan=fail_scan)

    monkeypatch.setattr(
        "app.services.scans.get_scanner",
        get_fake_scanner,
    )

    result = execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep", "gitleaks"],
    )

    findings = list(
        db.scalars(
            select(Finding).where(Finding.scan_id == scan.id)
        ).all()
    )

    assert result.status == "failed"
    assert "second scanner failed" in result.error_message
    assert len(findings) == 1
