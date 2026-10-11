import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import build_engine
from app.models import Finding, Repository, Scan, User


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Enable actual SQLite foreign-key enforcement for this test database.
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    Base.metadata.drop_all(engine)
    engine.dispose()


def test_all_four_tables_are_registered():
    assert set(Base.metadata.tables.keys()) == {
        "users",
        "repositories",
        "scans",
        "findings",
    }


def test_create_related_security_records(db_session: Session):
    user = User(
        email="developer@example.test",
        password_hash="test-hash-not-a-real-password",
    )
    repository = Repository(
        name="demo",
        full_name="example/demo",
        provider="github",
        owner=user,
    )
    scan = Scan(
        repository=repository,
        status="completed",
        commit_sha="a" * 40,
    )
    finding = Finding(
        scan=scan,
        fingerprint="test-fingerprint-001",
        title="Potential SQL injection",
        severity="high",
        scanner="test-scanner",
        file_path="src/example.py",
        line_number=42,
        evidence={"rule_id": "TEST-001"},
    )

    db_session.add(finding)
    db_session.commit()

    saved_finding = db_session.scalar(
        select(Finding).where(
            Finding.fingerprint == "test-fingerprint-001"
        )
    )

    assert saved_finding is not None
    assert saved_finding.severity == "high"
    assert saved_finding.scan.repository.owner.email == (
        "developer@example.test"
    )


def test_duplicate_user_email_is_rejected(db_session: Session):
    db_session.add_all(
        [
            User(
                email="duplicate@example.test",
                password_hash="hash-one",
            ),
            User(
                email="duplicate@example.test",
                password_hash="hash-two",
            ),
        ]
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_invalid_finding_severity_is_rejected(db_session: Session):
    user = User(
        email="severity@example.test",
        password_hash="test-hash",
    )
    repository = Repository(
        name="demo",
        full_name="example/severity-demo",
        owner=user,
    )
    scan = Scan(repository=repository, status="completed")

    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan=scan,
        fingerprint="invalid-severity",
        title="Invalid severity test",
        severity="super-critical",
        scanner="test-scanner",
    )

    db_session.add(finding)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_duplicate_fingerprint_within_scan_is_rejected(
    db_session: Session,
):
    user = User(
        email="fingerprint@example.test",
        password_hash="test-hash",
    )
    repository = Repository(
        name="demo",
        full_name="example/fingerprint-demo",
        owner=user,
    )
    scan = Scan(repository=repository, status="completed")

    db_session.add(scan)
    db_session.flush()

    common = {
        "scan": scan,
        "fingerprint": "same-fingerprint",
        "title": "Example finding",
        "severity": "medium",
        "scanner": "test-scanner",
    }

    db_session.add_all([Finding(**common), Finding(**common)])

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_sqlite_engine_enables_foreign_keys():
    engine = build_engine("sqlite://")

    try:
        with engine.connect() as connection:
            result = connection.exec_driver_sql(
                "PRAGMA foreign_keys"
            ).scalar_one()

        assert result == 1
    finally:
        engine.dispose()
