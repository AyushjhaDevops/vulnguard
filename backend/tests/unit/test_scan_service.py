from pathlib import Path

import pytest

from app.models.scan import Scan
from app.scanners.base import ScanResult, ScannerFinding, ScannerExecutionError
from app.services import scans as scan_service


class FakeSession:
    """Small session double for testing scan orchestration logic."""

    def __init__(self):
        self.objects = []
        self.commit_count = 0

    def add(self, obj):
        self.objects.append(obj)

    def commit(self):
        self.commit_count += 1

    def refresh(self, obj):
        pass

    def rollback(self):
        pass

    def get(self, model, object_id):
        for obj in self.objects:
            if isinstance(obj, model) and getattr(obj, "id", None) == object_id:
                return obj
        return None


class FakeScanner:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def scan(self, target):
        if self.error:
            raise self.error
        return self.result


def sample_result(target: Path) -> ScanResult:
    return ScanResult(
        scanner="semgrep",
        target=str(target),
        findings=[
            ScannerFinding(
                scanner="semgrep",
                title="Test security finding",
                description="Synthetic finding for a unit test.",
                severity="high",
                file_path="sample.py",
                line_number=10,
                evidence={"rule_id": "test.rule"},
            )
        ],
    )


def test_fingerprint_is_deterministic():
    arguments = {
        "scanner": "semgrep",
        "title": "Test finding",
        "file_path": "sample.py",
        "line_number": 10,
        "evidence": {"rule_id": "test.rule"},
    }

    first = scan_service.make_fingerprint(**arguments)
    second = scan_service.make_fingerprint(**arguments)

    assert first == second
    assert len(first) == 64


def test_successful_scan_persists_findings(monkeypatch, tmp_path):
    db = FakeSession()
    scan = Scan(id=1, repository_id=2, status="queued")

    monkeypatch.setattr(
        scan_service,
        "get_scanner",
        lambda name: FakeScanner(result=sample_result(tmp_path)),
    )

    result = scan_service.execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep"],
    )

    from app.models.finding import Finding

    saved_findings = [obj for obj in db.objects if isinstance(obj, Finding)]

    assert result.status == "completed"
    assert result.started_at is not None
    assert result.finished_at is not None
    assert result.error_message is None
    assert len(saved_findings) == 1
    assert saved_findings[0].severity == "high"
    assert saved_findings[0].fingerprint


def test_scanner_error_marks_scan_failed(monkeypatch, tmp_path):
    db = FakeSession()
    scan = Scan(id=2, repository_id=2, status="queued")

    monkeypatch.setattr(
        scan_service,
        "get_scanner",
        lambda name: FakeScanner(error=ScannerExecutionError("synthetic failure")),
    )

    result = scan_service.execute_scan(
        db,
        scan=scan,
        target=tmp_path,
        scanner_names=["semgrep"],
    )

    assert result.status == "failed"
    assert result.finished_at is not None
    assert "semgrep" in result.error_message
    assert "synthetic failure" in result.error_message


def test_workspace_must_exist_inside_configured_root(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNGUARD_WORKSPACE_ROOT", str(tmp_path))

    target = tmp_path / "7" / "12"
    target.mkdir(parents=True)

    result = scan_service.get_repository_workspace(7, 12)

    assert result == target.resolve()


def test_missing_workspace_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNGUARD_WORKSPACE_ROOT", str(tmp_path))

    with pytest.raises(scan_service.ScanServiceError):
        scan_service.get_repository_workspace(7, 12)