
import json
import subprocess
from pathlib import Path

import pytest

from app.scanners.base import (
    ScannerError,
    ScannerNotInstalledError,
    ScannerTimeoutError,
    normalize_severity,
    validate_target,
)
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.registry import available_scanners, get_scanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner


def completed_process(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["scanner"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


def test_severity_normalization():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity("WARNING") == "medium"
    assert normalize_severity("LOW") == "low"
    assert normalize_severity("unexpected-value") == "info"


def test_target_must_exist():
    with pytest.raises(ScannerError):
        validate_target("/path/that/does/not/exist/vulnguard")


def test_target_must_be_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(ScannerError):
        validate_target(file_path)


def test_registry_returns_supported_scanners():
    assert isinstance(get_scanner("semgrep"), SemgrepScanner)
    assert isinstance(get_scanner("GITLEAKS"), GitleaksScanner)
    assert isinstance(get_scanner("trivy"), TrivyScanner)


def test_registry_rejects_unknown_scanner():
    with pytest.raises(ScannerError):
        get_scanner("unknown-scanner")


def test_registry_reports_installation_status():
    results = available_scanners()

    assert {item["name"] for item in results} == {
        "semgrep",
        "gitleaks",
        "trivy",
    }
    assert all(isinstance(item["installed"], bool) for item in results)


def test_semgrep_normalizes_finding(monkeypatch, tmp_path):
    source_file = tmp_path / "example.py"
    source_file.write_text("print('test')\n", encoding="utf-8")

    payload = {
        "results": [
            {
                "check_id": "python.test-rule",
                "path": "example.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Potential security issue",
                    "severity": "ERROR",
                    "metadata": {"shortDescription": "Test rule"},
                },
            }
        ]
    }

    monkeypatch.setattr(
        "app.scanners.semgrep.run_command",
        lambda *args, **kwargs: completed_process(json.dumps(payload)),
    )

    result = SemgrepScanner().scan(tmp_path)

    assert result.scanner == "semgrep"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"
    assert result.findings[0].file_path == "example.py"
    assert result.findings[0].line_number == 1


def test_gitleaks_does_not_store_secret(monkeypatch, tmp_path):
    source_file = tmp_path / "example.txt"
    source_file.write_text("placeholder", encoding="utf-8")

    def fake_run(command, **kwargs):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "test-api-key",
                        "File": "example.txt",
                        "StartLine": 1,
                        "Secret": "DO_NOT_STORE_THIS_SECRET",
                        "Match": "DO_NOT_STORE_THIS_SECRET",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return completed_process("", returncode=1)

    monkeypatch.setattr("app.scanners.gitleaks.run_command", fake_run)

    result = GitleaksScanner().scan(tmp_path)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.file_path == "example.txt"
    assert "DO_NOT_STORE_THIS_SECRET" not in finding.title
    assert "DO_NOT_STORE_THIS_SECRET" not in finding.description
    assert "DO_NOT_STORE_THIS_SECRET" not in json.dumps(finding.evidence)


def test_trivy_normalizes_vulnerability(monkeypatch, tmp_path):
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-0001",
                        "PkgName": "example-package",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Title": "Example vulnerability",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }

    monkeypatch.setattr(
        "app.scanners.trivy.run_command",
        lambda *args, **kwargs: completed_process(json.dumps(payload)),
    )

    result = TrivyScanner().scan(tmp_path)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.scanner == "trivy"
    assert finding.severity == "high"
    assert finding.evidence["package"] == "example-package"
    assert finding.evidence["fixed_version"] == "1.1"


def test_scanner_missing_executable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "app.scanners.base.shutil.which",
        lambda executable: None,
    )

    with pytest.raises(ScannerNotInstalledError):
        SemgrepScanner().scan(tmp_path)


def test_scanner_timeout(monkeypatch, tmp_path):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1)

    monkeypatch.setattr("app.scanners.base.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("app.scanners.base.subprocess.run", raise_timeout)

    from app.scanners.base import run_command

    with pytest.raises(ScannerTimeoutError):
        run_command(
            ["semgrep", "--version"],
            target=tmp_path,
            timeout=1,
        )
