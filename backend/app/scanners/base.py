
from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def normalize_severity(value: Any) -> str:
    """Convert common scanner severities to VulnGuard severity values."""
    severity = str(value or "info").strip().lower()

    mapping = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "info",
    }
    return mapping.get(severity, "info")


@dataclass(slots=True)
class ScannerFinding:
    """Normalized, safe-to-process scanner finding."""

    scanner: str
    title: str
    description: str
    severity: str
    file_path: str | None = None
    line_number: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanResult:
    """Result returned by a scanner adapter."""

    scanner: str
    target: str
    findings: list[ScannerFinding] = field(default_factory=list)


class ScannerError(RuntimeError):
    """Base error for scanner integration failures."""


class ScannerNotInstalledError(ScannerError):
    """Raised when a scanner executable is unavailable."""


class ScannerTimeoutError(ScannerError):
    """Raised when a scanner exceeds its time limit."""


class ScannerExecutionError(ScannerError):
    """Raised when a scanner fails or returns invalid output."""


def validate_target(target: str | Path) -> Path:
    """Resolve and validate a local directory before scanning."""
    try:
        path = Path(target).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScannerError("Scan target does not exist or cannot be resolved.") from exc

    if not path.is_dir():
        raise ScannerError("Scan target must be an existing directory.")

    return path


def run_command(
    command: list[str],
    *,
    target: Path,
    timeout: int,
    allowed_exit_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a scanner without a shell, with a timeout and controlled cwd."""
    if not command:
        raise ScannerExecutionError("Scanner command is empty.")

    executable = command[0]
    if shutil.which(executable) is None:
        raise ScannerNotInstalledError(
            f"Required scanner '{executable}' is not installed or not on PATH."
        )

    try:
        result = subprocess.run(
            command,
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerTimeoutError(
            f"Scanner '{executable}' exceeded the {timeout}-second timeout."
        ) from exc
    except OSError as exc:
        raise ScannerExecutionError(
            f"Could not execute scanner '{executable}'."
        ) from exc

    allowed = allowed_exit_codes if allowed_exit_codes is not None else {0}
    if result.returncode not in allowed:
        # Do not include arbitrary scanner output in exception messages.
        raise ScannerExecutionError(
            f"Scanner '{executable}' failed with exit code {result.returncode}."
        )

    return result


def parse_json_output(output: str, scanner_name: str) -> Any:
    """Parse JSON output without leaking raw scanner output into errors."""
    try:
        return json.loads(output)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScannerExecutionError(
            f"Scanner '{scanner_name}' returned invalid JSON."
        ) from exc


class BaseScanner(ABC):
    """Interface shared by all scanner adapters."""

    name: str
    executable: str
    default_timeout: int = 300

    def __init__(self, timeout: int | None = None) -> None:
        self.timeout = timeout if timeout is not None else self.default_timeout
        if not 1 <= self.timeout <= 3600:
            raise ValueError("Scanner timeout must be between 1 and 3600 seconds.")

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    @abstractmethod
    def scan(self, target: str | Path) -> ScanResult:
        """Scan a local directory and return normalized findings."""
        raise NotImplementedError
