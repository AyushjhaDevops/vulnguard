
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.scanners.base import ScannerError, validate_target
from app.scanners.registry import get_scanner


class ScanServiceError(RuntimeError):
    """Raised when a scan cannot be prepared safely."""


class ScanCancelled(ScanServiceError):
    """Raised when cancellation is requested between scanner executions."""


ProgressCallback = Callable[[str, int], None]
CancelCheck = Callable[[], bool]


def get_repository_workspace(owner_id: int, repository_id: int) -> Path:
    default_root = Path(__file__).resolve().parents[2] / "workspaces"
    configured_root = os.environ.get("VULNGUARD_WORKSPACE_ROOT")
    root = Path(configured_root).expanduser() if configured_root else default_root
    root = root.resolve()
    target = (root / str(owner_id) / str(repository_id)).resolve()

    if not target.is_relative_to(root):
        raise ScanServiceError("Repository workspace is outside the permitted root.")

    if not target.is_dir():
        raise ScanServiceError(
            "Repository checkout not found. Place the checkout in the configured "
            "workspace directory before starting a scan."
        )

    try:
        return validate_target(target)
    except ScannerError as exc:
        raise ScanServiceError("Repository workspace is not a valid directory.") from exc


def make_fingerprint(
    *,
    scanner: str,
    title: str,
    file_path: str | None,
    line_number: int | None,
    evidence: dict | None,
) -> str:
    evidence = evidence or {}
    identity = {
        "scanner": scanner,
        "rule_id": evidence.get("rule_id", ""),
        "title": title,
        "file_path": file_path or "",
        "line_number": line_number,
    }
    canonical = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_owned_repository(
    db: Session, *, repository_id: int, owner_id: int
) -> Repository | None:
    return db.scalar(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.owner_id == owner_id,
        )
    )


def get_owned_scan(
    db: Session, *, scan_id: int, owner_id: int
) -> Scan | None:
    statement = (
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(Scan.id == scan_id, Repository.owner_id == owner_id)
    )
    return db.scalar(statement)


def execute_scan(
    db: Session,
    *,
    scan: Scan,
    target: Path,
    scanner_names: list[str],
    cancel_check: CancelCheck | None = None,
    progress_callback: ProgressCallback | None = None,
) -> Scan:
    """Run scanners sequentially, persisting findings and progress."""

    target = validate_target(target)
    normalized_names = list(
        dict.fromkeys(name.strip().lower() for name in scanner_names)
    )

    if not normalized_names or any(not name for name in normalized_names):
        raise ScanServiceError("Select at least one valid scanner.")
    if len(normalized_names) > 3:
        raise ScanServiceError("A maximum of three scanners can be selected.")

    # Validate all names before changing the scan state.
    scanners = [(name, get_scanner(name)) for name in normalized_names]

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.finished_at = None
    scan.error_message = None
    scan.current_scanner = None
    scan.progress_percent = 0
    db.add(scan)
    db.commit()
    db.refresh(scan)

    errors: list[str] = []
    seen_fingerprints: set[str] = set()
    total = len(scanners)

    try:
        for index, (scanner_name, scanner) in enumerate(scanners):
            if cancel_check is not None and cancel_check():
                scan.status = "cancelled"
                scan.finished_at = datetime.now(timezone.utc)
                scan.current_scanner = None
                scan.error_message = None
                db.add(scan)
                db.commit()
                db.refresh(scan)
                return scan

            scan.current_scanner = scanner_name
            scan.progress_percent = min(int(index * 100 / total), 99)
            db.add(scan)
            db.commit()

            if progress_callback is not None:
                progress_callback(scanner_name, scan.progress_percent)

            try:
                result = scanner.scan(target)
            except Exception as exc:
                # Don't store exception text, which may contain sensitive paths
                # or scanner output.
                errors.append(
                    f"{scanner_name}: {type(exc).__name__}: {str(exc)[:400]}"
                )
                continue

            for item in result.findings:
                evidence = item.evidence or {}
                fingerprint = make_fingerprint(
                    scanner=item.scanner,
                    title=item.title,
                    file_path=item.file_path,
                    line_number=item.line_number,
                    evidence=evidence,
                )

                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)

                db.add(
                    Finding(
                        scan_id=scan.id,
                        fingerprint=fingerprint,
                        title=item.title[:512],
                        description=item.description,
                        severity=item.severity,
                        status="open",
                        scanner=item.scanner[:100],
                        file_path=(
                            item.file_path[:2048] if item.file_path else None
                        ),
                        line_number=item.line_number,
                        evidence=evidence,
                    )
                )

            # Commit findings from each successful scanner, so results already
            # collected survive a later scanner failure or cancellation.
            db.commit()

            scan.progress_percent = min(
                int((index + 1) * 100 / total), 99
            )
            scan.current_scanner = (
                normalized_names[index + 1]
                if index + 1 < total
                else None
            )
            db.add(scan)
            db.commit()

            if progress_callback is not None:
                progress_callback(
                    scan.current_scanner or scanner_name,
                    scan.progress_percent,
                )

        if cancel_check is not None and cancel_check():
            scan.status = "cancelled"
            scan.error_message = None
        elif errors:
            scan.status = "failed"
            scan.error_message = "\n".join(errors)[:2000]
        else:
            scan.status = "completed"
            scan.error_message = None

        scan.finished_at = datetime.now(timezone.utc)
        scan.current_scanner = None

        if scan.status == "completed":
            scan.progress_percent = 100

        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    except Exception:
        db.rollback()

        try:
            persisted_scan = db.get(Scan, scan.id)
            if persisted_scan is not None:
                persisted_scan.status = "failed"
                persisted_scan.finished_at = datetime.now(timezone.utc)
                persisted_scan.current_scanner = None
                persisted_scan.error_message = (
                    "The scan could not save its results due to an internal error."
                )
                db.add(persisted_scan)
                db.commit()
                db.refresh(persisted_scan)
                return persisted_scan
        except Exception:
            db.rollback()

        raise
