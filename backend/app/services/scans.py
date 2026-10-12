import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.scanners.base import ScannerError, validate_target
from app.scanners.registry import get_scanner


class ScanServiceError(RuntimeError):
    """Raised when a scan cannot be prepared safely."""


def get_repository_workspace(owner_id: int, repository_id: int) -> Path:
    """
    Resolve a repository checkout under the configured workspace root.

    Directory layout:
        workspaces/<owner_id>/<repository_id>/

    Never accept a filesystem path supplied by the API caller.
    """
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
    """
    Build a deterministic identifier for a finding.

    Secret values and raw matched source text must not be used in fingerprints.
    """
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
    db: Session,
    *,
    repository_id: int,
    owner_id: int,
) -> Repository | None:
    statement = select(Repository).where(
        Repository.id == repository_id,
        Repository.owner_id == owner_id,
    )
    return db.scalar(statement)


def get_owned_scan(
    db: Session,
    *,
    scan_id: int,
    owner_id: int,
) -> Scan | None:
    statement = (
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(
            Scan.id == scan_id,
            Repository.owner_id == owner_id,
        )
    )
    return db.scalar(statement)


def execute_scan(
    db: Session,
    *,
    scan: Scan,
    target: Path,
    scanner_names: list[str],
) -> Scan:
    """
    Execute selected scanners and persist their normalized findings.

    Scanner failures are recorded on the scan. Findings from scanners that
    completed successfully are retained even if another scanner fails.
    """
    target = validate_target(target)

    normalized_names = list(
        dict.fromkeys(name.strip().lower() for name in scanner_names)
    )

    if not normalized_names or any(not name for name in normalized_names):
        raise ScanServiceError("Select at least one valid scanner.")

    if len(normalized_names) > 3:
        raise ScanServiceError("A maximum of three scanners can be selected.")

    # Validate scanner names before starting the scan.
    scanners = [(name, get_scanner(name)) for name in normalized_names]

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.finished_at = None
    scan.error_message = None

    db.add(scan)
    db.commit()
    db.refresh(scan)

    errors: list[str] = []
    seen_fingerprints: set[str] = set()

    try:
        for scanner_name, scanner in scanners:
            try:
                result = scanner.scan(target)
            except Exception as exc:
                # Avoid recording raw scanner output, which could contain
                # source code or sensitive data.
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

                finding = Finding(
                    scan_id=scan.id,
                    fingerprint=fingerprint,
                    title=item.title[:512],
                    description=item.description,
                    severity=item.severity,
                    status="open",
                    scanner=item.scanner[:100],
                    file_path=item.file_path[:2048] if item.file_path else None,
                    line_number=item.line_number,
                    evidence=evidence,
                )
                db.add(finding)

        scan.finished_at = datetime.now(timezone.utc)

        if errors:
            scan.status = "failed"
            scan.error_message = "\n".join(errors)[:2000]
        else:
            scan.status = "completed"
            scan.error_message = None

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return scan

    except Exception:
        db.rollback()

        # Try to persist a failure state independently. The initial scan
        # record was already committed before scanner execution began.
        try:
            persisted_scan = db.get(Scan, scan.id)

            if persisted_scan is not None:
                persisted_scan.status = "failed"
                persisted_scan.finished_at = datetime.now(timezone.utc)
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