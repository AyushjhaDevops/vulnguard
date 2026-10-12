
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import FindingRead, ScanCreate, ScanRead
from app.services.scans import (
    ScanServiceError,
    get_owned_repository,
    get_owned_scan,
    get_repository_workspace,
)
from app.workers.scan_worker import scan_worker
from datetime import datetime, timezone
router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Scan:
    repository = get_owned_repository(
        db,
        repository_id=payload.repository_id,
        owner_id=current_user.id,
    )

    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found.",
        )

    try:
        # Validate that the local checkout exists before creating the job.
        get_repository_workspace(current_user.id, repository.id)
    except ScanServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    scan = Scan(
        repository_id=repository.id,
        status="queued",
        progress_percent=0,
        cancel_requested=False,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        scan_worker.submit(
            scan_id=scan.id,
            owner_id=current_user.id,
            repository_id=repository.id,
            scanner_names=payload.scanners,
        )
    except Exception as exc:
        db.refresh(scan)
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        scan.error_message = "The scan could not be submitted to the worker pool."
        db.add(scan)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan worker is unavailable.",
        ) from exc

    # Return immediately; the worker uses its own database session.
    db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=ScanRead)
def read_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Scan:
    scan = get_owned_scan(
        db,
        scan_id=scan_id,
        owner_id=current_user.id,
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
def read_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Finding]:
    scan = get_owned_scan(
        db,
        scan_id=scan_id,
        owner_id=current_user.id,
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    statement = (
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    )
    return list(db.scalars(statement).all())


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Scan:
    scan = get_owned_scan(
        db,
        scan_id=scan_id,
        owner_id=current_user.id,
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    if scan.status in {"completed", "failed", "cancelled"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel a scan with status '{scan.status}'.",
        )

    scan.cancel_requested = True
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_worker.request_cancel(scan_id)

    return scan
