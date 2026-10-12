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
    execute_scan,
    get_owned_repository,
    get_owned_scan,
    get_repository_workspace,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
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
        target = get_repository_workspace(
            current_user.id,
            repository.id,
        )
    except ScanServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Validate scanner names before inserting a scan record.
    from app.scanners.base import ScannerError
    from app.scanners.registry import get_scanner

    scanner_names = list(
        dict.fromkeys(name.strip().lower() for name in payload.scanners)
    )

    if not scanner_names or any(not name for name in scanner_names):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Select at least one scanner.",
        )

    if len(scanner_names) > 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="A maximum of three scanners can be selected.",
        )

    try:
        for name in scanner_names:
            get_scanner(name)
    except ScannerError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    scan = Scan(
        repository_id=repository.id,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return execute_scan(
        db,
        scan=scan,
        target=target,
        scanner_names=scanner_names,
    )


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