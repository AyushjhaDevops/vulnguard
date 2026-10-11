
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.repository import RepositoryCreate, RepositoryPublic
from app.services.repository import (
    RepositoryConflictError,
    RepositoryInputError,
    create_repository,
    delete_repository,
    get_repository,
    list_repositories,
)

router = APIRouter(prefix="/repositories", tags=["Repositories"])


@router.post(
    "",
    response_model=RepositoryPublic,
    status_code=status.HTTP_201_CREATED,
)
def register_repository(
    payload: RepositoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return create_repository(
            db,
            owner_id=current_user.id,
            clone_url=payload.clone_url,
            default_branch=payload.default_branch,
        )
    except RepositoryInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except RepositoryConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get("", response_model=list[RepositoryPublic])
def get_my_repositories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_repositories(db, owner_id=current_user.id)


@router.get("/{repository_id}", response_model=RepositoryPublic)
def get_my_repository(
    repository_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repository = get_repository(
        db,
        owner_id=current_user.id,
        repository_id=repository_id,
    )

    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found",
        )

    return repository


@router.delete(
    "/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def remove_my_repository(
    repository_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        deleted = delete_repository(
            db,
            owner_id=current_user.id,
            repository_id=repository_id,
        )
    except RepositoryConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
