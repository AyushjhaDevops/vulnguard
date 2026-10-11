
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.repository import Repository


class RepositoryInputError(ValueError):
    """Raised when a repository URL is invalid or unsupported."""


class RepositoryConflictError(ValueError):
    """Raised when a repository is already registered."""


_ALLOWED_HOSTS = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "bitbucket.org": "bitbucket",
}


def parse_repository_url(clone_url: str) -> tuple[str, str, str]:
    """Validate a supported HTTPS repository URL and derive its identity."""

    try:
        parsed = urlsplit(clone_url.strip())
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise RepositoryInputError("Invalid repository URL") from exc

    if parsed.scheme.lower() != "https":
        raise RepositoryInputError("Repository URL must use HTTPS")

    if hostname not in _ALLOWED_HOSTS:
        raise RepositoryInputError(
            "Unsupported provider; use GitHub, GitLab, or Bitbucket"
        )

    if parsed.username or parsed.password:
        raise RepositoryInputError(
            "Repository URLs must not contain credentials"
        )

    if port not in (None, 443):
        raise RepositoryInputError("Custom URL ports are not allowed")

    if parsed.query or parsed.fragment:
        raise RepositoryInputError(
            "Repository URLs must not contain query parameters or fragments"
        )

    path = parsed.path.strip("/")

    if path.endswith(".git"):
        path = path[:-4]

    parts = path.split("/")

    # This initial implementation supports owner/project repositories.
    if len(parts) != 2 or not all(parts):
        raise RepositoryInputError(
            "Use a repository URL in the form "
            "https://github.com/owner/project.git"
        )

    owner, name = parts

    if owner in {".", ".."} or name in {".", ".."}:
        raise RepositoryInputError("Invalid repository path")

    provider = _ALLOWED_HOSTS[hostname]
    full_name = f"{owner}/{name}"
    normalized_url = f"https://{hostname}/{full_name}.git"

    return provider, full_name, normalized_url


def create_repository(
    db: Session,
    *,
    owner_id: int,
    clone_url: str,
    default_branch: str = "main",
) -> Repository:
    provider, full_name, normalized_url = parse_repository_url(clone_url)

    existing = db.scalar(
        select(Repository).where(
            Repository.owner_id == owner_id,
            Repository.provider == provider,
            Repository.full_name == full_name,
        )
    )

    if existing is not None:
        raise RepositoryConflictError(
            "This repository is already registered to your account"
        )

    repository = Repository(
        owner_id=owner_id,
        name=full_name.rsplit("/", 1)[-1],
        full_name=full_name,
        provider=provider,
        clone_url=normalized_url,
        default_branch=default_branch,
    )

    db.add(repository)

    try:
        db.commit()
        db.refresh(repository)
    except IntegrityError as exc:
        db.rollback()
        raise RepositoryConflictError(
            "This repository is already registered to your account"
        ) from exc
    except Exception:
        db.rollback()
        raise

    return repository


def list_repositories(
    db: Session,
    *,
    owner_id: int,
) -> list[Repository]:
    statement = (
        select(Repository)
        .where(Repository.owner_id == owner_id)
        .order_by(Repository.created_at.desc(), Repository.id.desc())
    )
    return list(db.scalars(statement).all())


def get_repository(
    db: Session,
    *,
    owner_id: int,
    repository_id: int,
) -> Repository | None:
    return db.scalar(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.owner_id == owner_id,
        )
    )


def delete_repository(
    db: Session,
    *,
    owner_id: int,
    repository_id: int,
) -> bool:
    repository = get_repository(
        db,
        owner_id=owner_id,
        repository_id=repository_id,
    )

    if repository is None:
        return False

    try:
        db.delete(repository)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise RepositoryConflictError(
            "Repository cannot be deleted while dependent records exist"
        ) from None
    except Exception:
        db.rollback()
        raise

    return True
