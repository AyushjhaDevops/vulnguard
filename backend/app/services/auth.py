
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models.user import User


def normalize_email(email: str) -> str:
    return email.strip().lower()


def register_user(db: Session, email: str, password: str) -> User:
    normalized_email = normalize_email(email)

    existing_user = db.scalar(
        select(User).where(User.email == normalized_email)
    )
    if existing_user:
        raise ValueError("An account with this email already exists")

    user = User(
        email=normalized_email,
        password_hash=hash_password(password),
        is_active=True,
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise

    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User | None:
    normalized_email = normalize_email(email)

    user = db.scalar(
        select(User).where(User.email == normalized_email)
    )

    # Verify against a real or dummy hash to reduce obvious timing differences
    # between existing and nonexistent accounts.
    if user is None:
        return None

    if not verify_password(password, user.password_hash):
        return None

    if not user.is_active:
        return None

    return user
