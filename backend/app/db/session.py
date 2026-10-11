
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def build_engine(database_url: str | None = None) -> Engine:
    """Build a SQLAlchemy engine with SQLite foreign keys enabled."""
    if database_url is None:
        database_url = get_settings().database_url

    connect_args = (
        {"check_same_thread": False}
        if database_url.startswith("sqlite")
        else {}
    )

    engine = create_engine(
        database_url,
        connect_args=connect_args,
    )

    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(
            dbapi_connection,
            connection_record,
        ):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = build_engine()

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
