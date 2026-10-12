
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    __table_args__ = (
        CheckConstraint(
            "status IN "
            "('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_scan_status",
        ),
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_scan_progress_percent",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20), default="queued", nullable=False, index=True
    )

    commit_sha: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    error_message: Mapped[str | None] = mapped_column(
        String(2000), nullable=True
    )

    current_scanner: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    progress_percent: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="0", nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="scans"
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
