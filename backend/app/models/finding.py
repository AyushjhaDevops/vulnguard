from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_finding_severity",
        ),
        UniqueConstraint(
            "scan_id",
            "fingerprint",
            name="uq_finding_scan_fingerprint",
        ),
        Index("ix_finding_severity_status", "severity", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), default="open", nullable=False, index=True
    )
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    file_path: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    line_number: Mapped[int | None] = mapped_column(nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")