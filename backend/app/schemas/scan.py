
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


ALLOWED_SCANNERS = {"semgrep", "gitleaks", "trivy"}


class ScanCreate(BaseModel):
    repository_id: int
    scanners: list[str] = Field(
        default_factory=lambda: ["semgrep", "gitleaks", "trivy"],
        min_length=1,
        max_length=3,
    )

    @field_validator("scanners")
    @classmethod
    def validate_scanners(cls, value: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(name.strip().lower() for name in value))

        if not normalized or any(not name for name in normalized):
            raise ValueError("Select at least one valid scanner.")

        unsupported = set(normalized) - ALLOWED_SCANNERS
        if unsupported:
            raise ValueError(
                "Unsupported scanner(s): " + ", ".join(sorted(unsupported))
            )

        return normalized


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int
    status: str
    commit_sha: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    current_scanner: str | None
    progress_percent: int
    cancel_requested: bool
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    fingerprint: str
    title: str
    description: str | None
    severity: str
    status: str
    scanner: str
    file_path: str | None
    line_number: int | None
    evidence: dict | None
    created_at: datetime
