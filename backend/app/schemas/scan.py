from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    repository_id: int
    scanners: list[str] = Field(
        default_factory=lambda: ["semgrep", "gitleaks", "trivy"],
        min_length=1,
        max_length=3,
    )


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int
    status: str
    commit_sha: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
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