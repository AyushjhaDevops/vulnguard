
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RepositoryCreate(BaseModel):
    """Input required to register a Git repository."""

    clone_url: str = Field(min_length=1, max_length=2048)
    default_branch: str = Field(
        default="main",
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9._/-]+$",
    )


class RepositoryPublic(BaseModel):
    """Safe repository representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    name: str
    full_name: str
    provider: Literal["github", "gitlab", "bitbucket"]
    clone_url: str
    default_branch: str
    created_at: datetime
