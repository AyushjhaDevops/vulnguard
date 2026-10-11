
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """VulnGuard application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application
    app_name: str = "VulnGuard API"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = "sqlite:///./vulnguard.db"

    # JWT authentication
    jwt_secret_key: str = (
        "dev-only-change-this-secret-before-deployment"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


# Keep both interfaces for existing application modules.
settings = get_settings()
