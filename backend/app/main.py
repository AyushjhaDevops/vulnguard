from fastapi import FastAPI
from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "VulnGuard is a security platform for analyzing authorized "
        "repositories and organizing security findings."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.include_router(
    health_router,
    prefix=settings.api_v1_prefix,
)
app.include_router(auth_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
def root() -> dict[str, str]:
    """Return basic API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "health_endpoint": f"{settings.api_v1_prefix}/health",
        "docs_endpoint": "/docs",
    }
