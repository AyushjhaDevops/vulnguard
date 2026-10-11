from fastapi import APIRouter, FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.repositories import router as repositories_router
from app.core.config import settings


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VulnGuard — AI-Powered DevSecOps Security Platform",
)


# Register all versioned API routes.
api_router = APIRouter(prefix=settings.api_v1_prefix)

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(repositories_router)

app.include_router(api_router)


@app.get("/", tags=["Root"])
def root() -> dict[str, str]:
    """Return basic API information and useful endpoint paths."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "health_endpoint": f"{settings.api_v1_prefix}/health",
        "docs_endpoint": "/docs",
    }
