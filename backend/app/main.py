
from fastapi import APIRouter, FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.scans import router as scans_router
from app.core.config import settings


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VulnGuard — AI-Powered DevSecOps Security Platform",
)

# Register all version 1 API routes.
api_router = APIRouter(prefix=settings.api_v1_prefix)

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(repositories_router)
api_router.include_router(scans_router)

# Mount the complete API router on the FastAPI application.
app.include_router(api_router)


@app.get("/", tags=["Root"])
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "health_endpoint": f"{settings.api_v1_prefix}/health",
        "docs_endpoint": "/docs",
    }
