
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.scans import router as scans_router
from app.core.config import settings
from app.workers.scan_worker import scan_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    scan_worker.start()
    try:
        yield
    finally:
        scan_worker.shutdown()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VulnGuard — AI-Powered DevSecOps Security Platform",
    lifespan=lifespan,
)

api_router = APIRouter(prefix=settings.api_v1_prefix)

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(repositories_router)
api_router.include_router(scans_router)

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
