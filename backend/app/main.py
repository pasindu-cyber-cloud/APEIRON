"""APEIRON API gateway: FastAPI app exposing REST + WebSocket endpoints."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .api import (
    routes_iocs,
    routes_rules,
    routes_samples,
    routes_stats,
    routes_ws,
)
from .config import settings
from .database import init_db
from .logging_config import configure_logging, get_logger
from .security import enforce_startup_security

configure_logging(settings.log_level)
logger = get_logger("apeiron.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast on insecure production configuration (API key / CORS).
    enforce_startup_security()
    init_db()
    logger.info(
        "APEIRON API starting",
        extra={
            "extra_fields": {
                "version": __version__,
                "env": settings.env,
                "allowed_origins": settings.allowed_origins,
            }
        },
    )
    yield
    logger.info("APEIRON API shutting down")


app = FastAPI(
    title="APEIRON Malware Sandbox API",
    description="Custom PE/ELF malware sandbox with API tracing, IOC extraction, "
    "and automated Sigma/YARA rule generation.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS: explicit allow-list only. Wildcards are rejected in production by
# enforce_startup_security(); in development this resolves to localhost defaults.
_allowed_origins = settings.allowed_origins
if settings.is_production and not _allowed_origins:
    logger.error(
        "No safe CORS origins configured for production; cross-origin "
        "browser requests will be blocked."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# REST routers are mounted under /api; websockets under /ws.
app.include_router(routes_stats.router, prefix="/api")
app.include_router(routes_samples.router, prefix="/api")
app.include_router(routes_iocs.router, prefix="/api")
app.include_router(routes_rules.router, prefix="/api")
app.include_router(routes_ws.router)


@app.get("/")
def root() -> dict:
    return {
        "name": "APEIRON",
        "version": __version__,
        "docs": "/api/docs",
        "health": "/api/health",
    }
