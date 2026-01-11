#!/usr/bin/env python3
"""
BREACH.AI Enterprise API Server
================================

REST API + WebSocket for real-time dashboard updates.
With authentication, rate limiting, and persistent storage.

Usage:
    uvicorn backend.api.server:app --reload

Endpoints:
    GET  /                      - API status
    GET  /health                - Basic health check
    GET  /health/deep           - Deep health check (DB, Redis)
    GET  /metrics               - Prometheus metrics
    POST /api/v1/auth/register  - Register
    POST /api/v1/auth/login     - Login
    GET  /api/v1/auth/me        - Current user
    POST /api/v1/scans          - Start scan
    GET  /api/v1/scans          - List scans
    GET  /api/v1/scans/{id}     - Scan details
    WS   /ws/scans/{id}         - Real-time updates
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Optional

import structlog
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.config import settings
from backend.db.database import init_db, close_db, check_db_health, async_session
from backend.db.models import Scan, ScanStatus
from backend.api.routes.auth import router as auth_router
from backend.api.routes.scans import router as scans_router, targets_router
from backend.api.routes.billing import router as billing_router

# Conditional imports for optional features
try:
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Configure structured logging
logger = structlog.get_logger(__name__)

# =============================================================================
# Rate Limiting
# =============================================================================

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit_global],
    storage_uri=settings.redis_url if REDIS_AVAILABLE else None,
)

# =============================================================================
# Prometheus Metrics
# =============================================================================

if PROMETHEUS_AVAILABLE:
    REQUEST_COUNT = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status_code"]
    )
    REQUEST_DURATION = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint"]
    )
    SCANS_IN_PROGRESS = Gauge(
        "scans_in_progress",
        "Number of scans currently running"
    )
    SCANS_TOTAL = Counter(
        "scans_total",
        "Total scans created",
        ["status"]
    )
    FINDINGS_TOTAL = Counter(
        "findings_total",
        "Total findings discovered",
        ["severity"]
    )

# =============================================================================
# Sentry Error Tracking
# =============================================================================

if SENTRY_AVAILABLE and settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),
            SqlalchemyIntegration(),
        ],
        traces_sample_rate=settings.sentry_traces_sample_rate,
        environment=settings.environment,
    )
    logger.info("sentry_initialized", dsn=settings.sentry_dsn[:20] + "...")


# =============================================================================
# Stale Scan Recovery
# =============================================================================

async def recover_stale_scans():
    """
    Recover scans that were running when the server crashed.
    Mark any scan that has been RUNNING for >2 hours as FAILED.
    """
    try:
        from sqlalchemy import select, update

        cutoff = datetime.now(timezone.utc) - timedelta(hours=2)

        async with async_session() as session:
            # Find stale scans
            result = await session.execute(
                select(Scan).where(
                    Scan.status == ScanStatus.RUNNING,
                    Scan.started_at < cutoff
                )
            )
            stale_scans = result.scalars().all()

            if stale_scans:
                # Mark them as failed
                await session.execute(
                    update(Scan).where(
                        Scan.id.in_([s.id for s in stale_scans])
                    ).values(
                        status=ScanStatus.FAILED,
                        error_message="Scan timed out or server restarted",
                        completed_at=datetime.now(timezone.utc)
                    )
                )
                await session.commit()

                logger.warning(
                    "recovered_stale_scans",
                    count=len(stale_scans),
                    scan_ids=[str(s.id) for s in stale_scans]
                )

            return len(stale_scans)
    except Exception as e:
        logger.error("stale_scan_recovery_failed", error=str(e))
        return 0


# =============================================================================
# Application Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown."""
    # Startup
    await init_db()
    logger.info("api_started", service="BREACH.AI Enterprise", version="4.0.0")
    logger.info("database_initialized")

    # Recover stale scans
    recovered = await recover_stale_scans()
    if recovered:
        logger.info("stale_scans_recovered", count=recovered)

    yield

    # Shutdown
    await close_db()
    logger.info("database_closed")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="BREACH.AI Enterprise",
    description="Autonomous Security Assessment Engine - Enterprise API",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda r, e: JSONResponse(
    status_code=429,
    content={"error": "Rate limit exceeded", "detail": str(e.detail)}
))
app.add_middleware(SlowAPIMiddleware)

# CORS - Properly configured, no wildcards
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
)


# =============================================================================
# Metrics Middleware
# =============================================================================

if PROMETHEUS_AVAILABLE:
    import time

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        """Track request metrics."""
        start_time = time.time()

        response = await call_next(request)

        duration = time.time() - start_time
        endpoint = request.url.path

        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status_code=response.status_code
        ).inc()

        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=endpoint
        ).observe(duration)

        return response


# =============================================================================
# Health Endpoints
# =============================================================================

@app.get("/", tags=["Health"])
async def root():
    """API health check."""
    return {
        "name": "BREACH.AI Enterprise",
        "version": "4.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    """Basic health check."""
    return {
        "status": "healthy",
        "service": "BREACH.AI",
        "version": "4.0.0",
    }


@app.get("/health/deep", tags=["Health"])
async def health_deep():
    """
    Deep health check - verifies database and Redis connections.
    Returns 503 if any check fails.
    """
    checks = {}
    overall_status = "healthy"

    # Database check
    try:
        db_health = await check_db_health()
        checks["database"] = {
            "status": "healthy",
            **db_health
        }
    except Exception as e:
        checks["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_status = "degraded"

    # Redis check (if available)
    if REDIS_AVAILABLE:
        try:
            r = redis.from_url(settings.redis_url)
            await r.ping()
            await r.close()
            checks["redis"] = {"status": "healthy"}
        except Exception as e:
            checks["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            overall_status = "degraded"
    else:
        checks["redis"] = {"status": "not_configured"}

    status_code = 200 if overall_status == "healthy" else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall_status,
            "service": "BREACH.AI",
            "version": "4.0.0",
            "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


# =============================================================================
# Prometheus Metrics Endpoint
# =============================================================================

@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """Prometheus metrics endpoint."""
    if not PROMETHEUS_AVAILABLE:
        return PlainTextResponse(
            "prometheus-client not installed",
            status_code=501
        )

    return PlainTextResponse(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# =============================================================================
# Include Routers
# =============================================================================

app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(targets_router, prefix="/api/v1")
app.include_router(billing_router, prefix="/api/v1")


# =============================================================================
# WebSocket for Real-Time Updates
# =============================================================================

class ConnectionManager:
    """Manage WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        """Broadcast message to all clients watching this scan."""
        if scan_id in self.active_connections:
            disconnected = []
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                self.active_connections[scan_id].discard(ws)


manager = ConnectionManager()


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    """WebSocket for real-time scan updates."""
    await manager.connect(websocket, scan_id)

    try:
        # Send connected confirmation
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id,
        })

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat"})

    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_error",
        error=str(exc),
        path=request.url.path,
        method=request.method,
        exc_info=True
    )

    # Report to Sentry if available
    if SENTRY_AVAILABLE and settings.sentry_dsn:
        sentry_sdk.capture_exception(exc)

    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Run the server."""
    import uvicorn
    uvicorn.run(
        "backend.api.server:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
