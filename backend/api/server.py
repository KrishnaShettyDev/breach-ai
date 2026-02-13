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
from backend.api.routes.breaches import router as breaches_router
from backend.api.routes.assessments import router as assessments_router
from backend.api.routes.schedules import router as schedules_router
from backend.api.routes.integrations import router as integrations_router
from backend.api.routes.attestations import router as attestations_router
from backend.api.routes.learning import router as learning_router
from backend.api.routes.recommendations import router as recommendations_router
from backend.api.routes.analytics import router as analytics_router

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
# Rate Limiting (Per-Organization)
# =============================================================================

def get_rate_limit_key(request: Request) -> str:
    """
    Get rate limit key - uses organization ID when authenticated, IP otherwise.

    This prevents abuse from any single organization while not penalizing
    legitimate users behind the same NAT/proxy.
    """
    # Try to get organization ID from request state (set by auth middleware)
    org_id = getattr(request.state, "organization_id", None)
    if org_id:
        return f"org:{org_id}"

    # Try to get API key prefix from header (for quick identification)
    api_key = request.headers.get("X-API-Key", "")
    if api_key and api_key.startswith("breach_"):
        # Use first 16 chars of API key as identifier (not full key for privacy)
        return f"apikey:{api_key[:16]}"

    # Fall back to IP address for unauthenticated requests
    return get_remote_address(request)


# Initialize rate limiter (uses memory storage unless Redis is explicitly configured)
limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=[settings.rate_limit_global],
    storage_uri=settings.redis_url if REDIS_AVAILABLE and settings.redis_url else None,
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

        cutoff = datetime.utcnow() - timedelta(hours=2)

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
                        completed_at=datetime.utcnow()
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

    # Start continuous scanner for scheduled scans
    try:
        from backend.services.scheduler import start_continuous_scanner
        await start_continuous_scanner()
        logger.info("continuous_scanner_started")
    except Exception as e:
        logger.warning("continuous_scanner_failed_to_start", error=str(e))

    yield

    # Shutdown
    # Stop continuous scanner
    try:
        from backend.services.scheduler import stop_continuous_scanner
        await stop_continuous_scanner()
        logger.info("continuous_scanner_stopped")
    except Exception as e:
        logger.warning("continuous_scanner_stop_failed", error=str(e))

    await close_db()
    logger.info("database_closed")


# =============================================================================
# FastAPI Application
# =============================================================================

API_DESCRIPTION = """
# BREACH.AI Enterprise API

**Autonomous Security Assessment Engine**

## Overview

BREACH.AI provides automated security testing and vulnerability assessment capabilities through a comprehensive REST API.

## Key Features

- **Scan Management**: Create, monitor, and manage security scans
- **Target Management**: Define and organize scan targets
- **Findings**: View and manage discovered vulnerabilities
- **Learning Engine**: AI-powered learning from past scans
- **Analytics**: Trend analysis, comparisons, and reporting
- **Integrations**: Slack, GitHub, Jira, webhooks
- **Attestations**: Security posture reports and compliance badges

## Authentication

All API endpoints require authentication via JWT token or API key:

```
Authorization: Bearer <token>
```

or

```
X-API-Key: breach_xxxxxxxxxxxx
```

## Rate Limiting

- Global: 100 requests/minute per organization
- Scan creation: 10 requests/minute
- Auth endpoints: 5 requests/minute

## WebSocket

Real-time scan updates are available via WebSocket:

```
ws://localhost:8000/ws/scans/{scan_id}
```

## Support

- Documentation: https://docs.breach.ai
- Issues: https://github.com/breach-ai/breach/issues
"""

API_TAGS = [
    {"name": "Health", "description": "Health check and status endpoints"},
    {"name": "Auth", "description": "Authentication and user management"},
    {"name": "Scans", "description": "Security scan management"},
    {"name": "Targets", "description": "Target configuration"},
    {"name": "Findings", "description": "Vulnerability findings"},
    {"name": "Learning Engine", "description": "AI learning and optimization"},
    {"name": "Analytics", "description": "Trends, comparisons, and reporting"},
    {"name": "Recommendations", "description": "Remediation guidance"},
    {"name": "Integrations", "description": "External service integrations"},
    {"name": "Attestations", "description": "Security posture and compliance"},
    {"name": "Billing", "description": "Subscription and billing management"},
    {"name": "Monitoring", "description": "Prometheus metrics and observability"},
]

app = FastAPI(
    title="BREACH.AI Enterprise",
    description=API_DESCRIPTION,
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=API_TAGS,
    contact={
        "name": "BREACH.AI Support",
        "url": "https://breach.ai/support",
        "email": "support@breach.ai",
    },
    license_info={
        "name": "Proprietary",
        "url": "https://breach.ai/license",
    },
)

# Add rate limiting
app.state.limiter = limiter

def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceptions safely."""
    detail = getattr(exc, 'detail', str(exc))
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded", "detail": str(detail)}
    )

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
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
# Organization Context Middleware (for per-org rate limiting)
# =============================================================================

@app.middleware("http")
async def org_context_middleware(request: Request, call_next):
    """
    Extract organization context for rate limiting.
    This middleware runs early to set request.state.organization_id
    which is then used by the rate limiter.

    NOTE: We don't do database lookups here to avoid async context issues
    when background scans are running. Rate limiting falls back to IP-based
    for unauthenticated requests, and the auth layer sets org context later.
    """
    # Initialize state
    if not hasattr(request.state, "organization_id"):
        request.state.organization_id = None

    # Use API key prefix for rate limiting identification (no DB lookup)
    # The full validation happens in the auth layer
    api_key = request.headers.get("X-API-Key", "")
    if api_key and api_key.startswith("breach_"):
        # Use a hash of the API key for rate limit grouping (without DB lookup)
        import hashlib
        key_id = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        request.state.organization_id = f"apikey:{key_id}"

    try:
        response = await call_next(request)
        return response
    except Exception as e:
        # Catch any middleware chain errors
        logger.error("middleware_error", error=str(e), path=request.url.path)
        # Include CORS headers in error response
        origin = request.headers.get("origin", "")
        headers = {}
        if origin and (origin in settings.cors_origins or "*" in settings.cors_origins):
            headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
            headers=headers
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

    # Redis check (if available and configured)
    if REDIS_AVAILABLE and settings.redis_url:
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
        checks["redis"] = {"status": "not_configured", "note": "Using in-memory rate limiting"}

    status_code = 200 if overall_status == "healthy" else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall_status,
            "service": "BREACH.AI",
            "version": "4.0.0",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat()
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
app.include_router(assessments_router, prefix="/api/v1")
app.include_router(schedules_router, prefix="/api/v1")
app.include_router(integrations_router, prefix="/api/v1")
app.include_router(attestations_router, prefix="/api/v1")
app.include_router(learning_router, prefix="/api/v1")
app.include_router(recommendations_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/api/v1")

# V2 Breach API
app.include_router(breaches_router)

# =============================================================================
# Abuse Detection Middleware (Optional)
# =============================================================================

try:
    from backend.api.middleware.abuse import setup_abuse_middleware
    setup_abuse_middleware(app)
    logger.info("abuse_detection_middleware_enabled")
except ImportError:
    logger.info("abuse_detection_middleware_not_available")


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


async def broadcast_scan_progress(scan_id: str, message: dict):
    """Broadcast scan progress to all connected clients."""
    await manager.broadcast(scan_id, message)


# Export for use by scan service
def get_ws_manager() -> ConnectionManager:
    """Get the WebSocket connection manager."""
    return manager


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
