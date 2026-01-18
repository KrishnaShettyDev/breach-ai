"""
BREACH.AI - Abuse Detection Middleware
======================================

FastAPI middleware for detecting and blocking abusive behavior.
"""

from typing import Callable
from uuid import UUID

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import structlog

from backend.services.abuse_detection import get_abuse_service

logger = structlog.get_logger(__name__)


class AbuseDetectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to check for and block abusive organizations.

    Checks:
    1. If organization is currently blocked
    2. Records scan attempts for rate limiting
    """

    # Paths that trigger abuse checks
    PROTECTED_PATHS = [
        "/api/v1/scans",
        "/api/v1/targets",
        "/api/v2/breaches",
        "/api/v1/assessments",
    ]

    async def dispatch(self, request: Request, call_next: Callable):
        """Process the request through abuse detection."""
        # Skip for non-protected paths
        if not any(request.url.path.startswith(p) for p in self.PROTECTED_PATHS):
            return await call_next(request)

        # Skip for GET requests (read operations)
        if request.method == "GET":
            return await call_next(request)

        # Try to get organization ID from auth context
        org_id = await self._get_organization_id(request)

        if org_id:
            abuse_service = get_abuse_service()

            # Check if blocked
            is_blocked, reason = await abuse_service.is_blocked(org_id)
            if is_blocked:
                logger.warning(
                    "abuse_request_blocked",
                    organization_id=str(org_id),
                    path=request.url.path,
                    reason=reason,
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": reason or "Your organization has been temporarily blocked due to suspicious activity. Please contact support.",
                        "code": "ABUSE_BLOCKED",
                    },
                )

            # Record scan attempts for rate limiting
            if request.url.path.endswith("/scans") and request.method == "POST":
                ip_address = self._get_client_ip(request)
                allowed = await abuse_service.record_scan_attempt(org_id, ip_address)

                if not allowed:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": "Too many scan requests. Please wait before trying again.",
                            "code": "RATE_LIMITED",
                        },
                    )

        response = await call_next(request)
        return response

    async def _get_organization_id(self, request: Request) -> UUID | None:
        """Try to extract organization ID from request state or auth."""
        # Check if already set by auth middleware
        if hasattr(request.state, "organization_id"):
            org_id = request.state.organization_id
            if isinstance(org_id, str):
                try:
                    return UUID(org_id)
                except ValueError:
                    pass
            return org_id

        # Could also extract from JWT token here if needed
        return None

    def _get_client_ip(self, request: Request) -> str | None:
        """Get client IP address from request."""
        # Check X-Forwarded-For header (behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        if request.client:
            return request.client.host

        return None


def setup_abuse_middleware(app):
    """Add abuse detection middleware to the FastAPI app."""
    app.add_middleware(AbuseDetectionMiddleware)
