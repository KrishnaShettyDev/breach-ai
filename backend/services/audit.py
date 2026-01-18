"""
BREACH.AI - Audit Logging Service
==================================
Track all security-relevant actions for compliance and forensics.
"""

from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID

import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import AuditLog

logger = structlog.get_logger(__name__)


class AuditService:
    """
    Service for logging security-relevant actions.

    Logs are written to:
    1. Database (AuditLog table) for persistence and querying
    2. Structured logs for real-time monitoring/alerting

    Usage:
        audit = AuditService(db)
        await audit.log(
            organization_id=org.id,
            user_id=user.id,
            action="scan.created",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"target_url": scan.target_url},
            request=request,
        )
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        organization_id: UUID,
        user_id: Optional[UUID],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """
        Log an auditable action.

        Args:
            organization_id: Organization performing the action
            user_id: User performing the action (None for system actions)
            action: Action type (e.g., "scan.created", "target.verified")
            resource_type: Type of resource affected (scan, target, user, etc.)
            resource_id: ID of the affected resource
            details: Additional context (JSON-serializable dict)
            request: FastAPI request object (for IP/user-agent extraction)

        Returns:
            Created AuditLog record
        """
        # Extract request info
        ip_address = None
        user_agent = None
        if request:
            ip_address = self._get_client_ip(request)
            user_agent = request.headers.get("User-Agent", "")[:500]

        # Create audit log entry
        audit_log = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)

        # Also log to structured logging for real-time monitoring
        logger.info(
            "audit_event",
            organization_id=str(organization_id),
            user_id=str(user_id) if user_id else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details,
        )

        return audit_log

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxies."""
        # Check X-Forwarded-For header (set by proxies/load balancers)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First IP in the list is the original client
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP (Nginx)
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return "unknown"

    # Convenience methods for common actions

    async def log_scan_created(
        self,
        organization_id: UUID,
        user_id: UUID,
        scan_id: str,
        target_url: str,
        mode: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log scan creation."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="scan.created",
            resource_type="scan",
            resource_id=scan_id,
            details={"target_url": target_url, "mode": mode},
            request=request,
        )

    async def log_scan_completed(
        self,
        organization_id: UUID,
        scan_id: str,
        findings_count: int,
        duration_seconds: int,
    ) -> AuditLog:
        """Log scan completion."""
        return await self.log(
            organization_id=organization_id,
            user_id=None,  # System action
            action="scan.completed",
            resource_type="scan",
            resource_id=scan_id,
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
            },
        )

    async def log_target_created(
        self,
        organization_id: UUID,
        user_id: UUID,
        target_id: str,
        url: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log target creation."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="target.created",
            resource_type="target",
            resource_id=target_id,
            details={"url": url},
            request=request,
        )

    async def log_target_verified(
        self,
        organization_id: UUID,
        user_id: UUID,
        target_id: str,
        method: str,
        success: bool,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log target verification attempt."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="target.verified" if success else "target.verification_failed",
            resource_type="target",
            resource_id=target_id,
            details={"method": method, "success": success},
            request=request,
        )

    async def log_target_deleted(
        self,
        organization_id: UUID,
        user_id: UUID,
        target_id: str,
        url: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log target deletion."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="target.deleted",
            resource_type="target",
            resource_id=target_id,
            details={"url": url},
            request=request,
        )

    async def log_api_key_created(
        self,
        organization_id: UUID,
        user_id: UUID,
        key_id: str,
        key_name: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log API key creation."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="api_key.created",
            resource_type="api_key",
            resource_id=key_id,
            details={"name": key_name},
            request=request,
        )

    async def log_api_key_revoked(
        self,
        organization_id: UUID,
        user_id: UUID,
        key_id: str,
        key_name: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log API key revocation."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="api_key.revoked",
            resource_type="api_key",
            resource_id=key_id,
            details={"name": key_name},
            request=request,
        )

    async def log_login(
        self,
        organization_id: UUID,
        user_id: UUID,
        method: str,  # "clerk", "api_key"
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log user login."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="user.login",
            resource_type="user",
            resource_id=str(user_id),
            details={"method": method},
            request=request,
        )

    async def log_subscription_changed(
        self,
        organization_id: UUID,
        user_id: Optional[UUID],
        old_tier: str,
        new_tier: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log subscription tier change."""
        return await self.log(
            organization_id=organization_id,
            user_id=user_id,
            action="subscription.changed",
            resource_type="organization",
            resource_id=str(organization_id),
            details={"old_tier": old_tier, "new_tier": new_tier},
            request=request,
        )
