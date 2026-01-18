"""
BREACH.AI - Abuse Detection Service
====================================

Detects and prevents abuse patterns:
- Rapid scan attempts
- Blocked domain scanning attempts
- Failed verification spam
- Suspicious activity patterns

Uses in-memory cache for fast lookups, with optional Redis backend.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID
import asyncio

import structlog

logger = structlog.get_logger(__name__)


class AbuseType(str, Enum):
    """Types of abuse detected."""
    BLOCKED_DOMAIN_ATTEMPT = "blocked_domain_attempt"
    RAPID_SCAN_ATTEMPTS = "rapid_scan_attempts"
    FAILED_VERIFICATION_SPAM = "failed_verification_spam"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


@dataclass
class AbuseEvent:
    """Record of an abuse event."""
    event_type: AbuseType
    organization_id: str
    user_id: Optional[str]
    details: dict
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None


@dataclass
class AbuseScore:
    """Abuse score for an organization."""
    organization_id: str
    score: int = 0  # 0-100, 100 = definitely abusive
    events: List[AbuseEvent] = field(default_factory=list)
    is_blocked: bool = False
    blocked_until: Optional[datetime] = None
    last_updated: datetime = field(default_factory=datetime.utcnow)


class AbuseDetectionService:
    """
    Service for detecting and preventing abuse.

    Thresholds:
    - 3 blocked domain attempts in 1 hour -> warning
    - 5 blocked domain attempts in 1 hour -> temporary block (1 hour)
    - 10 failed verifications in 1 hour -> temporary block (1 hour)
    - 20 scan attempts in 10 minutes -> rate limit
    - Score >= 80 -> automatic block pending review
    """

    # Thresholds
    BLOCKED_DOMAIN_WARNING = 3
    BLOCKED_DOMAIN_BLOCK = 5
    FAILED_VERIFICATION_BLOCK = 10
    RAPID_SCAN_THRESHOLD = 20
    RAPID_SCAN_WINDOW_MINUTES = 10
    AUTO_BLOCK_SCORE = 80

    # Time windows
    WINDOW_HOURS = 1
    BLOCK_DURATION_HOURS = 1

    def __init__(self):
        # In-memory storage (use Redis in production)
        self._scores: Dict[str, AbuseScore] = {}
        self._events: Dict[str, List[AbuseEvent]] = defaultdict(list)
        self._scan_timestamps: Dict[str, List[datetime]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def record_blocked_domain_attempt(
        self,
        organization_id: UUID,
        user_id: Optional[UUID],
        domain: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Record an attempt to scan a blocked domain."""
        org_id = str(organization_id)

        event = AbuseEvent(
            event_type=AbuseType.BLOCKED_DOMAIN_ATTEMPT,
            organization_id=org_id,
            user_id=str(user_id) if user_id else None,
            details={"domain": domain},
            ip_address=ip_address,
        )

        async with self._lock:
            self._events[org_id].append(event)
            await self._update_score(org_id, points=15)

        logger.warning(
            "abuse_blocked_domain_attempt",
            organization_id=org_id,
            domain=domain,
            ip_address=ip_address,
        )

        # Check if should block
        await self._check_and_block(org_id)

    async def record_failed_verification(
        self,
        organization_id: UUID,
        user_id: Optional[UUID],
        target_url: str,
        method: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Record a failed verification attempt."""
        org_id = str(organization_id)

        event = AbuseEvent(
            event_type=AbuseType.FAILED_VERIFICATION_SPAM,
            organization_id=org_id,
            user_id=str(user_id) if user_id else None,
            details={"target_url": target_url, "method": method},
            ip_address=ip_address,
        )

        async with self._lock:
            self._events[org_id].append(event)
            await self._update_score(org_id, points=5)

        # Check recent failed verifications
        recent = await self._get_recent_events(
            org_id, AbuseType.FAILED_VERIFICATION_SPAM, hours=self.WINDOW_HOURS
        )

        if len(recent) >= self.FAILED_VERIFICATION_BLOCK:
            await self._block_organization(
                org_id,
                reason=f"Too many failed verification attempts ({len(recent)} in {self.WINDOW_HOURS} hour)",
            )

    async def record_scan_attempt(
        self,
        organization_id: UUID,
        ip_address: Optional[str] = None,
    ) -> bool:
        """
        Record a scan attempt and check for rapid scanning.

        Returns:
            bool: True if allowed, False if rate limited
        """
        org_id = str(organization_id)
        now = datetime.utcnow()

        async with self._lock:
            # Clean old timestamps
            cutoff = now - timedelta(minutes=self.RAPID_SCAN_WINDOW_MINUTES)
            self._scan_timestamps[org_id] = [
                ts for ts in self._scan_timestamps[org_id] if ts > cutoff
            ]

            # Check rate
            if len(self._scan_timestamps[org_id]) >= self.RAPID_SCAN_THRESHOLD:
                await self._update_score(org_id, points=10)
                logger.warning(
                    "abuse_rapid_scan_detected",
                    organization_id=org_id,
                    attempts=len(self._scan_timestamps[org_id]),
                    window_minutes=self.RAPID_SCAN_WINDOW_MINUTES,
                )
                return False

            # Record this attempt
            self._scan_timestamps[org_id].append(now)

        return True

    async def is_blocked(self, organization_id: UUID) -> tuple[bool, Optional[str]]:
        """
        Check if an organization is blocked.

        Returns:
            Tuple[bool, Optional[str]]: (is_blocked, reason)
        """
        org_id = str(organization_id)

        async with self._lock:
            score = self._scores.get(org_id)

            if not score:
                return False, None

            if not score.is_blocked:
                return False, None

            # Check if block has expired
            if score.blocked_until and datetime.utcnow() > score.blocked_until:
                score.is_blocked = False
                score.blocked_until = None
                return False, None

            return True, f"Organization temporarily blocked due to suspicious activity"

    async def get_abuse_score(self, organization_id: UUID) -> int:
        """Get the current abuse score for an organization."""
        org_id = str(organization_id)

        async with self._lock:
            score = self._scores.get(org_id)
            return score.score if score else 0

    async def get_abuse_events(
        self,
        organization_id: UUID,
        hours: int = 24,
    ) -> List[dict]:
        """Get recent abuse events for an organization."""
        org_id = str(organization_id)
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        async with self._lock:
            events = self._events.get(org_id, [])
            recent = [e for e in events if e.timestamp > cutoff]

        return [
            {
                "type": e.event_type.value,
                "details": e.details,
                "timestamp": e.timestamp.isoformat(),
                "ip_address": e.ip_address,
            }
            for e in recent
        ]

    async def clear_block(self, organization_id: UUID) -> None:
        """Clear a block (admin action)."""
        org_id = str(organization_id)

        async with self._lock:
            if org_id in self._scores:
                self._scores[org_id].is_blocked = False
                self._scores[org_id].blocked_until = None
                self._scores[org_id].score = max(0, self._scores[org_id].score - 30)

        logger.info("abuse_block_cleared", organization_id=org_id)

    # ============== Internal Methods ==============

    async def _update_score(self, org_id: str, points: int) -> None:
        """Update abuse score (must be called within lock)."""
        if org_id not in self._scores:
            self._scores[org_id] = AbuseScore(organization_id=org_id)

        score = self._scores[org_id]
        score.score = min(100, score.score + points)
        score.last_updated = datetime.utcnow()

        # Decay score over time (1 point per hour)
        hours_since_update = (datetime.utcnow() - score.last_updated).total_seconds() / 3600
        score.score = max(0, score.score - int(hours_since_update))

    async def _check_and_block(self, org_id: str) -> None:
        """Check if organization should be blocked."""
        async with self._lock:
            score = self._scores.get(org_id)
            if not score:
                return

            # Check blocked domain attempts
            recent_blocked = await self._get_recent_events(
                org_id, AbuseType.BLOCKED_DOMAIN_ATTEMPT, hours=self.WINDOW_HOURS
            )

            if len(recent_blocked) >= self.BLOCKED_DOMAIN_BLOCK:
                await self._block_organization(
                    org_id,
                    reason=f"Multiple attempts to scan blocked domains ({len(recent_blocked)} in {self.WINDOW_HOURS} hour)",
                )
                return

            # Check overall score
            if score.score >= self.AUTO_BLOCK_SCORE:
                await self._block_organization(
                    org_id,
                    reason=f"Abuse score exceeded threshold ({score.score}/100)",
                )

    async def _block_organization(self, org_id: str, reason: str) -> None:
        """Block an organization (must be called within lock context or acquire lock)."""
        if org_id not in self._scores:
            self._scores[org_id] = AbuseScore(organization_id=org_id)

        score = self._scores[org_id]
        score.is_blocked = True
        score.blocked_until = datetime.utcnow() + timedelta(hours=self.BLOCK_DURATION_HOURS)

        logger.error(
            "abuse_organization_blocked",
            organization_id=org_id,
            reason=reason,
            blocked_until=score.blocked_until.isoformat(),
        )

    async def _get_recent_events(
        self, org_id: str, event_type: AbuseType, hours: int
    ) -> List[AbuseEvent]:
        """Get recent events of a specific type (no lock needed, read-only)."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        events = self._events.get(org_id, [])
        return [e for e in events if e.event_type == event_type and e.timestamp > cutoff]


# Global instance
_abuse_service: Optional[AbuseDetectionService] = None


def get_abuse_service() -> AbuseDetectionService:
    """Get the global abuse detection service instance."""
    global _abuse_service
    if _abuse_service is None:
        _abuse_service = AbuseDetectionService()
    return _abuse_service
