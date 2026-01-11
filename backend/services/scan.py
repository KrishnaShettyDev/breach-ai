"""
BREACH.AI - Scan Service
=========================
Scan orchestration and management with timeout handling.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional, List, Callable
from uuid import UUID

import structlog
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.models import (
    Scan, Finding, Target, Organization,
    ScanStatus, ScanMode, Severity as DBSeverity
)

logger = structlog.get_logger(__name__)


class ScanService:
    """Scan orchestration service."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ============== SCAN CRUD ==============

    async def create_scan(
        self,
        organization_id: UUID,
        target_url: str,
        user_id: UUID,
        mode: str = "normal",
        config: dict = None,
        target_id: Optional[UUID] = None,
    ) -> Scan:
        """Create a new scan."""

        # Check organization limits
        org = await self._get_organization(organization_id)
        if org.scans_this_month >= org.max_scans_per_month:
            raise ValueError("Monthly scan limit reached. Please upgrade your plan.")

        scan = Scan(
            organization_id=organization_id,
            target_id=target_id,
            created_by=user_id,
            target_url=target_url,
            mode=ScanMode(mode),
            status=ScanStatus.PENDING,
            config=config or {},
        )
        self.db.add(scan)

        # Increment scan count
        org.scans_this_month += 1

        await self.db.commit()
        await self.db.refresh(scan)

        logger.info(
            "scan_created",
            scan_id=str(scan.id),
            organization_id=str(organization_id),
            target_url=target_url,
            mode=mode
        )

        return scan

    async def get_scan(self, scan_id: UUID, organization_id: UUID) -> Optional[Scan]:
        """Get a scan by ID."""
        result = await self.db.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_scan_with_findings(self, scan_id: UUID, organization_id: UUID) -> Optional[Scan]:
        """Get a scan with all its findings."""
        scan = await self.get_scan(scan_id, organization_id)
        if scan:
            # Load findings
            result = await self.db.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.severity.desc(), Finding.discovered_at.desc())
            )
            scan.findings = result.scalars().all()
        return scan

    async def list_scans(
        self,
        organization_id: UUID,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
    ) -> dict:
        """List scans with pagination."""

        query = select(Scan).where(Scan.organization_id == organization_id)

        if status:
            query = query.where(Scan.status == ScanStatus(status))

        # Count total
        count_query = select(func.count(Scan.id)).where(Scan.organization_id == organization_id)
        if status:
            count_query = count_query.where(Scan.status == ScanStatus(status))

        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # Get paginated results
        query = query.order_by(Scan.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        result = await self.db.execute(query)
        scans = result.scalars().all()

        return {
            "items": scans,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }

    async def cancel_scan(self, scan_id: UUID, organization_id: UUID) -> bool:
        """Cancel a running scan."""
        scan = await self.get_scan(scan_id, organization_id)
        if not scan:
            return False

        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise ValueError("Can only cancel pending or running scans")

        scan.status = ScanStatus.CANCELED
        scan.completed_at = datetime.now(timezone.utc)
        await self.db.commit()

        logger.info("scan_canceled", scan_id=str(scan_id))

        return True

    async def delete_scan(self, scan_id: UUID, organization_id: UUID) -> bool:
        """Delete a scan and its findings."""
        scan = await self.get_scan(scan_id, organization_id)
        if not scan:
            return False

        await self.db.delete(scan)
        await self.db.commit()

        logger.info("scan_deleted", scan_id=str(scan_id))

        return True

    # ============== SCAN EXECUTION ==============

    async def start_scan(
        self,
        scan_id: UUID,
        organization_id: UUID,
        progress_callback: Optional[Callable] = None,
    ) -> Scan:
        """Start executing a scan with timeout handling."""

        scan = await self.get_scan(scan_id, organization_id)
        if not scan:
            raise ValueError("Scan not found")

        if scan.status != ScanStatus.PENDING:
            raise ValueError("Scan already started or completed")

        # Update status
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        logger.info(
            "scan_started",
            scan_id=str(scan_id),
            target_url=scan.target_url,
            mode=scan.mode.value
        )

        try:
            # Run scan with timeout
            await asyncio.wait_for(
                self._execute_scan(scan),
                timeout=settings.scan_timeout_seconds
            )

            # Mark completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )

            logger.info(
                "scan_completed",
                scan_id=str(scan_id),
                findings_count=scan.findings_count,
                duration_seconds=scan.duration_seconds
            )

        except asyncio.TimeoutError:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Scan timed out after {settings.scan_timeout_seconds} seconds"
            scan.completed_at = datetime.now(timezone.utc)

            logger.error(
                "scan_timeout",
                scan_id=str(scan_id),
                timeout_seconds=settings.scan_timeout_seconds
            )

            # Send failure alert
            await self._send_failure_alert(scan)

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)

            logger.error(
                "scan_failed",
                scan_id=str(scan_id),
                error=str(e),
                exc_info=True
            )

            # Send failure alert
            await self._send_failure_alert(scan)

        await self.db.commit()
        await self.db.refresh(scan)

        return scan

    async def _execute_scan(self, scan: Scan) -> None:
        """Execute the actual scan (called within timeout wrapper)."""
        from backend.breach.engine import BreachEngine

        # Determine mode
        deep_mode = scan.mode in [ScanMode.DEEP, ScanMode.CHAINBREAKER]

        # Extract config
        cookie = scan.config.get("cookies") if scan.config else None

        # Run the scan
        async with BreachEngine(deep_mode=deep_mode) as engine:
            await engine.breach(
                target=scan.target_url,
                cookie=cookie,
            )

            # Save findings
            await self._save_findings(scan, engine.state)

            # Update scan stats
            await self._update_scan_stats(scan, engine.state)

    async def _send_failure_alert(self, scan: Scan) -> None:
        """Send alert on scan failure via configured webhook."""
        if not settings.alert_webhook_url:
            return

        try:
            from backend.monitoring.alerts import send_scan_failure_alert
            await send_scan_failure_alert(
                scan_id=str(scan.id),
                target_url=scan.target_url,
                error_message=scan.error_message or "Unknown error",
            )
        except ImportError:
            logger.warning("alerts_module_not_available")
        except Exception as e:
            logger.error("alert_send_failed", error=str(e))

    async def _save_findings(self, scan: Scan, state) -> None:
        """Save findings from scan state to database."""

        severity_map = {
            4: DBSeverity.CRITICAL,
            3: DBSeverity.HIGH,
            2: DBSeverity.MEDIUM,
            1: DBSeverity.LOW,
            0: DBSeverity.INFO,
        }

        for finding_data in state.findings:
            finding = Finding(
                scan_id=scan.id,
                title=finding_data.title,
                severity=severity_map.get(finding_data.severity.value, DBSeverity.MEDIUM),
                category=finding_data.category,
                endpoint=finding_data.endpoint,
                method=finding_data.method,
                description=finding_data.description,
                evidence={"data": finding_data.evidence} if finding_data.evidence else {},
                business_impact=float(finding_data.business_impact),
                impact_explanation=finding_data.impact_explanation,
                records_exposed=finding_data.records_exposed,
                pii_fields=finding_data.pii_fields,
                fix_suggestion=finding_data.fix_suggestion,
                curl_command=finding_data.curl_command,
            )
            self.db.add(finding)

    async def _update_scan_stats(self, scan: Scan, state) -> None:
        """Update scan statistics from results."""

        findings = state.findings
        scan.findings_count = len(findings)
        scan.critical_count = len([f for f in findings if f.severity.value == 4])
        scan.high_count = len([f for f in findings if f.severity.value == 3])
        scan.medium_count = len([f for f in findings if f.severity.value == 2])
        scan.low_count = len([f for f in findings if f.severity.value == 1])
        scan.info_count = len([f for f in findings if f.severity.value == 0])
        scan.total_business_impact = sum(f.business_impact for f in findings)

    # ============== FINDINGS ==============

    async def get_finding(self, finding_id: UUID, organization_id: UUID) -> Optional[Finding]:
        """Get a finding by ID."""
        result = await self.db.execute(
            select(Finding)
            .join(Scan)
            .where(
                Finding.id == finding_id,
                Scan.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def update_finding(
        self,
        finding_id: UUID,
        organization_id: UUID,
        is_false_positive: Optional[bool] = None,
        is_resolved: Optional[bool] = None,
    ) -> Optional[Finding]:
        """Update finding status."""

        finding = await self.get_finding(finding_id, organization_id)
        if not finding:
            return None

        if is_false_positive is not None:
            finding.is_false_positive = is_false_positive

        if is_resolved is not None:
            finding.is_resolved = is_resolved
            if is_resolved:
                finding.resolved_at = datetime.now(timezone.utc)
            else:
                finding.resolved_at = None

        await self.db.commit()
        await self.db.refresh(finding)

        return finding

    async def list_findings(
        self,
        organization_id: UUID,
        scan_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> dict:
        """List findings with filters."""

        query = (
            select(Finding)
            .join(Scan)
            .where(Scan.organization_id == organization_id)
        )

        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        if severity:
            query = query.where(Finding.severity == DBSeverity(severity))
        if category:
            query = query.where(Finding.category == category)

        # Count
        count_query = (
            select(func.count(Finding.id))
            .join(Scan)
            .where(Scan.organization_id == organization_id)
        )
        if scan_id:
            count_query = count_query.where(Finding.scan_id == scan_id)

        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # Paginate
        query = query.order_by(Finding.severity.desc(), Finding.discovered_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        result = await self.db.execute(query)
        findings = result.scalars().all()

        return {
            "items": findings,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }

    # ============== STATISTICS ==============

    async def get_stats(self, organization_id: UUID) -> dict:
        """Get organization scan statistics."""

        # Total scans
        total_scans = await self.db.execute(
            select(func.count(Scan.id))
            .where(Scan.organization_id == organization_id)
        )

        # Scans this month
        org = await self._get_organization(organization_id)

        # Findings by severity
        findings_query = (
            select(Finding.severity, func.count(Finding.id))
            .join(Scan)
            .where(Scan.organization_id == organization_id)
            .group_by(Finding.severity)
        )
        findings_result = await self.db.execute(findings_query)
        severity_counts = {str(row[0].value): row[1] for row in findings_result.all()}

        # Total business impact
        impact_query = (
            select(func.sum(Finding.business_impact))
            .join(Scan)
            .where(Scan.organization_id == organization_id)
        )
        impact_result = await self.db.execute(impact_query)
        total_impact = impact_result.scalar() or 0

        # Avg scan duration
        duration_query = (
            select(func.avg(Scan.duration_seconds))
            .where(
                Scan.organization_id == organization_id,
                Scan.status == ScanStatus.COMPLETED,
            )
        )
        duration_result = await self.db.execute(duration_query)
        avg_duration = duration_result.scalar()

        return {
            "total_scans": total_scans.scalar() or 0,
            "scans_this_month": org.scans_this_month if org else 0,
            "total_findings": sum(severity_counts.values()),
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0),
            "total_business_impact": float(total_impact),
            "avg_scan_duration": float(avg_duration) if avg_duration else None,
        }

    # ============== TARGETS ==============

    async def create_target(
        self,
        organization_id: UUID,
        url: str,
        name: str,
        description: Optional[str] = None,
    ) -> Target:
        """Create a scan target."""
        import secrets

        target = Target(
            organization_id=organization_id,
            url=url,
            name=name,
            description=description,
            verification_token=secrets.token_urlsafe(32),
        )
        self.db.add(target)
        await self.db.commit()
        await self.db.refresh(target)

        return target

    async def list_targets(self, organization_id: UUID) -> List[Target]:
        """List all targets for an organization."""
        result = await self.db.execute(
            select(Target)
            .where(Target.organization_id == organization_id)
            .order_by(Target.created_at.desc())
        )
        return result.scalars().all()

    async def delete_target(self, target_id: UUID, organization_id: UUID) -> bool:
        """Delete a target."""
        result = await self.db.execute(
            select(Target).where(
                Target.id == target_id,
                Target.organization_id == organization_id,
            )
        )
        target = result.scalar_one_or_none()

        if not target:
            return False

        await self.db.delete(target)
        await self.db.commit()
        return True

    async def verify_target(self, target_id: UUID, organization_id: UUID, method: str) -> bool:
        """Verify target ownership."""
        result = await self.db.execute(
            select(Target).where(
                Target.id == target_id,
                Target.organization_id == organization_id,
            )
        )
        target = result.scalar_one_or_none()

        if not target:
            return False

        # TODO: Implement actual verification (DNS TXT, file upload, meta tag)
        # For now, just mark as verified
        target.is_verified = True
        target.verification_method = method
        target.verified_at = datetime.now(timezone.utc)

        await self.db.commit()
        return True

    # ============== HELPERS ==============

    async def _get_organization(self, organization_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        result = await self.db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        return result.scalar_one_or_none()
