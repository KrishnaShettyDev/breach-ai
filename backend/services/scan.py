"""
BREACH.AI - Scan Service
=========================
Scan orchestration and management with timeout handling.
"""

import asyncio
import re
import socket
from datetime import datetime, timezone
from typing import Optional, List, Callable, Tuple
from urllib.parse import urlparse
from uuid import UUID

import httpx
import structlog
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings, is_blocked_domain, validate_scan_target
from backend.db.models import (
    Scan, Finding, Target, Organization,
    ScanStatus, ScanMode, Severity as DBSeverity
)

logger = structlog.get_logger(__name__)

# Optional DNS library
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed, DNS verification disabled")


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
        """Create a new scan.

        SECURITY: Scans require a verified target. Ad-hoc URLs are not allowed.
        This prevents abuse where users scan sites they don't own.
        """

        # Check organization limits
        org = await self._get_organization(organization_id)
        if not org:
            raise ValueError("Organization not found")

        # Disabled for now - unlimited scans
        # if org.scans_this_month >= org.max_scans_per_month:
        #     raise ValueError("Monthly scan limit reached. Please upgrade your plan.")

        # SECURITY: Require a verified target
        if not target_id:
            raise ValueError(
                "Target ID is required. Please add and verify a target before scanning. "
                "Ad-hoc URLs are not allowed for security reasons."
            )

        # Get and validate the target
        target = await self._get_target(target_id)
        if not target:
            raise ValueError("Target not found")

        # Verify target belongs to this organization
        if target.organization_id != organization_id:
            logger.warning(
                "scan_target_org_mismatch",
                target_id=str(target_id),
                target_org=str(target.organization_id),
                request_org=str(organization_id),
            )
            raise ValueError("Target does not belong to this organization")

        # Use the target's URL
        verified_url = target.url

        scan = Scan(
            organization_id=organization_id,
            target_id=target_id,
            created_by=user_id,
            target_url=verified_url,  # Use verified target URL
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
            target_id=str(target_id),
            target_url=verified_url,
            mode=mode
        )

        return scan

    async def _get_target(self, target_id: UUID) -> Optional[Target]:
        """Get target by ID."""
        result = await self.db.execute(
            select(Target).where(Target.id == target_id)
        )
        return result.scalar_one_or_none()

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
        scan.completed_at = datetime.utcnow()
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
        """Start executing a scan with timeout handling and integrations."""

        scan = await self.get_scan(scan_id, organization_id)
        if not scan:
            raise ValueError("Scan not found")

        if scan.status != ScanStatus.PENDING:
            raise ValueError("Scan already started or completed")

        # Get target for integrations
        target = await self._get_target(scan.target_id) if scan.target_id else None

        # Initialize integration manager
        integration_manager = await self._init_integrations(organization_id)

        # Update status
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        await self.db.commit()

        logger.info(
            "scan_started",
            scan_id=str(scan_id),
            target_url=scan.target_url,
            mode=scan.mode.value
        )

        # Notify integrations: scan started
        if integration_manager and target:
            try:
                await integration_manager.notify_scan_started(scan, target)
            except Exception as e:
                logger.warning("integration_notify_failed", event="scan_started", error=str(e))

        try:
            # Run scan with timeout
            await asyncio.wait_for(
                self._execute_scan(scan, integration_manager, target),
                timeout=settings.scan_timeout_seconds
            )

            # Mark completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )

            logger.info(
                "scan_completed",
                scan_id=str(scan_id),
                findings_count=scan.findings_count,
                duration_seconds=scan.duration_seconds
            )

            # Notify integrations: scan completed
            if integration_manager and target:
                try:
                    findings_summary = {
                        "total": scan.findings_count,
                        "critical": scan.critical_count,
                        "high": scan.high_count,
                        "medium": scan.medium_count,
                        "low": scan.low_count,
                    }
                    await integration_manager.notify_scan_completed(
                        scan, target, findings_summary
                    )
                except Exception as e:
                    logger.warning("integration_notify_failed", event="scan_completed", error=str(e))

            # Send email notification
            await self._send_completion_email(scan, organization_id)

        except asyncio.TimeoutError:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Scan timed out after {settings.scan_timeout_seconds} seconds"
            scan.completed_at = datetime.utcnow()

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
            scan.completed_at = datetime.utcnow()

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

    async def _init_integrations(self, organization_id: UUID):
        """Initialize integration manager for organization."""
        try:
            from backend.services.integrations import IntegrationManager
            manager = IntegrationManager(self.db)
            await manager.load_integrations(organization_id)
            return manager
        except Exception as e:
            logger.warning("integrations_init_failed", error=str(e))
            return None

    async def _broadcast_progress(self, scan_id: str, event_type: str, data: dict) -> None:
        """Broadcast scan progress via WebSocket and update database."""
        try:
            from backend.api.server import broadcast_scan_progress
            await broadcast_scan_progress(scan_id, {
                "type": event_type,
                "scan_id": scan_id,
                **data
            })
        except Exception as e:
            logger.debug("ws_broadcast_failed", error=str(e))

        # Also update database with progress (sync to avoid greenlet issues)
        try:
            self._update_scan_progress_sync(scan_id, event_type, data)
        except Exception as e:
            logger.debug("db_progress_update_failed", error=str(e))

    def _update_scan_progress_sync(self, scan_id: str, event_type: str, data: dict) -> None:
        """Update scan progress in database using sync connection."""
        import psycopg2
        from backend.config import settings

        # For direct progress updates from engine callback
        if event_type == "progress_update":
            progress = data.get("progress", 0)
            phase = data.get("phase", "scanning")
        else:
            # Map events to progress percentages
            progress_map = {
                "scan_started": 5,
                "phase_update": 50,
                "finding_discovered": None,
                "scan_completed": 100,
            }

            phase_progress = {
                "initializing": 5,
                "scanning": 20,
                "recon": 15,
                "injection": 40,
                "auth": 60,
                "idor": 75,
                "saving_results": 90,
                "complete": 100,
            }

            progress = progress_map.get(event_type)
            phase = data.get("phase")

            if phase and phase in phase_progress:
                progress = phase_progress[phase]

            if progress is None:
                return

        # Connect with sync psycopg2
        db_url = settings.database_url
        db_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
        db_url = db_url.replace("?ssl=require", "?sslmode=require")

        try:
            conn = psycopg2.connect(db_url)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE scans SET progress = %s, current_phase = %s WHERE id = %s",
                (progress, phase, scan_id)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("sync_progress_update_failed", error=str(e))

    async def _execute_scan(
        self,
        scan: Scan,
        integration_manager=None,
        target=None
    ) -> None:
        """Execute the actual scan (called within timeout wrapper)."""
        # Check if this is a Shannon mode scan
        if scan.mode == ScanMode.SHANNON:
            await self._execute_shannon_scan(scan, integration_manager, target)
            return

        from backend.breach.engine import BreachEngine

        # Map scan mode to engine mode
        mode_map = {
            ScanMode.QUICK: "quick",
            ScanMode.NORMAL: "deep",  # Normal uses deep
            ScanMode.DEEP: "deep",
            ScanMode.CHAINBREAKER: "chainbreaker",
        }
        engine_mode = mode_map.get(scan.mode, "quick")

        # Extract config
        config = scan.config or {}
        cookie = config.get("cookies")
        cookie2 = config.get("cookies2")
        token = config.get("token")
        timeout_hours = config.get("timeout_hours", 1)

        # Broadcast scan started
        await self._broadcast_progress(str(scan.id), "scan_started", {
            "target_url": scan.target_url,
            "mode": scan.mode.value,
            "phase": "initializing",
        })

        # Run the scan with unified engine
        async with BreachEngine(mode=engine_mode, timeout_hours=timeout_hours) as engine:
            # Register progress callback for real-time DB updates
            def on_scan_progress(percent: int, message: str):
                self._update_scan_progress_sync(str(scan.id), "progress_update", {
                    "phase": message,
                    "progress": percent,
                })

            engine.on_progress(on_scan_progress)
            # Register callback for findings -> integrations + WebSocket
            async def on_finding_discovered(finding):
                # Broadcast finding via WebSocket
                await self._broadcast_progress(str(scan.id), "finding_discovered", {
                    "title": finding.title,
                    "severity": finding.severity.name if hasattr(finding.severity, 'name') else str(finding.severity),
                    "category": finding.category,
                    "endpoint": finding.endpoint,
                })

                # Notify integrations for critical findings
                if integration_manager and target and finding.severity.value >= 3:
                    try:
                        from backend.db.models import Finding as DBFinding
                        db_finding = DBFinding(
                            scan_id=scan.id,
                            title=finding.title,
                            severity=DBSeverity.CRITICAL if finding.severity.value == 4 else DBSeverity.HIGH,
                            category=finding.category,
                            endpoint=finding.endpoint,
                            description=finding.description,
                        )
                        await integration_manager.notify_critical_finding(
                            db_finding, target, scan.id
                        )
                    except Exception as e:
                        logger.warning("critical_finding_notify_failed", error=str(e))

            engine.on_finding(on_finding_discovered)

            # Broadcast phase update
            await self._broadcast_progress(str(scan.id), "phase_update", {
                "phase": "scanning",
                "message": f"Running {engine_mode} scan against {scan.target_url}",
            })

            # Run the breach
            await engine.breach(
                target=scan.target_url,
                cookie=cookie,
                cookie2=cookie2,
                token=token,
            )

            # Broadcast saving findings phase
            await self._broadcast_progress(str(scan.id), "phase_update", {
                "phase": "saving_results",
                "message": f"Saving {len(engine.state.findings)} findings...",
            })

            # Save findings
            await self._save_findings(scan, engine.state)

            # Update scan stats
            await self._update_scan_stats(scan, engine.state)

            # Broadcast completion
            await self._broadcast_progress(str(scan.id), "scan_completed", {
                "findings_count": scan.findings_count,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
            })

            # Notify if critical vulnerabilities found
            if integration_manager and target and engine.state.findings:
                critical_count = len([f for f in engine.state.findings if f.severity.value == 4])
                if critical_count > 0:
                    try:
                        await integration_manager.notify_breach_achieved(
                            target=target,
                            access_level="database" if critical_count > 2 else "user",
                            systems_compromised=[scan.target_url],
                        )
                    except Exception as e:
                        logger.warning("breach_notify_failed", error=str(e))

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

    async def _send_completion_email(self, scan: Scan, organization_id: UUID) -> None:
        """Send email notification when scan completes."""
        try:
            from backend.services.email import get_email_service

            # Get the user who created the scan
            if not scan.created_by:
                logger.debug("scan_no_creator", scan_id=str(scan.id))
                return

            from sqlalchemy import select
            from backend.db.models import User
            result = await self.db.execute(
                select(User).where(User.id == scan.created_by)
            )
            user = result.scalar_one_or_none()

            if not user or not user.email:
                logger.debug("scan_creator_no_email", scan_id=str(scan.id))
                return

            email_service = get_email_service()
            await email_service.send_scan_completed(
                to_email=user.email,
                target_url=scan.target_url,
                scan_id=str(scan.id),
                findings_count=scan.findings_count or 0,
                critical_count=scan.critical_count or 0,
                high_count=scan.high_count or 0,
                medium_count=scan.medium_count or 0,
                low_count=scan.low_count or 0,
                total_impact=scan.total_business_impact or 0,
                dashboard_url=settings.frontend_url,
            )

            logger.info("scan_completion_email_sent", scan_id=str(scan.id), to=user.email)

        except Exception as e:
            logger.warning("scan_completion_email_failed", scan_id=str(scan.id), error=str(e))

    async def _execute_shannon_scan(
        self,
        scan: Scan,
        integration_manager=None,
        target=None
    ) -> None:
        """Execute Shannon mode scan with proof-by-exploitation."""
        try:
            from backend.breach.exploitation.shannon_engine import ShannonEngine
        except ImportError as e:
            logger.error("shannon_import_failed", error=str(e))
            raise ValueError("Shannon engine not available. Please check installation.")

        # Extract config
        config = scan.config or {}
        cookies_str = config.get("cookies")
        timeout_hours = config.get("timeout_hours", 1)

        # Parse cookies from string to dict format
        cookies_dict = None
        if cookies_str:
            cookies_dict = {}
            for cookie in cookies_str.split(";"):
                if "=" in cookie:
                    key, value = cookie.strip().split("=", 1)
                    cookies_dict[key.strip()] = value.strip()

        # Shannon-specific config
        use_browser = config.get("browser_validation", True)
        use_source_analysis = config.get("source_analysis", False)  # White-box requires source
        parallel_agents = config.get("parallel_agents", 5)
        capture_screenshot = config.get("screenshot", True)

        # Broadcast scan started
        await self._broadcast_progress(str(scan.id), "scan_started", {
            "target_url": scan.target_url,
            "mode": "shannon",
            "phase": "initializing",
        })

        # Progress callback
        def on_progress(percent: int, message: str):
            self._update_scan_progress_sync(str(scan.id), "progress_update", {
                "phase": message,
                "progress": percent,
            })

        # Broadcast phase update
        await self._broadcast_progress(str(scan.id), "phase_update", {
            "phase": "shannon_exploitation",
            "message": f"Running Shannon proof-by-exploitation scan against {scan.target_url}",
        })

        # Use context manager pattern for ShannonEngine
        async with ShannonEngine(
            timeout_minutes=timeout_hours * 60,
            use_browser=use_browser,
            use_source_analysis=use_source_analysis,
            parallel_agents=parallel_agents,
            screenshot=capture_screenshot,
            evidence_dir=f"./evidence/{scan.id}",
        ) as engine:
            # Register progress callback
            engine.on_progress(on_progress)

            # Run the Shannon scan
            result = await engine.scan(
                target=scan.target_url,
                cookies=cookies_dict,
                progress_callback=on_progress,
            )

            # Broadcast saving findings phase
            await self._broadcast_progress(str(scan.id), "phase_update", {
                "phase": "saving_results",
                "message": f"Saving {len(result.findings)} validated findings...",
            })

            # Save Shannon findings (only exploited ones)
            await self._save_shannon_findings(scan, result)

            # Update scan stats
            await self._update_shannon_stats(scan, result)

            # Calculate exploitation rate
            total_tested = result.exploitation_attempts or 1
            exploitation_rate = (result.successful_exploits / total_tested) * 100

            # Broadcast completion
            await self._broadcast_progress(str(scan.id), "scan_completed", {
                "findings_count": scan.findings_count,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "exploitation_rate": f"{exploitation_rate:.1f}%",
            })

            # Notify if critical vulnerabilities found
            if integration_manager and target and result.findings:
                critical_count = len([f for f in result.findings if f.severity == "CRITICAL"])
                if critical_count > 0:
                    try:
                        await integration_manager.notify_breach_achieved(
                            target=target,
                            access_level="exploited",
                            systems_compromised=[scan.target_url],
                        )
                    except Exception as e:
                        logger.warning("breach_notify_failed", error=str(e))

    async def _save_shannon_findings(self, scan: Scan, result) -> None:
        """Save Shannon findings with exploitation proof data."""
        # Map severity strings (uppercase from ShannonFinding) to DB severity
        severity_map = {
            "CRITICAL": DBSeverity.CRITICAL,
            "HIGH": DBSeverity.HIGH,
            "MEDIUM": DBSeverity.MEDIUM,
            "LOW": DBSeverity.LOW,
            "INFO": DBSeverity.INFO,
            # Also support lowercase
            "critical": DBSeverity.CRITICAL,
            "high": DBSeverity.HIGH,
            "medium": DBSeverity.MEDIUM,
            "low": DBSeverity.LOW,
            "info": DBSeverity.INFO,
        }

        for finding_data in result.findings:
            # Get evidence and PoC data from ShannonFinding
            evidence_data = {}
            poc_script = None
            screenshot_path = None
            reproduction_steps = finding_data.reproduction_steps or []

            # Extract evidence from evidence_package
            if finding_data.evidence_package:
                evidence_items = finding_data.evidence_package.evidence_items or []
                for ev in evidence_items:
                    if ev.evidence_type == "screenshot":
                        screenshot_path = ev.file_path
                    evidence_data[ev.evidence_type] = {
                        "description": ev.description,
                        "proves": ev.proves,
                        "content_preview": str(ev.content)[:500] if ev.content else None,
                    }

            # Extract PoC data
            if finding_data.poc:
                poc_script = finding_data.poc.python_script or finding_data.poc.curl_command

            # Build title from vulnerability type
            title = f"{finding_data.vulnerability_type.upper()} Vulnerability in {finding_data.parameter or 'endpoint'}"

            # Build description
            description = (
                f"Successfully exploited {finding_data.vulnerability_type.upper()} vulnerability "
                f"at {finding_data.endpoint} using payload: {finding_data.payload[:100]}..."
            )

            finding = Finding(
                scan_id=scan.id,
                title=title,
                severity=severity_map.get(finding_data.severity, DBSeverity.MEDIUM),
                category=finding_data.vulnerability_type,
                endpoint=finding_data.endpoint,
                method="GET",  # Default, ShannonFinding doesn't track method
                parameter=finding_data.parameter,
                description=description,
                evidence=evidence_data,
                business_impact=float(finding_data.business_impact or 0),
                impact_explanation=finding_data.impact_explanation,
                records_exposed=0,  # Not tracked by ShannonFinding
                pii_fields=[],  # Not tracked by ShannonFinding
                fix_suggestion=finding_data.remediation,
                curl_command=finding_data.curl_command,
                # Shannon-specific fields
                is_exploited=True,  # Shannon only reports exploited findings
                exploitation_proof=finding_data.proof_data,
                exploitation_proof_type=finding_data.proof_type,
                exploitation_confidence=finding_data.confidence,
                screenshot_path=screenshot_path,
                reproduction_steps=reproduction_steps,
                poc_script=poc_script,
                # Source analysis fields (from data_flow if present)
                data_flow_source=finding_data.data_flow.source if finding_data.data_flow else None,
                data_flow_sink=finding_data.data_flow.sink if finding_data.data_flow else None,
                source_file=finding_data.data_flow.file_path if finding_data.data_flow else None,
                source_line=finding_data.data_flow.line_number if finding_data.data_flow else None,
            )
            self.db.add(finding)

    async def _update_shannon_stats(self, scan: Scan, result) -> None:
        """Update scan statistics from Shannon results."""
        findings = result.findings
        scan.findings_count = len(findings)
        # ShannonFinding uses uppercase severity values
        scan.critical_count = len([f for f in findings if f.severity in ("CRITICAL", "critical")])
        scan.high_count = len([f for f in findings if f.severity in ("HIGH", "high")])
        scan.medium_count = len([f for f in findings if f.severity in ("MEDIUM", "medium")])
        scan.low_count = len([f for f in findings if f.severity in ("LOW", "low")])
        scan.info_count = len([f for f in findings if f.severity in ("INFO", "info")])
        scan.total_business_impact = sum(f.business_impact or 0 for f in findings)

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
                finding.resolved_at = datetime.utcnow()
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

        # Running scans
        running_scans = await self.db.execute(
            select(func.count(Scan.id))
            .where(
                Scan.organization_id == organization_id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
            )
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
            "running_scans": running_scans.scalar() or 0,
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
        """Create a scan target.

        SECURITY: Validates the target domain against blocked patterns.
        """
        import secrets

        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            raise ValueError("Invalid URL: no domain found")

        # Remove port if present for validation
        validation_domain = domain.split(":")[0] if ":" in domain else domain

        # Get organization to check subscription tier
        org = await self._get_organization(organization_id)
        tier = org.subscription_tier.value if org else "free"

        # SECURITY: Check if domain is blocked or restricted
        is_valid, error_message = validate_scan_target(validation_domain, tier)
        if not is_valid:
            logger.warning(
                "target_creation_blocked",
                organization_id=str(organization_id),
                domain=validation_domain,
                reason=error_message,
            )
            raise ValueError(error_message)

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

        logger.info(
            "target_created",
            target_id=str(target.id),
            organization_id=str(organization_id),
            domain=validation_domain,
        )

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

    async def verify_target(
        self, target_id: UUID, organization_id: UUID, method: str
    ) -> Tuple[bool, str]:
        """Verify target ownership via DNS, file, or meta tag.

        Returns:
            Tuple[bool, str]: (success, message)
        """
        result = await self.db.execute(
            select(Target).where(
                Target.id == target_id,
                Target.organization_id == organization_id,
            )
        )
        target = result.scalar_one_or_none()

        if not target:
            return False, "Target not found"

        if not target.verification_token:
            return False, "No verification token found. Please recreate the target."

        # Extract domain from target URL
        parsed = urlparse(target.url)
        domain = parsed.netloc
        if not domain:
            return False, "Invalid target URL"

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        logger.info(
            "verifying_target",
            target_id=str(target_id),
            domain=domain,
            method=method,
        )

        # Perform verification based on method
        try:
            if method == "dns":
                success, message = await self._verify_dns(domain, target.verification_token)
            elif method == "file":
                success, message = await self._verify_file(target.url, target.verification_token)
            elif method == "meta":
                success, message = await self._verify_meta(target.url, target.verification_token)
            else:
                return False, f"Unknown verification method: {method}"

            if success:
                target.is_verified = True
                target.verification_method = method
                target.verified_at = datetime.utcnow()
                await self.db.commit()

                logger.info(
                    "target_verified",
                    target_id=str(target_id),
                    domain=domain,
                    method=method,
                )

            return success, message

        except Exception as e:
            logger.error(
                "verification_failed",
                target_id=str(target_id),
                method=method,
                error=str(e),
            )
            return False, f"Verification error: {str(e)}"

    async def _verify_dns(self, domain: str, token: str) -> Tuple[bool, str]:
        """Verify ownership via DNS TXT record.

        Expected record: _breach-verify.{domain} TXT {token}
        """
        if not DNS_AVAILABLE:
            return False, "DNS verification not available. Please install dnspython or use file/meta verification."

        verification_domain = f"_breach-verify.{domain}"

        try:
            answers = dns.resolver.resolve(verification_domain, "TXT")
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_value = txt_string.decode("utf-8").strip()
                    if txt_value == token:
                        return True, "DNS verification successful"

            return False, f"Token not found in TXT record for {verification_domain}"

        except dns.resolver.NXDOMAIN:
            return False, f"DNS record not found: {verification_domain}. Please add a TXT record."
        except dns.resolver.NoAnswer:
            return False, f"No TXT record found for {verification_domain}"
        except dns.resolver.Timeout:
            return False, "DNS lookup timed out. Please try again."
        except Exception as e:
            return False, f"DNS lookup error: {str(e)}"

    async def _verify_file(self, base_url: str, token: str) -> Tuple[bool, str]:
        """Verify ownership via file at /.well-known/breach-verify.txt"""
        # Ensure base URL doesn't have trailing slash
        base_url = base_url.rstrip("/")
        verification_url = f"{base_url}/.well-known/breach-verify.txt"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(verification_url)

                if response.status_code == 404:
                    return False, (
                        f"Verification file not found at {verification_url}. "
                        f"Please create the file with content: {token}"
                    )

                if response.status_code != 200:
                    return False, f"Failed to fetch verification file: HTTP {response.status_code}"

                content = response.text.strip()

                if content == token:
                    return True, "File verification successful"

                return False, (
                    f"Token mismatch. Expected: {token[:8]}... "
                    f"Found: {content[:20]}..."
                )

        except httpx.TimeoutException:
            return False, "Request timed out. Please ensure the server is accessible."
        except httpx.RequestError as e:
            return False, f"Request failed: {str(e)}"

    async def _verify_meta(self, base_url: str, token: str) -> Tuple[bool, str]:
        """Verify ownership via meta tag in HTML.

        Expected: <meta name="breach-site-verification" content="{token}">
        """
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(base_url)

                if response.status_code != 200:
                    return False, f"Failed to fetch page: HTTP {response.status_code}"

                html = response.text

                # Look for the meta tag
                # Pattern: <meta name="breach-site-verification" content="TOKEN">
                pattern = r'<meta\s+name=["\']breach-site-verification["\']\s+content=["\']([^"\']+)["\']'
                match = re.search(pattern, html, re.IGNORECASE)

                if not match:
                    # Try alternate attribute order
                    pattern = r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']breach-site-verification["\']'
                    match = re.search(pattern, html, re.IGNORECASE)

                if not match:
                    return False, (
                        'Meta tag not found. Please add to your <head>: '
                        f'<meta name="breach-site-verification" content="{token}">'
                    )

                found_token = match.group(1).strip()

                if found_token == token:
                    return True, "Meta tag verification successful"

                return False, f"Token mismatch in meta tag. Expected: {token[:8]}..."

        except httpx.TimeoutException:
            return False, "Request timed out. Please ensure the server is accessible."
        except httpx.RequestError as e:
            return False, f"Request failed: {str(e)}"

    def get_verification_instructions(self, target: Target) -> dict:
        """Get verification instructions for a target."""
        parsed = urlparse(target.url)
        domain = parsed.netloc
        if ":" in domain:
            domain = domain.split(":")[0]

        token = target.verification_token

        return {
            "dns": {
                "record_type": "TXT",
                "record_name": f"_breach-verify.{domain}",
                "record_value": token,
                "instructions": (
                    f"Add a TXT record to your DNS:\n"
                    f"  Name: _breach-verify.{domain}\n"
                    f"  Type: TXT\n"
                    f"  Value: {token}"
                ),
            },
            "file": {
                "file_path": "/.well-known/breach-verify.txt",
                "file_content": token,
                "full_url": f"{target.url.rstrip('/')}/.well-known/breach-verify.txt",
                "instructions": (
                    f"Create a file at /.well-known/breach-verify.txt with content:\n"
                    f"  {token}"
                ),
            },
            "meta": {
                "tag": f'<meta name="breach-site-verification" content="{token}">',
                "instructions": (
                    f'Add this meta tag to your homepage <head>:\n'
                    f'  <meta name="breach-site-verification" content="{token}">'
                ),
            },
        }

    # ============== HELPERS ==============

    async def _get_organization(self, organization_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        result = await self.db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        return result.scalar_one_or_none()
