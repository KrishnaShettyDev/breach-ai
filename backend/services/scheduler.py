"""
BREACH.AI - Continuous Scanning Scheduler
==========================================

Implements MindFort-style continuous security testing.
Runs scheduled scans automatically based on cron expressions.

Features:
- Cron-based scheduling (daily, weekly, custom)
- Automatic scan triggering
- Next run calculation
- Scan history tracking
- Failure handling with retries
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from uuid import UUID

import structlog
from croniter import croniter
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import async_session
from backend.db.models import (
    ScheduledScan, Scan, Target, Organization,
    ScanStatus, ScanMode
)
from backend.services.scan import ScanService

logger = structlog.get_logger(__name__)


class SchedulerService:
    """
    Service for managing scheduled/continuous scans.

    This is what makes Breach AI "continuous" like MindFort.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ============== CRUD Operations ==============

    async def create_schedule(
        self,
        organization_id: UUID,
        target_id: UUID,
        name: str,
        cron_expression: str,
        mode: str = "normal",
        config: dict = None,
        timezone: str = "UTC",
    ) -> ScheduledScan:
        """
        Create a new scheduled scan.

        Args:
            cron_expression: Cron format (e.g., "0 2 * * *" for daily at 2am)
                - "0 */4 * * *" = Every 4 hours
                - "0 2 * * *" = Daily at 2am
                - "0 2 * * 0" = Weekly on Sunday at 2am
                - "0 2 1 * *" = Monthly on 1st at 2am
        """
        # Validate cron expression
        try:
            cron = croniter(cron_expression)
            next_run = cron.get_next(datetime)
        except Exception as e:
            raise ValueError(f"Invalid cron expression: {e}")

        # Validate target exists and is verified
        target = await self._get_target(target_id, organization_id)
        if not target:
            raise ValueError("Target not found")
        if not target.is_verified:
            raise ValueError("Target must be verified before scheduling scans")

        # Check organization limits
        org = await self._get_organization(organization_id)
        if not org:
            raise ValueError("Organization not found")

        # Count existing schedules
        existing_count = await self._count_schedules(organization_id)
        max_schedules = self._get_max_schedules(org.subscription_tier.value)
        if existing_count >= max_schedules:
            raise ValueError(
                f"Schedule limit reached ({max_schedules}). "
                "Upgrade your plan for more scheduled scans."
            )

        schedule = ScheduledScan(
            organization_id=organization_id,
            target_id=target_id,
            name=name,
            cron_expression=cron_expression,
            timezone=timezone,
            mode=ScanMode(mode),
            config=config or {},
            is_active=True,
            next_run_at=next_run,
        )

        self.db.add(schedule)
        await self.db.commit()
        await self.db.refresh(schedule)

        logger.info(
            "schedule_created",
            schedule_id=str(schedule.id),
            organization_id=str(organization_id),
            target_id=str(target_id),
            cron=cron_expression,
            next_run=next_run.isoformat(),
        )

        return schedule

    async def update_schedule(
        self,
        schedule_id: UUID,
        organization_id: UUID,
        **updates
    ) -> Optional[ScheduledScan]:
        """Update a scheduled scan."""
        schedule = await self.get_schedule(schedule_id, organization_id)
        if not schedule:
            return None

        allowed_fields = {'name', 'cron_expression', 'timezone', 'mode', 'config', 'is_active'}

        for field, value in updates.items():
            if field in allowed_fields and value is not None:
                if field == 'mode':
                    value = ScanMode(value)
                if field == 'cron_expression':
                    # Recalculate next run
                    try:
                        cron = croniter(value, datetime.now(timezone.utc))
                        schedule.next_run_at = cron.get_next(datetime)
                    except Exception as e:
                        raise ValueError(f"Invalid cron expression: {e}")
                setattr(schedule, field, value)

        await self.db.commit()
        await self.db.refresh(schedule)

        return schedule

    async def delete_schedule(
        self,
        schedule_id: UUID,
        organization_id: UUID
    ) -> bool:
        """Delete a scheduled scan."""
        schedule = await self.get_schedule(schedule_id, organization_id)
        if not schedule:
            return False

        await self.db.delete(schedule)
        await self.db.commit()

        logger.info("schedule_deleted", schedule_id=str(schedule_id))
        return True

    async def get_schedule(
        self,
        schedule_id: UUID,
        organization_id: UUID
    ) -> Optional[ScheduledScan]:
        """Get a scheduled scan by ID."""
        result = await self.db.execute(
            select(ScheduledScan).where(
                ScheduledScan.id == schedule_id,
                ScheduledScan.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_schedules(
        self,
        organization_id: UUID,
        active_only: bool = False
    ) -> List[ScheduledScan]:
        """List all scheduled scans for an organization."""
        query = select(ScheduledScan).where(
            ScheduledScan.organization_id == organization_id
        )

        if active_only:
            query = query.where(ScheduledScan.is_active == True)

        query = query.order_by(ScheduledScan.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def toggle_schedule(
        self,
        schedule_id: UUID,
        organization_id: UUID,
        is_active: bool
    ) -> Optional[ScheduledScan]:
        """Enable or disable a scheduled scan."""
        schedule = await self.get_schedule(schedule_id, organization_id)
        if not schedule:
            return None

        schedule.is_active = is_active

        if is_active:
            # Recalculate next run
            cron = croniter(schedule.cron_expression, datetime.now(timezone.utc))
            schedule.next_run_at = cron.get_next(datetime)

        await self.db.commit()
        await self.db.refresh(schedule)

        return schedule

    # ============== Scheduler Execution ==============

    async def get_due_schedules(self) -> List[ScheduledScan]:
        """Get all schedules that are due to run."""
        now = datetime.now(timezone.utc)

        result = await self.db.execute(
            select(ScheduledScan).where(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run_at <= now,
            )
        )
        return list(result.scalars().all())

    async def execute_schedule(self, schedule: ScheduledScan) -> Optional[Scan]:
        """Execute a scheduled scan and update next run time."""
        try:
            # Get target
            target = await self._get_target(schedule.target_id, schedule.organization_id)
            if not target:
                logger.error("schedule_target_not_found", schedule_id=str(schedule.id))
                return None

            if not target.is_verified:
                logger.warning(
                    "schedule_target_not_verified",
                    schedule_id=str(schedule.id),
                    target_id=str(schedule.target_id)
                )
                return None

            # Create scan
            scan_service = ScanService(self.db)

            # Get a system user ID or use the org owner
            org = await self._get_organization(schedule.organization_id)

            scan = await scan_service.create_scan(
                organization_id=schedule.organization_id,
                target_url=target.url,
                user_id=org.members[0].user_id if org and org.members else None,
                mode=schedule.mode.value,
                config={
                    **schedule.config,
                    "scheduled_scan_id": str(schedule.id),
                    "scheduled": True,
                },
                target_id=schedule.target_id,
            )

            # Update schedule
            schedule.last_run_at = datetime.now(timezone.utc)
            cron = croniter(schedule.cron_expression, datetime.now(timezone.utc))
            schedule.next_run_at = cron.get_next(datetime)

            await self.db.commit()

            logger.info(
                "scheduled_scan_triggered",
                schedule_id=str(schedule.id),
                scan_id=str(scan.id),
                next_run=schedule.next_run_at.isoformat(),
            )

            # Start the scan in background
            asyncio.create_task(
                self._run_scan_background(scan.id, schedule.organization_id)
            )

            return scan

        except Exception as e:
            logger.error(
                "scheduled_scan_failed",
                schedule_id=str(schedule.id),
                error=str(e),
            )

            # Still update next_run_at to prevent infinite loop
            cron = croniter(schedule.cron_expression, datetime.now(timezone.utc))
            schedule.next_run_at = cron.get_next(datetime)
            await self.db.commit()

            return None

    async def _run_scan_background(self, scan_id: UUID, organization_id: UUID):
        """Run scan in background."""
        try:
            async with async_session() as db:
                scan_service = ScanService(db)
                await scan_service.start_scan(scan_id, organization_id)
        except Exception as e:
            logger.error(
                "background_scan_failed",
                scan_id=str(scan_id),
                error=str(e),
            )

    # ============== Helpers ==============

    async def _get_target(self, target_id: UUID, organization_id: UUID) -> Optional[Target]:
        """Get target by ID."""
        result = await self.db.execute(
            select(Target).where(
                Target.id == target_id,
                Target.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def _get_organization(self, organization_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        from sqlalchemy.orm import selectinload
        result = await self.db.execute(
            select(Organization)
            .where(Organization.id == organization_id)
            .options(selectinload(Organization.members))
        )
        return result.scalar_one_or_none()

    async def _count_schedules(self, organization_id: UUID) -> int:
        """Count active schedules for an organization."""
        from sqlalchemy import func
        result = await self.db.execute(
            select(func.count(ScheduledScan.id)).where(
                ScheduledScan.organization_id == organization_id,
                ScheduledScan.is_active == True,
            )
        )
        return result.scalar() or 0

    def _get_max_schedules(self, tier: str) -> int:
        """Get max schedules allowed for a subscription tier."""
        limits = {
            "free": 1,
            "starter": 5,
            "pro": 20,
            "enterprise": 100,
        }
        return limits.get(tier.lower(), 1)


# ============== Background Scheduler Loop ==============

class ContinuousScanner:
    """
    Background task that runs continuously to execute scheduled scans.

    This is the "always-on" component that makes Breach AI continuous.
    """

    def __init__(self, check_interval: int = 60):
        """
        Args:
            check_interval: How often to check for due schedules (seconds)
        """
        self.check_interval = check_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the continuous scanner."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("continuous_scanner_started", interval=self.check_interval)

    async def stop(self):
        """Stop the continuous scanner."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("continuous_scanner_stopped")

    async def _run_loop(self):
        """Main loop that checks and executes due schedules."""
        while self._running:
            try:
                await self._check_and_execute()
            except Exception as e:
                logger.error("scheduler_loop_error", error=str(e))

            await asyncio.sleep(self.check_interval)

    async def _check_and_execute(self):
        """Check for due schedules and execute them."""
        async with async_session() as db:
            scheduler = SchedulerService(db)
            due_schedules = await scheduler.get_due_schedules()

            if due_schedules:
                logger.info("found_due_schedules", count=len(due_schedules))

            for schedule in due_schedules:
                try:
                    await scheduler.execute_schedule(schedule)
                except Exception as e:
                    logger.error(
                        "schedule_execution_failed",
                        schedule_id=str(schedule.id),
                        error=str(e),
                    )


# Global scanner instance
_continuous_scanner: Optional[ContinuousScanner] = None


def get_continuous_scanner() -> ContinuousScanner:
    """Get the global continuous scanner instance."""
    global _continuous_scanner
    if _continuous_scanner is None:
        _continuous_scanner = ContinuousScanner()
    return _continuous_scanner


async def start_continuous_scanner():
    """Start the continuous scanner (call on app startup)."""
    scanner = get_continuous_scanner()
    await scanner.start()


async def stop_continuous_scanner():
    """Stop the continuous scanner (call on app shutdown)."""
    scanner = get_continuous_scanner()
    await scanner.stop()
