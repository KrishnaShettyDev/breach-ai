"""
BREACH.AI - Scheduler Integration Tests
========================================
Test scheduled scan functionality.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import (
    User, Organization, Target, ScheduledScan, ScanMode
)
from backend.services.scheduler import SchedulerService


class TestSchedulerService:
    """Test scheduler service operations."""

    @pytest.mark.asyncio
    async def test_create_schedule(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test creating a scheduled scan."""
        user, org = test_member

        # Create a target first
        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
            is_verified=True,
        )
        db_session.add(target)
        await db_session.commit()

        scheduler = SchedulerService(db_session)

        schedule = await scheduler.create_schedule(
            organization_id=org.id,
            target_id=target.id,
            name="Daily Scan",
            cron_expression="0 2 * * *",  # Daily at 2 AM
            mode="normal",
        )

        assert schedule is not None
        assert schedule.name == "Daily Scan"
        assert schedule.cron_expression == "0 2 * * *"
        assert schedule.is_active is True
        assert schedule.next_run_at is not None

    @pytest.mark.asyncio
    async def test_create_schedule_invalid_cron(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test creating schedule with invalid cron expression."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
            is_verified=True,
        )
        db_session.add(target)
        await db_session.commit()

        scheduler = SchedulerService(db_session)

        with pytest.raises(ValueError, match="Invalid cron expression"):
            await scheduler.create_schedule(
                organization_id=org.id,
                target_id=target.id,
                name="Bad Schedule",
                cron_expression="invalid cron",
            )

    @pytest.mark.asyncio
    async def test_create_schedule_unverified_target(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test creating schedule for unverified target fails."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Unverified Target",
            is_verified=False,  # Not verified
        )
        db_session.add(target)
        await db_session.commit()

        scheduler = SchedulerService(db_session)

        with pytest.raises(ValueError, match="Target must be verified"):
            await scheduler.create_schedule(
                organization_id=org.id,
                target_id=target.id,
                name="Daily Scan",
                cron_expression="0 2 * * *",
            )

    @pytest.mark.asyncio
    async def test_toggle_schedule(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test enabling/disabling a schedule."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
            is_verified=True,
        )
        db_session.add(target)
        await db_session.commit()

        scheduler = SchedulerService(db_session)

        schedule = await scheduler.create_schedule(
            organization_id=org.id,
            target_id=target.id,
            name="Test Schedule",
            cron_expression="0 2 * * *",
        )

        # Disable
        disabled = await scheduler.toggle_schedule(
            schedule.id, org.id, is_active=False
        )
        assert disabled.is_active is False

        # Enable
        enabled = await scheduler.toggle_schedule(
            schedule.id, org.id, is_active=True
        )
        assert enabled.is_active is True
        assert enabled.next_run_at is not None

    @pytest.mark.asyncio
    async def test_get_due_schedules(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test finding schedules that are due to run."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
            is_verified=True,
        )
        db_session.add(target)

        # Create a schedule that's due (next_run_at in the past)
        due_schedule = ScheduledScan(
            organization_id=org.id,
            target_id=target.id,
            name="Due Schedule",
            cron_expression="0 * * * *",
            mode=ScanMode.NORMAL,
            is_active=True,
            next_run_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(due_schedule)

        # Create a schedule that's not due yet
        future_schedule = ScheduledScan(
            organization_id=org.id,
            target_id=target.id,
            name="Future Schedule",
            cron_expression="0 * * * *",
            mode=ScanMode.NORMAL,
            is_active=True,
            next_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db_session.add(future_schedule)

        await db_session.commit()

        scheduler = SchedulerService(db_session)
        due = await scheduler.get_due_schedules()

        assert len(due) == 1
        assert due[0].name == "Due Schedule"


class TestScheduleAPI:
    """Test schedule API endpoints."""

    @pytest.mark.asyncio
    async def test_get_presets(self, authenticated_client: AsyncClient):
        """Test getting schedule presets."""
        response = await authenticated_client.get("/api/v1/schedules/presets")
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0
        assert all("name" in preset for preset in data)
        assert all("cron_expression" in preset for preset in data)

    @pytest.mark.asyncio
    async def test_list_schedules_empty(self, authenticated_client: AsyncClient):
        """Test listing schedules when none exist."""
        response = await authenticated_client.get("/api/v1/schedules")
        assert response.status_code == 200
        data = response.json()
        assert data == []
