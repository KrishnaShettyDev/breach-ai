"""
BREACH.AI - Scheduled Scans API Routes
======================================

API endpoints for managing continuous/scheduled security testing.
MindFort-style "always-on" scanning.
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.db.models import User, Organization, ScanMode
from backend.api.deps import get_current_user, require_member
from backend.services.scheduler import SchedulerService

router = APIRouter(prefix="/schedules", tags=["Scheduled Scans"])


# ============== Request/Response Models ==============

class ScheduleCreate(BaseModel):
    """Create a scheduled scan."""
    target_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    cron_expression: str = Field(
        ...,
        description="Cron expression (e.g., '0 2 * * *' for daily at 2am)",
        examples=["0 2 * * *", "0 */4 * * *", "0 2 * * 0"]
    )
    mode: str = Field(default="normal", description="Scan mode: quick, normal, deep, chainbreaker")
    timezone: str = Field(default="UTC")
    config: dict = Field(default={})


class ScheduleUpdate(BaseModel):
    """Update a scheduled scan."""
    name: Optional[str] = None
    cron_expression: Optional[str] = None
    mode: Optional[str] = None
    timezone: Optional[str] = None
    config: Optional[dict] = None
    is_active: Optional[bool] = None


class ScheduleResponse(BaseModel):
    """Scheduled scan response."""
    id: UUID
    organization_id: UUID
    target_id: UUID
    name: str
    cron_expression: str
    timezone: str
    mode: str
    config: dict
    is_active: bool
    last_run_at: Optional[str]
    next_run_at: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class SchedulePreset(BaseModel):
    """Preset schedule configuration."""
    name: str
    description: str
    cron_expression: str


# ============== Preset Schedules ==============

SCHEDULE_PRESETS = [
    SchedulePreset(
        name="Daily",
        description="Run every day at 2:00 AM UTC",
        cron_expression="0 2 * * *"
    ),
    SchedulePreset(
        name="Every 4 Hours",
        description="Run every 4 hours",
        cron_expression="0 */4 * * *"
    ),
    SchedulePreset(
        name="Every 12 Hours",
        description="Run twice daily at 2 AM and 2 PM UTC",
        cron_expression="0 2,14 * * *"
    ),
    SchedulePreset(
        name="Weekly",
        description="Run every Sunday at 2:00 AM UTC",
        cron_expression="0 2 * * 0"
    ),
    SchedulePreset(
        name="Monthly",
        description="Run on the 1st of every month at 2:00 AM UTC",
        cron_expression="0 2 1 * *"
    ),
    SchedulePreset(
        name="Continuous (Hourly)",
        description="Run every hour for maximum coverage",
        cron_expression="0 * * * *"
    ),
]


# ============== Endpoints ==============

@router.get("/presets", response_model=List[SchedulePreset])
async def get_schedule_presets():
    """
    Get available schedule presets.

    Returns common scheduling patterns that users can choose from.
    """
    return SCHEDULE_PRESETS


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    data: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Create a new scheduled scan.

    This enables continuous security testing for a target.
    Scans will run automatically based on the cron expression.

    **Cron Expression Examples:**
    - `0 2 * * *` - Daily at 2:00 AM
    - `0 */4 * * *` - Every 4 hours
    - `0 2 * * 0` - Weekly on Sunday at 2:00 AM
    - `0 * * * *` - Every hour (continuous)
    """
    user, org = current
    scheduler = SchedulerService(db)

    try:
        schedule = await scheduler.create_schedule(
            organization_id=org.id,
            target_id=data.target_id,
            name=data.name,
            cron_expression=data.cron_expression,
            mode=data.mode,
            config=data.config,
            timezone=data.timezone,
        )
        return _to_response(schedule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("", response_model=List[ScheduleResponse])
async def list_schedules(
    active_only: bool = Query(False, description="Only return active schedules"),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    List all scheduled scans for the organization.
    """
    user, org = current
    scheduler = SchedulerService(db)

    schedules = await scheduler.list_schedules(org.id, active_only=active_only)
    return [_to_response(s) for s in schedules]


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get a specific scheduled scan.
    """
    user, org = current
    scheduler = SchedulerService(db)

    schedule = await scheduler.get_schedule(schedule_id, org.id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found"
        )

    return _to_response(schedule)


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    data: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Update a scheduled scan.
    """
    user, org = current
    scheduler = SchedulerService(db)

    try:
        schedule = await scheduler.update_schedule(
            schedule_id=schedule_id,
            organization_id=org.id,
            **data.model_dump(exclude_none=True)
        )

        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Schedule not found"
            )

        return _to_response(schedule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Delete a scheduled scan.
    """
    user, org = current
    scheduler = SchedulerService(db)

    success = await scheduler.delete_schedule(schedule_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found"
        )


@router.post("/{schedule_id}/enable", response_model=ScheduleResponse)
async def enable_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Enable a scheduled scan.
    """
    user, org = current
    scheduler = SchedulerService(db)

    schedule = await scheduler.toggle_schedule(schedule_id, org.id, is_active=True)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found"
        )

    return _to_response(schedule)


@router.post("/{schedule_id}/disable", response_model=ScheduleResponse)
async def disable_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Disable a scheduled scan.
    """
    user, org = current
    scheduler = SchedulerService(db)

    schedule = await scheduler.toggle_schedule(schedule_id, org.id, is_active=False)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found"
        )

    return _to_response(schedule)


@router.post("/{schedule_id}/run-now", response_model=dict)
async def run_schedule_now(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_member),
):
    """
    Trigger a scheduled scan immediately.

    This runs the scan now without waiting for the next scheduled time.
    """
    user, org = current
    scheduler = SchedulerService(db)

    schedule = await scheduler.get_schedule(schedule_id, org.id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found"
        )

    scan = await scheduler.execute_schedule(schedule)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger scan"
        )

    return {
        "message": "Scan triggered successfully",
        "scan_id": str(scan.id),
        "next_scheduled_run": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
    }


# ============== Helpers ==============

def _to_response(schedule) -> ScheduleResponse:
    """Convert model to response."""
    return ScheduleResponse(
        id=schedule.id,
        organization_id=schedule.organization_id,
        target_id=schedule.target_id,
        name=schedule.name,
        cron_expression=schedule.cron_expression,
        timezone=schedule.timezone,
        mode=schedule.mode.value if schedule.mode else "normal",
        config=schedule.config or {},
        is_active=schedule.is_active,
        last_run_at=schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        next_run_at=schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        created_at=schedule.created_at.isoformat() if schedule.created_at else "",
        updated_at=schedule.updated_at.isoformat() if schedule.updated_at else "",
    )
