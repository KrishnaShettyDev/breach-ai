"""
BREACH.AI - Scan Routes
========================
Scan management endpoints with rate limiting.
"""

from typing import Optional, List
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.database import get_db
from backend.services.scan import ScanService
from backend.schemas.scans import (
    ScanCreate, ScanResponse, ScanListResponse, ScanDetailResponse,
    FindingResponse, FindingUpdate, ScanStats,
    TargetCreate, TargetResponse,
)
from backend.api.deps import get_current_user, require_member

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])

# Get limiter from app state
limiter = Limiter(key_func=get_remote_address)


# ============== SCANS ==============

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_scans)
async def create_scan(
    request: Request,
    data: ScanCreate,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Create and start a new scan."""
    user, org = current
    scan_service = ScanService(db)

    try:
        scan = await scan_service.create_scan(
            organization_id=org.id,
            target_url=str(data.target_url),
            user_id=user.id,
            mode=data.mode.value,
            config=data.config,
            target_id=data.target_id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Try to use ARQ job queue, fall back to direct execution
    try:
        from backend.worker import enqueue_scan
        job_id = await enqueue_scan(scan.id, org.id)
        logger.info("scan_enqueued", scan_id=str(scan.id), job_id=job_id)
    except Exception as e:
        # Fall back to background task if ARQ is not available
        logger.warning("arq_unavailable_falling_back", error=str(e))
        import asyncio
        asyncio.create_task(run_scan_background(scan.id, org.id))

    return scan


async def run_scan_background(scan_id: UUID, organization_id: UUID):
    """Run scan in background (fallback when ARQ is unavailable)."""
    from backend.db.database import async_session

    logger.info("scan_background_start", scan_id=str(scan_id))

    try:
        async with async_session() as db:
            scan_service = ScanService(db)
            await scan_service.start_scan(scan_id, organization_id)
    except Exception as e:
        logger.error(
            "scan_background_failed",
            scan_id=str(scan_id),
            error=str(e),
            exc_info=True
        )
        # Update scan status to failed
        try:
            async with async_session() as db:
                from sqlalchemy import update
                from backend.db.models import Scan, ScanStatus
                await db.execute(
                    update(Scan)
                    .where(Scan.id == scan_id)
                    .values(status=ScanStatus.FAILED, error_message=str(e))
                )
                await db.commit()
        except Exception as update_error:
            logger.error("scan_status_update_failed", error=str(update_error))


@router.get("", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    page: int = 1,
    per_page: int = 20,
    scan_status: Optional[str] = None,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scans for the organization."""
    user, org = current
    scan_service = ScanService(db)

    # Enforce pagination limits
    page = max(1, min(page, 1000))
    per_page = max(1, min(per_page, 100))

    result = await scan_service.list_scans(
        organization_id=org.id,
        page=page,
        per_page=per_page,
        status=scan_status,
    )

    return ScanListResponse(**result)


@router.get("/stats", response_model=ScanStats)
async def get_stats(
    request: Request,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan statistics for the organization."""
    user, org = current
    scan_service = ScanService(db)

    return await scan_service.get_stats(org.id)


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    request: Request,
    scan_id: UUID,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan details with findings."""
    user, org = current
    scan_service = ScanService(db)

    scan = await scan_service.get_scan_with_findings(scan_id, org.id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    request: Request,
    scan_id: UUID,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    user, org = current
    scan_service = ScanService(db)

    try:
        success = await scan_service.cancel_scan(scan_id, org.id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    scan = await scan_service.get_scan(scan_id, org.id)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    request: Request,
    scan_id: UUID,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan."""
    user, org = current
    scan_service = ScanService(db)

    success = await scan_service.delete_scan(scan_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )


# ============== FINDINGS ==============

@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    request: Request,
    scan_id: UUID,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a specific scan."""
    user, org = current
    scan_service = ScanService(db)

    # Enforce pagination limits
    page = max(1, min(page, 1000))
    per_page = max(1, min(per_page, 100))

    result = await scan_service.list_findings(
        organization_id=org.id,
        scan_id=scan_id,
        severity=severity,
        category=category,
        page=page,
        per_page=per_page,
    )

    return result["items"]


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    request: Request,
    finding_id: UUID,
    data: FindingUpdate,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Update finding status (mark as false positive or resolved)."""
    user, org = current
    scan_service = ScanService(db)

    finding = await scan_service.update_finding(
        finding_id=finding_id,
        organization_id=org.id,
        is_false_positive=data.is_false_positive,
        is_resolved=data.is_resolved,
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return finding


# ============== TARGETS ==============

targets_router = APIRouter(prefix="/targets", tags=["Targets"])


@targets_router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    request: Request,
    data: TargetCreate,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan target."""
    user, org = current
    scan_service = ScanService(db)

    target = await scan_service.create_target(
        organization_id=org.id,
        url=str(data.url),
        name=data.name,
        description=data.description,
    )

    return target


@targets_router.get("", response_model=List[TargetResponse])
async def list_targets(
    request: Request,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all targets for the organization."""
    user, org = current
    scan_service = ScanService(db)

    return await scan_service.list_targets(org.id)


@targets_router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    request: Request,
    target_id: UUID,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Delete a target."""
    user, org = current
    scan_service = ScanService(db)

    success = await scan_service.delete_target(target_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )


@targets_router.post("/{target_id}/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_target(
    request: Request,
    target_id: UUID,
    method: str = "dns",
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Verify target ownership."""
    user, org = current
    scan_service = ScanService(db)

    success = await scan_service.verify_target(target_id, org.id, method)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )
