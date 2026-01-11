"""
BREACH.AI - ARQ Worker
=======================
Background job queue worker for scan execution.

Usage:
    arq backend.worker.WorkerSettings
"""

import asyncio
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from arq import create_pool
from arq.connections import RedisSettings, ArqRedis

from backend.config import settings
from backend.db.database import async_session

logger = structlog.get_logger(__name__)


async def run_scan_job(ctx: dict, scan_id: str, organization_id: str) -> dict:
    """
    Execute a scan as a background job.

    Args:
        ctx: ARQ context with Redis connection
        scan_id: UUID of the scan to run
        organization_id: UUID of the organization

    Returns:
        dict with job result
    """
    logger.info(
        "scan_job_started",
        scan_id=scan_id,
        organization_id=organization_id,
        job_id=ctx.get("job_id")
    )

    try:
        from backend.services.scan import ScanService

        async with async_session() as db:
            service = ScanService(db)

            # Run the scan with timeout
            scan = await asyncio.wait_for(
                service.start_scan(
                    scan_id=UUID(scan_id),
                    organization_id=UUID(organization_id)
                ),
                timeout=settings.scan_timeout_seconds + 60  # Extra buffer for cleanup
            )

            result = {
                "success": scan.status.value == "completed",
                "scan_id": str(scan.id),
                "status": scan.status.value,
                "findings_count": scan.findings_count,
                "duration_seconds": scan.duration_seconds,
                "error_message": scan.error_message,
            }

            logger.info(
                "scan_job_completed",
                scan_id=scan_id,
                status=scan.status.value,
                findings_count=scan.findings_count
            )

            return result

    except asyncio.TimeoutError:
        logger.error(
            "scan_job_timeout",
            scan_id=scan_id,
            timeout_seconds=settings.scan_timeout_seconds + 60
        )
        return {
            "success": False,
            "scan_id": scan_id,
            "status": "failed",
            "error_message": "Job timed out"
        }

    except Exception as e:
        logger.error(
            "scan_job_failed",
            scan_id=scan_id,
            error=str(e),
            exc_info=True
        )
        return {
            "success": False,
            "scan_id": scan_id,
            "status": "failed",
            "error_message": str(e)
        }


async def startup(ctx: dict) -> None:
    """Worker startup hook."""
    logger.info("arq_worker_started", max_jobs=settings.max_concurrent_scans)


async def shutdown(ctx: dict) -> None:
    """Worker shutdown hook."""
    logger.info("arq_worker_shutdown")


async def on_job_start(ctx: dict) -> None:
    """Called when a job starts."""
    logger.debug(
        "job_started",
        job_id=ctx.get("job_id"),
        job_try=ctx.get("job_try")
    )


async def on_job_end(ctx: dict) -> None:
    """Called when a job ends."""
    logger.debug(
        "job_ended",
        job_id=ctx.get("job_id"),
        job_try=ctx.get("job_try")
    )


class WorkerSettings:
    """ARQ worker settings."""

    # Redis connection
    redis_settings = RedisSettings.from_dsn(settings.redis_url)

    # Job functions
    functions = [run_scan_job]

    # Concurrency
    max_jobs = settings.max_concurrent_scans

    # Job timeout (seconds) - set high to allow long scans
    job_timeout = settings.scan_timeout_seconds + 120

    # Retry settings
    max_tries = 2
    retry_delay = 60  # seconds

    # Startup/shutdown hooks
    on_startup = startup
    on_shutdown = shutdown
    on_job_start = on_job_start
    on_job_end = on_job_end

    # Health check
    health_check_interval = 30  # seconds

    # Keep results for 24 hours
    keep_result = 86400


async def get_arq_pool() -> ArqRedis:
    """Get ARQ Redis pool for enqueueing jobs."""
    return await create_pool(
        RedisSettings.from_dsn(settings.redis_url)
    )


async def enqueue_scan(scan_id: UUID, organization_id: UUID) -> str:
    """
    Enqueue a scan job.

    Args:
        scan_id: UUID of the scan
        organization_id: UUID of the organization

    Returns:
        Job ID
    """
    pool = await get_arq_pool()

    try:
        job = await pool.enqueue_job(
            "run_scan_job",
            str(scan_id),
            str(organization_id),
            _job_id=f"scan_{scan_id}",
        )
        logger.info("scan_job_enqueued", scan_id=str(scan_id), job_id=job.job_id)
        return job.job_id
    finally:
        await pool.close()


async def get_job_status(job_id: str) -> dict:
    """
    Get status of a job.

    Args:
        job_id: The job ID

    Returns:
        dict with job status
    """
    pool = await get_arq_pool()

    try:
        job = await pool.job(job_id)
        if job is None:
            return {"status": "not_found"}

        info = await job.info()
        if info is None:
            return {"status": "pending"}

        return {
            "status": info.status,
            "result": info.result,
            "start_time": info.start_time.isoformat() if info.start_time else None,
            "finish_time": info.finish_time.isoformat() if info.finish_time else None,
        }
    finally:
        await pool.close()
