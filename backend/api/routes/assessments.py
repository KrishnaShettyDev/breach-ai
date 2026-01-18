"""
BREACH.AI - Brutal Assessment API Routes
=========================================

One-time brutal assessment endpoints for consulting engagements.
Runs ALL 60+ attack modules and generates comprehensive reports.
"""

from typing import Optional, List
from uuid import UUID
import asyncio

import structlog
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.database import get_db
from backend.api.deps import get_current_user, require_member

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/assessments", tags=["Assessments"])


# =============================================================================
# Request/Response Models
# =============================================================================

class BrutalAssessmentCreate(BaseModel):
    """Request to create a brutal assessment."""
    target: HttpUrl
    scope: Optional[List[str]] = None
    exclude: Optional[List[str]] = None
    aggressive: bool = True
    timeout_per_module: int = 300
    max_concurrent: int = 5

    class Config:
        json_schema_extra = {
            "example": {
                "target": "https://example.com",
                "scope": ["*.example.com"],
                "exclude": ["/admin"],
                "aggressive": True,
                "timeout_per_module": 300,
                "max_concurrent": 5
            }
        }


class AssessmentStatus(BaseModel):
    """Assessment status response."""
    id: str
    target: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    modules_executed: int
    modules_total: int
    findings_count: int
    risk_score: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class AssessmentSummary(BaseModel):
    """Assessment summary response."""
    id: str
    target: str
    status: str
    risk_score: int
    estimated_breach_cost: int
    max_access_level: str
    findings: dict  # critical, high, medium, low, info counts
    modules_executed: int
    duration_seconds: int
    reports: dict  # URLs to generated reports


# =============================================================================
# In-Memory Assessment Storage (for demo - use DB in production)
# =============================================================================

_assessments = {}
_assessment_tasks = {}


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/brutal", response_model=AssessmentStatus, status_code=status.HTTP_202_ACCEPTED)
async def create_brutal_assessment(
    request: Request,
    data: BrutalAssessmentCreate,
    background_tasks: BackgroundTasks,
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new brutal one-time assessment.

    This runs ALL 60+ attack modules against the target:
    - 31 V1 Attack Modules (Web, API, Auth, Cloud, Injection)
    - 25 V2 Killchain Modules (Recon → Proof)
    - 7 Recon Modules
    - 6 AI Agents

    The assessment runs in the background. Use GET /assessments/{id}
    to check status and retrieve results.

    **Rate Limited**: 1 brutal assessment per hour per organization.
    """
    import uuid
    from datetime import datetime

    user, org = current

    # Generate assessment ID
    assessment_id = str(uuid.uuid4())

    # Create initial status
    assessment = {
        "id": assessment_id,
        "organization_id": str(org.id),
        "target": str(data.target),
        "scope": data.scope,
        "exclude": data.exclude,
        "aggressive": data.aggressive,
        "timeout_per_module": data.timeout_per_module,
        "max_concurrent": data.max_concurrent,
        "status": "pending",
        "progress": 0,
        "modules_executed": 0,
        "modules_total": 60,  # Approximate
        "findings_count": 0,
        "risk_score": None,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "error": None,
        "results": None,
        "reports": None,
    }

    _assessments[assessment_id] = assessment

    # Start assessment in background
    background_tasks.add_task(
        run_assessment_task,
        assessment_id,
        data.dict()
    )

    logger.info(
        "brutal_assessment_created",
        assessment_id=assessment_id,
        target=str(data.target),
        organization_id=str(org.id),
    )

    return AssessmentStatus(
        id=assessment_id,
        target=str(data.target),
        status="pending",
        progress=0,
        modules_executed=0,
        modules_total=60,
        findings_count=0,
        started_at=assessment["started_at"],
    )


async def run_assessment_task(assessment_id: str, config: dict):
    """Background task to run the assessment."""
    from datetime import datetime

    try:
        # Import here to avoid circular imports
        from backend.breach.brutal_assessment import BrutalAssessment
        from backend.breach.report.brutal_report import AssessmentReportGenerator

        # Update status to running
        _assessments[assessment_id]["status"] = "running"

        # Create and run assessment
        assessment = BrutalAssessment(
            target=config["target"],
            scope=config.get("scope"),
            exclude=config.get("exclude"),
            aggressive=config.get("aggressive", True),
            timeout_per_module=config.get("timeout_per_module", 300),
            max_concurrent=config.get("max_concurrent", 5),
        )

        results = await assessment.run()

        # Generate reports
        output_dir = f"./breach_output/{assessment_id}"
        generator = AssessmentReportGenerator(results, output_dir)
        report_files = generator.generate_all()

        # Update status with results
        _assessments[assessment_id].update({
            "status": "completed",
            "progress": 100,
            "modules_executed": results.modules_executed,
            "findings_count": results.total_findings,
            "risk_score": results.risk_score,
            "completed_at": datetime.utcnow().isoformat(),
            "results": results.to_dict(),
            "reports": report_files,
        })

        logger.info(
            "brutal_assessment_completed",
            assessment_id=assessment_id,
            findings=results.total_findings,
            risk_score=results.risk_score,
        )

    except Exception as e:
        logger.error(
            "brutal_assessment_failed",
            assessment_id=assessment_id,
            error=str(e),
            exc_info=True,
        )
        _assessments[assessment_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow().isoformat(),
        })


@router.get("/{assessment_id}", response_model=AssessmentStatus)
async def get_assessment_status(
    request: Request,
    assessment_id: str,
    current: tuple = Depends(get_current_user),
):
    """Get the status of a brutal assessment."""
    user, org = current

    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found",
        )

    # Verify organization ownership
    if assessment.get("organization_id") != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    return AssessmentStatus(
        id=assessment["id"],
        target=assessment["target"],
        status=assessment["status"],
        progress=assessment["progress"],
        modules_executed=assessment["modules_executed"],
        modules_total=assessment["modules_total"],
        findings_count=assessment["findings_count"],
        risk_score=assessment.get("risk_score"),
        started_at=assessment.get("started_at"),
        completed_at=assessment.get("completed_at"),
        error=assessment.get("error"),
    )


@router.get("/{assessment_id}/summary", response_model=AssessmentSummary)
async def get_assessment_summary(
    request: Request,
    assessment_id: str,
    current: tuple = Depends(get_current_user),
):
    """Get the summary of a completed assessment."""
    user, org = current

    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found",
        )

    if assessment.get("organization_id") != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    if assessment["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment is {assessment['status']}, not completed",
        )

    results = assessment.get("results", {})
    summary = results.get("summary", {})

    return AssessmentSummary(
        id=assessment["id"],
        target=assessment["target"],
        status=assessment["status"],
        risk_score=summary.get("risk_score", 0),
        estimated_breach_cost=summary.get("estimated_breach_cost", 0),
        max_access_level=summary.get("max_access_level", "none"),
        findings={
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "total": summary.get("total_findings", 0),
        },
        modules_executed=results.get("modules", {}).get("executed", 0),
        duration_seconds=results.get("duration_seconds", 0),
        reports=assessment.get("reports", {}),
    )


@router.get("/{assessment_id}/report/{report_type}")
async def get_assessment_report(
    request: Request,
    assessment_id: str,
    report_type: str,
    current: tuple = Depends(get_current_user),
):
    """
    Download a generated report.

    Report types:
    - executive_summary (TXT)
    - technical_report (HTML)
    - recommendations (TXT)
    - json_export (JSON)
    - evidence_package (ZIP)
    """
    import os

    user, org = current

    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found",
        )

    if assessment.get("organization_id") != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    reports = assessment.get("reports", {})
    filepath = reports.get(report_type)

    if not filepath or not os.path.exists(filepath):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_type}' not found",
        )

    # Determine media type
    media_types = {
        "executive_summary": "text/plain",
        "technical_report": "text/html",
        "recommendations": "text/plain",
        "json_export": "application/json",
        "evidence_package": "application/zip",
    }

    return FileResponse(
        filepath,
        media_type=media_types.get(report_type, "application/octet-stream"),
        filename=os.path.basename(filepath),
    )


@router.get("/{assessment_id}/findings")
async def get_assessment_findings(
    request: Request,
    assessment_id: str,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    current: tuple = Depends(get_current_user),
):
    """Get findings from a completed assessment."""
    user, org = current

    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found",
        )

    if assessment.get("organization_id") != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    if assessment["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment is {assessment['status']}, not completed",
        )

    results = assessment.get("results", {})
    findings_data = results.get("findings", {})

    # Collect all findings
    all_findings = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        for finding in findings_data.get(sev, []):
            finding["severity"] = sev
            all_findings.append(finding)

    # Filter by severity if specified
    if severity:
        all_findings = [f for f in all_findings if f["severity"] == severity.lower()]

    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    paginated = all_findings[start:end]

    return {
        "items": paginated,
        "total": len(all_findings),
        "page": page,
        "per_page": per_page,
        "pages": (len(all_findings) + per_page - 1) // per_page,
    }


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assessment(
    request: Request,
    assessment_id: str,
    current: tuple = Depends(require_member),
):
    """Delete an assessment and its reports."""
    import os
    import shutil

    user, org = current

    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found",
        )

    if assessment.get("organization_id") != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Delete report files
    output_dir = f"./breach_output/{assessment_id}"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    # Remove from storage
    del _assessments[assessment_id]

    logger.info(
        "assessment_deleted",
        assessment_id=assessment_id,
        organization_id=str(org.id),
    )
