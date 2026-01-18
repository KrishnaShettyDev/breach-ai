"""
BREACH.AI - Analytics & Comparison API Routes
==============================================

API endpoints for scan comparison, trending, and analytics.
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from backend.db.database import get_db
from backend.api.deps import get_current_user
from backend.db.models import Scan, Finding, Target, ScanStatus, Severity
from fastapi.responses import StreamingResponse
import io

router = APIRouter(prefix="/analytics", tags=["Analytics"])


# ============== Response Models ==============

class FindingDiff(BaseModel):
    """A finding that changed between scans."""
    id: str
    title: str
    severity: str
    category: str
    endpoint: Optional[str]
    status: str  # "new", "fixed", "unchanged", "regressed"


class ScanComparisonResponse(BaseModel):
    """Comparison between two scans."""
    scan_a: dict
    scan_b: dict
    summary: dict
    new_findings: List[FindingDiff]
    fixed_findings: List[FindingDiff]
    unchanged_findings: List[FindingDiff]
    regressed_findings: List[FindingDiff]


class TrendDataPoint(BaseModel):
    """A single point in a trend."""
    date: str
    value: int
    label: Optional[str] = None


class VulnerabilityTrend(BaseModel):
    """Vulnerability trends over time."""
    target_id: str
    period: str
    data_points: List[TrendDataPoint]
    total_scans: int
    avg_findings: float
    trend_direction: str  # "improving", "worsening", "stable"


class SeverityBreakdown(BaseModel):
    """Breakdown of findings by severity."""
    critical: int
    high: int
    medium: int
    low: int
    info: int


class TargetHealthScore(BaseModel):
    """Health score for a target."""
    target_id: str
    target_url: str
    score: int
    grade: str
    trend: str
    severity_breakdown: SeverityBreakdown
    last_scan: Optional[str]
    scans_count: int


# ============== Endpoints ==============

@router.get("/compare/{scan_a_id}/{scan_b_id}", response_model=ScanComparisonResponse)
async def compare_scans(
    scan_a_id: UUID,
    scan_b_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Compare two scans to see what changed.

    Returns:
    - new_findings: Vulnerabilities found in scan_b but not scan_a
    - fixed_findings: Vulnerabilities in scan_a that are gone in scan_b
    - unchanged_findings: Vulnerabilities present in both scans
    - regressed_findings: Previously fixed vulnerabilities that returned

    Use this to track remediation progress or detect regressions.
    """
    user, org = current

    # Get both scans
    result_a = await db.execute(select(Scan).where(Scan.id == scan_a_id))
    scan_a = result_a.scalar_one_or_none()

    result_b = await db.execute(select(Scan).where(Scan.id == scan_b_id))
    scan_b = result_b.scalar_one_or_none()

    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan_a.target_id != scan_b.target_id:
        raise HTTPException(status_code=400, detail="Scans must be for the same target")

    # Get findings for both scans
    findings_a_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_a_id)
    )
    findings_a = {
        _make_finding_key(f): f for f in findings_a_result.scalars().all()
    }

    findings_b_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_b_id)
    )
    findings_b = {
        _make_finding_key(f): f for f in findings_b_result.scalars().all()
    }

    # Compare
    keys_a = set(findings_a.keys())
    keys_b = set(findings_b.keys())

    new_keys = keys_b - keys_a
    fixed_keys = keys_a - keys_b
    unchanged_keys = keys_a & keys_b

    # Build response
    new_findings = [
        FindingDiff(
            id=str(findings_b[k].id),
            title=findings_b[k].title,
            severity=findings_b[k].severity.value if hasattr(findings_b[k].severity, 'value') else str(findings_b[k].severity),
            category=findings_b[k].category,
            endpoint=findings_b[k].affected_endpoint,
            status="new",
        )
        for k in new_keys
    ]

    fixed_findings = [
        FindingDiff(
            id=str(findings_a[k].id),
            title=findings_a[k].title,
            severity=findings_a[k].severity.value if hasattr(findings_a[k].severity, 'value') else str(findings_a[k].severity),
            category=findings_a[k].category,
            endpoint=findings_a[k].affected_endpoint,
            status="fixed",
        )
        for k in fixed_keys
    ]

    unchanged_findings = [
        FindingDiff(
            id=str(findings_b[k].id),
            title=findings_b[k].title,
            severity=findings_b[k].severity.value if hasattr(findings_b[k].severity, 'value') else str(findings_b[k].severity),
            category=findings_b[k].category,
            endpoint=findings_b[k].affected_endpoint,
            status="unchanged",
        )
        for k in unchanged_keys
    ]

    # Calculate severity changes for summary
    def count_by_severity(findings_dict, keys):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for k in keys:
            f = findings_dict.get(k)
            if f:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                if sev.lower() in counts:
                    counts[sev.lower()] += 1
        return counts

    new_by_sev = count_by_severity(findings_b, new_keys)
    fixed_by_sev = count_by_severity(findings_a, fixed_keys)

    return ScanComparisonResponse(
        scan_a={
            "id": str(scan_a.id),
            "status": scan_a.status.value if hasattr(scan_a.status, 'value') else str(scan_a.status),
            "started_at": scan_a.started_at.isoformat() if scan_a.started_at else None,
            "completed_at": scan_a.completed_at.isoformat() if scan_a.completed_at else None,
            "findings_count": len(findings_a),
        },
        scan_b={
            "id": str(scan_b.id),
            "status": scan_b.status.value if hasattr(scan_b.status, 'value') else str(scan_b.status),
            "started_at": scan_b.started_at.isoformat() if scan_b.started_at else None,
            "completed_at": scan_b.completed_at.isoformat() if scan_b.completed_at else None,
            "findings_count": len(findings_b),
        },
        summary={
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "unchanged_count": len(unchanged_findings),
            "new_by_severity": new_by_sev,
            "fixed_by_severity": fixed_by_sev,
            "improvement": len(fixed_findings) > len(new_findings),
        },
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        unchanged_findings=unchanged_findings,
        regressed_findings=[],  # Would need historical data to detect
    )


@router.get("/trends/{target_id}", response_model=VulnerabilityTrend)
async def get_vulnerability_trend(
    target_id: UUID,
    period: str = Query(default="30d", pattern="^(7d|30d|90d|1y)$"),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get vulnerability trends over time for a target.

    Periods:
    - 7d: Last 7 days
    - 30d: Last 30 days
    - 90d: Last 90 days
    - 1y: Last year
    """
    user, org = current

    # Calculate cutoff date
    period_days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
    cutoff = datetime.utcnow() - timedelta(days=period_days[period])

    # Get scans for this target in the period
    result = await db.execute(
        select(Scan)
        .where(
            Scan.target_id == target_id,
            Scan.status == ScanStatus.COMPLETED,
            Scan.completed_at >= cutoff,
        )
        .order_by(Scan.completed_at.asc())
    )
    scans = result.scalars().all()

    if not scans:
        return VulnerabilityTrend(
            target_id=str(target_id),
            period=period,
            data_points=[],
            total_scans=0,
            avg_findings=0.0,
            trend_direction="stable",
        )

    # Get finding counts for each scan
    data_points = []
    finding_counts = []

    for scan in scans:
        count_result = await db.execute(
            select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
        )
        count = count_result.scalar() or 0
        finding_counts.append(count)

        data_points.append(TrendDataPoint(
            date=scan.completed_at.isoformat() if scan.completed_at else "",
            value=count,
            label=f"Scan {str(scan.id)[:8]}",
        ))

    # Calculate trend direction
    if len(finding_counts) >= 2:
        first_half_avg = sum(finding_counts[:len(finding_counts)//2]) / max(1, len(finding_counts)//2)
        second_half_avg = sum(finding_counts[len(finding_counts)//2:]) / max(1, len(finding_counts) - len(finding_counts)//2)

        if second_half_avg < first_half_avg * 0.8:
            trend_direction = "improving"
        elif second_half_avg > first_half_avg * 1.2:
            trend_direction = "worsening"
        else:
            trend_direction = "stable"
    else:
        trend_direction = "stable"

    return VulnerabilityTrend(
        target_id=str(target_id),
        period=period,
        data_points=data_points,
        total_scans=len(scans),
        avg_findings=sum(finding_counts) / len(finding_counts) if finding_counts else 0,
        trend_direction=trend_direction,
    )


@router.get("/health-scores")
async def get_target_health_scores(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get health scores for all targets in the organization.

    Health score is calculated based on:
    - Number and severity of findings
    - Trend over time
    - Time since last scan
    """
    user, org = current

    # Get all targets for the organization
    result = await db.execute(
        select(Target).where(Target.organization_id == org.id)
    )
    targets = result.scalars().all()

    scores = []
    for target in targets:
        # Get latest completed scan
        scan_result = await db.execute(
            select(Scan)
            .where(
                Scan.target_id == target.id,
                Scan.status == ScanStatus.COMPLETED,
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        latest_scan = scan_result.scalar_one_or_none()

        # Get finding counts
        if latest_scan:
            findings_result = await db.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.scan_id == latest_scan.id)
                .group_by(Finding.severity)
            )
            severity_counts = {row[0]: row[1] for row in findings_result.fetchall()}
        else:
            severity_counts = {}

        breakdown = SeverityBreakdown(
            critical=severity_counts.get(Severity.CRITICAL, 0),
            high=severity_counts.get(Severity.HIGH, 0),
            medium=severity_counts.get(Severity.MEDIUM, 0),
            low=severity_counts.get(Severity.LOW, 0),
            info=severity_counts.get(Severity.INFO, 0),
        )

        # Calculate score (100 - penalty for each finding type)
        score = 100
        score -= breakdown.critical * 25
        score -= breakdown.high * 10
        score -= breakdown.medium * 3
        score -= breakdown.low * 1
        score = max(0, score)

        # Determine grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Count total scans
        count_result = await db.execute(
            select(func.count(Scan.id)).where(Scan.target_id == target.id)
        )
        scans_count = count_result.scalar() or 0

        scores.append(TargetHealthScore(
            target_id=str(target.id),
            target_url=target.url,
            score=score,
            grade=grade,
            trend="stable",  # Would need historical data
            severity_breakdown=breakdown,
            last_scan=latest_scan.completed_at.isoformat() if latest_scan and latest_scan.completed_at else None,
            scans_count=scans_count,
        ))

    return {
        "targets": scores,
        "organization_avg_score": sum(s.score for s in scores) / len(scores) if scores else 0,
    }


@router.get("/severity-distribution/{target_id}")
async def get_severity_distribution(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get severity distribution over time for a target.

    Shows how the proportion of critical/high/medium/low findings
    has changed across scans.
    """
    user, org = current

    # Get last 10 scans
    result = await db.execute(
        select(Scan)
        .where(
            Scan.target_id == target_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.completed_at.desc())
        .limit(10)
    )
    scans = list(reversed(result.scalars().all()))

    distribution = []
    for scan in scans:
        findings_result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan.id)
            .group_by(Finding.severity)
        )
        counts = {row[0]: row[1] for row in findings_result.fetchall()}

        distribution.append({
            "scan_id": str(scan.id),
            "date": scan.completed_at.isoformat() if scan.completed_at else None,
            "critical": counts.get(Severity.CRITICAL, 0),
            "high": counts.get(Severity.HIGH, 0),
            "medium": counts.get(Severity.MEDIUM, 0),
            "low": counts.get(Severity.LOW, 0),
            "total": sum(counts.values()),
        })

    return {
        "target_id": str(target_id),
        "scans": distribution,
    }


@router.get("/top-vulnerabilities")
async def get_top_vulnerabilities(
    target_id: Optional[UUID] = None,
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get the most common vulnerability types.

    Optionally filter by target. Returns vulnerability categories
    ranked by frequency.
    """
    user, org = current

    # Build query
    query = (
        select(Finding.category, func.count(Finding.id).label("count"))
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )

    if target_id:
        query = query.join(Scan).where(Scan.target_id == target_id)

    result = await db.execute(query)
    rows = result.fetchall()

    return {
        "vulnerabilities": [
            {"category": row[0], "count": row[1]} for row in rows
        ]
    }


@router.get("/executive-summary/{target_id}")
async def get_executive_summary(
    target_id: UUID,
    lookback_days: int = Query(default=30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get executive summary data for a target.

    Returns structured data suitable for executive presentations.
    """
    from backend.services.executive_report import ExecutiveSummaryReport

    user, org = current
    report_service = ExecutiveSummaryReport(db)

    try:
        summary = await report_service.generate_summary(target_id, lookback_days)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/executive-summary/{target_id}/pdf")
async def get_executive_summary_pdf(
    target_id: UUID,
    lookback_days: int = Query(default=30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Download executive summary as PDF.

    Returns a professionally formatted PDF suitable for
    board presentations or compliance audits.
    """
    from backend.services.executive_report import ExecutiveSummaryReport

    user, org = current
    report_service = ExecutiveSummaryReport(db)

    try:
        pdf_bytes = await report_service.generate_pdf(target_id, lookback_days)

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_summary_{target_id}.pdf"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/executive-summary/{target_id}/html")
async def get_executive_summary_html(
    target_id: UUID,
    lookback_days: int = Query(default=30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get executive summary as HTML.

    Returns a standalone HTML document that can be printed or embedded.
    """
    from backend.services.executive_report import ExecutiveSummaryReport

    user, org = current
    report_service = ExecutiveSummaryReport(db)

    try:
        html = await report_service.generate_html(target_id, lookback_days)

        return StreamingResponse(
            io.BytesIO(html.encode('utf-8')),
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=executive_summary_{target_id}.html"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


def _make_finding_key(finding: Finding) -> str:
    """Create a unique key for a finding to enable comparison."""
    # Use category + endpoint + title hash for matching
    # This way similar findings across scans can be matched
    import hashlib
    key_str = f"{finding.category}:{finding.affected_endpoint or ''}:{finding.title}"
    return hashlib.md5(key_str.encode()).hexdigest()
