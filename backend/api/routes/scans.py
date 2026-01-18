"""
BREACH.AI - Scan Routes
========================
Scan management endpoints with rate limiting and audit logging.
"""

import csv
import io
import json
from datetime import datetime
from typing import Optional, List
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.database import get_db
from backend.services.scan import ScanService
from backend.services.audit import AuditService
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
    """Create and start a new scan.

    IMPORTANT: Requires a verified target. Ad-hoc URLs are not allowed.
    """
    user, org = current
    scan_service = ScanService(db)
    audit_service = AuditService(db)

    try:
        scan = await scan_service.create_scan(
            organization_id=org.id,
            target_url=str(data.target_url) if data.target_url else "",
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

    # Audit log the scan creation
    await audit_service.log_scan_created(
        organization_id=org.id,
        user_id=user.id,
        scan_id=str(scan.id),
        target_url=scan.target_url,
        mode=scan.mode.value,
        request=request,
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


# ============== EXPORT ==============

@router.get("/{scan_id}/export")
async def export_scan(
    request: Request,
    scan_id: UUID,
    format: str = Query(default="html", pattern="^(html|json|csv|pdf)$"),
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan results in various formats.

    Formats:
    - html: Full HTML report with styling
    - json: Machine-readable JSON
    - csv: Spreadsheet-compatible CSV
    - pdf: PDF report (returns HTML for now, client renders to PDF)
    """
    user, org = current
    scan_service = ScanService(db)

    scan = await scan_service.get_scan_with_findings(scan_id, org.id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    findings = scan.findings or []

    if format == "json":
        # JSON export
        export_data = {
            "scan": {
                "id": str(scan.id),
                "target_url": scan.target_url,
                "mode": scan.mode.value if hasattr(scan.mode, 'value') else scan.mode,
                "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
                "progress": scan.progress,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "findings_count": scan.findings_count,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "total_business_impact": scan.total_business_impact,
            },
            "findings": [
                {
                    "id": str(f.id),
                    "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "business_impact": f.business_impact,
                    "impact_explanation": f.impact_explanation,
                    "records_exposed": f.records_exposed,
                    "pii_fields": f.pii_fields,
                    "fix_suggestion": f.fix_suggestion,
                    "curl_command": f.curl_command,
                    "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
                }
                for f in findings
            ],
            "exported_at": datetime.utcnow().isoformat(),
        }

        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'
            }
        )

    elif format == "csv":
        # CSV export
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Severity", "Category", "Title", "Description", "Endpoint",
            "Method", "Business Impact", "Records Exposed", "PII Fields",
            "Fix Suggestion", "Discovered At"
        ])

        # Data rows
        for f in findings:
            writer.writerow([
                f.severity.value if hasattr(f.severity, 'value') else f.severity,
                f.category,
                f.title,
                f.description,
                f.endpoint,
                f.method,
                f.business_impact,
                f.records_exposed,
                ", ".join(f.pii_fields) if f.pii_fields else "",
                f.fix_suggestion,
                f.discovered_at.isoformat() if f.discovered_at else "",
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'
            }
        )

    else:  # html or pdf (pdf returns HTML for client-side rendering)
        # HTML report
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        findings_html = ""
        for f in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(
            x.severity.value if hasattr(x.severity, 'value') else x.severity
        )):
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            color = severity_colors.get(sev, "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 15px; margin: 15px 0; background: #f8f9fa; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <h3 style="margin: 0 0 10px 0;">{f.title}</h3>
                    <span style="background: {color}; color: white; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold;">{sev.upper()}</span>
                </div>
                <p style="color: #666; margin: 10px 0;"><strong>Category:</strong> {f.category}</p>
                <p style="margin: 10px 0;">{f.description}</p>
                {f'<p style="color: #666;"><strong>Endpoint:</strong> <code style="background: #e9ecef; padding: 2px 6px; border-radius: 3px;">{f.method} {f.endpoint}</code></p>' if f.endpoint else ''}
                {f'<p style="color: #dc3545;"><strong>Business Impact:</strong> ${f.business_impact:,.0f}</p>' if f.business_impact else ''}
                {f'<p style="color: #dc3545;"><strong>Records Exposed:</strong> {f.records_exposed}</p>' if f.records_exposed else ''}
                {f'<div style="background: #d4edda; padding: 10px; border-radius: 4px; margin-top: 10px;"><strong>Remediation:</strong> {f.fix_suggestion}</div>' if f.fix_suggestion else ''}
                {f'<div style="margin-top: 10px;"><strong>Reproduce:</strong><pre style="background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px;">{f.curl_command}</pre></div>' if f.curl_command else ''}
            </div>
            """

        total_impact = sum(f.business_impact or 0 for f in findings)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BREACH.AI Security Report - {scan.target_url}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #eee;
            padding-bottom: 30px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            color: #1a1a1a;
            font-size: 28px;
        }}
        .header .target {{
            color: #666;
            font-size: 18px;
            word-break: break-all;
        }}
        .verdict {{
            font-size: 24px;
            font-weight: bold;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            margin: 25px 0;
            color: white;
        }}
        .verdict.critical {{ background: linear-gradient(135deg, #dc3545, #c82333); }}
        .verdict.high {{ background: linear-gradient(135deg, #fd7e14, #e8690b); }}
        .verdict.medium {{ background: linear-gradient(135deg, #ffc107, #e0a800); color: #333; }}
        .verdict.secure {{ background: linear-gradient(135deg, #28a745, #1e7e34); }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 25px 0;
        }}
        .stat {{
            text-align: center;
            padding: 20px 15px;
            border-radius: 10px;
            background: #f8f9fa;
        }}
        .stat.critical {{ background: #f8d7da; border: 1px solid #f5c6cb; }}
        .stat.high {{ background: #fff3cd; border: 1px solid #ffeeba; }}
        .stat.medium {{ background: #d1ecf1; border: 1px solid #bee5eb; }}
        .stat.low {{ background: #d4edda; border: 1px solid #c3e6cb; }}
        .stat.info {{ background: #e2e3e5; border: 1px solid #d6d8db; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ font-size: 13px; color: #666; margin-top: 5px; }}
        h2 {{
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-top: 40px;
            color: #1a1a1a;
        }}
        .meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 25px 0;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }}
        .meta-item {{ }}
        .meta-label {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }}
        .meta-value {{ font-size: 16px; font-weight: 500; margin-top: 4px; }}
        .footer {{
            margin-top: 50px;
            padding-top: 25px;
            border-top: 2px solid #eee;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}
        .footer strong {{ color: #333; }}
        @media print {{
            body {{ padding: 20px; background: white; }}
            .container {{ box-shadow: none; padding: 20px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 BREACH.AI Security Report</h1>
            <p class="target">{scan.target_url}</p>
            <p style="color: #999; font-size: 14px;">
                Generated {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}
            </p>
        </div>

        <div class="verdict {'critical' if scan.critical_count else 'high' if scan.high_count else 'medium' if scan.medium_count else 'secure'}">
            {'⚠️ CRITICAL VULNERABILITIES FOUND' if scan.critical_count else '⚠️ HIGH RISK VULNERABILITIES FOUND' if scan.high_count else '⚡ MEDIUM RISK ISSUES FOUND' if scan.medium_count else '✅ NO SIGNIFICANT VULNERABILITIES'}
        </div>

        <div class="stats">
            <div class="stat critical">
                <div class="stat-number">{scan.critical_count or 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-number">{scan.high_count or 0}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-number">{scan.medium_count or 0}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-number">{scan.low_count or 0}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat info">
                <div class="stat-number">{scan.info_count or 0}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        {f'<div style="text-align: center; padding: 20px; background: #fff3cd; border-radius: 8px; margin: 20px 0;"><strong style="font-size: 24px;">💰 Estimated Business Impact: ${total_impact:,.0f}</strong></div>' if total_impact else ''}

        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">Scan Mode</div>
                <div class="meta-value">{scan.mode.value.title() if hasattr(scan.mode, 'value') else scan.mode}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Status</div>
                <div class="meta-value">{scan.status.value.title() if hasattr(scan.status, 'value') else scan.status}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Started</div>
                <div class="meta-value">{scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Duration</div>
                <div class="meta-value">{f'{scan.duration_seconds // 60}m {scan.duration_seconds % 60}s' if scan.duration_seconds else 'N/A'}</div>
            </div>
        </div>

        <h2>📋 Findings ({len(findings)})</h2>
        {findings_html if findings else '<p style="color: #666; text-align: center; padding: 40px;">No vulnerabilities discovered. Great job! 🎉</p>'}

        <div class="footer">
            <p><strong>BREACH.AI</strong> - Autonomous Security Assessment</p>
            <p>"We hack you before they do."</p>
        </div>
    </div>
</body>
</html>"""

        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.html"'
            }
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
    """Create a new scan target.

    After creation, the target must be verified before scanning.
    """
    user, org = current
    scan_service = ScanService(db)
    audit_service = AuditService(db)

    target = await scan_service.create_target(
        organization_id=org.id,
        url=str(data.url),
        name=data.name,
        description=data.description,
    )

    # Audit log target creation
    await audit_service.log_target_created(
        organization_id=org.id,
        user_id=user.id,
        target_id=str(target.id),
        url=str(data.url),
        request=request,
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
    audit_service = AuditService(db)

    # Get target info for audit log before deletion
    targets = await scan_service.list_targets(org.id)
    target_url = None
    for t in targets:
        if t.id == target_id:
            target_url = t.url
            break

    success = await scan_service.delete_target(target_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    # Audit log deletion
    await audit_service.log_target_deleted(
        organization_id=org.id,
        user_id=user.id,
        target_id=str(target_id),
        url=target_url or "unknown",
        request=request,
    )


@targets_router.post("/{target_id}/verify")
async def verify_target(
    request: Request,
    target_id: UUID,
    method: str = "dns",
    current: tuple = Depends(require_member),
    db: AsyncSession = Depends(get_db),
):
    """Verify target ownership via DNS, file, or meta tag.

    Methods:
    - dns: Add TXT record _breach-verify.{domain} with verification token
    - file: Create /.well-known/breach-verify.txt with verification token
    - meta: Add <meta name="breach-site-verification" content="{token}"> to homepage

    Returns verification status and message.
    """
    if method not in ["dns", "file", "meta"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification method. Use: dns, file, or meta",
        )

    user, org = current
    scan_service = ScanService(db)
    audit_service = AuditService(db)

    success, message = await scan_service.verify_target(target_id, org.id, method)

    # Audit log verification attempt
    await audit_service.log_target_verified(
        organization_id=org.id,
        user_id=user.id,
        target_id=str(target_id),
        method=method,
        success=success,
        request=request,
    )

    if success:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "message": message}
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": message}
        )


@targets_router.get("/{target_id}/verification-instructions")
async def get_verification_instructions(
    request: Request,
    target_id: UUID,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get verification instructions for a target.

    Returns the verification token and instructions for DNS, file, and meta methods.
    """
    user, org = current
    scan_service = ScanService(db)

    # Get target
    targets = await scan_service.list_targets(org.id)
    target = None
    for t in targets:
        if t.id == target_id:
            target = t
            break

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    instructions = scan_service.get_verification_instructions(target)

    return {
        "target_id": str(target_id),
        "url": target.url,
        "is_verified": target.is_verified,
        "verification_token": target.verification_token,
        "instructions": instructions,
    }
