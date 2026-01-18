"""
BREACH.AI - Attestation API Routes
===================================

API endpoints for generating compliance attestations and security badges.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import io

from backend.db.database import get_db
from backend.api.deps import get_current_user
from backend.services.attestation import AttestationService

router = APIRouter(prefix="/attestations", tags=["Attestations"])


# ============== Request/Response Models ==============

class SecurityPostureResponse(BaseModel):
    """Security posture summary."""
    score: int = Field(..., ge=0, le=100, description="Security score 0-100")
    grade: str = Field(..., description="Letter grade (A+ to F)")
    risk_level: str = Field(..., description="Risk level (Critical/High/Medium/Low)")
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_scans: int
    last_scan_date: Optional[str]
    compliance_status: str


class AttestationRequest(BaseModel):
    """Request for generating attestation."""
    target_id: UUID = Field(..., description="Target to generate attestation for")
    attestation_type: str = Field(
        default="summary",
        description="Type: summary, full, or compliance"
    )
    validity_days: int = Field(default=30, ge=7, le=365)


class AttestationResponse(BaseModel):
    """Attestation document metadata."""
    id: str
    organization_name: str
    target_url: str
    generated_at: str
    valid_until: str
    posture: SecurityPostureResponse
    attestation_type: str
    document_hash: str


class BadgeResponse(BaseModel):
    """Security badge details."""
    badge_url: str
    embed_code: str
    score: int
    grade: str
    valid_until: str


# ============== Endpoints ==============

@router.get("/posture/{target_id}", response_model=SecurityPostureResponse)
async def get_security_posture(
    target_id: UUID,
    lookback_days: int = 30,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get current security posture for a target.

    Returns score, grade, and risk assessment based on recent scan results.
    """
    user, org = current

    service = AttestationService(db)

    try:
        posture = await service.calculate_security_posture(
            target_id=target_id,
            lookback_days=lookback_days
        )

        return SecurityPostureResponse(
            score=posture.score,
            grade=posture.grade,
            risk_level=posture.risk_level,
            critical_findings=posture.critical_findings,
            high_findings=posture.high_findings,
            medium_findings=posture.medium_findings,
            low_findings=posture.low_findings,
            total_scans=posture.total_scans,
            last_scan_date=posture.last_scan_date.isoformat() if posture.last_scan_date else None,
            compliance_status=posture.compliance_status,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("", response_model=AttestationResponse)
async def generate_attestation(
    request: AttestationRequest,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Generate an attestation document.

    Types:
    - summary: Quick overview for stakeholders
    - full: Detailed report for auditors
    - compliance: Formatted for compliance questionnaires
    """
    user, org = current

    if request.attestation_type not in ["summary", "full", "compliance"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid attestation type. Use: summary, full, or compliance"
        )

    service = AttestationService(db)

    try:
        attestation = await service.generate_attestation(
            organization_id=org.id,
            target_id=request.target_id,
            attestation_type=request.attestation_type,
            validity_days=request.validity_days,
        )

        return AttestationResponse(
            id=attestation.id,
            organization_name=attestation.organization_name,
            target_url=attestation.target_url,
            generated_at=attestation.generated_at.isoformat(),
            valid_until=attestation.valid_until.isoformat(),
            posture=SecurityPostureResponse(
                score=attestation.posture.score,
                grade=attestation.posture.grade,
                risk_level=attestation.posture.risk_level,
                critical_findings=attestation.posture.critical_findings,
                high_findings=attestation.posture.high_findings,
                medium_findings=attestation.posture.medium_findings,
                low_findings=attestation.posture.low_findings,
                total_scans=attestation.posture.total_scans,
                last_scan_date=attestation.posture.last_scan_date.isoformat() if attestation.posture.last_scan_date else None,
                compliance_status=attestation.posture.compliance_status,
            ),
            attestation_type=attestation.attestation_type,
            document_hash=attestation.document_hash,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/pdf", response_class=StreamingResponse)
async def generate_attestation_pdf(
    request: AttestationRequest,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Generate attestation as downloadable PDF.

    Returns a PDF document suitable for compliance audits.
    """
    user, org = current

    service = AttestationService(db)

    try:
        pdf_bytes = await service.generate_attestation_pdf(
            organization_id=org.id,
            target_id=request.target_id,
            attestation_type=request.attestation_type,
        )

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=breach_attestation_{request.target_id}.pdf"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {str(e)}"
        )


@router.get("/badge/{target_id}", response_model=BadgeResponse)
async def get_security_badge(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get embeddable security badge for a target.

    Returns HTML/Markdown embed code for displaying security score.
    """
    user, org = current

    service = AttestationService(db)

    try:
        posture = await service.calculate_security_posture(target_id)

        # Generate badge URL (would be served by a badge endpoint)
        badge_url = f"/api/v1/attestations/badge/{target_id}/image"

        # Generate embed code
        embed_html = f'''<a href="https://breach.ai/security/{target_id}">
  <img src="{badge_url}" alt="Security Score: {posture.grade}" />
</a>'''

        embed_md = f"[![Security Score: {posture.grade}]({badge_url})](https://breach.ai/security/{target_id})"

        return BadgeResponse(
            badge_url=badge_url,
            embed_code=embed_html,
            score=posture.score,
            grade=posture.grade,
            valid_until=(posture.last_scan_date.isoformat() if posture.last_scan_date else "N/A"),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/badge/{target_id}/image")
async def get_badge_image(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and return the actual badge image (SVG).

    This endpoint is public for embedding in external sites.
    """
    service = AttestationService(db)

    try:
        svg_bytes = await service.generate_security_badge(target_id)

        return StreamingResponse(
            io.BytesIO(svg_bytes),
            media_type="image/svg+xml",
            headers={
                "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
            }
        )
    except ValueError as e:
        # Return a "unknown" badge for missing targets
        unknown_badge = b'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
  <rect width="120" height="20" fill="#555"/>
  <rect x="60" width="60" height="20" fill="#999"/>
  <text x="30" y="14" fill="#fff" font-size="11" text-anchor="middle">security</text>
  <text x="90" y="14" fill="#fff" font-size="11" text-anchor="middle">unknown</text>
</svg>'''
        return StreamingResponse(
            io.BytesIO(unknown_badge),
            media_type="image/svg+xml",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Badge generation failed: {str(e)}"
        )
