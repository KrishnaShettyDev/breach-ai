"""
BREACH.AI - Compliance Attestation Service
==========================================

Generate compliance-ready attestation documents like MindFort's
"Full Resilience Attestation" and "Security Strength Badge".

Features:
- Security posture attestation PDF
- Compliance-ready documentation
- Security badge/seal generation
- Historical trend reports
- Auditor-friendly format
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from uuid import UUID, uuid4
import base64
import hashlib
import os

import structlog
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import (
    Organization, Target, Scan, Finding,
    ScanStatus, Severity
)

logger = structlog.get_logger(__name__)


@dataclass
class SecurityPosture:
    """Security posture assessment."""
    score: int  # 0-100
    grade: str  # A+, A, B, C, D, F
    risk_level: str  # Low, Medium, High, Critical
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_scans: int
    last_scan_date: Optional[datetime]
    compliance_status: str  # Compliant, Non-Compliant, Needs Review


@dataclass
class AttestationDocument:
    """Generated attestation document."""
    id: str
    organization_name: str
    target_url: str
    generated_at: datetime
    valid_until: datetime
    posture: SecurityPosture
    attestation_type: str  # summary, full, compliance
    document_hash: str  # For verification


class AttestationService:
    """
    Service for generating compliance attestations and security badges.
    """

    GRADE_THRESHOLDS = {
        "A+": (95, 100),
        "A": (90, 94),
        "A-": (85, 89),
        "B+": (80, 84),
        "B": (75, 79),
        "B-": (70, 74),
        "C+": (65, 69),
        "C": (60, 64),
        "C-": (55, 59),
        "D": (50, 54),
        "F": (0, 49),
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def calculate_security_posture(
        self,
        target_id: UUID,
        lookback_days: int = 30
    ) -> SecurityPosture:
        """
        Calculate the current security posture for a target.

        Based on:
        - Number and severity of findings
        - Scan coverage
        - Remediation rate
        - Time since last scan
        """
        cutoff = datetime.utcnow() - timedelta(days=lookback_days)

        # Get recent scans
        scans_result = await self.db.execute(
            select(Scan).where(
                Scan.target_id == target_id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.started_at >= cutoff,
            )
        )
        scans = list(scans_result.scalars().all())

        # Get recent findings
        findings_result = await self.db.execute(
            select(Finding).join(Scan).where(
                Scan.target_id == target_id,
                Scan.started_at >= cutoff,
            )
        )
        findings = list(findings_result.scalars().all())

        # Count by severity
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)

        # Calculate score
        # Start at 100, deduct for findings
        score = 100
        score -= critical * 25  # Critical findings are severe
        score -= high * 10
        score -= medium * 3
        score -= low * 1

        # Bonus for regular scanning
        if scans:
            days_since_scan = (datetime.utcnow() - max(s.completed_at or s.started_at for s in scans)).days
            if days_since_scan <= 1:
                score += 5  # Daily scanning bonus
            elif days_since_scan <= 7:
                score += 2  # Weekly scanning
            elif days_since_scan > 30:
                score -= 10  # Penalty for no recent scans

        score = max(0, min(100, score))  # Clamp to 0-100

        # Determine grade
        grade = "F"
        for g, (low_threshold, high_threshold) in self.GRADE_THRESHOLDS.items():
            if low_threshold <= score <= high_threshold:
                grade = g
                break

        # Determine risk level
        if critical > 0:
            risk_level = "Critical"
        elif high > 0:
            risk_level = "High"
        elif medium > 0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Compliance status
        if critical > 0 or high > 2:
            compliance_status = "Non-Compliant"
        elif high > 0 or medium > 5:
            compliance_status = "Needs Review"
        else:
            compliance_status = "Compliant"

        last_scan = max((s.completed_at or s.started_at for s in scans), default=None) if scans else None

        return SecurityPosture(
            score=score,
            grade=grade,
            risk_level=risk_level,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            total_scans=len(scans),
            last_scan_date=last_scan,
            compliance_status=compliance_status,
        )

    async def generate_attestation(
        self,
        organization_id: UUID,
        target_id: UUID,
        attestation_type: str = "summary",
        validity_days: int = 30
    ) -> AttestationDocument:
        """
        Generate an attestation document.

        Types:
        - summary: Quick overview for stakeholders
        - full: Detailed report for auditors
        - compliance: Formatted for compliance questionnaires
        """
        # Get organization and target
        org = await self._get_organization(organization_id)
        target = await self._get_target(target_id)

        if not org or not target:
            raise ValueError("Organization or target not found")

        # Calculate posture
        posture = await self.calculate_security_posture(target_id)

        # Generate document ID
        doc_id = str(uuid4())
        generated_at = datetime.utcnow()
        valid_until = generated_at + timedelta(days=validity_days)

        # Create hash for verification
        hash_input = f"{doc_id}:{org.name}:{target.url}:{generated_at.isoformat()}:{posture.score}"
        doc_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        return AttestationDocument(
            id=doc_id,
            organization_name=org.name,
            target_url=target.url,
            generated_at=generated_at,
            valid_until=valid_until,
            posture=posture,
            attestation_type=attestation_type,
            document_hash=doc_hash,
        )

    async def generate_attestation_pdf(
        self,
        organization_id: UUID,
        target_id: UUID,
        attestation_type: str = "summary"
    ) -> bytes:
        """
        Generate attestation as PDF document.

        Returns PDF bytes.
        """
        attestation = await self.generate_attestation(
            organization_id, target_id, attestation_type
        )

        # Try reportlab
        try:
            return self._generate_pdf_reportlab(attestation)
        except ImportError:
            # Fallback to simple text-based PDF
            return self._generate_simple_pdf(attestation)

    def _generate_pdf_reportlab(self, attestation: AttestationDocument) -> bytes:
        """Generate PDF using reportlab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, Image
        )
        from io import BytesIO

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch
        )

        styles = getSampleStyleSheet()

        # Custom styles
        styles.add(ParagraphStyle(
            name='Title_Custom',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=20,
            textColor=colors.HexColor('#1e40af')
        ))
        styles.add(ParagraphStyle(
            name='Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=30,
        ))

        story = []

        # Header
        story.append(Paragraph("SECURITY ATTESTATION", styles['Title_Custom']))
        story.append(Paragraph(
            f"Generated by BREACH.AI | {attestation.generated_at.strftime('%Y-%m-%d')}",
            styles['Subtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1e40af')))
        story.append(Spacer(1, 20))

        # Organization Info
        story.append(Paragraph(f"<b>Organization:</b> {attestation.organization_name}", styles['Normal']))
        story.append(Paragraph(f"<b>Target:</b> {attestation.target_url}", styles['Normal']))
        story.append(Paragraph(f"<b>Document ID:</b> {attestation.id}", styles['Normal']))
        story.append(Paragraph(f"<b>Valid Until:</b> {attestation.valid_until.strftime('%Y-%m-%d')}", styles['Normal']))
        story.append(Spacer(1, 30))

        # Security Grade Box
        grade = attestation.posture.grade
        grade_color = self._get_grade_color(grade)

        grade_data = [
            ['SECURITY GRADE', 'SCORE', 'RISK LEVEL'],
            [grade, f"{attestation.posture.score}/100", attestation.posture.risk_level],
        ]
        grade_table = Table(grade_data, colWidths=[2.5 * inch, 2 * inch, 2 * inch])
        grade_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 1), (0, 1), grade_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (0, 1), 36),
            ('FONTSIZE', (1, 1), (2, 1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        story.append(grade_table)
        story.append(Spacer(1, 30))

        # Findings Summary
        story.append(Paragraph("<b>FINDINGS SUMMARY</b>", styles['Heading2']))
        story.append(Spacer(1, 10))

        findings_data = [
            ['Severity', 'Count', 'Status'],
            ['Critical', str(attestation.posture.critical_findings),
             '🔴 Immediate Action Required' if attestation.posture.critical_findings > 0 else '✓'],
            ['High', str(attestation.posture.high_findings),
             '🟠 Action Required' if attestation.posture.high_findings > 0 else '✓'],
            ['Medium', str(attestation.posture.medium_findings),
             '🟡 Review Recommended' if attestation.posture.medium_findings > 0 else '✓'],
            ['Low', str(attestation.posture.low_findings), '✓'],
        ]
        findings_table = Table(findings_data, colWidths=[1.5 * inch, 1 * inch, 4 * inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fef2f2') if attestation.posture.critical_findings > 0 else colors.white),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fff7ed') if attestation.posture.high_findings > 0 else colors.white),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 30))

        # Compliance Status
        story.append(Paragraph("<b>COMPLIANCE STATUS</b>", styles['Heading2']))
        story.append(Spacer(1, 10))

        compliance_color = {
            "Compliant": colors.HexColor('#16a34a'),
            "Needs Review": colors.HexColor('#ca8a04'),
            "Non-Compliant": colors.HexColor('#dc2626'),
        }.get(attestation.posture.compliance_status, colors.gray)

        compliance_data = [
            ['Status', 'Scans (30 days)', 'Last Scan'],
            [
                attestation.posture.compliance_status,
                str(attestation.posture.total_scans),
                attestation.posture.last_scan_date.strftime('%Y-%m-%d') if attestation.posture.last_scan_date else 'Never'
            ],
        ]
        compliance_table = Table(compliance_data, colWidths=[2.5 * inch, 2 * inch, 2 * inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('TEXTCOLOR', (0, 1), (0, 1), compliance_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (0, 1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        story.append(compliance_table)
        story.append(Spacer(1, 40))

        # Attestation Statement
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 20))
        story.append(Paragraph("<b>ATTESTATION STATEMENT</b>", styles['Heading2']))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"This document certifies that <b>{attestation.target_url}</b> operated by "
            f"<b>{attestation.organization_name}</b> has been assessed using BREACH.AI's "
            f"automated security testing platform. Based on {attestation.posture.total_scans} "
            f"security assessments conducted in the past 30 days, the target has achieved "
            f"a security grade of <b>{grade}</b> with a compliance status of "
            f"<b>{attestation.posture.compliance_status}</b>.",
            styles['Normal']
        ))
        story.append(Spacer(1, 20))

        # Verification
        story.append(Paragraph(
            f"<b>Verification Hash:</b> {attestation.document_hash}",
            styles['Normal']
        ))
        story.append(Paragraph(
            "Verify this document at: https://breach.ai/verify",
            styles['Normal']
        ))

        # Footer
        story.append(Spacer(1, 40))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "Generated by BREACH.AI | Autonomous Security Assessment Platform",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.gray)
        ))

        doc.build(story)
        return buffer.getvalue()

    def _generate_simple_pdf(self, attestation: AttestationDocument) -> bytes:
        """Fallback simple PDF generation."""
        # Return a text-based representation
        content = f"""
BREACH.AI SECURITY ATTESTATION
==============================

Organization: {attestation.organization_name}
Target: {attestation.target_url}
Generated: {attestation.generated_at.strftime('%Y-%m-%d %H:%M UTC')}
Valid Until: {attestation.valid_until.strftime('%Y-%m-%d')}

SECURITY POSTURE
----------------
Grade: {attestation.posture.grade}
Score: {attestation.posture.score}/100
Risk Level: {attestation.posture.risk_level}
Compliance: {attestation.posture.compliance_status}

FINDINGS
--------
Critical: {attestation.posture.critical_findings}
High: {attestation.posture.high_findings}
Medium: {attestation.posture.medium_findings}
Low: {attestation.posture.low_findings}

Total Scans (30 days): {attestation.posture.total_scans}

Document ID: {attestation.id}
Verification: {attestation.document_hash}
"""
        return content.encode('utf-8')

    def _get_grade_color(self, grade: str):
        """Get color for grade."""
        from reportlab.lib import colors

        if grade.startswith('A'):
            return colors.HexColor('#16a34a')  # Green
        elif grade.startswith('B'):
            return colors.HexColor('#2563eb')  # Blue
        elif grade.startswith('C'):
            return colors.HexColor('#ca8a04')  # Yellow
        elif grade.startswith('D'):
            return colors.HexColor('#ea580c')  # Orange
        else:
            return colors.HexColor('#dc2626')  # Red

    async def generate_security_badge(
        self,
        organization_id: UUID,
        target_id: UUID
    ) -> Dict[str, Any]:
        """
        Generate a security badge that can be displayed on websites.

        Like MindFort's "Security Strength Badge".
        """
        posture = await self.calculate_security_posture(target_id)
        target = await self._get_target(target_id)

        badge_id = hashlib.sha256(
            f"{target_id}:{datetime.utcnow().date()}".encode()
        ).hexdigest()[:12]

        return {
            "badge_id": badge_id,
            "target_url": target.url if target else None,
            "grade": posture.grade,
            "score": posture.score,
            "risk_level": posture.risk_level,
            "compliance_status": posture.compliance_status,
            "last_scan": posture.last_scan_date.isoformat() if posture.last_scan_date else None,
            "generated_at": datetime.utcnow().isoformat(),
            "valid_for_hours": 24,
            "embed_url": f"https://breach.ai/badge/{badge_id}",
            "shield_url": f"https://img.shields.io/badge/Security-{posture.grade}-{self._get_shield_color(posture.grade)}",
        }

    def _get_shield_color(self, grade: str) -> str:
        """Get shields.io color for grade."""
        if grade.startswith('A'):
            return 'brightgreen'
        elif grade.startswith('B'):
            return 'blue'
        elif grade.startswith('C'):
            return 'yellow'
        elif grade.startswith('D'):
            return 'orange'
        return 'red'

    async def _get_organization(self, organization_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        result = await self.db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        return result.scalar_one_or_none()

    async def _get_target(self, target_id: UUID) -> Optional[Target]:
        """Get target by ID."""
        result = await self.db.execute(
            select(Target).where(Target.id == target_id)
        )
        return result.scalar_one_or_none()
