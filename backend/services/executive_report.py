"""
BREACH.AI - Executive Summary Report Generator
===============================================

Generates executive-friendly PDF reports suitable for:
- Board presentations
- Compliance audits
- Client deliverables
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID
from io import BytesIO

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Scan, Finding, Target, ScanStatus, Severity
import structlog

logger = structlog.get_logger(__name__)


class ExecutiveSummaryReport:
    """Generate executive summary reports."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_summary(
        self,
        target_id: UUID,
        lookback_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Generate executive summary data.

        Returns structured data that can be rendered into various formats.
        """
        # Get target
        result = await self.db.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()
        if not target:
            raise ValueError(f"Target {target_id} not found")

        cutoff = datetime.utcnow() - timedelta(days=lookback_days)

        # Get scans in period
        scans_result = await self.db.execute(
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.completed_at >= cutoff,
            )
            .order_by(Scan.completed_at.desc())
        )
        scans = scans_result.scalars().all()

        # Get all findings from these scans
        all_findings = []
        for scan in scans:
            findings_result = await self.db.execute(
                select(Finding).where(Finding.scan_id == scan.id)
            )
            all_findings.extend(findings_result.scalars().all())

        # Calculate metrics
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        categories = {}
        for finding in all_findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev.lower() in severity_counts:
                severity_counts[sev.lower()] += 1

            cat = finding.category
            categories[cat] = categories.get(cat, 0) + 1

        # Top categories
        top_categories = sorted(
            categories.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        grade = self._score_to_grade(risk_score)

        # Trend analysis (if multiple scans)
        trend = "stable"
        if len(scans) >= 2:
            # Get findings count for first and last scan
            first_scan = scans[-1]
            last_scan = scans[0]

            first_count_result = await self.db.execute(
                select(func.count(Finding.id)).where(Finding.scan_id == first_scan.id)
            )
            first_count = first_count_result.scalar() or 0

            last_count_result = await self.db.execute(
                select(func.count(Finding.id)).where(Finding.scan_id == last_scan.id)
            )
            last_count = last_count_result.scalar() or 0

            if last_count < first_count * 0.8:
                trend = "improving"
            elif last_count > first_count * 1.2:
                trend = "worsening"

        # Get critical findings for highlights
        critical_findings = [
            f for f in all_findings
            if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).lower() == "critical"
        ][:5]

        return {
            "target": {
                "id": str(target.id),
                "url": target.url,
                "name": target.name or target.url,
            },
            "period": {
                "start": cutoff.isoformat(),
                "end": datetime.utcnow().isoformat(),
                "days": lookback_days,
            },
            "summary": {
                "total_scans": len(scans),
                "total_findings": len(all_findings),
                "unique_findings": len(set(f.title for f in all_findings)),
                "risk_score": risk_score,
                "grade": grade,
                "trend": trend,
            },
            "severity_breakdown": severity_counts,
            "top_vulnerability_categories": [
                {"category": cat, "count": count} for cat, count in top_categories
            ],
            "critical_highlights": [
                {
                    "title": f.title,
                    "category": f.category,
                    "endpoint": f.affected_endpoint,
                }
                for f in critical_findings
            ],
            "recommendations": self._generate_recommendations(severity_counts, categories),
            "generated_at": datetime.utcnow().isoformat(),
        }

    async def generate_pdf(
        self,
        target_id: UUID,
        lookback_days: int = 30,
    ) -> bytes:
        """Generate PDF report."""
        summary = await self.generate_summary(target_id, lookback_days)
        html = self._render_html(summary)

        # Try to use weasyprint for PDF
        try:
            from weasyprint import HTML
            pdf_buffer = BytesIO()
            HTML(string=html).write_pdf(pdf_buffer)
            return pdf_buffer.getvalue()
        except ImportError:
            # Fallback: return HTML as PDF-like content
            # In production, you'd use a PDF service
            logger.warning("weasyprint not installed, returning HTML")
            return html.encode('utf-8')

    async def generate_html(
        self,
        target_id: UUID,
        lookback_days: int = 30,
    ) -> str:
        """Generate HTML report."""
        summary = await self.generate_summary(target_id, lookback_days)
        return self._render_html(summary)

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100, lower is better)."""
        # Weighted scoring
        weights = {
            "critical": 25,
            "high": 10,
            "medium": 4,
            "low": 1,
            "info": 0,
        }

        total_penalty = sum(
            count * weights.get(sev, 0)
            for sev, count in severity_counts.items()
        )

        # Cap at 100
        return min(100, total_penalty)

    def _score_to_grade(self, risk_score: int) -> str:
        """Convert risk score to letter grade."""
        security_score = 100 - risk_score
        if security_score >= 95:
            return "A+"
        elif security_score >= 90:
            return "A"
        elif security_score >= 85:
            return "A-"
        elif security_score >= 80:
            return "B+"
        elif security_score >= 75:
            return "B"
        elif security_score >= 70:
            return "B-"
        elif security_score >= 65:
            return "C+"
        elif security_score >= 60:
            return "C"
        elif security_score >= 55:
            return "C-"
        elif security_score >= 50:
            return "D"
        else:
            return "F"

    def _generate_recommendations(
        self,
        severity_counts: Dict[str, int],
        categories: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Critical/High findings are urgent
        if severity_counts.get("critical", 0) > 0:
            recommendations.append({
                "priority": 1,
                "title": "Address Critical Vulnerabilities Immediately",
                "description": f"You have {severity_counts['critical']} critical vulnerabilities that could lead to complete system compromise.",
                "action": "Schedule emergency remediation within 24-48 hours",
            })

        if severity_counts.get("high", 0) > 0:
            recommendations.append({
                "priority": 2,
                "title": "Remediate High-Severity Issues",
                "description": f"You have {severity_counts['high']} high-severity vulnerabilities that pose significant risk.",
                "action": "Plan remediation within 1-2 weeks",
            })

        # Category-specific recommendations
        for category, count in sorted(categories.items(), key=lambda x: -x[1])[:3]:
            recommendations.append({
                "priority": 3,
                "title": f"Review {category} Security",
                "description": f"{count} findings related to {category} were discovered.",
                "action": f"Conduct focused security review of {category} implementation",
            })

        # General recommendations
        if severity_counts.get("medium", 0) > 5:
            recommendations.append({
                "priority": 4,
                "title": "Establish Regular Security Testing",
                "description": "Multiple medium-severity findings suggest gaps in security testing.",
                "action": "Implement continuous security scanning and regular penetration testing",
            })

        return recommendations[:5]  # Top 5 recommendations

    def _render_html(self, summary: Dict[str, Any]) -> str:
        """Render summary data as HTML report."""
        grade_color = {
            "A+": "#22c55e", "A": "#22c55e", "A-": "#22c55e",
            "B+": "#3b82f6", "B": "#3b82f6", "B-": "#3b82f6",
            "C+": "#eab308", "C": "#eab308", "C-": "#eab308",
            "D": "#f97316",
            "F": "#ef4444",
        }.get(summary["summary"]["grade"], "#6b7280")

        trend_icon = {
            "improving": "↑",
            "worsening": "↓",
            "stable": "→",
        }.get(summary["summary"]["trend"], "→")

        trend_color = {
            "improving": "#22c55e",
            "worsening": "#ef4444",
            "stable": "#6b7280",
        }.get(summary["summary"]["trend"], "#6b7280")

        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Executive Summary - {summary["target"]["name"]}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
        .container {{ max-width: 900px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .logo {{ font-size: 28px; font-weight: 700; color: #d97706; margin-bottom: 8px; }}
        .subtitle {{ color: #64748b; font-size: 14px; }}
        .card {{ background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; }}
        .card-title {{ font-size: 18px; font-weight: 600; color: #0f172a; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
        .grade-box {{ display: flex; justify-content: center; align-items: center; width: 120px; height: 120px; border-radius: 50%; background: {grade_color}20; margin: 20px auto; }}
        .grade {{ font-size: 48px; font-weight: 700; color: {grade_color}; }}
        .score-row {{ display: flex; justify-content: space-around; text-align: center; margin-top: 20px; }}
        .score-item {{ }}
        .score-value {{ font-size: 24px; font-weight: 600; color: #0f172a; }}
        .score-label {{ font-size: 12px; color: #64748b; }}
        .severity-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
        .severity-item {{ padding: 16px; border-radius: 8px; text-align: center; }}
        .severity-critical {{ background: #fef2f2; color: #dc2626; }}
        .severity-high {{ background: #fff7ed; color: #ea580c; }}
        .severity-medium {{ background: #fefce8; color: #ca8a04; }}
        .severity-low {{ background: #eff6ff; color: #2563eb; }}
        .severity-count {{ font-size: 32px; font-weight: 700; }}
        .severity-label {{ font-size: 12px; text-transform: uppercase; }}
        .category-list {{ }}
        .category-item {{ display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #e2e8f0; }}
        .category-name {{ font-weight: 500; }}
        .category-count {{ background: #f1f5f9; padding: 2px 8px; border-radius: 12px; font-size: 12px; }}
        .rec-list {{ }}
        .rec-item {{ padding: 16px; background: #f8fafc; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid #d97706; }}
        .rec-priority {{ font-size: 11px; color: #d97706; font-weight: 600; text-transform: uppercase; }}
        .rec-title {{ font-weight: 600; margin: 4px 0; }}
        .rec-desc {{ font-size: 14px; color: #64748b; }}
        .trend {{ display: inline-flex; align-items: center; gap: 4px; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; background: {trend_color}20; color: {trend_color}; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; }}
        .highlight {{ background: #fef3c7; padding: 16px; border-radius: 8px; margin-bottom: 12px; }}
        .highlight-title {{ font-weight: 600; color: #92400e; }}
        .highlight-meta {{ font-size: 12px; color: #a16207; }}
        @media print {{
            body {{ background: white; }}
            .card {{ box-shadow: none; border: 1px solid #e2e8f0; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">BREACH.AI</div>
            <div class="subtitle">Security Executive Summary</div>
        </div>

        <div class="card">
            <div class="card-title">Target: {summary["target"]["name"]}</div>
            <p style="color: #64748b; font-size: 14px;">
                Report Period: {summary["period"]["days"]} days | Generated: {summary["generated_at"][:10]}
            </p>

            <div class="grade-box">
                <span class="grade">{summary["summary"]["grade"]}</span>
            </div>

            <div class="score-row">
                <div class="score-item">
                    <div class="score-value">{summary["summary"]["total_scans"]}</div>
                    <div class="score-label">Total Scans</div>
                </div>
                <div class="score-item">
                    <div class="score-value">{summary["summary"]["total_findings"]}</div>
                    <div class="score-label">Total Findings</div>
                </div>
                <div class="score-item">
                    <span class="trend">{trend_icon} {summary["summary"]["trend"].title()}</span>
                    <div class="score-label" style="margin-top: 4px;">Trend</div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Severity Distribution</div>
            <div class="severity-grid">
                <div class="severity-item severity-critical">
                    <div class="severity-count">{summary["severity_breakdown"]["critical"]}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-item severity-high">
                    <div class="severity-count">{summary["severity_breakdown"]["high"]}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-item severity-medium">
                    <div class="severity-count">{summary["severity_breakdown"]["medium"]}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-item severity-low">
                    <div class="severity-count">{summary["severity_breakdown"]["low"]}</div>
                    <div class="severity-label">Low</div>
                </div>
            </div>
        </div>

        {self._render_critical_highlights(summary.get("critical_highlights", []))}

        <div class="card">
            <div class="card-title">Top Vulnerability Categories</div>
            <div class="category-list">
                {"".join(f'<div class="category-item"><span class="category-name">{cat["category"]}</span><span class="category-count">{cat["count"]} findings</span></div>' for cat in summary["top_vulnerability_categories"])}
            </div>
        </div>

        <div class="card">
            <div class="card-title">Recommendations</div>
            <div class="rec-list">
                {"".join(f'<div class="rec-item"><div class="rec-priority">Priority {rec["priority"]}</div><div class="rec-title">{rec["title"]}</div><div class="rec-desc">{rec["description"]}</div></div>' for rec in summary["recommendations"])}
            </div>
        </div>

        <div class="footer">
            <p>Generated by BREACH.AI | Confidential</p>
            <p style="margin-top: 4px;">{summary["generated_at"]}</p>
        </div>
    </div>
</body>
</html>'''

    def _render_critical_highlights(self, highlights: List[Dict]) -> str:
        """Render critical highlights section."""
        if not highlights:
            return ""

        items = "".join(
            f'<div class="highlight"><div class="highlight-title">{h["title"]}</div><div class="highlight-meta">{h["category"]} | {h.get("endpoint", "N/A")}</div></div>'
            for h in highlights
        )

        return f'''
        <div class="card">
            <div class="card-title" style="color: #dc2626;">Critical Findings</div>
            {items}
        </div>
        '''
