"""
BREACH.AI v2 - Brutal Report Generator

Generates the kind of report that makes executives lose sleep.
Not a list of CVEs - a proof of total compromise.

Supports both:
- BreachSession (from killchain orchestrator)
- AssessmentResults (from BrutalAssessment)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import json
import os
import zipfile
import base64
import structlog
from io import BytesIO

from breach.core.killchain import (
    BreachSession,
    BreachStep,
    BreachPhase,
)
from breach.core.memory import (
    Evidence,
    AccessLevel,
    Severity,
)

# Alias for backward compatibility
EvidenceType = str  # Simple string type for evidence type


class BrutalReportGenerator:
    """
    Generate the Brutal Report - proof of breach, not just vulnerabilities.

    The report structure:
    1. Executive Summary - "We own your infrastructure"
    2. Attack Timeline - Step by step breach path
    3. Evidence Gallery - Screenshots, data samples, proof
    4. Attack Chain Visualization - How we got from A to Z
    5. Business Impact - Real dollar amounts
    6. Remediation Priority - What to fix first
    """

    def generate(self, session: BreachSession) -> dict:
        """Generate the complete brutal report."""
        return {
            "metadata": self._generate_metadata(session),
            "executive_summary": self._generate_executive_summary(session),
            "attack_timeline": self._generate_timeline(session),
            "evidence": self._generate_evidence_section(session),
            "attack_chain": self._generate_attack_chain(session),
            "business_impact": self._generate_business_impact(session),
            "remediation": self._generate_remediation(session),
            "technical_details": self._generate_technical_details(session),
        }

    def generate_markdown(self, session: BreachSession) -> str:
        """Generate report in Markdown format."""
        report = self.generate(session)
        return self._to_markdown(report, session)

    def generate_html(self, session: BreachSession) -> str:
        """Generate report in HTML format."""
        report = self.generate(session)
        return self._to_html(report, session)

    def _generate_metadata(self, session: BreachSession) -> dict:
        """Generate report metadata."""
        return {
            "report_id": session.id,
            "target": session.target,
            "generated_at": datetime.utcnow().isoformat(),
            "assessment_started": session.started_at.isoformat() if session.started_at else None,
            "assessment_completed": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": session.get_duration_seconds(),
            "breach_achieved": session.breach_achieved,
            "highest_access": session.highest_access.value,
        }

    def _generate_executive_summary(self, session: BreachSession) -> dict:
        """Generate the executive summary - the wake-up call."""
        # Determine severity
        if session.highest_access >= AccessLevel.ROOT:
            headline = "CRITICAL: Complete Infrastructure Compromise"
            summary = "We achieved full root access to your systems. An attacker could do anything."
        elif session.highest_access >= AccessLevel.DATABASE:
            headline = "CRITICAL: Full Database Access Achieved"
            summary = "We accessed your production database with all customer data."
        elif session.highest_access >= AccessLevel.ADMIN:
            headline = "HIGH: Administrative Access Achieved"
            summary = "We gained admin-level access to your application."
        elif session.highest_access >= AccessLevel.USER:
            headline = "MEDIUM: User Access Achieved"
            summary = "We bypassed authentication and accessed user-level functionality."
        else:
            headline = "Vulnerabilities Found"
            summary = "We identified security issues that could lead to compromise."

        # What was accessed
        accessed = []
        for step in session.get_successful_steps():
            if step.result and step.result.data_extracted:
                accessed.append({
                    "system": step.target or session.target,
                    "data_type": step.result.action,
                })

        # Calculate impact
        total_records = 0
        pii_exposed = False
        for step in session.steps:
            if step.result and step.result.data_extracted:
                data = step.result.data_extracted
                if isinstance(data, dict):
                    total_records += data.get("total_records", 0)
                    if data.get("pii_types"):
                        pii_exposed = True

        return {
            "headline": headline,
            "summary": summary,
            "what_was_accessed": accessed[:10],  # Top 10
            "systems_compromised": session.systems_compromised,
            "total_records_exposed": total_records,
            "pii_exposed": pii_exposed,
            "evidence_count": len(session.evidence_collected),
        }

    def _generate_timeline(self, session: BreachSession) -> list[dict]:
        """Generate attack timeline - step by step."""
        timeline = []

        for step in session.steps:
            if step.started_at:
                elapsed = (step.started_at - session.started_at).total_seconds() if session.started_at else 0

                entry = {
                    "timestamp": f"{int(elapsed // 3600):02d}:{int((elapsed % 3600) // 60):02d}:{int(elapsed % 60):02d}",
                    "elapsed_seconds": elapsed,
                    "phase": step.phase.display_name,
                    "action": step.action,
                    "module": step.module_name,
                    "target": step.target,
                    "success": step.success,
                    "details": step.result.details if step.result else step.error,
                }

                # Add access level changes
                if step.result and step.result.access_gained:
                    entry["access_gained"] = step.result.access_gained.value

                timeline.append(entry)

        return timeline

    def _generate_evidence_section(self, session: BreachSession) -> dict:
        """Generate evidence section with all proof."""
        evidence_by_type = {t.value: [] for t in EvidenceType}

        for evidence in session.evidence_collected:
            evidence_dict = evidence.to_dict()
            evidence_by_type[evidence.evidence_type.value].append(evidence_dict)

        # Create summary
        return {
            "total_count": len(session.evidence_collected),
            "by_type": {
                k: len(v) for k, v in evidence_by_type.items() if v
            },
            "screenshots": evidence_by_type.get(EvidenceType.SCREENSHOT.value, []),
            "data_samples": evidence_by_type.get(EvidenceType.DATA_SAMPLE.value, []),
            "command_outputs": evidence_by_type.get(EvidenceType.COMMAND_OUTPUT.value, []),
            "credentials": evidence_by_type.get(EvidenceType.CREDENTIAL.value, []),
            "api_responses": evidence_by_type.get(EvidenceType.API_RESPONSE.value, []),
        }

    def _generate_attack_chain(self, session: BreachSession) -> dict:
        """Generate attack chain visualization data."""
        successful_steps = session.get_successful_steps()

        # Build chain
        chain = []
        prev_phase = None

        for step in successful_steps:
            node = {
                "id": step.id,
                "phase": step.phase.value,
                "module": step.module_name,
                "action": step.action,
                "access_gained": step.result.access_gained.value if step.result and step.result.access_gained else None,
            }

            if prev_phase and prev_phase != step.phase:
                node["transition"] = f"{prev_phase.value} → {step.phase.value}"

            chain.append(node)
            prev_phase = step.phase

        # Generate text visualization
        ascii_chain = self._generate_ascii_chain(chain)

        return {
            "nodes": chain,
            "total_steps": len(chain),
            "phases_traversed": list(set(n["phase"] for n in chain)),
            "ascii_visualization": ascii_chain,
        }

    def _generate_ascii_chain(self, chain: list[dict]) -> str:
        """Generate ASCII attack chain visualization."""
        if not chain:
            return "No attack chain"

        lines = []
        current_phase = None

        for i, node in enumerate(chain):
            if node["phase"] != current_phase:
                current_phase = node["phase"]
                lines.append(f"\n┌─{'─' * 50}┐")
                lines.append(f"│ PHASE: {current_phase.upper():<42} │")
                lines.append(f"└─{'─' * 50}┘")

            access = f" → {node['access_gained']}" if node.get("access_gained") else ""
            lines.append(f"  │")
            lines.append(f"  ├── {node['module']}: {node['action'][:30]}{access}")

            if i < len(chain) - 1:
                lines.append(f"  │")
                lines.append(f"  ▼")

        return "\n".join(lines)

    def _generate_business_impact(self, session: BreachSession) -> dict:
        """Generate business impact analysis."""
        # Collect impact data from evidence
        total_records = 0
        pii_types = set()

        for step in session.steps:
            if step.result and step.result.data_extracted:
                data = step.result.data_extracted
                if isinstance(data, dict):
                    total_records += data.get("total_records", 0)
                    pii_types.update(data.get("pii_types", []))
                    if data.get("business_impact"):
                        # Use calculated impact from module
                        pass

        # Calculate costs
        # GDPR fines: Up to €20M or 4% of revenue, use $150 per record with PII
        gdpr_cost = total_records * 150 if pii_types else total_records * 50

        # Breach notification: ~$150 per record in US
        notification_cost = total_records * 150

        # Legal/forensics: Minimum $100K for any breach
        legal_cost = max(100000, total_records * 10)

        # Credit monitoring: $25/person for 2 years if PII
        credit_monitoring = total_records * 25 if pii_types else 0

        # Reputation damage: Estimated 5-10% revenue impact
        reputation_cost = 500000  # Conservative estimate

        total_cost = gdpr_cost + notification_cost + legal_cost + credit_monitoring + reputation_cost

        return {
            "records_exposed": total_records,
            "pii_types_exposed": list(pii_types),
            "has_pii": bool(pii_types),
            "cost_breakdown": {
                "gdpr_potential": gdpr_cost,
                "breach_notification": notification_cost,
                "legal_forensics": legal_cost,
                "credit_monitoring": credit_monitoring,
                "reputation_damage": reputation_cost,
            },
            "total_estimated_cost": total_cost,
            "severity_rating": "CRITICAL" if total_cost > 1000000 else "HIGH" if total_cost > 100000 else "MEDIUM",
            "disclaimer": "Estimates based on industry averages. Actual costs may vary significantly.",
        }

    def _generate_remediation(self, session: BreachSession) -> dict:
        """Generate remediation priorities."""
        findings = []

        # Extract findings from steps
        for step in session.get_successful_steps():
            if step.result and step.result.evidence:
                for evidence in step.result.evidence:
                    finding = {
                        "title": evidence.description,
                        "severity": evidence.severity.value,
                        "phase": step.phase.value,
                        "module": step.module_name,
                        "proves": evidence.proves,
                        "priority": self._get_priority(evidence.severity),
                    }
                    findings.append(finding)

        # Sort by priority
        findings.sort(key=lambda f: f["priority"])

        # Group by priority
        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]
        medium = [f for f in findings if f["severity"] == "medium"]
        low = [f for f in findings if f["severity"] in ["low", "info"]]

        return {
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "fix_immediately": [f["title"] for f in critical[:3]],
            "fix_this_week": [f["title"] for f in high[:5]],
            "fix_this_month": [f["title"] for f in medium[:5]],
        }

    def _get_priority(self, severity: Severity) -> int:
        """Get numeric priority from severity."""
        return {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5,
        }.get(severity, 5)

    def _generate_technical_details(self, session: BreachSession) -> dict:
        """Generate technical details section."""
        return {
            "session_id": session.id,
            "target": session.target,
            "scope": session.scope,
            "total_steps": len(session.steps),
            "successful_steps": len(session.get_successful_steps()),
            "phases_completed": list(set(s.phase.value for s in session.steps)),
            "modules_used": list(set(s.module_name for s in session.steps)),
            "duration_seconds": session.get_duration_seconds(),
        }

    def _to_markdown(self, report: dict, session: BreachSession) -> str:
        """Convert report to Markdown format."""
        lines = []

        # Header
        lines.append("# BREACH.AI v2 - BREACH REPORT")
        lines.append("")
        lines.append(f"**Target:** {session.target}")
        lines.append(f"**Generated:** {datetime.utcnow().isoformat()}")
        lines.append(f"**Duration:** {session.get_duration_seconds():.0f} seconds")
        lines.append("")

        # Executive Summary
        summary = report["executive_summary"]
        lines.append("---")
        lines.append("")
        lines.append(f"## {summary['headline']}")
        lines.append("")
        lines.append(summary["summary"])
        lines.append("")

        if summary["what_was_accessed"]:
            lines.append("### What We Accessed:")
            for item in summary["what_was_accessed"]:
                lines.append(f"- {item['system']}: {item['data_type']}")
            lines.append("")

        # Attack Timeline
        lines.append("---")
        lines.append("")
        lines.append("## Attack Timeline")
        lines.append("")
        for entry in report["attack_timeline"][:20]:  # Limit to 20
            status = "✓" if entry["success"] else "✗"
            lines.append(f"**{entry['timestamp']}** [{entry['phase']}] {status} {entry['action']}")
            if entry.get("access_gained"):
                lines.append(f"  → Access: {entry['access_gained']}")
        lines.append("")

        # Attack Chain
        lines.append("---")
        lines.append("")
        lines.append("## Attack Chain")
        lines.append("")
        lines.append("```")
        lines.append(report["attack_chain"]["ascii_visualization"])
        lines.append("```")
        lines.append("")

        # Business Impact
        impact = report["business_impact"]
        lines.append("---")
        lines.append("")
        lines.append("## Business Impact")
        lines.append("")
        lines.append(f"**Total Estimated Cost: ${impact['total_estimated_cost']:,}**")
        lines.append("")
        lines.append("| Category | Cost |")
        lines.append("|----------|------|")
        for category, cost in impact["cost_breakdown"].items():
            lines.append(f"| {category.replace('_', ' ').title()} | ${cost:,} |")
        lines.append("")

        # Remediation
        remediation = report["remediation"]
        lines.append("---")
        lines.append("")
        lines.append("## Remediation Priority")
        lines.append("")
        lines.append("### Fix Immediately (Critical)")
        for item in remediation.get("fix_immediately", []):
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Fix This Week (High)")
        for item in remediation.get("fix_this_week", []):
            lines.append(f"- {item}")
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Generated by BREACH.AI v2 - We don't find vulnerabilities. We prove breaches.*")

        return "\n".join(lines)

    def _to_html(self, report: dict, session: BreachSession) -> str:
        """Convert report to HTML format."""
        # Simplified HTML generation
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>BREACH.AI Report - {session.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }}
        h1, h2, h3 {{ color: #f0c040; }}
        .critical {{ color: #ff4444; font-weight: bold; }}
        .high {{ color: #ff8844; }}
        .medium {{ color: #ffcc44; }}
        .evidence {{ background: #1a1a1a; padding: 15px; border-radius: 8px; margin: 10px 0; }}
        .timeline-entry {{ border-left: 2px solid #f0c040; padding-left: 15px; margin: 10px 0; }}
        .success {{ color: #44ff44; }}
        .failed {{ color: #ff4444; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
        th {{ background: #1a1a1a; }}
        .impact-total {{ font-size: 2em; color: #ff4444; }}
    </style>
</head>
<body>
    <h1>BREACH.AI v2 - BREACH REPORT</h1>
    <p><strong>Target:</strong> {session.target}</p>
    <p><strong>Breach Achieved:</strong> <span class="{'critical' if session.breach_achieved else ''}">{session.breach_achieved}</span></p>

    <h2 class="critical">{report['executive_summary']['headline']}</h2>
    <p>{report['executive_summary']['summary']}</p>

    <h2>Business Impact</h2>
    <p class="impact-total">Estimated Cost: ${report['business_impact']['total_estimated_cost']:,}</p>

    <h2>Attack Timeline</h2>
    {''.join(f'<div class="timeline-entry"><strong>{e["timestamp"]}</strong> [{e["phase"]}] <span class="{"success" if e["success"] else "failed"}">{"✓" if e["success"] else "✗"}</span> {e["action"]}</div>' for e in report['attack_timeline'][:20])}

    <h2>Remediation Priority</h2>
    <h3 class="critical">Fix Immediately</h3>
    <ul>{''.join(f"<li>{item}</li>" for item in report['remediation'].get('fix_immediately', []))}</ul>

    <footer>
        <p><em>Generated by BREACH.AI v2 - We don't find vulnerabilities. We prove breaches.</em></p>
    </footer>
</body>
</html>"""
        return html


# =============================================================================
# ASSESSMENT REPORT GENERATOR - For BrutalAssessment Results
# =============================================================================

class AssessmentReportGenerator:
    """
    Generate comprehensive reports from BrutalAssessment results.

    Output formats:
    - Executive Summary (TXT)
    - Technical Report (HTML)
    - Recommendations (TXT)
    - Evidence Package (ZIP)
    - Machine-readable (JSON)
    """

    def __init__(self, results: Any, output_dir: str = "./breach_output"):
        """
        Initialize report generator.

        Args:
            results: AssessmentResults from BrutalAssessment
            output_dir: Directory for output files
        """
        self.results = results
        self.output_dir = output_dir
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self) -> Dict[str, str]:
        """Generate all report formats."""
        reports = {
            "executive_summary": self.generate_executive_summary(),
            "technical_report": self.generate_technical_report(),
            "recommendations": self.generate_recommendations(),
            "json_export": self.generate_json_export(),
            "evidence_package": self.generate_evidence_package(),
        }

        # Try to generate PDF (optional, requires weasyprint or xhtml2pdf)
        try:
            reports["pdf_report"] = self.generate_pdf_report()
        except ImportError:
            pass  # PDF generation not available
        except Exception as e:
            # Log but don't fail if PDF generation fails
            logger = structlog.get_logger(__name__)
            logger.warning("pdf_generation_failed", error=str(e))

        return reports

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        filepath = os.path.join(self.output_dir, f"executive_summary_{self.timestamp}.txt")

        risk_level = self._get_risk_level()
        critical_count = len(self.results.critical_findings)
        high_count = len(self.results.high_findings)

        summary = f"""
================================================================================
                    BREACH.AI SECURITY ASSESSMENT
                       EXECUTIVE SUMMARY
================================================================================

Target: {self.results.target}
Date: {self.results.started_at.strftime("%Y-%m-%d %H:%M UTC")}
Duration: {self.results.duration_seconds} seconds

================================================================================
                         RISK SUMMARY
================================================================================

Overall Risk Score: {self.results.risk_score}/100 ({risk_level})
Estimated Breach Cost: ${self.results.estimated_breach_cost:,}
Maximum Access Achieved: {self.results.max_access_level.value.upper()}

================================================================================
                       FINDINGS SUMMARY
================================================================================

Total Vulnerabilities: {self.results.total_findings}

  CRITICAL: {critical_count:3d}  [IMMEDIATE ACTION REQUIRED]
  HIGH:     {high_count:3d}  [Fix within 7 days]
  MEDIUM:   {len(self.results.medium_findings):3d}  [Fix within 30 days]
  LOW:      {len(self.results.low_findings):3d}  [Fix during maintenance]
  INFO:     {len(self.results.info_findings):3d}  [For awareness]

================================================================================
                    TOP CRITICAL FINDINGS
================================================================================
{self._format_top_findings()}
================================================================================
                       ATTACK PATH
================================================================================
{self._format_attack_path()}
================================================================================
                   IMMEDIATE ACTIONS
================================================================================

1. Address all {critical_count} CRITICAL findings immediately
2. Schedule fixes for {high_count} HIGH severity issues within 7 days
3. Plan remediation for MEDIUM issues within 30 days
4. Review LOW findings during maintenance cycles

================================================================================

Generated by BREACH.AI Autonomous Security Engine
{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}

================================================================================
"""
        with open(filepath, 'w') as f:
            f.write(summary)
        return filepath

    def generate_technical_report(self) -> str:
        """Generate detailed HTML technical report."""
        filepath = os.path.join(self.output_dir, f"technical_report_{self.timestamp}.html")

        findings_html = self._generate_findings_html()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BREACH.AI Security Assessment</title>
    <style>
        :root {{
            --critical: #dc2626; --high: #ea580c; --medium: #ca8a04;
            --low: #16a34a; --info: #2563eb;
            --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 40px 20px; border-bottom: 1px solid #334155; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: var(--card); border-radius: 8px; padding: 20px; text-align: center; }}
        .card h3 {{ font-size: 0.85rem; color: var(--muted); margin-bottom: 8px; }}
        .card .value {{ font-size: 1.8rem; font-weight: bold; }}
        .risk-score {{ color: {self._get_risk_color()}; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ font-size: 1.4rem; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #334155; }}
        .finding {{ background: var(--card); border-radius: 8px; padding: 20px; margin-bottom: 15px; border-left: 4px solid; }}
        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}
        .finding.info {{ border-color: var(--info); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-weight: bold; }}
        .badge {{ padding: 4px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); }}
        .badge.low {{ background: var(--low); }}
        .badge.info {{ background: var(--info); }}
        .finding-meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 10px; }}
        .rec-box {{ background: rgba(37, 99, 235, 0.1); border: 1px solid var(--info); border-radius: 4px; padding: 15px; margin-top: 15px; }}
        .rec-box h4 {{ color: var(--info); margin-bottom: 8px; }}
        pre {{ background: var(--bg); padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; white-space: pre-wrap; }}
        .footer {{ text-align: center; padding: 30px; color: var(--muted); border-top: 1px solid #334155; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BREACH.AI Security Assessment</h1>
            <p style="color: var(--muted);">{self.results.target}</p>
            <p style="color: var(--muted); margin-top: 10px;">
                {self.results.started_at.strftime("%Y-%m-%d %H:%M UTC")} |
                Duration: {self.results.duration_seconds}s |
                {self.results.modules_executed} modules
            </p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Risk Score</h3>
                <div class="value risk-score">{self.results.risk_score}/100</div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">{self.results.total_findings}</div>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="value" style="color: var(--critical);">{len(self.results.critical_findings)}</div>
            </div>
            <div class="card">
                <h3>Breach Cost</h3>
                <div class="value">${self.results.estimated_breach_cost:,}</div>
            </div>
            <div class="card">
                <h3>Max Access</h3>
                <div class="value">{self.results.max_access_level.value}</div>
            </div>
        </div>

        {findings_html}

        <div class="footer">
            <p>Generated by BREACH.AI Autonomous Security Engine</p>
            <p>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </div>
    </div>
</body>
</html>"""

        with open(filepath, 'w') as f:
            f.write(html)
        return filepath

    def generate_recommendations(self) -> str:
        """Generate recommendations report."""
        filepath = os.path.join(self.output_dir, f"recommendations_{self.timestamp}.txt")

        all_findings = (
            self.results.critical_findings +
            self.results.high_findings +
            self.results.medium_findings +
            self.results.low_findings
        )

        report = f"""
================================================================================
               BREACH.AI - REMEDIATION RECOMMENDATIONS
================================================================================

Target: {self.results.target}
Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
Findings Requiring Remediation: {len(all_findings)}

================================================================================
                   PRIORITIZED REMEDIATION
================================================================================
"""

        for i, finding in enumerate(all_findings, 1):
            severity_icon = {
                Severity.CRITICAL: "[!!!]",
                Severity.HIGH: "[!!]",
                Severity.MEDIUM: "[!]",
                Severity.LOW: "[*]",
            }.get(finding.severity, "[*]")

            fix = finding.fix_guidance or finding.recommendation or "See technical documentation."
            if len(fix) > 800:
                fix = fix[:800] + "\n... [truncated - see full report]"

            report += f"""
{i}. {severity_icon} {finding.title}
   ID: {finding.id}
   Severity: {finding.severity.value.upper()}
   Component: {finding.affected_component}
   CWE: {finding.cwe_id or 'N/A'}

   {finding.description[:300]}{'...' if len(finding.description) > 300 else ''}

   FIX:
   {fix}

"""

        report += f"""
================================================================================
                    STRATEGIC RECOMMENDATIONS
================================================================================

1. IMMEDIATE (0-7 days): Address {len(self.results.critical_findings)} CRITICAL findings
2. SHORT-TERM (1-4 weeks): Fix {len(self.results.high_findings)} HIGH severity issues
3. MEDIUM-TERM (1-3 months): Remediate MEDIUM issues
4. ONGOING: Address LOW issues in maintenance cycles

================================================================================

Generated by BREACH.AI Autonomous Security Engine

================================================================================
"""

        with open(filepath, 'w') as f:
            f.write(report)
        return filepath

    def generate_json_export(self) -> str:
        """Generate JSON export."""
        filepath = os.path.join(self.output_dir, f"assessment_{self.timestamp}.json")

        data = self.results.to_dict()
        data['metadata'] = {
            'generated_at': datetime.utcnow().isoformat(),
            'generator': 'BREACH.AI',
            'version': '2.0',
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def generate_evidence_package(self) -> str:
        """Generate evidence ZIP package."""
        filepath = os.path.join(self.output_dir, f"evidence_{self.timestamp}.zip")

        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('summary.json', json.dumps(self.results.to_dict(), indent=2, default=str))
            zf.writestr('module_results.json', json.dumps(self.results.module_results, indent=2))

            for i, finding in enumerate(self.results.critical_findings):
                content = self._format_finding(finding)
                zf.writestr(f'critical/{finding.id}.txt', content)

            for i, finding in enumerate(self.results.high_findings):
                content = self._format_finding(finding)
                zf.writestr(f'high/{finding.id}.txt', content)

        return filepath

    def generate_pdf_report(self) -> str:
        """
        Generate PDF report from HTML.

        Requires weasyprint or xhtml2pdf to be installed.
        Install with: pip install weasyprint
        or: pip install xhtml2pdf
        """
        filepath = os.path.join(self.output_dir, f"report_{self.timestamp}.pdf")

        # Get HTML content
        html_filepath = self.generate_technical_report()
        with open(html_filepath, 'r') as f:
            html_content = f.read()

        # Try weasyprint first (better quality)
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(filepath)
            return filepath
        except ImportError:
            pass

        # Fall back to xhtml2pdf
        try:
            from xhtml2pdf import pisa

            with open(filepath, 'wb') as pdf_file:
                pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)

            if pisa_status.err:
                raise Exception(f"PDF generation error: {pisa_status.err}")

            return filepath
        except ImportError:
            pass

        # Final fallback: try reportlab directly
        try:
            return self._generate_pdf_reportlab(filepath)
        except ImportError:
            raise ImportError(
                "PDF generation requires one of: weasyprint, xhtml2pdf, or reportlab. "
                "Install with: pip install weasyprint"
            )

    def _generate_pdf_reportlab(self, filepath: str) -> str:
        """Generate PDF using reportlab directly."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='Title_Custom',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#dc2626')
        ))
        styles.add(ParagraphStyle(
            name='Critical',
            parent=styles['Normal'],
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        ))
        styles.add(ParagraphStyle(
            name='High',
            parent=styles['Normal'],
            textColor=colors.HexColor('#ea580c'),
            fontName='Helvetica-Bold'
        ))

        story = []

        # Title
        story.append(Paragraph("BREACH.AI Security Assessment", styles['Title_Custom']))
        story.append(Paragraph(f"Target: {self.results.target}", styles['Normal']))
        story.append(Paragraph(f"Date: {self.results.started_at.strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Summary Table
        summary_data = [
            ['Risk Score', f'{self.results.risk_score}/100'],
            ['Total Findings', str(self.results.total_findings)],
            ['Critical', str(len(self.results.critical_findings))],
            ['High', str(len(self.results.high_findings))],
            ['Estimated Breach Cost', f'${self.results.estimated_breach_cost:,}'],
        ]
        summary_table = Table(summary_data, colWidths=[2.5 * inch, 3 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#334155'))
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Critical Findings
        if self.results.critical_findings:
            story.append(Paragraph("Critical Findings", styles['Heading1']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dc2626')))
            story.append(Spacer(1, 10))

            for finding in self.results.critical_findings[:10]:
                story.append(Paragraph(f"[CRITICAL] {self._escape(finding.title)}", styles['Critical']))
                story.append(Paragraph(self._escape(finding.description[:300]), styles['Normal']))
                story.append(Spacer(1, 10))

        # High Findings
        if self.results.high_findings:
            story.append(PageBreak())
            story.append(Paragraph("High Severity Findings", styles['Heading1']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#ea580c')))
            story.append(Spacer(1, 10))

            for finding in self.results.high_findings[:10]:
                story.append(Paragraph(f"[HIGH] {self._escape(finding.title)}", styles['High']))
                story.append(Paragraph(self._escape(finding.description[:300]), styles['Normal']))
                story.append(Spacer(1, 10))

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.gray))
        story.append(Paragraph(
            f"Generated by BREACH.AI - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles['Normal']
        ))

        doc.build(story)
        return filepath

    def _get_risk_level(self) -> str:
        """Get risk level string."""
        score = self.results.risk_score
        if score >= 75: return "CRITICAL"
        elif score >= 50: return "HIGH"
        elif score >= 25: return "MEDIUM"
        return "LOW"

    def _get_risk_color(self) -> str:
        """Get risk color for HTML."""
        level = self._get_risk_level()
        return {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(level, "#2563eb")

    def _format_top_findings(self) -> str:
        """Format top findings for summary."""
        findings = self.results.critical_findings[:5]
        if not findings:
            return "  No critical findings identified.\n"
        return '\n'.join([f"  {i}. [{f.severity.value.upper()}] {f.title}" for i, f in enumerate(findings, 1)])

    def _format_attack_path(self) -> str:
        """Format attack path."""
        if not self.results.access_chain:
            return "  No attack chain established.\n"
        return '\n'.join([f"  {i}. {step}" for i, step in enumerate(self.results.access_chain, 1)])

    def _generate_findings_html(self) -> str:
        """Generate HTML for all findings."""
        html = ""
        for severity, findings, sev_class in [
            ("Critical", self.results.critical_findings, "critical"),
            ("High", self.results.high_findings, "high"),
            ("Medium", self.results.medium_findings, "medium"),
            ("Low", self.results.low_findings, "low"),
        ]:
            if findings:
                html += f'<div class="section"><h2>{severity} Findings ({len(findings)})</h2>'
                for f in findings:
                    rec = ""
                    if f.fix_guidance:
                        truncated = f.fix_guidance[:600] + "..." if len(f.fix_guidance) > 600 else f.fix_guidance
                        rec = f'<div class="rec-box"><h4>Recommendation</h4><pre>{self._escape(truncated)}</pre></div>'
                    html += f'''
                    <div class="finding {sev_class}">
                        <div class="finding-header">
                            <span class="finding-title">{self._escape(f.title)}</span>
                            <span class="badge {sev_class}">{f.severity.value}</span>
                        </div>
                        <div class="finding-meta">
                            {f.id} | {self._escape(f.affected_component)} | {f.cwe_id or 'N/A'}
                        </div>
                        <p>{self._escape(f.description[:400])}{"..." if len(f.description) > 400 else ""}</p>
                        {rec}
                    </div>'''
                html += '</div>'
        return html

    def _format_finding(self, finding) -> str:
        """Format finding for evidence package."""
        return f"""ID: {finding.id}
Title: {finding.title}
Severity: {finding.severity.value}
Component: {finding.affected_component}
CWE: {finding.cwe_id or 'N/A'}

Description:
{finding.description}

Recommendation:
{finding.fix_guidance or finding.recommendation or 'N/A'}
"""

    def _escape(self, text: str) -> str:
        """Escape HTML."""
        if not text: return ""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def generate_assessment_report(results, output_dir: str = "./breach_output") -> Dict[str, str]:
    """
    Convenience function to generate all assessment reports.

    Args:
        results: AssessmentResults from BrutalAssessment
        output_dir: Output directory

    Returns:
        Dictionary mapping report type to file path
    """
    generator = AssessmentReportGenerator(results, output_dir)
    return generator.generate_all()
