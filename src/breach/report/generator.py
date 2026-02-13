"""
BREACH.AI - Report Generator

Generates brutal, evidence-based security reports.
Reports designed to create urgency - show exactly what an attacker would do.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from breach.core.memory import Memory, Finding, Severity, AccessLevel
from breach.utils.helpers import format_duration, safe_filename
from breach.utils.logger import logger


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_dir: str = "./reports"
    include_evidence: bool = True
    include_poc_scripts: bool = True
    include_timeline: bool = True
    include_recommendations: bool = True
    redact_sensitive: bool = False
    format: str = "html"  # html, json, markdown


@dataclass
class ReportData:
    """Data structure for report generation."""
    target: str
    scan_start: datetime
    scan_end: datetime
    duration: str

    # Verdict
    verdict: str  # FULLY_COMPROMISED, SEVERELY_COMPROMISED, MODERATELY_VULNERABLE, MINIMALLY_VULNERABLE, SECURE
    verdict_color: str
    verdict_description: str

    # Summary stats
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    # Access achieved
    access_level: str
    access_description: str

    # Findings
    findings: list[dict] = field(default_factory=list)

    # Timeline
    timeline: list[dict] = field(default_factory=list)

    # Attack surface
    subdomains: list[str] = field(default_factory=list)
    endpoints_count: int = 0
    technologies: list[str] = field(default_factory=list)

    # Evidence
    poc_scripts: list[dict] = field(default_factory=list)

    # Recommendations
    recommendations: list[dict] = field(default_factory=list)


class ReportGenerator:
    """
    Generates comprehensive security assessment reports.

    Reports are designed to be "brutal" - showing exactly what
    an attacker could achieve with the discovered vulnerabilities.
    """

    VERDICTS = {
        "FULLY_COMPROMISED": {
            "color": "#dc3545",
            "description": "Critical vulnerabilities allow complete system compromise. Immediate action required.",
            "threshold": lambda c, h, m: c >= 1 or h >= 3,
        },
        "SEVERELY_COMPROMISED": {
            "color": "#fd7e14",
            "description": "High-severity vulnerabilities present significant risk. Urgent remediation needed.",
            "threshold": lambda c, h, m: h >= 1 or m >= 5,
        },
        "MODERATELY_VULNERABLE": {
            "color": "#ffc107",
            "description": "Medium-severity issues found. Should be addressed in planned maintenance.",
            "threshold": lambda c, h, m: m >= 1,
        },
        "MINIMALLY_VULNERABLE": {
            "color": "#28a745",
            "description": "Only low-severity or informational findings. Good security posture.",
            "threshold": lambda c, h, m: True,
        },
        "SECURE": {
            "color": "#20c997",
            "description": "No vulnerabilities found. Excellent security posture.",
            "threshold": lambda c, h, m: False,  # Only if no findings
        },
    }

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()

        # Ensure output directory exists
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)

        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        if template_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.env = None

    async def generate(self, result, memory: Memory) -> str:
        """
        Generate a complete report from scan results.

        Args:
            result: ScanResult from the agent
            memory: Memory containing all findings and evidence

        Returns:
            Path to generated report
        """
        logger.info("Generating report...")

        # Build report data
        report_data = self._build_report_data(result, memory)

        # Generate report based on format
        if self.config.format == "html":
            report_path = await self._generate_html(report_data)
        elif self.config.format == "json":
            report_path = await self._generate_json(report_data)
        elif self.config.format == "markdown":
            report_path = await self._generate_markdown(report_data)
        else:
            report_path = await self._generate_html(report_data)

        logger.info(f"Report generated: {report_path}")
        return report_path

    def _build_report_data(self, result, memory: Memory) -> ReportData:
        """Build the report data structure."""
        # Calculate counts
        counts = memory.severity_counts()
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        medium = counts.get("medium", 0)
        low = counts.get("low", 0)
        info = counts.get("info", 0)

        # Determine verdict
        verdict, verdict_info = self._determine_verdict(critical, high, medium, len(memory.findings))

        # Format duration
        if result.end_time and result.start_time:
            duration = format_duration((result.end_time - result.start_time).total_seconds())
        else:
            duration = "Unknown"

        # Build findings list
        findings = []
        for finding in sorted(memory.findings, key=lambda f: f.severity, reverse=True):
            findings.append(self._format_finding(finding))

        # Build timeline
        timeline = self._build_timeline(memory, result)

        # Build recommendations
        recommendations = self._generate_recommendations(memory.findings)

        return ReportData(
            target=result.target,
            scan_start=result.start_time,
            scan_end=result.end_time,
            duration=duration,
            verdict=verdict,
            verdict_color=verdict_info["color"],
            verdict_description=verdict_info["description"],
            total_findings=len(memory.findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            access_level=memory.get_highest_access().value,
            access_description=self._describe_access(memory.get_highest_access()),
            findings=findings,
            timeline=timeline,
            subdomains=memory.attack_surface.subdomains[:20],
            endpoints_count=len(memory.attack_surface.endpoints),
            technologies=memory.attack_surface.technologies,
            recommendations=recommendations,
        )

    def _determine_verdict(self, critical: int, high: int, medium: int, total: int) -> tuple[str, dict]:
        """Determine the overall security verdict."""
        if total == 0:
            return "SECURE", self.VERDICTS["SECURE"]

        for verdict_name, verdict_info in self.VERDICTS.items():
            if verdict_name == "SECURE":
                continue
            if verdict_info["threshold"](critical, high, medium):
                return verdict_name, verdict_info

        return "MINIMALLY_VULNERABLE", self.VERDICTS["MINIMALLY_VULNERABLE"]

    def _format_finding(self, finding: Finding) -> dict:
        """Format a finding for the report."""
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "severity_color": self._severity_color(finding.severity),
            "vuln_type": finding.vuln_type,
            "target": finding.target,
            "endpoint": finding.endpoint,
            "parameter": finding.parameter,
            "details": finding.details,
            "payload": finding.payload if not self.config.redact_sensitive else "[REDACTED]",
            "evidence": [e.to_dict() for e in finding.evidence] if self.config.include_evidence else [],
            "remediation": finding.remediation or self._default_remediation(finding.vuln_type),
            "references": finding.references,
            "discovered_at": finding.discovered_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#28a745",
            Severity.INFO: "#17a2b8",
        }
        return colors.get(severity, "#6c757d")

    def _describe_access(self, access: AccessLevel) -> str:
        """Describe what the access level means."""
        descriptions = {
            AccessLevel.NONE: "No unauthorized access achieved.",
            AccessLevel.ANONYMOUS: "Anonymous/unauthenticated access to restricted resources.",
            AccessLevel.USER: "Regular user-level access achieved.",
            AccessLevel.ADMIN: "Administrative access achieved - can modify system settings.",
            AccessLevel.ROOT: "Full system compromise - complete control achieved.",
            AccessLevel.DATABASE: "Direct database access - can read/modify all data.",
            AccessLevel.CLOUD: "Cloud infrastructure access - potential for lateral movement.",
        }
        return descriptions.get(access, "Unknown access level.")

    def _build_timeline(self, memory: Memory, result) -> list[dict]:
        """Build attack timeline for the report."""
        timeline = []

        # Add scan start
        timeline.append({
            "time": result.start_time.strftime("%H:%M:%S"),
            "event": "Scan Started",
            "details": f"Target: {result.target}",
            "type": "info",
        })

        # Add findings in chronological order
        for finding in sorted(memory.findings, key=lambda f: f.discovered_at):
            timeline.append({
                "time": finding.discovered_at.strftime("%H:%M:%S"),
                "event": f"Found: {finding.title}",
                "details": finding.details[:100] if finding.details else "",
                "type": finding.severity.value,
            })

        # Add access milestones
        for milestone in memory.access_milestones:
            timeline.append({
                "time": milestone.achieved_at.strftime("%H:%M:%S"),
                "event": f"Access Escalated: {milestone.level.value}",
                "details": milestone.method,
                "type": "critical" if milestone.level in [AccessLevel.ADMIN, AccessLevel.ROOT] else "high",
            })

        # Add scan end
        if result.end_time:
            timeline.append({
                "time": result.end_time.strftime("%H:%M:%S"),
                "event": "Scan Completed",
                "details": f"Total findings: {len(memory.findings)}",
                "type": "info",
            })

        return sorted(timeline, key=lambda t: t["time"])

    def _generate_recommendations(self, findings: list[Finding]) -> list[dict]:
        """Generate prioritized recommendations."""
        recommendations = []
        seen_types = set()

        for finding in sorted(findings, key=lambda f: f.severity, reverse=True):
            if finding.vuln_type not in seen_types:
                seen_types.add(finding.vuln_type)
                recommendations.append({
                    "priority": "Immediate" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "This Month",
                    "vuln_type": finding.vuln_type,
                    "title": self._recommendation_title(finding.vuln_type),
                    "description": finding.remediation or self._default_remediation(finding.vuln_type),
                    "affected_count": sum(1 for f in findings if f.vuln_type == finding.vuln_type),
                })

        return recommendations

    def _recommendation_title(self, vuln_type: str) -> str:
        """Get recommendation title for vulnerability type."""
        titles = {
            "sqli": "Fix SQL Injection Vulnerabilities",
            "xss": "Implement XSS Protection",
            "ssrf": "Restrict Server-Side Requests",
            "auth_bypass": "Strengthen Authentication",
            "idor": "Implement Proper Access Controls",
            "command_injection": "Sanitize System Commands",
            "ssti": "Secure Template Rendering",
            "xxe": "Disable XML External Entities",
            "sensitive_file_exposure": "Remove Exposed Sensitive Files",
            "exposed_service": "Restrict Network Access",
        }
        return titles.get(vuln_type, f"Address {vuln_type.replace('_', ' ').title()} Issues")

    def _default_remediation(self, vuln_type: str) -> str:
        """Get default remediation advice for vulnerability type."""
        remediations = {
            "sqli": "Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
            "xss": "Implement Content Security Policy (CSP). Escape all user input before rendering. Use framework-provided XSS protection.",
            "ssrf": "Validate and whitelist allowed URLs. Block requests to internal IP ranges. Use a URL parser to validate schemes.",
            "auth_bypass": "Implement proper authentication checks. Use secure session management. Enable multi-factor authentication.",
            "idor": "Implement object-level authorization checks. Use indirect references. Verify user permissions for each request.",
            "command_injection": "Avoid system commands when possible. Use allowlists for permitted commands. Never pass user input directly to shell.",
            "ssti": "Use logic-less templates. Sandbox template execution. Validate and escape all user input.",
            "xxe": "Disable external entity processing. Use JSON instead of XML where possible.",
            "sensitive_file_exposure": "Remove or restrict access to sensitive files. Configure web server to block access to dotfiles.",
            "exposed_service": "Use firewall rules to restrict access. Move services to internal network. Implement authentication.",
        }
        return remediations.get(vuln_type, "Review and address this vulnerability according to security best practices.")

    async def _generate_html(self, data: ReportData) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"breach_report_{safe_filename(data.target)}_{timestamp}.html"
        filepath = os.path.join(self.config.output_dir, filename)

        # Use template if available, otherwise generate inline
        if self.env:
            try:
                template = self.env.get_template("report.html")
                html = template.render(report=data)
            except Exception:
                html = self._generate_inline_html(data)
        else:
            html = self._generate_inline_html(data)

        with open(filepath, 'w') as f:
            f.write(html)

        return filepath

    def _generate_inline_html(self, data: ReportData) -> str:
        """Generate HTML report without template."""
        findings_html = ""
        for f in data.findings:
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {f['severity_color']}; padding: 15px; margin: 15px 0; background: #f8f9fa;">
                <h3>{f['title']}</h3>
                <span class="badge" style="background: {f['severity_color']}; color: white; padding: 2px 8px; border-radius: 3px;">{f['severity'].upper()}</span>
                <p><strong>Type:</strong> {f['vuln_type']}</p>
                <p><strong>Endpoint:</strong> {f['endpoint'] or f['target']}</p>
                <p><strong>Details:</strong> {f['details']}</p>
                <p><strong>Remediation:</strong> {f['remediation']}</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>BREACH.AI Security Report - {data.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
        .verdict {{ font-size: 24px; font-weight: bold; color: {data.verdict_color}; padding: 20px; border: 3px solid {data.verdict_color}; border-radius: 8px; text-align: center; margin: 20px 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ text-align: center; padding: 15px; border-radius: 8px; }}
        .stat.critical {{ background: #f8d7da; }}
        .stat.high {{ background: #fff3cd; }}
        .stat.medium {{ background: #d1ecf1; }}
        .stat.low {{ background: #d4edda; }}
        .stat.info {{ background: #e2e3e5; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        h2 {{ border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .finding {{ border-left: 4px solid; padding: 15px; margin: 15px 0; background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BREACH.AI Security Assessment Report</h1>
            <p>Target: <strong>{data.target}</strong></p>
            <p>Scan Duration: {data.duration} | Completed: {data.scan_end.strftime('%Y-%m-%d %H:%M:%S') if data.scan_end else 'N/A'}</p>
        </div>

        <div class="verdict">
            {data.verdict.replace('_', ' ')}
        </div>
        <p style="text-align: center;">{data.verdict_description}</p>

        <h2>Summary</h2>
        <div class="stats">
            <div class="stat critical"><div class="stat-number">{data.critical_count}</div>Critical</div>
            <div class="stat high"><div class="stat-number">{data.high_count}</div>High</div>
            <div class="stat medium"><div class="stat-number">{data.medium_count}</div>Medium</div>
            <div class="stat low"><div class="stat-number">{data.low_count}</div>Low</div>
            <div class="stat info"><div class="stat-number">{data.info_count}</div>Info</div>
        </div>

        <p><strong>Highest Access Achieved:</strong> {data.access_level.upper()}</p>
        <p>{data.access_description}</p>

        <h2>Findings ({data.total_findings})</h2>
        {findings_html}

        <h2>Attack Surface</h2>
        <p><strong>Endpoints Discovered:</strong> {data.endpoints_count}</p>
        <p><strong>Technologies:</strong> {', '.join(data.technologies) if data.technologies else 'None detected'}</p>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #eee; text-align: center; color: #666;">
            <p>Generated by BREACH.AI - Autonomous Security Assessment Agent</p>
            <p>"We hack you before they do."</p>
        </div>
    </div>
</body>
</html>"""

    async def _generate_json(self, data: ReportData) -> str:
        """Generate JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"breach_report_{safe_filename(data.target)}_{timestamp}.json"
        filepath = os.path.join(self.config.output_dir, filename)

        report_dict = {
            "target": data.target,
            "scan_start": data.scan_start.isoformat() if data.scan_start else None,
            "scan_end": data.scan_end.isoformat() if data.scan_end else None,
            "duration": data.duration,
            "verdict": data.verdict,
            "summary": {
                "total_findings": data.total_findings,
                "critical": data.critical_count,
                "high": data.high_count,
                "medium": data.medium_count,
                "low": data.low_count,
                "info": data.info_count,
            },
            "access_achieved": {
                "level": data.access_level,
                "description": data.access_description,
            },
            "findings": data.findings,
            "timeline": data.timeline,
            "attack_surface": {
                "subdomains": data.subdomains,
                "endpoints_count": data.endpoints_count,
                "technologies": data.technologies,
            },
            "recommendations": data.recommendations,
        }

        with open(filepath, 'w') as f:
            json.dump(report_dict, f, indent=2)

        return filepath

    async def _generate_markdown(self, data: ReportData) -> str:
        """Generate Markdown report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"breach_report_{safe_filename(data.target)}_{timestamp}.md"
        filepath = os.path.join(self.config.output_dir, filename)

        findings_md = ""
        for f in data.findings:
            findings_md += f"""
### {f['title']}

- **Severity:** {f['severity'].upper()}
- **Type:** {f['vuln_type']}
- **Endpoint:** {f['endpoint'] or f['target']}
- **Details:** {f['details']}
- **Remediation:** {f['remediation']}

---
"""

        md = f"""# BREACH.AI Security Assessment Report

**Target:** {data.target}
**Scan Duration:** {data.duration}
**Completed:** {data.scan_end.strftime('%Y-%m-%d %H:%M:%S') if data.scan_end else 'N/A'}

## Verdict: {data.verdict.replace('_', ' ')}

{data.verdict_description}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {data.critical_count} |
| High | {data.high_count} |
| Medium | {data.medium_count} |
| Low | {data.low_count} |
| Info | {data.info_count} |

**Highest Access Achieved:** {data.access_level.upper()}

{data.access_description}

## Findings

{findings_md}

## Attack Surface

- **Endpoints Discovered:** {data.endpoints_count}
- **Technologies:** {', '.join(data.technologies) if data.technologies else 'None detected'}

---

*Generated by BREACH.AI - Autonomous Security Assessment Agent*
*"We hack you before they do."*
"""

        with open(filepath, 'w') as f:
            f.write(md)

        return filepath
