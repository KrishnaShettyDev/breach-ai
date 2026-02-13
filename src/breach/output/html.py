"""
BREACH.AI - HTML Output Formatter
=================================
Export scan results to HTML format.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import html


class HTMLFormatter:
    """
    Format scan results as HTML.

    Outputs a standalone HTML report suitable for:
    - Browser viewing
    - PDF generation
    - Email reports
    - Client deliverables
    """

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
    }

    def __init__(self, include_poc: bool = True, dark_mode: bool = False):
        """
        Initialize the HTML formatter.

        Args:
            include_poc: Include PoC code blocks
            dark_mode: Use dark color scheme
        """
        self.include_poc = include_poc
        self.dark_mode = dark_mode

    def format(
        self,
        target: str,
        mode: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
        duration_seconds: int,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> str:
        """
        Format scan results as HTML string.

        Args:
            target: The scanned target URL
            mode: Scan mode used
            findings: List of finding dictionaries
            stats: Scan statistics
            duration_seconds: Total scan duration
            started_at: Scan start time
            completed_at: Scan completion time

        Returns:
            HTML string
        """
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5)
        )

        findings_html = "\n".join(
            self._format_finding(i, f) for i, f in enumerate(sorted_findings, 1)
        )

        # Calculate stats
        total_findings = len(findings)
        exploited_count = sum(1 for f in findings if f.get("is_exploited"))

        # Format impact
        impact = stats.get("total_impact", 0)
        if impact >= 1_000_000:
            impact_str = f"${impact/1_000_000:.1f}M"
        elif impact >= 1_000:
            impact_str = f"${impact/1_000:.0f}K"
        else:
            impact_str = f"${impact:.0f}"

        # Color scheme
        bg_color = "#1a1a2e" if self.dark_mode else "#f8f9fa"
        text_color = "#ffffff" if self.dark_mode else "#212529"
        card_bg = "#16213e" if self.dark_mode else "#ffffff"
        border_color = "#0f3460" if self.dark_mode else "#dee2e6"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BREACH Security Report - {html.escape(target)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: {bg_color};
            color: {text_color};
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #6f42c1, #0d6efd);
            color: white;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .meta {{
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: {card_bg};
            border: 1px solid {border_color};
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}
        .summary-card.critical h3 {{ color: {self.SEVERITY_COLORS['critical']}; }}
        .summary-card.high h3 {{ color: {self.SEVERITY_COLORS['high']}; }}
        .summary-card.medium h3 {{ color: {self.SEVERITY_COLORS['medium']}; }}
        .summary-card.low h3 {{ color: {self.SEVERITY_COLORS['low']}; }}
        .summary-card.impact h3 {{ color: #dc3545; }}
        .finding {{
            background: {card_bg};
            border: 1px solid {border_color};
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid {border_color};
        }}
        .finding-header h3 {{
            margin: 0;
            font-size: 1.1em;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
        }}
        .severity-badge.critical {{ background: {self.SEVERITY_COLORS['critical']}; }}
        .severity-badge.high {{ background: {self.SEVERITY_COLORS['high']}; }}
        .severity-badge.medium {{ background: {self.SEVERITY_COLORS['medium']}; }}
        .severity-badge.low {{ background: {self.SEVERITY_COLORS['low']}; }}
        .severity-badge.info {{ background: {self.SEVERITY_COLORS['info']}; }}
        .exploited-badge {{
            background: #28a745;
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            margin-left: 10px;
        }}
        .finding-body {{
            padding: 20px;
        }}
        .finding-body table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }}
        .finding-body td {{
            padding: 8px 12px;
            border-bottom: 1px solid {border_color};
        }}
        .finding-body td:first-child {{
            font-weight: bold;
            width: 150px;
            color: {"#aaa" if self.dark_mode else "#666"};
        }}
        .code-block {{
            background: {"#0d1117" if self.dark_mode else "#f6f8fa"};
            border: 1px solid {border_color};
            border-radius: 6px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 0.9em;
            margin: 10px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .section-title {{
            font-weight: bold;
            margin: 15px 0 8px 0;
            color: {"#aaa" if self.dark_mode else "#666"};
        }}
        .remediation {{
            background: {"#1e3a1e" if self.dark_mode else "#d4edda"};
            border: 1px solid {"#28a745" if self.dark_mode else "#c3e6cb"};
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: {"#666" if self.dark_mode else "#6c757d"};
            font-size: 0.9em;
        }}
        @media print {{
            body {{ background: white; color: black; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BREACH Security Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {html.escape(target)}</p>
                <p><strong>Mode:</strong> {mode.upper()} | <strong>Duration:</strong> {duration_seconds // 60}m {duration_seconds % 60}s</p>
                <p><strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>{total_findings}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card critical">
                <h3>{stats.get('critical_count', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{stats.get('high_count', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{stats.get('medium_count', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card impact">
                <h3>{impact_str}</h3>
                <p>Business Impact</p>
            </div>
        </div>

        <h2 style="margin-bottom: 20px;">Findings</h2>

        {findings_html if findings_html else '<p style="text-align: center; padding: 40px; color: #28a745;">No vulnerabilities discovered.</p>'}

        <div class="footer">
            <p>Generated by BREACH v2.0.0</p>
            <p>{datetime.utcnow().isoformat()}</p>
        </div>
    </div>
</body>
</html>"""

    def _format_finding(self, index: int, finding: Dict[str, Any]) -> str:
        """Format a single finding as HTML."""
        severity = finding.get("severity", "info").lower()
        title = html.escape(finding.get("title", "Unknown Vulnerability"))

        # Exploited badge
        exploited_badge = ""
        if finding.get("is_exploited"):
            confidence = finding.get("exploitation_confidence", 0) * 100
            exploited_badge = f'<span class="exploited-badge">EXPLOITED {confidence:.0f}%</span>'

        # Details table
        details_rows = []
        details_rows.append(f"<tr><td>Category</td><td>{html.escape(str(finding.get('vulnerability_type') or finding.get('category', 'N/A')))}</td></tr>")
        details_rows.append(f"<tr><td>Endpoint</td><td><code>{html.escape(str(finding.get('endpoint', 'N/A')))}</code></td></tr>")
        details_rows.append(f"<tr><td>Method</td><td>{html.escape(str(finding.get('method', 'GET')))}</td></tr>")

        if finding.get("parameter"):
            details_rows.append(f"<tr><td>Parameter</td><td><code>{html.escape(str(finding['parameter']))}</code></td></tr>")

        impact = finding.get("business_impact", 0)
        if impact > 0:
            if impact >= 1_000_000:
                impact_str = f"${impact/1_000_000:.1f}M"
            elif impact >= 1_000:
                impact_str = f"${impact/1_000:.0f}K"
            else:
                impact_str = f"${impact:.0f}"
            details_rows.append(f"<tr><td>Business Impact</td><td><strong style='color: #dc3545;'>{impact_str}</strong></td></tr>")

        details_html = "\n".join(details_rows)

        # Description
        description_html = ""
        if finding.get("description"):
            description_html = f"""
            <div class="section-title">Description</div>
            <p>{html.escape(str(finding['description']))}</p>
            """

        # Payload
        payload_html = ""
        if finding.get("payload"):
            payload_html = f"""
            <div class="section-title">Payload</div>
            <div class="code-block">{html.escape(str(finding['payload']))}</div>
            """

        # cURL
        curl_html = ""
        if self.include_poc and finding.get("curl_command"):
            curl_html = f"""
            <div class="section-title">Reproduction (cURL)</div>
            <div class="code-block">{html.escape(str(finding['curl_command']))}</div>
            """

        # Remediation
        remediation_html = ""
        remediation = finding.get("remediation") or finding.get("fix_suggestion")
        if remediation:
            remediation_html = f"""
            <div class="remediation">
                <strong>Remediation:</strong><br>
                {html.escape(str(remediation))}
            </div>
            """

        return f"""
        <div class="finding">
            <div class="finding-header">
                <h3>{index}. {title}</h3>
                <div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                    {exploited_badge}
                </div>
            </div>
            <div class="finding-body">
                <table>
                    {details_html}
                </table>
                {description_html}
                {payload_html}
                {curl_html}
                {remediation_html}
            </div>
        </div>
        """

    def save(
        self,
        filepath: str,
        target: str,
        mode: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
        duration_seconds: int,
        **kwargs,
    ) -> None:
        """
        Save scan results to an HTML file.

        Args:
            filepath: Output file path
            target: The scanned target URL
            mode: Scan mode used
            findings: List of finding dictionaries
            stats: Scan statistics
            duration_seconds: Total scan duration
            **kwargs: Additional arguments passed to format()
        """
        content = self.format(
            target=target,
            mode=mode,
            findings=findings,
            stats=stats,
            duration_seconds=duration_seconds,
            **kwargs,
        )

        Path(filepath).write_text(content)
