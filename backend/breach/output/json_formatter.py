"""
BREACH.AI - JSON Output Formatter
=================================
Export scan results to JSON format.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path


class JSONFormatter:
    """
    Format scan results as JSON.

    Outputs machine-readable JSON suitable for:
    - CI/CD integration
    - SIEM ingestion
    - API responses
    - Programmatic analysis
    """

    def __init__(self, pretty: bool = True):
        """
        Initialize the JSON formatter.

        Args:
            pretty: Whether to format with indentation (default True)
        """
        self.pretty = pretty

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
        Format scan results as JSON string.

        Args:
            target: The scanned target URL
            mode: Scan mode used
            findings: List of finding dictionaries
            stats: Scan statistics
            duration_seconds: Total scan duration
            started_at: Scan start time
            completed_at: Scan completion time

        Returns:
            JSON string
        """
        report = {
            "breach_version": "2.0.0",
            "scan": {
                "target": target,
                "mode": mode,
                "started_at": started_at.isoformat() if started_at else None,
                "completed_at": completed_at.isoformat() if completed_at else None,
                "duration_seconds": duration_seconds,
            },
            "summary": {
                "total_findings": len(findings),
                "critical": stats.get("critical_count", 0),
                "high": stats.get("high_count", 0),
                "medium": stats.get("medium_count", 0),
                "low": stats.get("low_count", 0),
                "info": stats.get("info_count", 0),
                "total_business_impact": stats.get("total_impact", 0),
                "endpoints_discovered": stats.get("endpoints_discovered", 0),
                "endpoints_tested": stats.get("endpoints_tested", 0),
                "exploitation_attempts": stats.get("exploitation_attempts", 0),
                "successful_exploits": stats.get("successful_exploits", 0),
            },
            "findings": self._format_findings(findings),
            "generated_at": datetime.utcnow().isoformat(),
        }

        if self.pretty:
            return json.dumps(report, indent=2, default=str)
        else:
            return json.dumps(report, default=str)

    def _format_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings for JSON output."""
        formatted = []

        for f in findings:
            finding = {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity", "info"),
                "category": f.get("vulnerability_type") or f.get("category"),
                "endpoint": f.get("endpoint"),
                "method": f.get("method", "GET"),
                "parameter": f.get("parameter"),
                "description": f.get("description"),
                "payload": f.get("payload"),
                "evidence": f.get("evidence", {}),
                "business_impact": f.get("business_impact", 0),
                "impact_explanation": f.get("impact_explanation"),
                "exploitation": {
                    "is_exploited": f.get("is_exploited", False),
                    "confidence": f.get("exploitation_confidence", 0),
                    "proof_type": f.get("proof_type") or f.get("exploitation_proof_type"),
                    "proof_data": f.get("exploitation_proof", {}),
                },
                "reproduction": {
                    "curl_command": f.get("curl_command"),
                    "steps": f.get("reproduction_steps", []),
                    "poc_script": f.get("poc_script"),
                },
                "remediation": f.get("remediation") or f.get("fix_suggestion"),
                "references": {
                    "cwe_id": f.get("cwe_id"),
                },
            }
            formatted.append(finding)

        return formatted

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
        Save scan results to a JSON file.

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
