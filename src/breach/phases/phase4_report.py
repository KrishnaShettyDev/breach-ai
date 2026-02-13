"""
BREACH v3.0 - Phase 4: Reporting
=================================

Generate comprehensive security assessment report.

Output structure follows Shannon's audit-logs format:
audit-logs/{target}_{session_id}/
├── session.json
├── agents/
├── prompts/
└── deliverables/
    └── comprehensive_security_assessment_report.md
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .phase1_recon import ReconResult
from .phase2_analysis import AnalysisResult
from .phase3_exploit import ExploitResult, ValidatedFinding


@dataclass
class ReportResult:
    """Result of reporting phase."""
    output_dir: Path = None
    report_path: Path = None
    session_path: Path = None

    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "report_path": str(self.report_path) if self.report_path else None,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class ReportPhase:
    """
    Phase 4: Reporting.

    Generates structured output in Shannon's audit-logs format.
    """

    def __init__(
        self,
        output_dir: Path = Path("./audit-logs"),
        session_id: str = None,
    ):
        self.output_dir = output_dir
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")

    async def run(
        self,
        target: str,
        recon_result: ReconResult,
        analysis_result: AnalysisResult,
        exploit_result: ExploitResult,
    ) -> ReportResult:
        """
        Generate comprehensive report.

        Args:
            target: Target URL
            recon_result: Phase 1 results
            analysis_result: Phase 2 results
            exploit_result: Phase 3 results (validated findings)

        Returns:
            ReportResult with paths to generated files
        """
        result = ReportResult()

        # Create session directory
        from urllib.parse import urlparse
        domain = urlparse(target).netloc.replace(":", "_")
        session_dir = self.output_dir / f"{domain}_{self.session_id}"
        session_dir.mkdir(parents=True, exist_ok=True)
        result.output_dir = session_dir

        # Create subdirectories
        (session_dir / "agents").mkdir(exist_ok=True)
        (session_dir / "prompts").mkdir(exist_ok=True)
        (session_dir / "deliverables").mkdir(exist_ok=True)
        (session_dir / "deliverables" / "findings").mkdir(exist_ok=True)
        (session_dir / "deliverables" / "evidence").mkdir(exist_ok=True)

        # Generate session.json
        session_data = self._generate_session_json(
            target, recon_result, analysis_result, exploit_result
        )
        session_path = session_dir / "session.json"
        session_path.write_text(json.dumps(session_data, indent=2, default=str))
        result.session_path = session_path

        # Generate main report
        report_content = self._generate_report(
            target, recon_result, analysis_result, exploit_result
        )
        report_path = session_dir / "deliverables" / "comprehensive_security_assessment_report.md"
        report_path.write_text(report_content)
        result.report_path = report_path

        # Generate individual finding files
        for finding in exploit_result.findings:
            finding_content = self._generate_finding_file(finding)
            finding_path = session_dir / "deliverables" / "findings" / f"{finding.id}.md"
            finding_path.write_text(finding_content)

            # Save screenshots
            if finding.screenshot:
                screenshot_path = session_dir / "deliverables" / "evidence" / f"{finding.id}.png"
                screenshot_path.write_bytes(finding.screenshot)

        result.completed_at = datetime.utcnow()
        return result

    def _generate_session_json(
        self,
        target: str,
        recon: ReconResult,
        analysis: AnalysisResult,
        exploit: ExploitResult,
    ) -> Dict:
        """Generate session metadata."""
        return {
            "id": self.session_id,
            "target": target,
            "started_at": recon.started_at.isoformat(),
            "completed_at": exploit.completed_at.isoformat() if exploit.completed_at else None,
            "phases": {
                "recon": {
                    "duration_seconds": recon.duration_seconds,
                    "endpoints_found": len(recon.endpoints),
                    "parameters_found": len(recon.parameters),
                    "technologies": [t.name for t in recon.technologies],
                },
                "analysis": {
                    "duration_seconds": analysis.duration_seconds,
                    "hypotheses_generated": analysis.total_hypotheses,
                    "agents_run": analysis.agents_run,
                },
                "exploitation": {
                    "duration_seconds": exploit.duration_seconds,
                    "hypotheses_tested": exploit.hypotheses_tested,
                    "successful_exploits": exploit.successful_exploits,
                    "false_positives_filtered": exploit.false_positives,
                },
            },
            "summary": {
                "total_findings": len(exploit.findings),
                "critical": exploit.critical_count,
                "high": exploit.high_count,
                "medium": exploit.medium_count,
                "low": exploit.low_count,
                "total_business_impact": exploit.total_business_impact,
            },
            "findings": [
                {
                    "id": f.id,
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "endpoint": f.endpoint,
                    "cwe": f.cwe_id,
                }
                for f in exploit.findings
            ],
        }

    def _generate_report(
        self,
        target: str,
        recon: ReconResult,
        analysis: AnalysisResult,
        exploit: ExploitResult,
    ) -> str:
        """Generate the main security assessment report."""
        findings = exploit.findings

        report = f"""# Comprehensive Security Assessment Report

**Target:** {target}
**Assessment Date:** {datetime.now().strftime("%Y-%m-%d")}
**Report Generated:** {datetime.now().isoformat()}
**Assessment Mode:** BREACH v3.0 Shannon-Style (Proof-by-Exploitation)

---

## Executive Summary

This assessment was conducted using BREACH's Shannon-style methodology, which only reports vulnerabilities that have been **successfully exploited** with proof. Pattern matching alone is not considered validation.

### Key Findings

| Severity | Count |
|----------|-------|
| 🔴 Critical | {exploit.critical_count} |
| 🟠 High | {exploit.high_count} |
| 🟡 Medium | {exploit.medium_count} |
| 🟢 Low | {exploit.low_count} |

**Total Validated Vulnerabilities:** {len(findings)}

**Estimated Business Impact:** ${exploit.total_business_impact:,}

### Assessment Statistics

- Endpoints Discovered: {len(recon.endpoints)}
- Parameters Found: {len(recon.parameters)}
- Hypotheses Generated: {analysis.total_hypotheses}
- Hypotheses Tested: {exploit.hypotheses_tested}
- False Positives Filtered: {exploit.false_positives}
- **Successful Exploits:** {exploit.successful_exploits}

---

## Methodology

This assessment followed Shannon's "No Exploit, No Report" philosophy:

1. **Phase 1: Reconnaissance** - Mapped attack surface through crawling, JavaScript analysis, and source code analysis
2. **Phase 2: Vulnerability Analysis** - Parallel OWASP-specialized agents generated exploitation hypotheses
3. **Phase 3: Exploitation** - Each hypothesis was tested through actual exploitation attempts
4. **Phase 4: Reporting** - Only successfully exploited vulnerabilities are included

**Important:** Every finding in this report has been validated through actual exploitation with captured proof.

---

## Technical Findings

"""
        # Add each finding
        for i, finding in enumerate(sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 4)), 1):
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.severity, "⚪")

            report += f"""
### {i}. {severity_emoji} [{finding.severity}] {finding.vuln_type.upper()} - {finding.endpoint}

**Vulnerability Type:** {finding.vuln_type.upper()}
**Severity:** {finding.severity}
**CWE:** {finding.cwe_id}
**Endpoint:** `{finding.endpoint}`
**Parameter:** `{finding.parameter}`
**Business Impact:** ${finding.business_impact:,}

#### Description

{finding.impact_explanation or f"A {finding.vuln_type} vulnerability was identified and successfully exploited."}

#### Proof of Exploitation

**Proof Type:** {finding.proof_type}

```
{finding.evidence[:500] if finding.evidence else "See curl command for reproduction"}
```

#### Reproduction

```bash
{finding.curl_command}
```

{"**Screenshot:** See `evidence/" + finding.id + ".png`" if finding.screenshot else ""}

#### Remediation

{finding.remediation}

---
"""

        # Risk assessment
        report += """
## Risk Assessment

Based on the validated findings, the following risks have been identified:

"""
        if exploit.critical_count > 0:
            report += """### 🔴 Critical Risk
Critical vulnerabilities allow immediate system compromise, data theft, or service disruption. These should be remediated immediately.

"""
        if exploit.high_count > 0:
            report += """### 🟠 High Risk
High severity vulnerabilities can lead to significant data exposure or system compromise. Remediation should be prioritized.

"""

        # Appendix
        report += f"""
---

## Appendix

### A. Technologies Detected

"""
        for tech in recon.technologies:
            report += f"- {tech.name}" + (f" ({tech.version})" if tech.version else "") + f" - {tech.category}\n"

        report += f"""
### B. Endpoints Analyzed

Total: {len(recon.endpoints)}

| Endpoint | Method | Parameters |
|----------|--------|------------|
"""
        for ep in recon.endpoints[:30]:
            report += f"| {ep.url[:50]}... | {ep.method} | {', '.join(ep.parameters[:3])} |\n"

        report += f"""
### C. Assessment Timeline

| Phase | Duration |
|-------|----------|
| Reconnaissance | {recon.duration_seconds:.1f}s |
| Analysis | {analysis.duration_seconds:.1f}s |
| Exploitation | {exploit.duration_seconds:.1f}s |
| **Total** | **{recon.duration_seconds + analysis.duration_seconds + exploit.duration_seconds:.1f}s** |

---

*Report generated by BREACH v3.0 - Shannon-Style Autonomous Security Scanner*
*https://github.com/breach-ai*
"""
        return report

    def _generate_finding_file(self, finding: ValidatedFinding) -> str:
        """Generate individual finding file."""
        return f"""# Finding: {finding.id}

## Overview

| Field | Value |
|-------|-------|
| Type | {finding.vuln_type.upper()} |
| Severity | {finding.severity} |
| CWE | {finding.cwe_id} |
| Endpoint | {finding.endpoint} |
| Parameter | {finding.parameter} |
| Impact | ${finding.business_impact:,} |

## Proof of Exploitation

**Proof Type:** {finding.proof_type}

### Evidence

```
{finding.evidence}
```

### Proof Data

```json
{json.dumps(finding.proof_data, indent=2, default=str)}
```

## Reproduction

### Curl Command

```bash
{finding.curl_command}
```

### Steps

{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(finding.reproduction_steps)) if finding.reproduction_steps else "See curl command"}

## Payload

```
{finding.payload}
```

## Remediation

{finding.remediation}

## Impact

{finding.impact_explanation}

---

*Discovered: {finding.discovered_at.isoformat()}*
*Exploitation Time: {finding.exploitation_time_ms:.0f}ms*
"""
