"""
BREACH v3.1 - Prompt Management
================================

Structured prompts for each phase of the pentest.
"""

from pathlib import Path
from typing import Dict, Optional


class PromptManager:
    """Manages prompts for the autonomous agent."""

    # Phase 1: Reconnaissance
    RECON_PROMPT = """# Phase 1: Reconnaissance

You are an autonomous security researcher performing reconnaissance on a target application.

## Target
URL: {target}
Source Code Available: {has_source}

## Objectives
1. Map the attack surface
2. Identify all endpoints and parameters
3. Detect technologies and frameworks
4. Find entry points for testing

## Tools Available
- http_request: Make HTTP requests
- browser: Browser automation for JS-heavy apps
- analyze_source: Source code analysis (if available)

## Expected Output
Provide a JSON summary of:
- endpoints: List of discovered endpoints with parameters
- technologies: Detected tech stack
- entry_points: Potential injection points
- notes: Any interesting observations

Begin reconnaissance now.
"""

    # Phase 2: Vulnerability Analysis
    ANALYSIS_PROMPT = """# Phase 2: Vulnerability Analysis

You are a specialized {vuln_type} security researcher.

## Target
URL: {target}
Endpoints: {endpoints}

## Your Specialization: {vuln_type}
Focus exclusively on finding {vuln_type} vulnerabilities.

## Recon Results
{recon_results}

## Objectives
1. Analyze each endpoint for {vuln_type} vulnerabilities
2. Generate exploitation hypotheses
3. Identify the most promising attack vectors

## Expected Output
For each potential vulnerability:
- endpoint: The vulnerable endpoint
- parameter: The vulnerable parameter
- payload: Suggested exploitation payload
- confidence: Your confidence level (0-1)
- rationale: Why you believe this is vulnerable

Do not attempt exploitation yet - only analyze and hypothesize.
"""

    # Phase 3: Exploitation
    EXPLOITATION_PROMPT = """# Phase 3: Exploitation

You are an autonomous exploit developer. Your task is to PROVE vulnerabilities exist.

## NO EXPLOIT = NO REPORT
If you cannot successfully exploit a vulnerability, do not report it.
Pattern matching is NOT proof. You must demonstrate actual exploitation.

## Hypothesis to Test
Type: {vuln_type}
Endpoint: {endpoint}
Parameter: {parameter}
Payload: {payload}
Confidence: {confidence}

## Tools Available
- http_request: Make HTTP requests
- browser: For XSS/CSRF (captures screenshots)
- sqli_test: SQL injection testing

## Exploitation Requirements by Type

### SQL Injection
- Must trigger SQL error OR extract data OR cause time delay
- Evidence: Error message, extracted data, or consistent delay

### XSS
- Must execute JavaScript in browser
- Evidence: Alert triggered, DOM modified, or console output
- SCREENSHOT REQUIRED

### SSRF
- Must access internal resource or cloud metadata
- Evidence: Internal data in response

### Command Injection
- Must execute system command
- Evidence: Command output in response

## Expected Output
If EXPLOITED:
```json
{{
  "exploited": true,
  "proof_type": "sql_error|js_executed|data_extracted|...",
  "evidence": "...",
  "curl_command": "...",
  "screenshot": "..." (if applicable)
}}
```

If NOT exploited:
```json
{{
  "exploited": false,
  "reason": "..."
}}
```

Attempt exploitation now. Remember: NO PROOF = NO REPORT.
"""

    # Phase 4: Reporting
    REPORT_PROMPT = """# Phase 4: Security Assessment Report

Generate a comprehensive security assessment report.

## Validated Findings
{findings}

## Report Requirements
Generate a professional penetration test report including:

1. **Executive Summary**
   - Total findings by severity
   - Risk assessment
   - Key recommendations

2. **Technical Findings**
   For each finding:
   - Title and severity
   - Affected endpoint
   - Technical description
   - Proof of exploitation
   - Reproduction steps (curl command)
   - Business impact
   - Remediation guidance

3. **Appendix**
   - Full request/response pairs
   - Screenshots (if available)
   - Timeline

## Output Format
Generate the report in Markdown format.
"""

    def __init__(self, prompts_dir: Path = None):
        self.prompts_dir = prompts_dir
        self._custom_prompts: Dict[str, str] = {}

        if prompts_dir and prompts_dir.exists():
            self._load_custom_prompts()

    def _load_custom_prompts(self):
        """Load custom prompts from directory."""
        for file in self.prompts_dir.glob("*.md"):
            name = file.stem
            self._custom_prompts[name] = file.read_text()

    def get_recon_prompt(
        self,
        target: str,
        has_source: bool = False,
    ) -> str:
        """Get reconnaissance prompt."""
        template = self._custom_prompts.get("recon", self.RECON_PROMPT)
        return template.format(
            target=target,
            has_source="Yes" if has_source else "No",
        )

    def get_analysis_prompt(
        self,
        target: str,
        vuln_type: str,
        endpoints: list,
        recon_results: dict,
    ) -> str:
        """Get vulnerability analysis prompt."""
        import json
        template = self._custom_prompts.get("analysis", self.ANALYSIS_PROMPT)
        return template.format(
            target=target,
            vuln_type=vuln_type,
            endpoints=json.dumps(endpoints, indent=2),
            recon_results=json.dumps(recon_results, indent=2),
        )

    def get_exploitation_prompt(
        self,
        vuln_type: str,
        endpoint: str,
        parameter: str,
        payload: str,
        confidence: float,
    ) -> str:
        """Get exploitation prompt."""
        template = self._custom_prompts.get("exploitation", self.EXPLOITATION_PROMPT)
        return template.format(
            vuln_type=vuln_type,
            endpoint=endpoint,
            parameter=parameter,
            payload=payload,
            confidence=confidence,
        )

    def get_report_prompt(self, findings: list) -> str:
        """Get reporting prompt."""
        import json
        template = self._custom_prompts.get("reporting", self.REPORT_PROMPT)
        return template.format(
            findings=json.dumps(findings, indent=2, default=str),
        )

    def save_prompt(self, name: str, content: str, session_dir: Path):
        """Save prompt to session directory for reproducibility."""
        prompts_dir = session_dir / "prompts"
        prompts_dir.mkdir(parents=True, exist_ok=True)
        (prompts_dir / f"{name}.md").write_text(content)
