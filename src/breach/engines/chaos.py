"""
BREACH.AI - Chaos Engine
========================

All-out attack mode. Runs ALL 60+ attack modules for maximum coverage.

Best for: Comprehensive penetration testing, red team assessments.
WARNING: Most aggressive mode - use only on authorized targets!
"""

import time
from datetime import datetime

from .base import BaseEngine, ScanConfig, ScanResult, Finding, Severity


class ChaosEngine(BaseEngine):
    """
    Chaos mode engine (brutal assessment).

    Runs ALL attack modules including:
    - All injection types (SQLi, XSS, SSRF, CMDi, NoSQLi, XXE, SSTI, LDAPi)
    - Authentication attacks (JWT, OAuth, SAML, MFA bypass)
    - Access control (IDOR, privilege escalation)
    - API attacks (GraphQL, REST, WebSocket)
    - File attacks (LFI, RFI, upload, traversal)
    - Cloud attacks (AWS, Azure, GCP, K8s, Docker)
    - Business logic (race conditions, price manipulation)
    - And 30+ more modules

    WARNING: This is the most aggressive mode.
    """

    MODE = "chaos"
    DESCRIPTION = "All 60+ attack modules (maximum coverage)"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._assessment = None

    async def initialize(self):
        """Initialize the brutal assessment."""
        pass  # BrutalAssessment doesn't need async init

    async def cleanup(self):
        """Cleanup resources."""
        pass

    async def scan(self) -> ScanResult:
        """Execute chaos mode scan."""
        from breach.brutal_assessment import BrutalAssessment

        start_time = time.time()
        self.result.started_at = datetime.utcnow()

        await self._emit_progress(0, "Initializing chaos mode...")

        try:
            # Create assessment
            self._assessment = BrutalAssessment(
                target=self.config.target,
                scope=None,
                exclude=self.config.exclude_paths,
                aggressive=True,
                timeout_per_module=max(60, self.config.timeout_minutes * 60 // 60),
                max_concurrent=self.config.parallel,
            )

            await self._emit_progress(5, "Running 60+ attack modules...")

            # Run assessment
            result = await self._assessment.run()

            await self._emit_progress(90, "Processing results...")

            # Convert findings
            if hasattr(result, 'findings'):
                for category, findings_list in result.findings.items():
                    for f in findings_list:
                        finding = self._convert_finding(f, category)
                        self.result.findings.append(finding)
                        await self._emit_finding(finding)
            elif hasattr(result, 'all_findings'):
                for f in result.all_findings:
                    finding = self._convert_finding(f, 'unknown')
                    self.result.findings.append(finding)
                    await self._emit_finding(finding)

            # Update stats
            self.result.endpoints_tested = getattr(result, 'endpoints_tested', 0)
            self.result.requests_made = getattr(result, 'requests_made', 0)

            await self._emit_progress(100, "Chaos mode scan complete")

        except Exception as e:
            self.result.errors.append(str(e))
            if self.config.verbose:
                import traceback
                self.result.errors.append(traceback.format_exc())

        # Finalize
        self.result.completed_at = datetime.utcnow()
        self.result.duration_seconds = int(time.time() - start_time)
        self.result.total_business_impact = sum(f.business_impact for f in self.result.findings)

        return self.result

    def _convert_finding(self, raw_finding, category: str) -> Finding:
        """Convert brutal assessment finding to unified Finding format."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        # Handle dict or object
        if isinstance(raw_finding, dict):
            raw_severity = raw_finding.get('severity', 'medium')
            title = raw_finding.get('title', raw_finding.get('vulnerability', 'Unknown'))
            vuln_type = raw_finding.get('type', raw_finding.get('vulnerability_type', category))
            endpoint = raw_finding.get('endpoint', raw_finding.get('url', ''))
            method = raw_finding.get('method', 'GET')
            parameter = raw_finding.get('parameter')
            description = raw_finding.get('description', '')
            payload = raw_finding.get('payload', '')
            evidence = raw_finding.get('evidence', {})
            impact = raw_finding.get('business_impact', raw_finding.get('impact', 0))
            curl = raw_finding.get('curl_command', raw_finding.get('reproduction', ''))
            remediation = raw_finding.get('remediation', raw_finding.get('fix', ''))
            cwe = raw_finding.get('cwe_id', raw_finding.get('cwe', ''))
        else:
            raw_severity = getattr(raw_finding, 'severity', 'medium')
            if hasattr(raw_severity, 'value'):
                raw_severity = raw_severity.value
            title = getattr(raw_finding, 'title', getattr(raw_finding, 'vulnerability', 'Unknown'))
            vuln_type = getattr(raw_finding, 'type', getattr(raw_finding, 'vulnerability_type', category))
            endpoint = getattr(raw_finding, 'endpoint', getattr(raw_finding, 'url', ''))
            method = getattr(raw_finding, 'method', 'GET')
            parameter = getattr(raw_finding, 'parameter', None)
            description = getattr(raw_finding, 'description', '')
            payload = getattr(raw_finding, 'payload', '')
            evidence = getattr(raw_finding, 'evidence', {})
            impact = getattr(raw_finding, 'business_impact', getattr(raw_finding, 'impact', 0))
            curl = getattr(raw_finding, 'curl_command', getattr(raw_finding, 'reproduction', ''))
            remediation = getattr(raw_finding, 'remediation', getattr(raw_finding, 'fix', ''))
            cwe = getattr(raw_finding, 'cwe_id', getattr(raw_finding, 'cwe', ''))

        severity = severity_map.get(str(raw_severity).lower(), Severity.MEDIUM)

        return Finding(
            title=str(title),
            severity=severity,
            vulnerability_type=str(vuln_type),
            endpoint=str(endpoint),
            method=str(method),
            parameter=parameter,
            description=str(description),
            payload=str(payload),
            evidence=evidence if isinstance(evidence, dict) else {},
            business_impact=float(impact) if impact else 0.0,
            curl_command=str(curl),
            remediation=str(remediation),
            cwe_id=str(cwe),
        )
