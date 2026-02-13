"""
BREACH.AI - Proven Engine
=========================

Proof-by-exploitation scanning. Only reports vulnerabilities that
have been successfully exploited with undeniable proof.

"If we can't exploit it, we don't report it."

Best for: Bug bounty, penetration testing, compliance audits.
"""

import time
from datetime import datetime

from .base import BaseEngine, ScanConfig, ScanResult, Finding, Severity


class ProvenEngine(BaseEngine):
    """
    Proven mode engine (proof-by-exploitation).

    Performs:
    - Vulnerability hypothesis generation
    - Active exploitation attempts
    - Browser-based validation (XSS, CSRF, Clickjacking)
    - Evidence collection (screenshots, DOM, network)
    - PoC generation (cURL, Python, JavaScript)

    Only reports vulnerabilities that are SUCCESSFULLY EXPLOITED.
    """

    MODE = "proven"
    DESCRIPTION = "Proof-by-exploitation (only reports exploited vulnerabilities)"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._engine = None

    async def initialize(self):
        """Initialize the proven engine."""
        from breach.exploitation.shannon_engine import ShannonEngine
        self._engine = ShannonEngine(
            timeout_minutes=self.config.timeout_minutes,
            use_browser=self.config.browser_enabled,
            use_source_analysis=False,  # Requires source code
            parallel_agents=self.config.parallel,
            screenshot=self.config.browser_enabled,
        )
        await self._engine.__aenter__()

    async def cleanup(self):
        """Cleanup resources."""
        if self._engine:
            await self._engine.__aexit__(None, None, None)

    async def scan(self) -> ScanResult:
        """Execute proof-by-exploitation scan."""
        start_time = time.time()
        self.result.started_at = datetime.utcnow()

        await self._emit_progress(0, "Starting proven mode scan...")

        try:
            # Progress callback bridge
            def on_progress(percent, message):
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(self._emit_progress(percent, message))
                except:
                    pass

            self._engine.on_progress(on_progress)

            # Finding callback
            async def on_finding(shannon_finding):
                finding = self._convert_finding(shannon_finding)
                self.result.findings.append(finding)
                await self._emit_finding(finding)

            self._engine.on_finding(on_finding)

            # Run exploitation scan
            result = await self._engine.scan(
                target=self.config.target,
                cookies=self.config.get_cookies_dict(),
            )

            await self._emit_progress(95, "Finalizing results...")

            # Update stats from result
            self.result.endpoints_discovered = getattr(result, 'endpoints_discovered', 0)
            self.result.exploitation_attempts = getattr(result, 'exploitation_attempts', 0)
            self.result.successful_exploits = getattr(result, 'successful_exploits', 0)
            self.result.false_positives_filtered = getattr(result, 'false_positives_filtered', 0)

            # Convert any findings we might have missed
            if hasattr(result, 'findings') and not self.result.findings:
                for f in result.findings:
                    finding = self._convert_finding(f)
                    self.result.findings.append(finding)

            await self._emit_progress(100, "Proven mode scan complete")

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

    def _convert_finding(self, raw_finding) -> Finding:
        """Convert ShannonFinding to unified Finding format."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        raw_severity = getattr(raw_finding, 'severity', 'medium')
        severity = severity_map.get(str(raw_severity), Severity.MEDIUM)

        # Extract PoC data
        poc = getattr(raw_finding, 'poc', None)
        curl_command = getattr(raw_finding, 'curl_command', '')
        poc_script = ''
        reproduction_steps = getattr(raw_finding, 'reproduction_steps', [])

        if poc:
            curl_command = curl_command or getattr(poc, 'curl_command', '')
            poc_script = getattr(poc, 'python_script', '') or getattr(poc, 'javascript', '')
            reproduction_steps = reproduction_steps or getattr(poc, 'steps', [])

        return Finding(
            title=f"{getattr(raw_finding, 'vulnerability_type', 'Unknown').upper()} - {getattr(raw_finding, 'endpoint', '')}",
            severity=severity,
            vulnerability_type=getattr(raw_finding, 'vulnerability_type', 'unknown'),
            endpoint=getattr(raw_finding, 'endpoint', ''),
            method="GET",
            parameter=getattr(raw_finding, 'parameter', None),
            description=f"Successfully exploited {getattr(raw_finding, 'vulnerability_type', 'vulnerability')} vulnerability",
            payload=getattr(raw_finding, 'payload', ''),
            evidence=getattr(raw_finding, 'proof_data', {}),
            business_impact=float(getattr(raw_finding, 'business_impact', 0)),
            impact_explanation=getattr(raw_finding, 'impact_explanation', ''),
            # Exploitation proof - always True for proven mode
            is_exploited=True,
            exploitation_proof=getattr(raw_finding, 'proof_data', {}),
            exploitation_confidence=getattr(raw_finding, 'confidence', 0.0),
            proof_type=getattr(raw_finding, 'proof_type', ''),
            # Reproduction
            curl_command=curl_command,
            reproduction_steps=reproduction_steps,
            poc_script=poc_script,
            # Remediation
            remediation=getattr(raw_finding, 'remediation', ''),
            cwe_id=getattr(raw_finding, 'cwe_id', ''),
        )
