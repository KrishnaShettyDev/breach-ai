"""
BREACH.AI - Base Attack Module

Base class for all attack implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from breach.core.memory import AccessLevel, Evidence, Finding, Severity
from breach.utils.helpers import generate_id
from breach.utils.http import HTTPClient, HTTPResponse


@dataclass
class AttackResult:
    """Result of an attack attempt."""
    success: bool
    attack_type: str
    target: str

    # Attack details
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    method: str = "GET"

    # Response info
    request: Optional[str] = None
    response: Optional[str] = None
    status_code: Optional[int] = None

    # Exploitation results
    details: str = ""
    data_sample: Optional[str] = None
    access_gained: Optional[AccessLevel] = None

    # Evidence
    evidence: list[Evidence] = field(default_factory=list)

    # Context for chaining
    context: dict = field(default_factory=dict)

    # Timing
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration_ms: float = 0

    def to_finding(self, severity: Severity = Severity.MEDIUM) -> Finding:
        """Convert attack result to a Finding."""
        finding = Finding.create(
            title=f"{self.attack_type.upper()} Vulnerability",
            vuln_type=self.attack_type,
            severity=severity,
            target=self.target,
            endpoint=self.endpoint,
            parameter=self.parameter,
            payload=self.payload,
            details=self.details,
            request=self.request,
            response=self.response[:2000] if self.response else None,
            access_gained=self.access_gained,
            data_exposed=self.data_sample,
        )

        for evidence in self.evidence:
            finding.evidence.append(evidence)

        return finding

    def add_evidence(self, evidence_type: str, description: str, content: Any):
        """Add evidence to this result."""
        self.evidence.append(Evidence(
            type=evidence_type,
            description=description,
            content=content,
        ))


class BaseAttack(ABC):
    """
    Base class for all attack implementations.

    Each attack module should inherit from this class and implement:
    - check(): Quick vulnerability check
    - exploit(): Full exploitation attempt
    - get_payloads(): Return list of payloads to try
    """

    # Attack metadata
    name: str = "Base Attack"
    attack_type: str = "unknown"
    description: str = ""
    severity: Severity = Severity.MEDIUM

    # OWASP reference
    owasp_category: str = ""
    cwe_id: Optional[int] = None

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.results: list[AttackResult] = []

    @abstractmethod
    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """
        Quick check if target might be vulnerable.

        Args:
            url: Target URL
            parameter: Parameter to test (if applicable)
            method: HTTP method

        Returns:
            True if potentially vulnerable
        """
        pass

    @abstractmethod
    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """
        Attempt full exploitation of vulnerability.

        Args:
            url: Target URL
            parameter: Parameter to exploit
            method: HTTP method

        Returns:
            AttackResult with exploitation details
        """
        pass

    @abstractmethod
    def get_payloads(self) -> list[str]:
        """
        Get list of payloads for this attack type.

        Returns:
            List of payload strings
        """
        pass

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """
        Run the full attack flow: check then exploit.

        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method

        Returns:
            AttackResult if successful, None otherwise
        """
        # First, quick check
        if await self.check(url, parameter, method, **kwargs):
            # If check passes, attempt exploitation
            result = await self.exploit(url, parameter, method, **kwargs)
            if result.success:
                self.results.append(result)
                return result

        return None

    async def _send_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str = "GET",
        headers: Optional[dict] = None,
    ) -> HTTPResponse:
        """
        Send a payload to the target.

        Args:
            url: Target URL
            parameter: Parameter name
            payload: Payload value
            method: HTTP method
            headers: Additional headers

        Returns:
            HTTP response
        """
        if method.upper() == "GET":
            # Add payload to URL parameter
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{parameter}={payload}"
            return await self.http_client.get(test_url, headers=headers)

        elif method.upper() == "POST":
            # Send as form data
            data = {parameter: payload}
            return await self.http_client.post(url, data=data, headers=headers)

        else:
            # Other methods
            return await self.http_client.request(
                method, url, data={parameter: payload}, headers=headers
            )

    def _create_result(
        self,
        success: bool,
        url: str,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        response: Optional[HTTPResponse] = None,
        **kwargs
    ) -> AttackResult:
        """Create an AttackResult with common fields filled in."""
        return AttackResult(
            success=success,
            attack_type=self.attack_type,
            target=url,
            endpoint=url,
            parameter=parameter,
            payload=payload,
            response=response.body[:5000] if response else None,
            status_code=response.status_code if response else None,
            **kwargs
        )

    def _detect_error_patterns(self, response_body: str, patterns: list[str]) -> bool:
        """Check if response contains any of the error patterns."""
        body_lower = response_body.lower()
        return any(pattern.lower() in body_lower for pattern in patterns)

    def _extract_data_sample(self, response_body: str, max_length: int = 500) -> str:
        """Extract a sample of sensitive data from response."""
        # Try to find structured data
        import re

        # Look for JSON-like structures
        json_match = re.search(r'\{[^{}]+\}', response_body)
        if json_match:
            return json_match.group(0)[:max_length]

        # Look for table data
        if '<table' in response_body.lower():
            table_match = re.search(r'<table[^>]*>.*?</table>', response_body, re.DOTALL | re.IGNORECASE)
            if table_match:
                return table_match.group(0)[:max_length]

        return response_body[:max_length]


class InjectionAttack(BaseAttack):
    """Base class for injection-type attacks."""

    # Common error patterns for injection detection
    error_patterns: list[str] = []

    # Common success patterns
    success_patterns: list[str] = []

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """
        Check for injection vulnerability using error-based detection.
        """
        if not parameter:
            return False

        # Get baseline response
        baseline = await self._send_payload(url, parameter, "test123", method)

        # Try payloads and look for error patterns
        for payload in self.get_payloads()[:5]:  # Quick check with first 5
            response = await self._send_payload(url, parameter, payload, method)

            # Check for error patterns in response
            if self._detect_error_patterns(response.body, self.error_patterns):
                return True

            # Check for significant response difference
            if abs(len(response.body) - len(baseline.body)) > 500:
                return True

        return False
