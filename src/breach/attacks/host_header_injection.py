"""
BREACH.AI - Host Header Injection Exploiter
===========================================
Detects Host header injection vulnerabilities.
"""

import asyncio
from typing import List, Optional
from .base import BaseAttack, Finding, Severity


class HostHeaderInjection(BaseAttack):
    """
    Host Header Injection Exploiter

    Tests for:
    - Password reset poisoning
    - Cache poisoning via Host header
    - SSRF via Host header
    - Open redirect via Host header
    - Web cache deception
    """

    name = "Host Header Injection"

    EVIL_HOSTS = [
        "evil.com",
        "attacker.com",
        "localhost",
        "127.0.0.1",
    ]

    async def run(self) -> List[Finding]:
        findings = []

        # Test basic host header injection
        basic_findings = await self._test_basic_injection()
        findings.extend(basic_findings)

        # Test password reset poisoning
        reset_finding = await self._test_password_reset_poisoning()
        if reset_finding:
            findings.append(reset_finding)

        # Test X-Forwarded-Host
        forwarded_findings = await self._test_forwarded_host()
        findings.extend(forwarded_findings)

        # Test absolute URL handling
        absolute_findings = await self._test_absolute_url()
        findings.extend(absolute_findings)

        return findings

    async def _test_basic_injection(self) -> List[Finding]:
        """Test basic Host header injection."""
        findings = []

        for evil_host in self.EVIL_HOSTS:
            try:
                response = await self.client.get(
                    self.target,
                    headers={"Host": evil_host}
                )

                # Check if evil host is reflected in response
                if evil_host in response.text:
                    findings.append(Finding(
                        title="Host Header Injection",
                        severity=Severity.MEDIUM,
                        category="Host Header",
                        endpoint=self.target,
                        method="GET",
                        description=f"The Host header value '{evil_host}' is reflected in the response. "
                                   f"This can be exploited for cache poisoning or phishing.",
                        evidence=f"Host: {evil_host} reflected in response",
                        business_impact=50000,
                        impact_explanation="Can be used for phishing, cache poisoning, "
                                         "or password reset token theft.",
                        fix_suggestion="Validate the Host header against a whitelist. "
                                     "Never use Host header values in URLs or links.",
                        curl_command=f"curl -H 'Host: {evil_host}' '{self.target}'"
                    ))
                    break

                # Check redirect location
                location = response.headers.get("Location", "")
                if evil_host in location:
                    findings.append(Finding(
                        title="Host Header Redirect Injection",
                        severity=Severity.HIGH,
                        category="Host Header",
                        endpoint=self.target,
                        method="GET",
                        description=f"The Host header is used in redirect Location header.",
                        evidence=f"Location: {location}",
                        business_impact=75000,
                        impact_explanation="Allows open redirect and phishing attacks.",
                        fix_suggestion="Use a hardcoded domain for redirects.",
                        curl_command=f"curl -H 'Host: {evil_host}' -I '{self.target}'"
                    ))
                    break

            except Exception:
                continue

        return findings

    async def _test_password_reset_poisoning(self) -> Optional[Finding]:
        """Test password reset link poisoning."""
        reset_endpoints = [
            "/forgot-password",
            "/api/forgot-password",
            "/api/v1/forgot-password",
            "/api/auth/forgot-password",
            "/reset-password",
            "/password/reset",
        ]

        for endpoint in reset_endpoints:
            url = f"{self.target.rstrip('/')}{endpoint}"

            for evil_host in self.EVIL_HOSTS:
                try:
                    response = await self.client.post(
                        url,
                        data={"email": "test@example.com"},
                        headers={"Host": evil_host}
                    )

                    # Check if request was processed (not 404)
                    if response.status_code in [200, 201, 302]:
                        # If the evil host appears in the response, it's vulnerable
                        if evil_host in response.text:
                            return Finding(
                                title="Password Reset Poisoning",
                                severity=Severity.CRITICAL,
                                category="Host Header",
                                endpoint=url,
                                method="POST",
                                description="Password reset links can be poisoned via Host header. "
                                           "Reset emails will contain attacker-controlled links.",
                                evidence=f"Host header '{evil_host}' appears in reset response/email link",
                                business_impact=150000,
                                impact_explanation="Attackers can steal password reset tokens "
                                                 "by sending poisoned reset emails to victims.",
                                fix_suggestion="Never use Host header for generating links. "
                                             "Use a hardcoded, validated domain.",
                                curl_command=f"curl -X POST -H 'Host: {evil_host}' -d 'email=victim@example.com' '{url}'"
                            )

                except Exception:
                    continue

        return None

    async def _test_forwarded_host(self) -> List[Finding]:
        """Test X-Forwarded-Host injection."""
        findings = []

        forwarded_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "Forwarded",
        ]

        for header in forwarded_headers:
            for evil_host in self.EVIL_HOSTS[:2]:  # Limit tests
                try:
                    header_value = evil_host
                    if header == "Forwarded":
                        header_value = f"host={evil_host}"

                    response = await self.client.get(
                        self.target,
                        headers={header: header_value}
                    )

                    if evil_host in response.text:
                        findings.append(Finding(
                            title=f"Host Injection via {header}",
                            severity=Severity.MEDIUM,
                            category="Host Header",
                            endpoint=self.target,
                            method="GET",
                            description=f"The {header} header is reflected in responses.",
                            evidence=f"{header}: {header_value}",
                            business_impact=50000,
                            impact_explanation="Can be used for cache poisoning or phishing.",
                            fix_suggestion=f"Validate {header} against whitelist.",
                            curl_command=f"curl -H '{header}: {header_value}' '{self.target}'"
                        ))
                        break

                except Exception:
                    continue

        return findings

    async def _test_absolute_url(self) -> List[Finding]:
        """Test absolute URL with different Host header."""
        findings = []

        for evil_host in self.EVIL_HOSTS[:2]:
            try:
                # Send request with absolute URL but different Host
                from urllib.parse import urlparse
                parsed = urlparse(self.target)

                # This tests if the server ignores Host header when absolute URL is used
                response = await self.client.request(
                    "GET",
                    self.target,
                    headers={"Host": evil_host}
                )

                # If we get a valid response with evil host reflected
                if response.status_code == 200 and evil_host in response.text:
                    findings.append(Finding(
                        title="Absolute URL Host Override",
                        severity=Severity.MEDIUM,
                        category="Host Header",
                        endpoint=self.target,
                        method="GET",
                        description="Server accepts mismatched Host header with absolute URL.",
                        evidence=f"Host: {evil_host} with absolute URL",
                        business_impact=40000,
                        impact_explanation="May enable request routing bypass.",
                        fix_suggestion="Validate Host matches request URL.",
                        curl_command=f"curl -H 'Host: {evil_host}' '{self.target}'"
                    ))
                    break

            except Exception:
                continue

        return findings
