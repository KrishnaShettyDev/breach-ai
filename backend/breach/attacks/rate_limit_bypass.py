"""
BREACH.AI - Rate Limit Bypass Exploiter
=======================================
Detects rate limiting bypass vulnerabilities.
"""

import asyncio
from typing import List, Optional
from .base import BaseAttack, Finding, Severity


class RateLimitBypass(BaseAttack):
    """
    Rate Limit Bypass Exploiter

    Tests for:
    - IP-based bypass (X-Forwarded-For, X-Real-IP)
    - Case sensitivity bypass
    - Endpoint variation bypass
    - HTTP method switching
    - Adding parameters
    - Unicode/encoding bypass
    - Null byte injection
    """

    name = "Rate Limit Bypass"

    IP_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Originating-IP",
        "X-Host",
        "X-Forwarded-Host",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
    ]

    async def run(self) -> List[Finding]:
        findings = []

        # Find endpoints with rate limiting
        rate_limited_endpoints = await self._find_rate_limited_endpoints()

        for endpoint in rate_limited_endpoints:
            # Test IP header bypass
            ip_bypass = await self._test_ip_bypass(endpoint)
            if ip_bypass:
                findings.append(ip_bypass)

            # Test case sensitivity
            case_bypass = await self._test_case_bypass(endpoint)
            if case_bypass:
                findings.append(case_bypass)

            # Test path variation
            path_bypass = await self._test_path_variation(endpoint)
            if path_bypass:
                findings.append(path_bypass)

            # Test HTTP method switching
            method_bypass = await self._test_method_switching(endpoint)
            if method_bypass:
                findings.append(method_bypass)

        return findings

    async def _find_rate_limited_endpoints(self) -> List[str]:
        """Find endpoints that have rate limiting."""
        endpoints = []

        # Common rate-limited endpoints
        common_paths = [
            "/api/login",
            "/api/auth/login",
            "/api/v1/auth/login",
            "/login",
            "/api/forgot-password",
            "/api/reset-password",
            "/api/register",
            "/api/otp/send",
            "/api/otp/verify",
            "/api/sms/send",
        ]

        for path in common_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                # Send multiple requests to trigger rate limit
                for _ in range(10):
                    response = await self.client.post(url, data={"test": "test"})

                    # Check for rate limit indicators
                    if response.status_code == 429:
                        endpoints.append(url)
                        break

                    rate_limit_headers = [
                        "X-RateLimit-Remaining",
                        "X-Rate-Limit-Remaining",
                        "RateLimit-Remaining",
                        "Retry-After",
                    ]

                    for header in rate_limit_headers:
                        if header in response.headers:
                            endpoints.append(url)
                            break

            except Exception:
                continue

        # Add from discovered endpoints
        for ep in self.state.discovered_endpoints:
            if any(x in ep.lower() for x in ["login", "auth", "password", "otp", "register"]):
                endpoints.append(ep)

        return list(set(endpoints))[:10]

    async def _test_ip_bypass(self, endpoint: str) -> Optional[Finding]:
        """Test IP-based rate limit bypass."""
        import random

        for header in self.IP_HEADERS:
            try:
                # Generate random IPs to bypass rate limit
                successful_requests = 0

                for i in range(10):
                    random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    response = await self.client.post(
                        endpoint,
                        data={"username": f"test{i}", "password": "test"},
                        headers={header: random_ip}
                    )

                    if response.status_code != 429:
                        successful_requests += 1

                if successful_requests >= 8:  # Most requests bypassed
                    return Finding(
                        title=f"Rate Limit Bypass via {header}",
                        severity=Severity.HIGH,
                        category="Rate Limiting",
                        endpoint=endpoint,
                        method="POST",
                        description=f"Rate limiting can be bypassed by rotating the {header} header. "
                                   f"The application trusts this header for IP identification.",
                        evidence=f"Header: {header}\nSuccessful bypass requests: {successful_requests}/10",
                        business_impact=50000,
                        impact_explanation="Allows brute-force attacks on login, OTP, and other "
                                         "security-sensitive endpoints.",
                        fix_suggestion=f"Do not trust {header} for rate limiting unless behind a "
                                     f"trusted proxy. Use the actual client IP from the connection.",
                        curl_command=f"curl -X POST -H '{header}: 1.2.3.4' '{endpoint}'"
                    )

            except Exception:
                continue

        return None

    async def _test_case_bypass(self, endpoint: str) -> Optional[Finding]:
        """Test case sensitivity bypass."""
        from urllib.parse import urlparse

        parsed = urlparse(endpoint)
        variations = [
            parsed.path.upper(),
            parsed.path.lower(),
            parsed.path.title(),
            parsed.path.swapcase(),
        ]

        for variation in variations:
            if variation == parsed.path:
                continue

            try:
                varied_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
                response = await self.client.post(varied_url, data={"test": "test"})

                if response.status_code != 429 and response.status_code != 404:
                    return Finding(
                        title="Rate Limit Bypass via Case Variation",
                        severity=Severity.MEDIUM,
                        category="Rate Limiting",
                        endpoint=endpoint,
                        method="POST",
                        description=f"Rate limiting can be bypassed using case variations: {variation}",
                        evidence=f"Original: {parsed.path}\nBypass: {variation}",
                        business_impact=30000,
                        impact_explanation="Allows partial bypass of brute-force protections.",
                        fix_suggestion="Normalize URL paths to lowercase before rate limiting.",
                        curl_command=f"curl -X POST '{varied_url}'"
                    )

            except Exception:
                continue

        return None

    async def _test_path_variation(self, endpoint: str) -> Optional[Finding]:
        """Test path variation bypass."""
        from urllib.parse import urlparse

        parsed = urlparse(endpoint)

        # Path variations
        variations = [
            parsed.path + "/",
            parsed.path + "?",
            parsed.path + "#",
            parsed.path + "%20",
            parsed.path + "/.",
            parsed.path + "//",
            "//" + parsed.path.lstrip("/"),
            parsed.path.replace("/", "//"),
        ]

        for variation in variations:
            try:
                varied_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
                response = await self.client.post(varied_url, data={"test": "test"})

                if response.status_code not in [429, 404, 400]:
                    return Finding(
                        title="Rate Limit Bypass via Path Variation",
                        severity=Severity.MEDIUM,
                        category="Rate Limiting",
                        endpoint=endpoint,
                        method="POST",
                        description=f"Rate limiting bypassed with path: {variation}",
                        evidence=f"Original: {parsed.path}\nBypass: {variation}",
                        business_impact=30000,
                        impact_explanation="Path normalization issue allows bypass.",
                        fix_suggestion="Normalize paths before applying rate limits.",
                        curl_command=f"curl -X POST '{varied_url}'"
                    )

            except Exception:
                continue

        return None

    async def _test_method_switching(self, endpoint: str) -> Optional[Finding]:
        """Test HTTP method switching bypass."""
        methods = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"]

        for method in methods:
            try:
                response = await self.client.request(method, endpoint)

                if response.status_code not in [429, 404, 405]:
                    return Finding(
                        title=f"Rate Limit Bypass via HTTP Method ({method})",
                        severity=Severity.MEDIUM,
                        category="Rate Limiting",
                        endpoint=endpoint,
                        method=method,
                        description=f"Rate limiting bypassed using {method} instead of POST.",
                        evidence=f"Method: {method} returned {response.status_code}",
                        business_impact=25000,
                        impact_explanation="Different HTTP methods may bypass rate limits.",
                        fix_suggestion="Apply rate limiting regardless of HTTP method.",
                        curl_command=f"curl -X {method} '{endpoint}'"
                    )

            except Exception:
                continue

        return None
