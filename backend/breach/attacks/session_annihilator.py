"""
BREACH.AI - Session Annihilator

Comprehensive session management attack module.
Sessions are the keys to the kingdom - we take them all.

Attack Categories:
1. Session Fixation - Force victim into attacker's session
2. Session Prediction - Weak session ID generation
3. Session Hijacking - Steal active sessions
4. Insecure Cookies - Missing security flags
5. Session Puzzling - Variable confusion attacks
6. Concurrent Session - Bypass session limits
"""

import asyncio
import hashlib
import math
import re
import statistics
import string
import time
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class SessionInfo:
    """Information about a session cookie."""
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = None
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    expires: Optional[str] = None


class SessionAnnihilator(BaseAttack):
    """
    Session ANNIHILATOR - Comprehensive session attacks.

    Every session management implementation has weaknesses.
    We find and exploit them all.
    """

    name = "Session Annihilator"
    attack_type = "session_attack"
    description = "Comprehensive session management exploitation"
    severity = Severity.HIGH
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 384

    # Common session cookie names
    SESSION_COOKIE_NAMES = [
        "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "ASPSESSIONID",
        "session", "sessionid", "session_id", "sid", "sess",
        "connect.sid", "express:sess", "express.sid",
        "_session", "_session_id", "user_session",
        "CFID", "CFTOKEN", "CGISESSID",
        "laravel_session", "symfony", "PLAY_SESSION",
        "rack.session", "_rails_session", "wordpress_logged_in",
    ]

    # Weak entropy patterns
    WEAK_PATTERNS = [
        r'^[0-9]+$',  # Pure numeric
        r'^[a-f0-9]{32}$',  # MD5 of something
        r'^[a-f0-9]{40}$',  # SHA1 of something
        r'^[A-Za-z0-9]{8}$',  # Short alphanumeric
        r'^\d{10,13}$',  # Timestamp-based
    ]

    def get_payloads(self) -> list[str]:
        return self.SESSION_COOKIE_NAMES

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if session management is in use."""
        response = await self.http_client.get(url)

        # Check for session cookies
        for cookie_name in self.SESSION_COOKIE_NAMES:
            if cookie_name.lower() in [c.lower() for c in response.cookies.keys()]:
                return True

        return bool(response.cookies)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive session attacks."""
        result = self._create_result(False, url, parameter)

        # Gather session info
        sessions = await self._gather_session_info(url)

        if not sessions:
            result.details = "No session cookies found"
            return result

        logger.info(f"[Session] Found {len(sessions)} session cookie(s)")

        # Attack 1: Insecure Cookie Flags
        flag_result = await self._attack_insecure_flags(sessions)
        if flag_result:
            result.success = True
            result.details = f"Insecure cookie flags: {flag_result['issues']}"
            result.add_evidence(
                "session_insecure_flags",
                "Session cookies missing security flags",
                str(flag_result['issues'])
            )
            # Don't return - collect all issues

        # Attack 2: Session Fixation
        fixation_result = await self._attack_session_fixation(url, sessions)
        if fixation_result:
            result.success = True
            result.details = "Session fixation vulnerability!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "session_fixation",
                "Session ID not regenerated after authentication",
                fixation_result["details"]
            )
            return result

        # Attack 3: Weak Session ID Entropy
        entropy_result = await self._attack_weak_entropy(url, sessions)
        if entropy_result:
            result.success = True
            result.payload = entropy_result["pattern"]
            result.details = f"Weak session ID: {entropy_result['type']}"
            result.add_evidence(
                "session_weak_entropy",
                "Session IDs have predictable patterns",
                entropy_result["details"]
            )
            return result

        # Attack 4: Session Prediction
        predict_result = await self._attack_session_prediction(url, sessions)
        if predict_result:
            result.success = True
            result.payload = predict_result["predicted"]
            result.details = "Session ID prediction possible!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "session_prediction",
                "Session IDs can be predicted",
                predict_result["details"]
            )
            return result

        # Attack 5: Session Timeout Issues
        timeout_result = await self._attack_session_timeout(url, sessions)
        if timeout_result:
            result.success = True
            result.details = f"Session timeout issue: {timeout_result['issue']}"
            result.add_evidence(
                "session_timeout",
                "Session timeout misconfiguration",
                timeout_result["details"]
            )

        # Attack 6: Concurrent Session Bypass
        concurrent_result = await self._attack_concurrent_sessions(url)
        if concurrent_result:
            result.success = True
            result.details = "No concurrent session limit"
            result.add_evidence(
                "session_concurrent",
                "Unlimited concurrent sessions allowed",
                concurrent_result["details"]
            )

        # Attack 7: Session in URL
        url_result = await self._attack_session_in_url(url)
        if url_result:
            result.success = True
            result.details = "Session ID exposed in URL!"
            result.add_evidence(
                "session_in_url",
                "Session ID transmitted in URL (referrer leakage risk)",
                url_result["url"]
            )

        # Attack 8: Cross-subdomain Session
        subdomain_result = await self._attack_subdomain_session(url, sessions)
        if subdomain_result:
            result.success = True
            result.details = "Session cookie accessible to subdomains"
            result.add_evidence(
                "session_subdomain",
                "Session cookie domain too broad",
                subdomain_result["details"]
            )

        return result

    async def _gather_session_info(self, url: str) -> list[SessionInfo]:
        """Gather information about session cookies."""
        response = await self.http_client.get(url)
        sessions = []

        for name, value in response.cookies.items():
            session = SessionInfo(
                name=name,
                value=value,
            )

            # Parse Set-Cookie header for attributes
            set_cookie_headers = response.headers.get("Set-Cookie", "")
            if isinstance(set_cookie_headers, list):
                set_cookie_headers = "; ".join(set_cookie_headers)

            if name in set_cookie_headers:
                session.secure = "secure" in set_cookie_headers.lower()
                session.httponly = "httponly" in set_cookie_headers.lower()

                samesite_match = re.search(r'samesite=(\w+)', set_cookie_headers, re.I)
                if samesite_match:
                    session.samesite = samesite_match.group(1)

                domain_match = re.search(rf'{name}=[^;]+;[^;]*domain=([^;]+)', set_cookie_headers, re.I)
                if domain_match:
                    session.domain = domain_match.group(1).strip()

            sessions.append(session)

        return sessions

    async def _attack_insecure_flags(self, sessions: list[SessionInfo]) -> Optional[dict]:
        """Check for missing security flags on session cookies."""
        issues = []

        for session in sessions:
            session_issues = []

            if not session.secure:
                session_issues.append("Missing Secure flag")

            if not session.httponly:
                session_issues.append("Missing HttpOnly flag")

            if not session.samesite or session.samesite.lower() == "none":
                session_issues.append("SameSite not strict")

            if session_issues:
                issues.append(f"{session.name}: {', '.join(session_issues)}")

        if issues:
            return {"issues": issues}

        return None

    async def _attack_session_fixation(self, url: str, sessions: list[SessionInfo]) -> Optional[dict]:
        """Test for session fixation vulnerability."""
        logger.debug("[Session] Testing session fixation...")

        # Get pre-auth session
        pre_auth_response = await self.http_client.get(url)
        pre_auth_sessions = dict(pre_auth_response.cookies)

        if not pre_auth_sessions:
            return None

        # Find login endpoint
        login_endpoints = [
            "/login", "/signin", "/auth/login", "/api/login",
            "/user/login", "/account/login", "/authenticate",
        ]

        login_url = None
        for endpoint in login_endpoints:
            test_url = urljoin(url, endpoint)
            response = await self.http_client.get(test_url)
            if response.status_code == 200 and ("login" in response.body.lower() or "password" in response.body.lower()):
                login_url = test_url
                break

        if not login_url:
            return None

        # Simulate login (without actual creds, just check if session changes)
        login_response = await self.http_client.post(login_url, data={
            "username": "test_fixation_check",
            "password": "test_fixation_check",
        })

        post_auth_sessions = dict(login_response.cookies)

        # Check if session ID remained the same
        for name, pre_value in pre_auth_sessions.items():
            if name in post_auth_sessions:
                if pre_value == post_auth_sessions[name]:
                    return {
                        "details": f"Session cookie '{name}' not regenerated after login attempt. "
                                  f"Session fixation may be possible."
                    }

        return None

    async def _attack_weak_entropy(self, url: str, sessions: list[SessionInfo]) -> Optional[dict]:
        """Analyze session ID entropy."""
        logger.debug("[Session] Analyzing session ID entropy...")

        for session in sessions:
            sid = session.value

            # Check for weak patterns
            for pattern in self.WEAK_PATTERNS:
                if re.match(pattern, sid):
                    return {
                        "type": "Weak pattern detected",
                        "pattern": pattern,
                        "details": f"Session ID matches weak pattern: {pattern}"
                    }

            # Check entropy
            entropy = self._calculate_entropy(sid)
            if entropy < 4.0:  # Less than 4 bits per character is weak
                return {
                    "type": "Low entropy",
                    "pattern": f"Entropy: {entropy:.2f} bits/char",
                    "details": f"Session ID has low entropy ({entropy:.2f} bits/char). "
                              f"Recommended: >= 4.0 bits/char"
                }

            # Check length
            if len(sid) < 16:
                return {
                    "type": "Short session ID",
                    "pattern": f"Length: {len(sid)} chars",
                    "details": f"Session ID is only {len(sid)} characters. "
                              f"Recommended: >= 128 bits (32+ hex chars)"
                }

        return None

    async def _attack_session_prediction(self, url: str, sessions: list[SessionInfo]) -> Optional[dict]:
        """Attempt to predict session IDs."""
        logger.debug("[Session] Testing session ID predictability...")

        # Collect multiple session IDs
        session_ids = []
        for _ in range(10):
            # Clear cookies and get new session
            response = await self.http_client.get(url, headers={"Cookie": ""})

            for session in sessions:
                if session.name in response.cookies:
                    session_ids.append(response.cookies[session.name])
                    break

            await asyncio.sleep(0.1)

        if len(session_ids) < 5:
            return None

        # Analyze for patterns
        # Check if purely incremental
        try:
            numeric_ids = [int(sid) for sid in session_ids]
            diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]

            if len(set(diffs)) == 1:
                # Constant increment - very predictable!
                predicted = numeric_ids[-1] + diffs[0]
                return {
                    "predicted": str(predicted),
                    "details": f"Session IDs are sequential with increment {diffs[0]}"
                }

        except ValueError:
            pass

        # Check for timestamp-based patterns
        try:
            # Look for embedded timestamps
            for i, sid in enumerate(session_ids):
                # Try to find timestamp patterns
                for pos in range(len(sid) - 9):
                    chunk = sid[pos:pos+10]
                    try:
                        ts = int(chunk)
                        if 1600000000 < ts < 2000000000:  # Unix timestamp range
                            return {
                                "predicted": "timestamp-based",
                                "details": f"Session ID contains timestamp at position {pos}"
                            }
                    except ValueError:
                        continue
        except Exception:
            pass

        # Check character distribution
        char_counts = Counter("".join(session_ids))
        most_common_ratio = char_counts.most_common(1)[0][1] / len("".join(session_ids))
        if most_common_ratio > 0.3:
            return {
                "predicted": "biased-distribution",
                "details": f"Session ID character distribution is biased. "
                          f"Most common char appears {most_common_ratio*100:.1f}% of time"
            }

        return None

    async def _attack_session_timeout(self, url: str, sessions: list[SessionInfo]) -> Optional[dict]:
        """Check for session timeout issues."""
        logger.debug("[Session] Testing session timeout...")

        issues = []

        for session in sessions:
            # Check if session has no expiry
            if not session.expires:
                issues.append(f"{session.name} has no expiry (session cookie)")

        if issues:
            return {
                "issue": "No expiration",
                "details": "; ".join(issues)
            }

        return None

    async def _attack_concurrent_sessions(self, url: str) -> Optional[dict]:
        """Test if concurrent sessions are limited."""
        logger.debug("[Session] Testing concurrent session limits...")

        # Get multiple sessions
        sessions = []
        for _ in range(5):
            response = await self.http_client.get(url, headers={"Cookie": ""})
            if response.cookies:
                sessions.append(dict(response.cookies))

        if len(sessions) >= 5:
            # All sessions created - no limit
            return {
                "details": f"Created {len(sessions)} concurrent sessions without limit"
            }

        return None

    async def _attack_session_in_url(self, url: str) -> Optional[dict]:
        """Check if session ID is passed in URL."""
        logger.debug("[Session] Testing for session in URL...")

        response = await self.http_client.get(url)

        # Check for session ID in any redirects
        if response.redirect_url:
            for pattern in [r'[?&]session=', r'[?&]sid=', r'[?&]PHPSESSID=', r';jsessionid=']:
                if re.search(pattern, response.redirect_url, re.I):
                    return {"url": response.redirect_url}

        # Check for session rewriting in links
        session_url_patterns = [
            r'href=["\'][^"\']*[?&;]session[=]',
            r'href=["\'][^"\']*[?&;]sid[=]',
            r'href=["\'][^"\']*;jsessionid=',
        ]

        for pattern in session_url_patterns:
            if re.search(pattern, response.body, re.I):
                match = re.search(pattern, response.body, re.I)
                return {"url": match.group(0)[:100]}

        return None

    async def _attack_subdomain_session(self, url: str, sessions: list[SessionInfo]) -> Optional[dict]:
        """Check if session cookie domain is too broad."""
        logger.debug("[Session] Testing session cookie domain...")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc

        for session in sessions:
            if session.domain:
                # Domain set to parent domain
                if session.domain.startswith("."):
                    domain_parts = session.domain.lstrip(".").split(".")
                    host_parts = host.split(".")

                    # Cookie domain is broader than host
                    if len(domain_parts) < len(host_parts):
                        return {
                            "details": f"Cookie '{session.name}' domain ({session.domain}) "
                                      f"is broader than host ({host}). "
                                      f"Session accessible from all subdomains."
                        }

        return None

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        char_counts = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy
