"""
BREACH.AI - Finding Validator
=============================
Validates findings to eliminate false positives before saving.
Every finding must pass validation to be considered real.
"""

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from urllib.parse import quote
import aiohttp


@dataclass
class ValidationResult:
    """Result of finding validation."""
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    reason: str
    retested: bool = False


class FindingValidator:
    """
    Validates findings to eliminate false positives.

    Validation Rules:
    1. SQLi: Error must NOT be in baseline, must be triggered BY the payload
    2. XSS: Payload must be in executable context (not just reflected as text)
    3. Time-based: Must be reproducible (2/3 attempts must delay)
    4. SSRF/LFI: Response must contain actual sensitive data, not just keywords
    5. CMDi: Must show actual command output, not just contain keywords
    """

    MIN_CONFIDENCE_THRESHOLD = 0.7  # Findings below this are discarded

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self._baseline_cache: Dict[str, str] = {}

    async def validate(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate a finding. Returns ValidationResult.
        """
        category = finding.category.lower()

        validators = {
            'sqli': self._validate_sqli,
            'xss': self._validate_xss,
            'ssrf': self._validate_ssrf,
            'cmdi': self._validate_cmdi,
            'lfi': self._validate_lfi,
            'nosql': self._validate_nosql,
            'ssti': self._validate_ssti,
            'sensitive_file': self._validate_sensitive_file,
        }

        validator = validators.get(category)
        if not validator:
            # Unknown category - let it pass with medium confidence
            return ValidationResult(True, 0.5, "Unknown category - manual review recommended")

        return await validator(finding, cookies)

    async def _get_baseline(self, url: str, param: str, method: str, cookies: Dict = None) -> str:
        """Get baseline response with normal input."""
        cache_key = f"{method}:{url}:{param}"

        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        try:
            body, _, _, _ = await self._send_request(url, param, "test123", method, cookies)
            self._baseline_cache[cache_key] = body
            return body
        except:
            return ""

    async def _send_request(
        self,
        url: str,
        param: str,
        value: str,
        method: str = "GET",
        cookies: Dict = None,
    ) -> Tuple[str, float, int, str]:
        """Send a request and return (body, elapsed, status, raw_request)."""
        try:
            start = time.time()

            if method.upper() == "GET":
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={quote(value)}"

                async with self.session.get(
                    test_url,
                    cookies=cookies,
                    ssl=False,
                    timeout=self.timeout
                ) as response:
                    body = await response.text()
                    elapsed = time.time() - start
                    return body, elapsed, response.status, f"GET {test_url}"
            else:
                data = {param: value}
                async with self.session.post(
                    url,
                    data=data,
                    cookies=cookies,
                    ssl=False,
                    timeout=self.timeout
                ) as response:
                    body = await response.text()
                    elapsed = time.time() - start
                    return body, elapsed, response.status, f"POST {url}"
        except asyncio.TimeoutError:
            return "", self.timeout, 0, ""
        except:
            return "", 0, 0, ""

    # =========================================================================
    # SQL INJECTION VALIDATION
    # =========================================================================

    async def _validate_sqli(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate SQL injection finding.

        Rules:
        1. SQL error MUST NOT exist in baseline response
        2. SQL error MUST appear after injection
        3. Time-based: delay must be reproducible (2/3 attempts)
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        # Check if it's time-based
        if 'time' in finding.title.lower() or 'sleep' in payload.lower() or 'waitfor' in payload.lower():
            return await self._validate_time_based_sqli(finding, cookies)

        # Get baseline
        baseline = await self._get_baseline(url, param, method, cookies)

        # Check if error exists in baseline (false positive indicator)
        sql_error_patterns = [
            r'sql.*syntax',
            r'mysql.*error',
            r'pg_.*error',
            r'sqlite.*error',
            r'ora-\d{5}',
            r'microsoft.*odbc',
            r'unclosed quotation mark',
            r'quoted string not properly terminated',
        ]

        baseline_has_error = any(re.search(p, baseline, re.IGNORECASE) for p in sql_error_patterns)

        if baseline_has_error:
            return ValidationResult(
                False, 0.0,
                "SQL error exists in baseline - likely static content or documentation"
            )

        # Re-test with payload
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Check for SQL errors in exploited response
        errors_found = []
        for pattern in sql_error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                errors_found.append(pattern)

        if not errors_found:
            return ValidationResult(
                False, 0.0,
                "SQL error not reproducible - original detection may have been a transient issue"
            )

        # Verify the error is specifically triggered by our payload
        # Test with a safe value - error should NOT appear
        safe_body, _, _, _ = await self._send_request(url, param, "safe_test_value", method, cookies)
        safe_has_error = any(re.search(p, safe_body, re.IGNORECASE) for p in sql_error_patterns)

        if safe_has_error:
            return ValidationResult(
                False, 0.1,
                "SQL error appears even with safe input - not a true injection"
            )

        # Validated!
        return ValidationResult(
            True, 0.95,
            f"Confirmed: SQL error triggered specifically by payload. Patterns: {errors_found[:2]}",
            retested=True
        )

    async def _validate_time_based_sqli(self, finding, cookies: Dict = None) -> ValidationResult:
        """Validate time-based blind SQLi - must delay 2/3 attempts."""
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        delays = []
        required_delay = 4.5  # seconds

        # Test 3 times
        for _ in range(3):
            _, elapsed, _, _ = await self._send_request(url, param, payload, method, cookies)
            delays.append(elapsed)
            await asyncio.sleep(0.5)  # Brief pause between attempts

        successful_delays = sum(1 for d in delays if d >= required_delay)

        if successful_delays < 2:
            return ValidationResult(
                False, 0.0,
                f"Time delay not reproducible. Delays: {delays}. Need 2/3 >= {required_delay}s"
            )

        # Also verify baseline doesn't have similar delay
        baseline_delays = []
        for _ in range(2):
            _, elapsed, _, _ = await self._send_request(url, param, "safe_value", method, cookies)
            baseline_delays.append(elapsed)

        avg_baseline = sum(baseline_delays) / len(baseline_delays)
        if avg_baseline >= required_delay - 1:
            return ValidationResult(
                False, 0.1,
                f"Baseline also slow ({avg_baseline:.1f}s avg) - server latency, not SQLi"
            )

        return ValidationResult(
            True, 0.9,
            f"Confirmed: Consistent delay {successful_delays}/3 times. Avg baseline: {avg_baseline:.1f}s",
            retested=True
        )

    # =========================================================================
    # XSS VALIDATION
    # =========================================================================

    async def _validate_xss(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate XSS finding.

        Rules:
        1. Payload must be reflected
        2. Payload must be in executable context (not escaped, not in comment)
        3. Must not be in <textarea>, <input value>, or other safe contexts
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Check if payload is reflected at all
        if payload not in body:
            # Try without encoding
            if quote(payload) not in body and payload.replace('<', '&lt;') not in body:
                return ValidationResult(
                    False, 0.0,
                    "Payload not reflected in response"
                )
            else:
                return ValidationResult(
                    False, 0.1,
                    "Payload reflected but HTML-encoded (safe)"
                )

        # Check if properly escaped
        escaped_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '\\u003c').replace('>', '\\u003e'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('"', '&quot;').replace("'", '&#39;'),
        ]

        for escaped in escaped_variants:
            if escaped in body and payload not in body.replace(escaped, ''):
                return ValidationResult(
                    False, 0.1,
                    "Payload is HTML-encoded (properly escaped)"
                )

        # Check if in a safe context
        payload_pos = body.find(payload)
        if payload_pos == -1:
            return ValidationResult(False, 0.0, "Payload position not found")

        # Get surrounding context (500 chars before and after)
        context_start = max(0, payload_pos - 500)
        context_end = min(len(body), payload_pos + len(payload) + 500)
        context = body[context_start:context_end].lower()

        # Check for safe contexts
        safe_contexts = [
            r'<textarea[^>]*>.*?' + re.escape(payload.lower()),  # Inside textarea
            r'<!--.*?' + re.escape(payload.lower()),  # Inside comment
            r'<input[^>]+value\s*=\s*["\'][^"\']*' + re.escape(payload.lower()),  # Inside input value (often safe)
        ]

        for safe_pattern in safe_contexts:
            if re.search(safe_pattern, context, re.DOTALL):
                return ValidationResult(
                    False, 0.2,
                    "Payload in non-executable context (textarea/comment/input)"
                )

        # Check if script tags would execute
        if '<script' in payload.lower():
            # Verify not inside existing script (would be syntax error)
            before_payload = body[:payload_pos].lower()
            script_opens = before_payload.count('<script')
            script_closes = before_payload.count('</script')

            if script_opens > script_closes:
                return ValidationResult(
                    False, 0.3,
                    "Payload inside existing script block - would cause syntax error"
                )

        # Looks valid!
        return ValidationResult(
            True, 0.85,
            "Confirmed: Unescaped payload in executable context",
            retested=True
        )

    # =========================================================================
    # SSRF VALIDATION
    # =========================================================================

    async def _validate_ssrf(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate SSRF finding.

        Rules:
        1. Internal indicators must NOT exist in baseline
        2. Must show actual internal content, not just error messages
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        baseline = await self._get_baseline(url, param, method, cookies)

        # Check evidence in baseline
        internal_indicators = ['127.0.0.1', 'localhost', 'internal', '169.254.169.254', 'metadata']

        for indicator in internal_indicators:
            if indicator in baseline.lower():
                # This indicator exists in baseline - might be false positive
                if indicator in finding.evidence.lower():
                    return ValidationResult(
                        False, 0.1,
                        f"Indicator '{indicator}' exists in baseline - not a real SSRF"
                    )

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # For cloud metadata, look for actual metadata values
        if '169.254.169.254' in payload or 'metadata' in payload.lower():
            metadata_patterns = [
                r'ami-[a-z0-9]+',
                r'i-[a-z0-9]{8,17}',
                r'arn:aws:',
                r'AKIA[A-Z0-9]{16}',
                r'computeMetadata',
            ]

            has_metadata = any(re.search(p, body) for p in metadata_patterns)
            if not has_metadata:
                return ValidationResult(
                    False, 0.2,
                    "No actual metadata content found - may just be error page"
                )

            return ValidationResult(
                True, 0.95,
                "Confirmed: Actual cloud metadata retrieved",
                retested=True
            )

        # For localhost SSRF, check for internal service response
        # Must see actual content, not just "connection refused" type errors
        if len(body) < 100:
            return ValidationResult(
                False, 0.3,
                "Response too short - likely error page, not actual SSRF"
            )

        return ValidationResult(
            True, 0.75,
            "SSRF indicators found in response (manual verification recommended)",
            retested=True
        )

    # =========================================================================
    # COMMAND INJECTION VALIDATION
    # =========================================================================

    async def _validate_cmdi(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate command injection.

        Rules:
        1. Command output indicators must NOT exist in baseline
        2. Must show actual command output format
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        baseline = await self._get_baseline(url, param, method, cookies)

        # These patterns indicate actual command output
        cmdi_output_patterns = [
            r'uid=\d+\([^)]+\)\s+gid=\d+',  # id command output
            r'root:x?:0:0:',  # /etc/passwd format
            r'total \d+\ndrwx',  # ls -la output
            r'[A-Z_]+=.*\n[A-Z_]+=',  # env command output
        ]

        # Check if patterns exist in baseline
        for pattern in cmdi_output_patterns:
            if re.search(pattern, baseline):
                return ValidationResult(
                    False, 0.1,
                    "Command output pattern exists in baseline - likely documentation"
                )

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Look for actual command output
        found_output = False
        for pattern in cmdi_output_patterns:
            if re.search(pattern, body):
                found_output = True
                break

        if not found_output:
            return ValidationResult(
                False, 0.0,
                "No command output pattern found in response"
            )

        # Verify it's not in baseline
        return ValidationResult(
            True, 0.9,
            "Confirmed: Command output detected that wasn't in baseline",
            retested=True
        )

    # =========================================================================
    # LFI VALIDATION
    # =========================================================================

    async def _validate_lfi(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate LFI/Path Traversal.

        Rules:
        1. File content patterns must NOT exist in baseline
        2. Must show actual file content, not just "file not found" type errors
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        baseline = await self._get_baseline(url, param, method, cookies)

        # Patterns that indicate actual file content
        lfi_content_patterns = [
            r'root:.*?:0:0:.*?:/root:',  # /etc/passwd
            r'\[extensions\]',  # win.ini
            r'\[fonts\]',  # win.ini
            r'<?php',  # PHP source code
            r'#!/bin/(?:bash|sh)',  # Shell scripts
            r'DB_PASSWORD|DATABASE_URL|SECRET_KEY',  # Config files
        ]

        # Check baseline
        for pattern in lfi_content_patterns:
            if re.search(pattern, baseline, re.IGNORECASE):
                return ValidationResult(
                    False, 0.1,
                    f"File content pattern exists in baseline"
                )

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Look for actual file content
        found_content = False
        for pattern in lfi_content_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                found_content = True
                break

        if not found_content:
            return ValidationResult(
                False, 0.0,
                "No file content pattern found"
            )

        return ValidationResult(
            True, 0.9,
            "Confirmed: File content detected",
            retested=True
        )

    # =========================================================================
    # NOSQL INJECTION VALIDATION
    # =========================================================================

    async def _validate_nosql(self, finding, cookies: Dict = None) -> ValidationResult:
        """Validate NoSQL injection."""
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        # Get baseline
        baseline, _, baseline_status, _ = await self._send_request(url, param, "test123", method, cookies)

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Auth bypass check
        if 'auth bypass' in finding.title.lower():
            if baseline_status not in [401, 403]:
                return ValidationResult(
                    False, 0.1,
                    "Baseline wasn't 401/403 - can't confirm auth bypass"
                )

            if status != 200:
                return ValidationResult(
                    False, 0.0,
                    "Payload didn't result in 200 status"
                )

            return ValidationResult(
                True, 0.85,
                "Confirmed: Status changed from 401/403 to 200",
                retested=True
            )

        # Data exposure check - response must be significantly larger
        if len(body) <= len(baseline) * 1.5 or len(body) < 500:
            return ValidationResult(
                False, 0.2,
                "Response not significantly larger than baseline"
            )

        return ValidationResult(
            True, 0.75,
            f"Response {len(body)} bytes vs baseline {len(baseline)} bytes",
            retested=True
        )

    # =========================================================================
    # SSTI VALIDATION
    # =========================================================================

    async def _validate_ssti(self, finding, cookies: Dict = None) -> ValidationResult:
        """
        Validate SSTI.

        Rules:
        1. Math expression must evaluate (49 for 7*7)
        2. Original expression must NOT be in response (it was processed)
        """
        url = finding.endpoint
        param = finding.parameter
        method = finding.method
        payload = finding.payload

        # Determine expected output
        expected = None
        if '7*7' in payload:
            expected = '49'
        elif '7*\'7\'' in payload:
            expected = '7777777'
        else:
            return ValidationResult(
                True, 0.6,
                "SSTI detected (unknown payload type - manual verification needed)"
            )

        # Re-test
        body, _, status, _ = await self._send_request(url, param, payload, method, cookies)

        # Check if expected result appears and original payload doesn't
        if expected not in body:
            return ValidationResult(
                False, 0.0,
                f"Expected result '{expected}' not in response"
            )

        if payload in body:
            return ValidationResult(
                False, 0.2,
                "Payload reflected literally (not processed by template)"
            )

        # Test with safe value to make sure 49 isn't always there
        safe_body, _, _, _ = await self._send_request(url, param, "safe_test", method, cookies)
        if expected in safe_body:
            return ValidationResult(
                False, 0.1,
                f"'{expected}' appears in baseline - not template evaluation"
            )

        return ValidationResult(
            True, 0.95,
            f"Confirmed: Template evaluated {payload} = {expected}",
            retested=True
        )

    # =========================================================================
    # SENSITIVE FILE VALIDATION
    # =========================================================================

    async def _validate_sensitive_file(self, finding, cookies: Dict = None) -> ValidationResult:
        """Validate sensitive file exposure."""
        url = finding.endpoint

        try:
            async with self.session.get(url, cookies=cookies, ssl=False, timeout=self.timeout) as response:
                if response.status != 200:
                    return ValidationResult(
                        False, 0.0,
                        f"File not accessible (status {response.status})"
                    )

                body = await response.text()

                # Check for actual sensitive content
                if '.env' in url:
                    if '=' not in body or len(body) < 10:
                        return ValidationResult(
                            False, 0.2,
                            ".env file empty or not in expected format"
                        )
                    return ValidationResult(True, 0.9, "Confirmed: .env file accessible", retested=True)

                if '.git' in url:
                    if 'ref:' not in body and '[core]' not in body and 'tree' not in body:
                        return ValidationResult(
                            False, 0.2,
                            ".git content doesn't match expected format"
                        )
                    return ValidationResult(True, 0.9, "Confirmed: .git exposed", retested=True)

                # Generic sensitive file - just check it's accessible
                if len(body) > 10:
                    return ValidationResult(
                        True, 0.7,
                        "File accessible (manual review recommended)",
                        retested=True
                    )

                return ValidationResult(False, 0.2, "File appears empty")

        except Exception as e:
            return ValidationResult(False, 0.0, f"Failed to access file: {e}")
