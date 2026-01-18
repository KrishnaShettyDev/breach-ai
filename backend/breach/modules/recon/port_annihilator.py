"""
BREACH.AI v2 - Port Annihilator Module

Full port scanning with service identification.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from backend.breach.modules.base import (
    ReconModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    Severity,
)


@dataclass
class PortResult:
    """Result of port scan."""
    port: int
    state: str = "closed"  # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""


# Common ports and their services
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb", 9200: "elasticsearch", 11211: "memcached",
}

# Extended ports for deep scans
EXTENDED_PORTS = list(range(1, 1025)) + [
    1080, 1433, 1521, 2049, 2181, 3000, 3306, 3389, 4000, 4443,
    5000, 5432, 5900, 6000, 6379, 6443, 7000, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211,
    27017, 27018, 28017, 50000, 50070, 50075,
]


@register_module
class PortAnnihilator(ReconModule):
    """
    Port Annihilator - Comprehensive port scanning.

    Features:
    - TCP SYN scan (fast)
    - TCP connect scan (accurate)
    - Service fingerprinting
    - Version detection
    - Banner grabbing
    """

    info = ModuleInfo(
        name="port_annihilator",
        phase=BreachPhase.RECON,
        description="Full port scanning with service identification",
        author="BREACH.AI",
        techniques=["T1046"],  # Network Service Discovery
        platforms=["infrastructure"],
        requires_access=False,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we can scan this target."""
        if not config.target:
            return False

        parsed = urlparse(config.target)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]

        return bool(host)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Run port scan."""
        self._start_execution()

        parsed = urlparse(config.target)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]

        # Resolve hostname
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return self._create_result(
                success=False,
                action="port_scan",
                error=f"Could not resolve hostname: {host}",
            )

        # Select ports to scan
        ports_to_scan = list(COMMON_PORTS.keys())
        if config.aggressive:
            ports_to_scan = EXTENDED_PORTS

        # Scan ports
        open_ports = await self._scan_ports(ip, ports_to_scan)

        # Get service info for open ports
        services = await self._identify_services(ip, open_ports)

        # Collect evidence
        if open_ports:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Port scan of {host} ({ip})",
                content={
                    "host": host,
                    "ip": ip,
                    "open_ports": [
                        {
                            "port": s.port,
                            "service": s.service,
                            "version": s.version,
                            "banner": s.banner[:100] if s.banner else "",
                        }
                        for s in services
                    ],
                },
                proves=f"Target has {len(open_ports)} open ports",
                severity=Severity.INFO,
            )

            # Flag interesting services
            interesting = [s for s in services if s.service in [
                "ssh", "rdp", "ftp", "mysql", "postgresql", "mongodb",
                "redis", "elasticsearch", "memcached",
            ]]
            if interesting:
                self._add_evidence(
                    evidence_type=EvidenceType.API_RESPONSE,
                    description="Potentially exploitable services found",
                    content={
                        "services": [
                            {"port": s.port, "service": s.service}
                            for s in interesting
                        ]
                    },
                    proves="Attack vectors via exposed services",
                    severity=Severity.MEDIUM,
                )

        return self._create_result(
            success=len(open_ports) > 0,
            action="port_scan",
            details=f"Scanned {len(ports_to_scan)} ports, {len(open_ports)} open",
            data_extracted={
                "host": host,
                "ip": ip,
                "open_ports": open_ports,
                "services": [
                    {"port": s.port, "service": s.service, "version": s.version}
                    for s in services
                ],
            },
            new_targets=[f"{host}:{p}" for p in open_ports],
        )

    async def _scan_ports(self, ip: str, ports: list[int]) -> list[int]:
        """Scan ports using TCP connect."""
        open_ports = []
        semaphore = asyncio.Semaphore(100)  # Limit concurrent connections

        async def scan_port(port: int) -> Optional[int]:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=2,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception:
                    return None

        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, int):
                open_ports.append(result)

        return sorted(open_ports)

    async def _identify_services(
        self, ip: str, ports: list[int]
    ) -> list[PortResult]:
        """Identify services on open ports."""
        results = []

        for port in ports:
            result = PortResult(port=port, state="open")

            # Known service mapping
            if port in COMMON_PORTS:
                result.service = COMMON_PORTS[port]

            # Try to grab banner
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=3,
                )

                # Send probe for some services
                if port in [80, 8080, 8000, 8443, 443]:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()

                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=2,
                )
                result.banner = banner.decode("utf-8", errors="ignore").strip()

                # Extract version from banner
                if result.banner:
                    result.version = self._extract_version(result.banner)

                writer.close()
                await writer.wait_closed()

            except Exception:
                pass

            results.append(result)

        return results

    def _extract_version(self, banner: str) -> str:
        """Extract version information from banner."""
        import re

        # Common version patterns
        patterns = [
            r"(\d+\.\d+(?:\.\d+)?)",  # X.Y.Z
            r"version[:\s]+([^\s,]+)",
            r"([A-Za-z]+/\d+\.\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""
