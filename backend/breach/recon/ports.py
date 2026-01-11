"""
BREACH.AI - Port Scanner

Async port scanning with service detection.
"""

import asyncio
import socket
from dataclasses import dataclass
from typing import Optional

from backend.breach.utils.logger import logger


@dataclass
class PortResult:
    """Result of scanning a port."""
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    version: str = ""


class PortScanner:
    """
    Asynchronous port scanner with service detection.
    """

    # Common ports to scan (covers most web and database services)
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
        8888, 9090, 9200, 9300, 27017, 27018, 28017,
    ]

    # Extended ports for thorough scans
    EXTENDED_PORTS = COMMON_PORTS + [
        81, 82, 83, 84, 85, 88, 280, 444, 591, 593, 623, 631, 636, 832,
        873, 888, 902, 1080, 1099, 1311, 1352, 1414, 1720, 1723, 1883,
        2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375,
        2376, 2379, 2480, 2483, 2484, 3000, 3001, 3128, 3268, 3269, 3310,
        3333, 3389, 4000, 4040, 4242, 4243, 4369, 4443, 4445, 4505, 4506,
        4567, 4711, 4712, 4848, 4990, 5000, 5001, 5050, 5060, 5222, 5269,
        5357, 5601, 5632, 5672, 5800, 5984, 5985, 5986, 6000, 6001, 6066,
        6082, 6379, 6443, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7070,
        7396, 7474, 7548, 7777, 7778, 8000, 8001, 8008, 8009, 8010, 8020,
        8042, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
        8089, 8090, 8091, 8098, 8099, 8100, 8180, 8181, 8200, 8222, 8243,
        8280, 8281, 8333, 8383, 8400, 8443, 8500, 8530, 8531, 8800, 8834,
        8880, 8883, 8888, 8983, 9000, 9001, 9002, 9043, 9060, 9080, 9090,
        9091, 9100, 9200, 9300, 9418, 9443, 9500, 9800, 9943, 9944, 9981,
        9999, 10000, 10080, 10443, 11211, 11214, 11215, 12345, 15672,
        16080, 17000, 18080, 18091, 18092, 20000, 27017, 27018, 28017,
        28015, 30000, 32400, 50000, 50030, 50060, 50070, 50090, 61616,
    ]

    # Service identification by port
    PORT_SERVICES = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        2049: "nfs",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        9200: "elasticsearch",
        11211: "memcached",
        27017: "mongodb",
    }

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def scan_port(self, host: str, port: int) -> Optional[PortResult]:
        """
        Scan a single port.

        Args:
            host: Target hostname or IP
            port: Port number to scan

        Returns:
            PortResult if port is open, None otherwise
        """
        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

            # Get service info
            service = self.PORT_SERVICES.get(port, "unknown")

            # Try to grab banner
            banner = ""
            try:
                # Send empty line to prompt response
                writer.write(b"\r\n")
                await writer.drain()

                # Read banner with short timeout
                banner_data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=1.0
                )
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass

            # Close connection
            writer.close()
            await writer.wait_closed()

            return PortResult(
                port=port,
                is_open=True,
                service=service,
                banner=banner[:200] if banner else "",
            )

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            logger.debug(f"Port scan error {host}:{port}: {e}")
            return None

    async def scan_ports(
        self,
        host: str,
        ports: list[int] = None,
        extended: bool = False
    ) -> list[dict]:
        """
        Scan multiple ports on a host.

        Args:
            host: Target hostname or IP
            ports: List of ports to scan (defaults to COMMON_PORTS)
            extended: Use extended port list

        Returns:
            List of open port info dictionaries
        """
        if ports is None:
            ports = self.EXTENDED_PORTS if extended else self.COMMON_PORTS

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            logger.warning(f"Could not resolve hostname: {host}")
            ip = host

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_with_semaphore(port: int) -> Optional[PortResult]:
            async with semaphore:
                return await self.scan_port(ip, port)

        # Scan all ports concurrently
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks)

        # Filter to open ports
        open_ports = []
        for result in results:
            if result and result.is_open:
                open_ports.append({
                    "port": result.port,
                    "service": result.service,
                    "banner": result.banner,
                })

        return open_ports

    async def quick_scan(self, host: str) -> list[dict]:
        """
        Quick scan of most important ports.
        """
        important_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
        return await self.scan_ports(host, important_ports)

    async def scan_range(
        self,
        host: str,
        start_port: int,
        end_port: int
    ) -> list[dict]:
        """
        Scan a range of ports.
        """
        ports = list(range(start_port, end_port + 1))
        return await self.scan_ports(host, ports)

    async def detect_service(self, host: str, port: int) -> Optional[str]:
        """
        Attempt to identify the service on a port using probes.
        """
        result = await self.scan_port(host, port)
        if not result:
            return None

        # Try to identify from banner
        banner = result.banner.lower()

        service_signatures = {
            "ssh": ["ssh", "openssh", "dropbear"],
            "http": ["http", "apache", "nginx", "iis"],
            "ftp": ["ftp", "vsftpd", "proftpd", "pure-ftpd"],
            "smtp": ["smtp", "postfix", "sendmail", "exim"],
            "mysql": ["mysql", "mariadb"],
            "postgresql": ["postgresql", "postgres"],
            "redis": ["redis"],
            "mongodb": ["mongodb", "mongo"],
            "elasticsearch": ["elasticsearch"],
        }

        for service, signatures in service_signatures.items():
            if any(sig in banner for sig in signatures):
                return service

        return result.service or "unknown"

    async def check_http(self, host: str, port: int, https: bool = False) -> bool:
        """
        Check if port is running HTTP(S).
        """
        import httpx

        scheme = "https" if https or port in [443, 8443] else "http"
        url = f"{scheme}://{host}:{port}/"

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                response = await client.head(url)
                return response.status_code > 0
        except Exception:
            return False
