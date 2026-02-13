"""
BREACH.AI - Reconnaissance Engine

Main orchestrator for all reconnaissance activities.
Maps the complete attack surface before attacking.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from breach.core.memory import AttackSurface, Finding, Severity, Endpoint
from breach.recon.dns import DNSEnumerator
from breach.recon.ports import PortScanner
from breach.recon.web import WebCrawler
from breach.utils.helpers import extract_domain, normalize_url
from breach.utils.http import HTTPClient
from breach.utils.logger import logger


@dataclass
class ReconResult:
    """Results from reconnaissance."""
    target: str
    attack_surface: AttackSurface
    findings: list[Finding] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    # Stats
    subdomains_found: int = 0
    endpoints_found: int = 0
    ports_scanned: int = 0
    sensitive_files_found: int = 0

    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0


@dataclass
class ReconConfig:
    """Configuration for reconnaissance."""
    # DNS
    enumerate_dns: bool = True
    dns_wordlist: Optional[str] = None

    # Port scanning
    scan_ports: bool = True
    port_range: str = "common"  # common, full, custom
    custom_ports: list[int] = field(default_factory=list)

    # Web crawling
    crawl_web: bool = True
    max_depth: int = 3
    max_pages: int = 500

    # Timeouts
    dns_timeout: float = 5.0
    port_timeout: float = 2.0
    http_timeout: float = 10.0

    # Rate limiting
    rate_limit: int = 50


class ReconEngine:
    """
    Main reconnaissance engine.

    Orchestrates:
    - DNS enumeration (subdomains)
    - Port scanning
    - Web crawling
    - Technology fingerprinting
    - Sensitive file detection
    """

    # Common sensitive files to check
    SENSITIVE_FILES = [
        ".git/HEAD",
        ".git/config",
        ".env",
        ".env.local",
        ".env.production",
        "config.php",
        "wp-config.php",
        "configuration.php",
        "web.config",
        ".htaccess",
        "robots.txt",
        "sitemap.xml",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        ".DS_Store",
        "Thumbs.db",
        "backup.sql",
        "database.sql",
        "dump.sql",
        ".svn/entries",
        "package.json",
        "composer.json",
        "Gemfile",
        "requirements.txt",
        ".travis.yml",
        "Dockerfile",
        "docker-compose.yml",
        "swagger.json",
        "swagger.yaml",
        "openapi.json",
        "openapi.yaml",
        "api-docs",
        "graphql",
        "actuator/health",
        "actuator/info",
        "actuator/env",
        "server-status",
        "server-info",
        "phpinfo.php",
        "info.php",
        "test.php",
        "debug.php",
        "elmah.axd",
        "trace.axd",
    ]

    def __init__(self, config: Optional[ReconConfig] = None):
        self.config = config or ReconConfig()
        self.http_client: Optional[HTTPClient] = None

    async def run_full_recon(self, target_url: str) -> ReconResult:
        """
        Run full reconnaissance on a target.

        Args:
            target_url: The target URL to scan

        Returns:
            ReconResult with mapped attack surface
        """
        logger.phase_start("RECONNAISSANCE")

        target_url = normalize_url(target_url)
        domain = extract_domain(target_url)

        result = ReconResult(
            target=target_url,
            attack_surface=AttackSurface(target=target_url),
        )

        # Initialize HTTP client
        self.http_client = HTTPClient(
            base_url=target_url,
            timeout=self.config.http_timeout,
            rate_limit=self.config.rate_limit,
        )

        try:
            # Run recon modules in parallel where possible
            tasks = []

            if self.config.enumerate_dns:
                tasks.append(self._run_dns_enum(domain, result))

            if self.config.scan_ports:
                tasks.append(self._run_port_scan(domain, result))

            if self.config.crawl_web:
                tasks.append(self._run_web_crawl(target_url, result))

            # Always check for sensitive files
            tasks.append(self._check_sensitive_files(target_url, result))

            # Run all tasks
            await asyncio.gather(*tasks, return_exceptions=True)

            # Fingerprint technologies
            await self._fingerprint_technologies(target_url, result)

            result.end_time = datetime.utcnow()

            # Log summary
            logger.phase_end("RECONNAISSANCE", {
                "subdomains": result.subdomains_found,
                "endpoints": result.endpoints_found,
                "ports": result.ports_scanned,
                "sensitive_files": result.sensitive_files_found,
                "findings": len(result.findings),
            })

        finally:
            if self.http_client:
                await self.http_client.close()

        return result

    async def _run_dns_enum(self, domain: str, result: ReconResult):
        """Run DNS enumeration."""
        logger.recon("DNS", f"Enumerating {domain}")

        dns_enum = DNSEnumerator(timeout=self.config.dns_timeout)

        try:
            # Get DNS records
            records = await dns_enum.get_all_records(domain)

            # Get subdomains
            subdomains = await dns_enum.enumerate_subdomains(domain)

            for subdomain in subdomains:
                result.attack_surface.add_subdomain(subdomain)
                result.subdomains_found += 1
                logger.recon("DNS", f"Found subdomain: {subdomain}")

            # Check for zone transfer vulnerability
            if await dns_enum.check_zone_transfer(domain):
                result.findings.append(Finding.create(
                    title="DNS Zone Transfer Allowed",
                    vuln_type="dns_zone_transfer",
                    severity=Severity.HIGH,
                    target=domain,
                    details="DNS server allows zone transfers, exposing all DNS records",
                    remediation="Disable zone transfers or restrict to authorized servers",
                ))
                logger.finding("high", "DNS Zone Transfer Allowed", domain)

        except Exception as e:
            logger.debug(f"DNS enumeration error: {e}")

    async def _run_port_scan(self, domain: str, result: ReconResult):
        """Run port scanning."""
        logger.recon("PORTS", f"Scanning {domain}")

        scanner = PortScanner(timeout=self.config.port_timeout)

        try:
            # Determine ports to scan
            if self.config.port_range == "common":
                ports = scanner.COMMON_PORTS
            elif self.config.port_range == "full":
                ports = range(1, 65536)
            else:
                ports = self.config.custom_ports or scanner.COMMON_PORTS

            # Scan ports
            open_ports = await scanner.scan_ports(domain, ports)
            result.ports_scanned = len(ports)

            for port_info in open_ports:
                result.attack_surface.add_port(
                    port=port_info["port"],
                    service=port_info.get("service", ""),
                    banner=port_info.get("banner", ""),
                )
                logger.recon("PORTS", f"Open port: {port_info['port']} ({port_info.get('service', 'unknown')})")

                # Check for dangerous exposed services
                self._check_dangerous_port(port_info, domain, result)

        except Exception as e:
            logger.debug(f"Port scan error: {e}")

    def _check_dangerous_port(self, port_info: dict, domain: str, result: ReconResult):
        """Check if an open port represents a security risk."""
        port = port_info["port"]
        service = port_info.get("service", "").lower()

        dangerous_ports = {
            21: ("FTP", Severity.MEDIUM),
            22: ("SSH", Severity.LOW),  # Expected but note it
            23: ("Telnet", Severity.HIGH),
            3306: ("MySQL", Severity.CRITICAL),
            5432: ("PostgreSQL", Severity.CRITICAL),
            27017: ("MongoDB", Severity.CRITICAL),
            6379: ("Redis", Severity.CRITICAL),
            9200: ("Elasticsearch", Severity.HIGH),
            11211: ("Memcached", Severity.HIGH),
        }

        if port in dangerous_ports:
            service_name, severity = dangerous_ports[port]
            if severity in [Severity.CRITICAL, Severity.HIGH]:
                result.findings.append(Finding.create(
                    title=f"Exposed {service_name} Service",
                    vuln_type="exposed_service",
                    severity=severity,
                    target=domain,
                    endpoint=f"{domain}:{port}",
                    details=f"{service_name} service exposed on port {port}",
                    remediation=f"Restrict access to {service_name} using firewall rules",
                ))
                logger.finding(severity.value, f"Exposed {service_name}", f"{domain}:{port}")

    async def _run_web_crawl(self, target_url: str, result: ReconResult):
        """Run web crawling."""
        logger.recon("WEB", f"Crawling {target_url}")

        crawler = WebCrawler(
            http_client=self.http_client,
            max_depth=self.config.max_depth,
            max_pages=self.config.max_pages,
        )

        try:
            crawl_result = await crawler.crawl(target_url)

            for endpoint in crawl_result.endpoints:
                result.attack_surface.add_endpoint(endpoint)
                result.endpoints_found += 1

            for form in crawl_result.forms:
                result.attack_surface.forms.append(form)

            # Extract parameters
            for endpoint in crawl_result.endpoints:
                for param in endpoint.parameters:
                    result.attack_surface.add_parameter(
                        endpoint=endpoint.url,
                        param_name=param,
                        param_type="query"
                    )

            logger.recon("WEB", f"Found {result.endpoints_found} endpoints, {len(result.attack_surface.forms)} forms")

        except Exception as e:
            logger.debug(f"Web crawl error: {e}")

    async def _check_sensitive_files(self, target_url: str, result: ReconResult):
        """Check for sensitive files."""
        logger.recon("FILES", "Checking for sensitive files")

        base_url = target_url.rstrip('/')

        async def check_file(path: str):
            url = f"{base_url}/{path}"
            try:
                response = await self.http_client.get(url)
                if response.is_success and not response.contains("404") and not response.contains("not found"):
                    return (path, response)
            except Exception:
                pass
            return None

        # Check files in parallel (batched)
        batch_size = 10
        for i in range(0, len(self.SENSITIVE_FILES), batch_size):
            batch = self.SENSITIVE_FILES[i:i + batch_size]
            tasks = [check_file(path) for path in batch]
            results = await asyncio.gather(*tasks)

            for file_result in results:
                if file_result:
                    path, response = file_result
                    result.attack_surface.sensitive_files.append(path)
                    result.sensitive_files_found += 1

                    # Create finding for critical files
                    severity = self._get_file_severity(path)
                    if severity in [Severity.CRITICAL, Severity.HIGH]:
                        result.findings.append(Finding.create(
                            title=f"Sensitive File Exposed: {path}",
                            vuln_type="sensitive_file_exposure",
                            severity=severity,
                            target=target_url,
                            endpoint=f"{base_url}/{path}",
                            details=f"Sensitive file accessible: {path}",
                            remediation="Remove or restrict access to sensitive files",
                        ))
                        logger.finding(severity.value, f"Exposed: {path}", f"{base_url}/{path}")
                    else:
                        logger.recon("FILES", f"Found: {path}")

    def _get_file_severity(self, path: str) -> Severity:
        """Get severity for exposed file."""
        critical_files = [".git", ".env", "config.php", "wp-config", "database", "backup", ".sql"]
        high_files = [".svn", "docker-compose", "actuator", "phpinfo", "debug"]
        medium_files = ["swagger", "openapi", "package.json", "composer.json"]

        path_lower = path.lower()

        for pattern in critical_files:
            if pattern in path_lower:
                return Severity.CRITICAL

        for pattern in high_files:
            if pattern in path_lower:
                return Severity.HIGH

        for pattern in medium_files:
            if pattern in path_lower:
                return Severity.MEDIUM

        return Severity.LOW

    async def _fingerprint_technologies(self, target_url: str, result: ReconResult):
        """Fingerprint technologies used by the target."""
        logger.recon("TECH", "Fingerprinting technologies")

        try:
            response = await self.http_client.get(target_url)

            if response.is_success:
                # Check headers
                headers = response.headers

                # Server header
                server = headers.get("server", "")
                if server:
                    result.attack_surface.add_technology(server.split("/")[0])

                # X-Powered-By
                powered_by = headers.get("x-powered-by", "")
                if powered_by:
                    result.attack_surface.add_technology(powered_by)

                # Check for specific headers
                if "x-aspnet-version" in headers:
                    result.attack_surface.add_technology("ASP.NET")
                if "x-drupal-cache" in headers:
                    result.attack_surface.add_technology("Drupal")

                # Body-based detection
                from breach.utils.helpers import detect_technology
                body_techs = detect_technology(headers, response.body)
                for tech in body_techs:
                    result.attack_surface.add_technology(tech)

                logger.recon("TECH", f"Detected: {', '.join(result.attack_surface.technologies)}")

        except Exception as e:
            logger.debug(f"Technology fingerprinting error: {e}")
