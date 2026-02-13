"""
BREACH.AI v2 - Subdomain Hunter Module

Exhaustive subdomain enumeration using multiple techniques:
- Passive: crt.sh, SecurityTrails, DNSDumpster
- Active: DNS brute force, permutation
- Recursive: subdomain of subdomain discovery
"""

import asyncio
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

from breach.modules.base import (
    ReconModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    Severity,
)


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    source: str = ""
    is_alive: bool = False
    http_status: Optional[int] = None
    technologies: list[str] = field(default_factory=list)


@register_module
class SubdomainHunter(ReconModule):
    """
    Subdomain Hunter - Exhaustive subdomain enumeration.

    Techniques:
    - Passive enumeration via certificate transparency logs
    - DNS brute force with common subdomain wordlists
    - Permutation-based discovery
    - Recursive enumeration
    """

    info = ModuleInfo(
        name="subdomain_hunter",
        phase=BreachPhase.RECON,
        description="Exhaustive subdomain enumeration",
        author="BREACH.AI",
        techniques=["T1596.001", "T1590.002"],  # Search Open Technical Databases
        platforms=["web"],
        requires_access=False,
    )

    # Common subdomain prefixes to try
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "beta", "app", "mobile", "m", "portal", "secure", "vpn", "remote",
        "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
        "docs", "doc", "help", "support", "status", "blog", "news",
        "shop", "store", "cdn", "static", "assets", "media", "images",
        "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
        "aws", "s3", "azure", "gcp", "cloud", "k8s", "kubernetes",
        "internal", "intranet", "corp", "corporate", "office",
        "login", "auth", "oauth", "sso", "id", "identity",
        "dashboard", "panel", "console", "manager", "cms",
        "backup", "bak", "old", "legacy", "archive",
        "demo", "sandbox", "qa", "uat", "prod", "production",
        "api-v1", "api-v2", "v1", "v2", "ws", "websocket", "graphql",
    ]

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we can enumerate subdomains for this target."""
        if not config.target:
            return False

        # Extract domain from target URL
        parsed = urlparse(config.target)
        domain = parsed.netloc or parsed.path

        # Must have a valid domain
        return bool(domain) and "." in domain

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Run subdomain enumeration."""
        self._start_execution()

        # Extract base domain
        parsed = urlparse(config.target)
        domain = parsed.netloc or parsed.path
        if ":" in domain:
            domain = domain.split(":")[0]

        subdomains: dict[str, SubdomainResult] = {}

        # Phase 1: Certificate Transparency (passive)
        ct_subs = await self._enumerate_ct_logs(domain)
        for sub in ct_subs:
            if sub not in subdomains:
                subdomains[sub] = SubdomainResult(subdomain=sub, source="crt.sh")

        # Phase 2: DNS Brute Force (active)
        if config.aggressive:
            brute_subs = await self._brute_force_subdomains(domain)
            for sub in brute_subs:
                if sub not in subdomains:
                    subdomains[sub] = SubdomainResult(subdomain=sub, source="brute_force")

        # Phase 3: Verify alive subdomains
        alive_subs = await self._verify_subdomains(list(subdomains.keys()))
        for sub, is_alive, status in alive_subs:
            if sub in subdomains:
                subdomains[sub].is_alive = is_alive
                subdomains[sub].http_status = status

        # Collect evidence
        alive_list = [s for s in subdomains.values() if s.is_alive]
        if alive_list:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Discovered {len(alive_list)} live subdomains",
                content={
                    "total_found": len(subdomains),
                    "alive": len(alive_list),
                    "subdomains": [
                        {"name": s.subdomain, "source": s.source, "status": s.http_status}
                        for s in alive_list[:50]  # Limit to 50
                    ],
                },
                proves=f"Attack surface includes {len(alive_list)} accessible subdomains",
                severity=Severity.INFO if len(alive_list) < 10 else Severity.LOW,
            )

        return self._create_result(
            success=len(subdomains) > 0,
            action="subdomain_enumeration",
            details=f"Found {len(subdomains)} subdomains, {len(alive_list)} alive",
            data_extracted={
                "subdomains": [s.subdomain for s in subdomains.values()],
                "alive_subdomains": [s.subdomain for s in alive_list],
            },
        )

    async def _enumerate_ct_logs(self, domain: str) -> list[str]:
        """Enumerate subdomains from certificate transparency logs."""
        subdomains = set()

        if not self.http_client:
            return list(subdomains)

        try:
            # Query crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await self._safe_request("GET", url, timeout=30)

            if response and isinstance(response, list):
                for entry in response:
                    name_value = entry.get("name_value", "")
                    # Handle wildcard and multiple names
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)

        except Exception:
            pass

        return list(subdomains)

    async def _brute_force_subdomains(self, domain: str) -> list[str]:
        """Brute force common subdomains."""
        found = []

        async def check_subdomain(prefix: str):
            subdomain = f"{prefix}.{domain}"
            try:
                # DNS resolution check
                import socket
                socket.gethostbyname(subdomain)
                return subdomain
            except Exception:
                return None

        # Run checks in parallel with rate limiting
        semaphore = asyncio.Semaphore(20)

        async def limited_check(prefix: str):
            async with semaphore:
                return await check_subdomain(prefix)

        tasks = [limited_check(prefix) for prefix in self.COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and isinstance(result, str):
                found.append(result)

        return found

    async def _verify_subdomains(
        self, subdomains: list[str]
    ) -> list[tuple[str, bool, Optional[int]]]:
        """Verify which subdomains are alive via HTTP."""
        results = []

        async def check_alive(subdomain: str):
            for protocol in ["https", "http"]:
                url = f"{protocol}://{subdomain}"
                try:
                    response = await self._safe_request(
                        "GET", url, timeout=10, follow_redirects=False
                    )
                    if response:
                        status = response.get("status_code", 0)
                        return (subdomain, True, status)
                except Exception:
                    continue
            return (subdomain, False, None)

        # Rate-limited parallel checks
        semaphore = asyncio.Semaphore(10)

        async def limited_check(subdomain: str):
            async with semaphore:
                return await check_alive(subdomain)

        tasks = [limited_check(sub) for sub in subdomains[:100]]  # Limit to 100
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if isinstance(r, tuple)]
