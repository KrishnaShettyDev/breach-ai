"""
BREACH.AI - DNS Enumeration

DNS reconnaissance including subdomain enumeration and zone transfer checks.
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from backend.breach.utils.logger import logger


@dataclass
class DNSRecord:
    """A DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int = 0


class DNSEnumerator:
    """
    DNS enumeration for subdomain discovery and DNS reconnaissance.
    """

    # Common subdomain prefixes to check
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging", "stage",
        "test", "testing", "api", "api1", "api2", "app", "admin", "administrator",
        "beta", "demo", "shop", "store", "m", "mobile", "secure", "ssl", "vpn",
        "remote", "server", "server1", "server2", "web", "web1", "web2", "portal",
        "host", "support", "email", "cloud", "git", "svn", "cvs", "db", "database",
        "mysql", "postgres", "mongo", "redis", "cache", "cdn", "static", "assets",
        "img", "images", "media", "video", "download", "downloads", "files",
        "backup", "backups", "old", "new", "legacy", "internal", "intranet",
        "extranet", "corp", "corporate", "private", "public", "dev1", "dev2",
        "qa", "uat", "prod", "production", "preprod", "pre-prod", "auth",
        "login", "sso", "oauth", "id", "identity", "accounts", "account",
        "billing", "payment", "payments", "checkout", "cart", "orders",
        "dashboard", "panel", "cpanel", "whm", "plesk", "webmin",
        "jenkins", "ci", "cd", "build", "deploy", "status", "monitor",
        "metrics", "logs", "elk", "kibana", "grafana", "prometheus",
        "docs", "documentation", "wiki", "help", "kb", "knowledge",
        "forum", "forums", "community", "social", "chat", "slack",
        "jira", "confluence", "bitbucket", "gitlab", "github",
    ]

    def __init__(self, timeout: float = 5.0, nameservers: list[str] = None):
        self.timeout = timeout
        self.nameservers = nameservers

        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout * 2
            if nameservers:
                self.resolver.nameservers = nameservers

    async def get_all_records(self, domain: str) -> dict[str, list[DNSRecord]]:
        """
        Get all DNS records for a domain.

        Returns:
            Dictionary of record type -> list of records
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed, skipping DNS enumeration")
            return {}

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        records = {}

        for rtype in record_types:
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, domain, rtype
                )
                records[rtype] = [
                    DNSRecord(
                        record_type=rtype,
                        name=domain,
                        value=str(rdata),
                        ttl=answers.ttl,
                    )
                    for rdata in answers
                ]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception as e:
                logger.debug(f"DNS query failed for {domain} {rtype}: {e}")

        return records

    async def enumerate_subdomains(
        self,
        domain: str,
        wordlist: list[str] = None,
        max_concurrent: int = 50
    ) -> list[str]:
        """
        Enumerate subdomains using wordlist.

        Args:
            domain: Base domain to enumerate
            wordlist: Custom wordlist (defaults to COMMON_SUBDOMAINS)
            max_concurrent: Maximum concurrent DNS queries

        Returns:
            List of discovered subdomains
        """
        if not DNS_AVAILABLE:
            return []

        wordlist = wordlist or self.COMMON_SUBDOMAINS
        found_subdomains = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_subdomain(prefix: str) -> Optional[str]:
            subdomain = f"{prefix}.{domain}"
            async with semaphore:
                try:
                    await asyncio.to_thread(
                        self.resolver.resolve, subdomain, "A"
                    )
                    return subdomain
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    return None
                except Exception:
                    return None

        # Check all subdomains concurrently
        tasks = [check_subdomain(prefix) for prefix in wordlist]
        results = await asyncio.gather(*tasks)

        found_subdomains = [r for r in results if r is not None]
        return found_subdomains

    async def check_zone_transfer(self, domain: str) -> bool:
        """
        Check if DNS zone transfer is allowed.

        Args:
            domain: Domain to check

        Returns:
            True if zone transfer is allowed (vulnerability!)
        """
        if not DNS_AVAILABLE:
            return False

        try:
            # Get nameservers
            ns_records = await asyncio.to_thread(
                self.resolver.resolve, domain, "NS"
            )

            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                try:
                    # Attempt zone transfer
                    zone = await asyncio.to_thread(
                        dns.zone.from_xfr,
                        dns.query.xfr(ns_host, domain, timeout=self.timeout)
                    )
                    if zone:
                        logger.warning(f"Zone transfer successful from {ns_host}!")
                        return True
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Zone transfer check failed: {e}")

        return False

    async def reverse_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address to lookup

        Returns:
            Hostname if found
        """
        if not DNS_AVAILABLE:
            return None

        try:
            # Convert IP to reverse DNS format
            from dns.reversename import from_address
            rev_name = from_address(ip)
            answers = await asyncio.to_thread(
                self.resolver.resolve, rev_name, "PTR"
            )
            return str(answers[0]).rstrip('.')
        except Exception:
            return None

    async def get_mx_records(self, domain: str) -> list[tuple[int, str]]:
        """
        Get MX records with priorities.

        Returns:
            List of (priority, mail_server) tuples
        """
        if not DNS_AVAILABLE:
            return []

        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, "MX"
            )
            return [(rdata.preference, str(rdata.exchange).rstrip('.'))
                    for rdata in answers]
        except Exception:
            return []

    async def get_txt_records(self, domain: str) -> list[str]:
        """
        Get TXT records (useful for SPF, DKIM, etc.).

        Returns:
            List of TXT record values
        """
        if not DNS_AVAILABLE:
            return []

        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, "TXT"
            )
            return [str(rdata).strip('"') for rdata in answers]
        except Exception:
            return []

    async def check_dnssec(self, domain: str) -> bool:
        """
        Check if DNSSEC is enabled for domain.

        Returns:
            True if DNSSEC is enabled
        """
        if not DNS_AVAILABLE:
            return False

        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, "DNSKEY"
            )
            return len(list(answers)) > 0
        except Exception:
            return False
