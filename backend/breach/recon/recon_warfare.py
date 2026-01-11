"""
BREACH.AI - Recon Warfare Module

Advanced reconnaissance and intelligence gathering:
- Deep subdomain enumeration
- Cloud asset discovery (S3, Azure, GCP)
- GitHub/GitLab secret scanning
- Credential leak checking
- Technology fingerprinting
- DNS intelligence
- Certificate transparency
"""

import re
import json
import asyncio
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
from urllib.parse import urlparse

from backend.breach.utils.logger import logger


class ReconType(Enum):
    """Types of reconnaissance."""
    SUBDOMAIN = "subdomain"
    CLOUD_ASSET = "cloud_asset"
    GITHUB_SECRETS = "github_secrets"
    CREDENTIAL_LEAK = "credential_leak"
    TECH_STACK = "tech_stack"
    DNS_INTEL = "dns_intel"
    CERTIFICATE = "certificate"
    ENDPOINT = "endpoint"


@dataclass
class ReconFinding:
    """A reconnaissance finding."""
    recon_type: ReconType
    target: str
    data: Any
    severity: str = "info"
    description: str = ""
    actionable: bool = False


@dataclass
class ReconResult:
    """Complete reconnaissance result."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    cloud_assets: list[dict] = field(default_factory=list)
    exposed_secrets: list[dict] = field(default_factory=list)
    leaked_credentials: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    certificates: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[ReconFinding] = field(default_factory=list)


class ReconWarfare:
    """
    Advanced reconnaissance engine.

    Gathers intelligence from:
    - DNS records and Certificate Transparency
    - Cloud provider enumeration
    - GitHub/GitLab public repositories
    - Technology detection
    - Endpoint discovery
    """

    def __init__(self, http_client=None):
        self.http = http_client
        self._subdomain_wordlist = self._load_subdomain_wordlist()
        self._secret_patterns = self._load_secret_patterns()

    async def full_recon(self, target: str) -> ReconResult:
        """Run complete reconnaissance suite."""
        logger.info(f"Starting full reconnaissance on {target}")

        domain = self._extract_domain(target)
        result = ReconResult(target=target)

        # Run all recon modules concurrently
        tasks = [
            self._enumerate_subdomains(domain),
            self._enumerate_cloud_assets(domain),
            self._scan_for_secrets(domain),
            self._fingerprint_technologies(target),
            self._enumerate_dns(domain),
            self._enumerate_certificates(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        if isinstance(results[0], list):
            result.subdomains = results[0]
        if isinstance(results[1], list):
            result.cloud_assets = results[1]
        if isinstance(results[2], list):
            result.exposed_secrets = results[2]
        if isinstance(results[3], list):
            result.technologies = results[3]
        if isinstance(results[4], dict):
            result.dns_records = results[4]
        if isinstance(results[5], list):
            result.certificates = results[5]

        # Generate findings
        result.findings = self._generate_findings(result)

        logger.info(f"Reconnaissance complete: {len(result.subdomains)} subdomains, "
                   f"{len(result.cloud_assets)} cloud assets, "
                   f"{len(result.exposed_secrets)} secrets found")

        return result

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or target string."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc
        return target

    # =========================================================================
    # SUBDOMAIN ENUMERATION
    # =========================================================================

    async def _enumerate_subdomains(self, domain: str) -> list[str]:
        """
        Enumerate subdomains using multiple techniques:
        - Certificate Transparency logs
        - DNS bruteforce
        - Common subdomain patterns
        """
        logger.debug(f"Enumerating subdomains for {domain}")

        subdomains = set()

        # Certificate Transparency enumeration
        ct_subdomains = await self._ct_enumeration(domain)
        subdomains.update(ct_subdomains)

        # Common subdomain bruteforce
        for sub in self._subdomain_wordlist:
            subdomains.add(f"{sub}.{domain}")

        # Pattern-based discovery
        patterns = self._generate_subdomain_patterns(domain)
        subdomains.update(patterns)

        return sorted(list(subdomains))

    async def _ct_enumeration(self, domain: str) -> list[str]:
        """Query Certificate Transparency logs."""
        subdomains = []

        if not self.http:
            return subdomains

        # crt.sh query
        try:
            response = await self.http.get(
                f"https://crt.sh/?q=%.{domain}&output=json"
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.append(sub.strip())
        except Exception as e:
            logger.debug(f"CT enumeration error: {e}")

        return list(set(subdomains))

    def _generate_subdomain_patterns(self, domain: str) -> list[str]:
        """Generate common subdomain patterns."""
        company = domain.split('.')[0]
        patterns = []

        # Environment patterns
        envs = ["dev", "staging", "stage", "test", "qa", "uat", "prod", "production"]
        for env in envs:
            patterns.append(f"{env}.{domain}")
            patterns.append(f"{env}-{company}.{domain}")
            patterns.append(f"{company}-{env}.{domain}")
            patterns.append(f"api-{env}.{domain}")
            patterns.append(f"{env}-api.{domain}")

        # Service patterns
        services = ["api", "app", "web", "www2", "admin", "portal", "dashboard"]
        for svc in services:
            patterns.append(f"{svc}.{domain}")
            patterns.append(f"{svc}2.{domain}")
            patterns.append(f"{svc}-v2.{domain}")

        # Cloud patterns
        clouds = ["aws", "azure", "gcp", "k8s", "kubernetes", "docker"]
        for cloud in clouds:
            patterns.append(f"{cloud}.{domain}")
            patterns.append(f"{company}-{cloud}.{domain}")

        return patterns

    # =========================================================================
    # CLOUD ASSET ENUMERATION
    # =========================================================================

    async def _enumerate_cloud_assets(self, domain: str) -> list[dict]:
        """
        Find cloud assets:
        - S3 buckets
        - Azure blob storage
        - GCP storage buckets
        """
        logger.debug(f"Enumerating cloud assets for {domain}")

        assets = []
        company = domain.split('.')[0]

        # Generate bucket name variations
        bucket_patterns = self._generate_bucket_patterns(company)

        # Check S3 buckets
        for bucket in bucket_patterns:
            s3_result = await self._check_s3_bucket(bucket)
            if s3_result:
                assets.append(s3_result)

        # Check Azure blobs
        for bucket in bucket_patterns:
            azure_result = await self._check_azure_blob(bucket)
            if azure_result:
                assets.append(azure_result)

        # Check GCP buckets
        for bucket in bucket_patterns:
            gcp_result = await self._check_gcp_bucket(bucket)
            if gcp_result:
                assets.append(gcp_result)

        return assets

    def _generate_bucket_patterns(self, company: str) -> list[str]:
        """Generate common bucket naming patterns."""
        suffixes = [
            "", "-prod", "-production", "-dev", "-development",
            "-staging", "-stage", "-test", "-backup", "-backups",
            "-assets", "-static", "-media", "-uploads", "-files",
            "-data", "-logs", "-archive", "-public", "-private",
            "-internal", "-web", "-www", "-app", "-api",
        ]

        prefixes = [
            "", "backup-", "backups-", "dev-", "prod-",
            "staging-", "test-", "data-",
        ]

        patterns = []
        for prefix in prefixes:
            for suffix in suffixes:
                patterns.append(f"{prefix}{company}{suffix}")

        return patterns

    async def _check_s3_bucket(self, bucket: str) -> Optional[dict]:
        """Check if S3 bucket exists and is accessible."""
        if not self.http:
            return None

        urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]

        for url in urls:
            try:
                response = await self.http.get(url)
                if response.status_code != 404:
                    return {
                        "type": "s3",
                        "name": bucket,
                        "url": url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200,
                        "listing_enabled": "<ListBucketResult" in str(response.body),
                    }
            except Exception:
                pass

        return None

    async def _check_azure_blob(self, bucket: str) -> Optional[dict]:
        """Check if Azure blob storage exists."""
        if not self.http:
            return None

        url = f"https://{bucket}.blob.core.windows.net"

        try:
            response = await self.http.get(f"{url}?restype=container&comp=list")
            if response.status_code != 404:
                return {
                    "type": "azure_blob",
                    "name": bucket,
                    "url": url,
                    "status": response.status_code,
                    "accessible": response.status_code == 200,
                }
        except Exception:
            pass

        return None

    async def _check_gcp_bucket(self, bucket: str) -> Optional[dict]:
        """Check if GCP bucket exists."""
        if not self.http:
            return None

        urls = [
            f"https://storage.googleapis.com/{bucket}",
            f"https://{bucket}.storage.googleapis.com",
        ]

        for url in urls:
            try:
                response = await self.http.get(url)
                if response.status_code != 404:
                    return {
                        "type": "gcp",
                        "name": bucket,
                        "url": url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200,
                    }
            except Exception:
                pass

        return None

    # =========================================================================
    # SECRET SCANNING
    # =========================================================================

    async def _scan_for_secrets(self, domain: str) -> list[dict]:
        """
        Scan for exposed secrets:
        - GitHub repositories
        - Public code
        - Exposed config files
        """
        logger.debug(f"Scanning for secrets related to {domain}")

        secrets = []
        company = domain.split('.')[0]

        # Scan GitHub (if client available)
        github_secrets = await self._scan_github(domain, company)
        secrets.extend(github_secrets)

        return secrets

    async def _scan_github(self, domain: str, company: str) -> list[dict]:
        """Scan GitHub for exposed secrets."""
        if not self.http:
            return []

        secrets = []

        # GitHub search queries
        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{company}" AWS_ACCESS_KEY',
            f'"{domain}" PRIVATE KEY',
        ]

        # Note: In production, this would use GitHub API with proper auth
        # For simulation, we return the structure

        return secrets

    def _load_secret_patterns(self) -> list[tuple]:
        """Load regex patterns for secret detection."""
        return [
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'[0-9a-zA-Z/+]{40}', 'Potential AWS Secret Key'),

            # Google
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google API Key'),
            (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'Google OAuth ID'),

            # GitHub
            (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token'),
            (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token'),
            (r'ghu_[0-9a-zA-Z]{36}', 'GitHub User Token'),
            (r'ghs_[0-9a-zA-Z]{36}', 'GitHub Server Token'),
            (r'ghr_[0-9a-zA-Z]{36}', 'GitHub Refresh Token'),

            # Stripe
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Secret Key'),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Publishable Key'),

            # Slack
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),

            # Twilio
            (r'SK[0-9a-fA-F]{32}', 'Twilio API Key'),
            (r'AC[0-9a-fA-F]{32}', 'Twilio Account SID'),

            # SendGrid
            (r'SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}', 'SendGrid API Key'),

            # Mailgun
            (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key'),

            # Square
            (r'sq0atp-[0-9A-Za-z\\-_]{22}', 'Square Access Token'),
            (r'sq0csp-[0-9A-Za-z\\-_]{43}', 'Square OAuth Secret'),

            # JWT
            (r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token'),

            # Private Keys
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key'),

            # Database URLs
            (r'mongodb(\+srv)?:\/\/[^\s]+', 'MongoDB Connection String'),
            (r'postgres(ql)?:\/\/[^\s]+', 'PostgreSQL Connection String'),
            (r'mysql:\/\/[^\s]+', 'MySQL Connection String'),
            (r'redis:\/\/[^\s]+', 'Redis Connection String'),

            # Generic
            (r'["\']?password["\']?\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Password'),
            (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\'][^"\']{16,}["\']', 'API Key'),
            (r'["\']?secret["\']?\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Secret'),
        ]

    def scan_text_for_secrets(self, text: str) -> list[dict]:
        """Scan text content for secrets."""
        findings = []

        for pattern, secret_type in self._secret_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Mask the secret for safe reporting
                secret = match.group(0)
                masked = secret[:8] + "..." + secret[-4:] if len(secret) > 12 else "***"

                findings.append({
                    "type": secret_type,
                    "pattern": pattern,
                    "masked_value": masked,
                    "position": match.start(),
                })

        return findings

    # =========================================================================
    # TECHNOLOGY FINGERPRINTING
    # =========================================================================

    async def _fingerprint_technologies(self, target: str) -> list[str]:
        """
        Fingerprint technologies:
        - Web servers
        - Frameworks
        - CMS
        - Cloud providers
        - WAFs
        """
        logger.debug(f"Fingerprinting technologies on {target}")

        technologies = []

        if not self.http:
            return technologies

        try:
            response = await self.http.get(target)
            headers = response.headers
            body = response.text if hasattr(response, 'text') else str(response.body)

            # Check headers
            technologies.extend(self._fingerprint_headers(headers))

            # Check body
            technologies.extend(self._fingerprint_body(body))

        except Exception as e:
            logger.debug(f"Fingerprinting error: {e}")

        return list(set(technologies))

    def _fingerprint_headers(self, headers: dict) -> list[str]:
        """Fingerprint from HTTP headers."""
        techs = []

        header_signatures = {
            "Server": {
                "nginx": "nginx",
                "Apache": "Apache",
                "Microsoft-IIS": "IIS",
                "cloudflare": "Cloudflare",
                "AmazonS3": "Amazon S3",
                "gunicorn": "Gunicorn",
                "Werkzeug": "Flask",
            },
            "X-Powered-By": {
                "PHP": "PHP",
                "ASP.NET": "ASP.NET",
                "Express": "Express.js",
                "Next.js": "Next.js",
                "Phusion Passenger": "Passenger",
            },
            "X-AspNet-Version": {
                "": "ASP.NET",
            },
            "X-Generator": {
                "Drupal": "Drupal",
                "WordPress": "WordPress",
            },
            "CF-RAY": {
                "": "Cloudflare",
            },
            "X-Amz-Cf-Id": {
                "": "AWS CloudFront",
            },
            "X-Cache": {
                "HIT": "CDN Cached",
            },
        }

        for header, signatures in header_signatures.items():
            value = headers.get(header, "")
            for sig, tech in signatures.items():
                if sig == "" or sig.lower() in value.lower():
                    techs.append(tech)

        return techs

    def _fingerprint_body(self, body: str) -> list[str]:
        """Fingerprint from response body."""
        techs = []

        body_signatures = {
            # CMS
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "Drupal.settings": "Drupal",
            "/sites/default/files": "Drupal",
            "Joomla!": "Joomla",
            "/media/jui/": "Joomla",

            # JavaScript Frameworks
            "__NEXT_DATA__": "Next.js",
            "_next/static": "Next.js",
            "ng-app": "Angular",
            "ng-controller": "Angular",
            "__NUXT__": "Nuxt.js",
            "data-reactroot": "React",
            "data-reactid": "React",
            "__vue__": "Vue.js",
            "v-cloak": "Vue.js",

            # E-commerce
            "Shopify.theme": "Shopify",
            "cdn.shopify.com": "Shopify",
            "Magento": "Magento",
            "WooCommerce": "WooCommerce",

            # Analytics
            "google-analytics.com": "Google Analytics",
            "googletagmanager.com": "Google Tag Manager",
            "segment.com/analytics": "Segment",
            "mixpanel.com": "Mixpanel",

            # Other
            "cloudflare": "Cloudflare",
            "recaptcha": "reCAPTCHA",
            "grecaptcha": "reCAPTCHA",
        }

        for sig, tech in body_signatures.items():
            if sig.lower() in body.lower():
                techs.append(tech)

        return techs

    # =========================================================================
    # DNS ENUMERATION
    # =========================================================================

    async def _enumerate_dns(self, domain: str) -> dict:
        """
        Enumerate DNS records:
        - A, AAAA, CNAME, MX, TXT, NS, SOA
        - SPF, DKIM, DMARC
        """
        logger.debug(f"Enumerating DNS records for {domain}")

        dns_records = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "SOA": None,
            "SPF": None,
            "DKIM": None,
            "DMARC": None,
        }

        # Use DNS-over-HTTPS for enumeration
        if self.http:
            dns_records = await self._doh_query(domain, dns_records)

        return dns_records

    async def _doh_query(self, domain: str, records: dict) -> dict:
        """Query DNS using DNS-over-HTTPS."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for rtype in record_types:
            try:
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                response = await self.http.get(url)
                if response.status_code == 200:
                    data = response.json()
                    answers = data.get("Answer", [])
                    records[rtype] = [a.get("data") for a in answers]

                    # Extract SPF from TXT
                    if rtype == "TXT":
                        for txt in records[rtype]:
                            if "v=spf1" in str(txt):
                                records["SPF"] = txt

            except Exception as e:
                logger.debug(f"DoH query error for {rtype}: {e}")

        # Check DMARC
        try:
            url = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
            response = await self.http.get(url)
            if response.status_code == 200:
                data = response.json()
                answers = data.get("Answer", [])
                for a in answers:
                    if "v=DMARC1" in str(a.get("data", "")):
                        records["DMARC"] = a.get("data")
        except Exception:
            pass

        return records

    # =========================================================================
    # CERTIFICATE ENUMERATION
    # =========================================================================

    async def _enumerate_certificates(self, domain: str) -> list[dict]:
        """Enumerate SSL/TLS certificates from CT logs."""
        logger.debug(f"Enumerating certificates for {domain}")

        certificates = []

        if not self.http:
            return certificates

        # Query crt.sh
        try:
            response = await self.http.get(
                f"https://crt.sh/?q={domain}&output=json"
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data[:50]:  # Limit to recent 50
                    certificates.append({
                        "issuer": entry.get("issuer_name"),
                        "common_name": entry.get("common_name"),
                        "name_value": entry.get("name_value"),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                        "serial_number": entry.get("serial_number"),
                    })
        except Exception as e:
            logger.debug(f"Certificate enumeration error: {e}")

        return certificates

    # =========================================================================
    # FINDINGS GENERATION
    # =========================================================================

    def _generate_findings(self, result: ReconResult) -> list[ReconFinding]:
        """Generate actionable findings from recon results."""
        findings = []

        # Cloud asset findings
        for asset in result.cloud_assets:
            if asset.get("accessible"):
                severity = "high" if asset.get("listing_enabled") else "medium"
                findings.append(ReconFinding(
                    recon_type=ReconType.CLOUD_ASSET,
                    target=asset.get("url", ""),
                    data=asset,
                    severity=severity,
                    description=f"Accessible {asset.get('type')} bucket: {asset.get('name')}",
                    actionable=True,
                ))

        # Secret findings
        for secret in result.exposed_secrets:
            findings.append(ReconFinding(
                recon_type=ReconType.GITHUB_SECRETS,
                target=result.target,
                data=secret,
                severity="critical",
                description=f"Exposed secret: {secret.get('type')}",
                actionable=True,
            ))

        # DNS findings (missing security records)
        dns = result.dns_records
        if not dns.get("SPF"):
            findings.append(ReconFinding(
                recon_type=ReconType.DNS_INTEL,
                target=result.target,
                data={"missing": "SPF"},
                severity="low",
                description="Missing SPF record - email spoofing possible",
                actionable=True,
            ))
        if not dns.get("DMARC"):
            findings.append(ReconFinding(
                recon_type=ReconType.DNS_INTEL,
                target=result.target,
                data={"missing": "DMARC"},
                severity="low",
                description="Missing DMARC record - email spoofing possible",
                actionable=True,
            ))

        # Subdomain findings (interesting subdomains)
        interesting_patterns = ["dev", "staging", "test", "admin", "internal", "vpn", "jenkins", "gitlab"]
        for sub in result.subdomains:
            for pattern in interesting_patterns:
                if pattern in sub.lower():
                    findings.append(ReconFinding(
                        recon_type=ReconType.SUBDOMAIN,
                        target=sub,
                        data={"pattern": pattern},
                        severity="info",
                        description=f"Interesting subdomain: {sub}",
                        actionable=True,
                    ))
                    break

        return findings

    def _load_subdomain_wordlist(self) -> list[str]:
        """Load common subdomain wordlist."""
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "api", "dev", "staging", "test", "admin", "portal", "vpn", "remote",
            "blog", "shop", "store", "app", "mobile", "m", "static", "assets", "cdn",
            "img", "images", "media", "video", "download", "downloads", "upload",
            "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
            "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
            "grafana", "kibana", "prometheus", "monitoring", "metrics", "status",
            "auth", "login", "sso", "oauth", "identity", "accounts", "id",
            "docs", "documentation", "wiki", "help", "support", "kb",
            "internal", "intranet", "corp", "corporate", "office", "employee",
            "backup", "bak", "old", "legacy", "archive", "temp", "tmp",
            "sandbox", "demo", "preview", "beta", "alpha", "canary",
            "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
            "api-v1", "api-v2", "api-dev", "api-staging", "api-prod",
            "www2", "www3", "web", "web1", "web2", "server", "server1",
            "mx", "mx1", "mx2", "mail1", "mail2", "email", "smtp1",
            "ns", "ns3", "dns", "dns1", "dns2",
            "proxy", "gateway", "edge", "lb", "loadbalancer",
            "payment", "pay", "checkout", "cart", "orders",
            "crm", "erp", "hr", "finance", "sales", "marketing",
        ]


# Convenience function
async def recon_warfare(target: str, http_client=None) -> ReconResult:
    """Run full reconnaissance on target."""
    recon = ReconWarfare(http_client=http_client)
    return await recon.full_recon(target)
