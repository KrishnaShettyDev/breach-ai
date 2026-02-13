"""
BREACH.AI - Subdomain Takeover Scanner
======================================
Detects subdomain takeover vulnerabilities.
"""

import asyncio
from typing import List, Dict, Optional
from .base import BaseAttack, Finding, Severity


class SubdomainTakeover(BaseAttack):
    """
    Subdomain Takeover Scanner

    Checks for:
    - Dangling DNS records (CNAME to deprovisioned services)
    - Cloud service takeover (AWS, Azure, GCP, Heroku, etc.)
    - CDN takeover (CloudFront, Fastly, etc.)
    - SaaS platform takeover
    """

    name = "Subdomain Takeover"

    # Fingerprints for vulnerable services
    FINGERPRINTS: Dict[str, Dict] = {
        "aws_s3": {
            "cname": [".s3.amazonaws.com", ".s3-website"],
            "response": ["NoSuchBucket", "The specified bucket does not exist"],
            "service": "AWS S3",
        },
        "aws_cloudfront": {
            "cname": [".cloudfront.net"],
            "response": ["Bad request", "ERROR: The request could not be satisfied"],
            "service": "AWS CloudFront",
        },
        "azure": {
            "cname": [".azurewebsites.net", ".cloudapp.azure.com", ".azure-api.net", ".azureedge.net"],
            "response": ["404 Web Site not found", "The resource you are looking for has been removed"],
            "service": "Microsoft Azure",
        },
        "github": {
            "cname": [".github.io", ".githubusercontent.com"],
            "response": ["There isn't a GitHub Pages site here", "For root URLs"],
            "service": "GitHub Pages",
        },
        "heroku": {
            "cname": [".herokuapp.com", ".herokudns.com"],
            "response": ["No such app", "no-such-app"],
            "service": "Heroku",
        },
        "shopify": {
            "cname": [".myshopify.com"],
            "response": ["Sorry, this shop is currently unavailable", "Only one step left"],
            "service": "Shopify",
        },
        "fastly": {
            "cname": [".fastly.net", ".fastlylb.net"],
            "response": ["Fastly error: unknown domain"],
            "service": "Fastly CDN",
        },
        "ghost": {
            "cname": [".ghost.io"],
            "response": ["The thing you were looking for is no longer here"],
            "service": "Ghost",
        },
        "pantheon": {
            "cname": [".pantheonsite.io"],
            "response": ["The gods are wise", "404 error unknown site"],
            "service": "Pantheon",
        },
        "tumblr": {
            "cname": [".tumblr.com"],
            "response": ["There's nothing here", "Whatever you were looking for"],
            "service": "Tumblr",
        },
        "wordpress": {
            "cname": [".wordpress.com"],
            "response": ["Do you want to register"],
            "service": "WordPress.com",
        },
        "zendesk": {
            "cname": [".zendesk.com"],
            "response": ["Help Center Closed", "this help center no longer exists"],
            "service": "Zendesk",
        },
        "unbounce": {
            "cname": [".unbouncepages.com"],
            "response": ["The requested URL was not found", "This page is not available"],
            "service": "Unbounce",
        },
        "surge": {
            "cname": [".surge.sh"],
            "response": ["project not found"],
            "service": "Surge.sh",
        },
        "bitbucket": {
            "cname": [".bitbucket.io"],
            "response": ["Repository not found"],
            "service": "Bitbucket",
        },
        "intercom": {
            "cname": [".custom.intercom.help"],
            "response": ["This page is reserved for a Intercom"],
            "service": "Intercom",
        },
        "netlify": {
            "cname": [".netlify.app", ".netlify.com"],
            "response": ["Not Found - Request ID"],
            "service": "Netlify",
        },
        "vercel": {
            "cname": [".vercel.app", ".now.sh"],
            "response": ["The deployment could not be found"],
            "service": "Vercel",
        },
    }

    async def run(self) -> List[Finding]:
        findings = []

        # Get subdomains from state
        subdomains = self._get_subdomains()

        for subdomain in subdomains:
            takeover_finding = await self._check_takeover(subdomain)
            if takeover_finding:
                findings.append(takeover_finding)

        return findings

    def _get_subdomains(self) -> List[str]:
        """Get subdomains to check from state."""
        subdomains = []

        # From discovered endpoints
        for endpoint in self.state.discovered_endpoints:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(endpoint)
                if parsed.netloc:
                    subdomains.append(parsed.netloc)
            except Exception:
                continue

        # From target
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        if parsed.netloc:
            subdomains.append(parsed.netloc)

        return list(set(subdomains))[:50]  # Limit

    async def _check_takeover(self, subdomain: str) -> Optional[Finding]:
        """Check if subdomain is vulnerable to takeover."""
        try:
            # Get CNAME record
            cname = await self._get_cname(subdomain)
            if not cname:
                return None

            # Check against fingerprints
            for service_id, fingerprint in self.FINGERPRINTS.items():
                for cname_pattern in fingerprint["cname"]:
                    if cname_pattern in cname.lower():
                        # Check HTTP response
                        is_vulnerable = await self._check_http_fingerprint(
                            subdomain, fingerprint["response"]
                        )

                        if is_vulnerable:
                            return Finding(
                                title=f"Subdomain Takeover: {fingerprint['service']}",
                                severity=Severity.CRITICAL,
                                category="Subdomain Takeover",
                                endpoint=f"https://{subdomain}",
                                method="GET",
                                description=f"The subdomain {subdomain} has a CNAME pointing to "
                                           f"{fingerprint['service']} ({cname}), but the resource "
                                           f"no longer exists. An attacker could claim this resource.",
                                evidence=f"CNAME: {cname}\nService: {fingerprint['service']}",
                                business_impact=150000,
                                impact_explanation="Subdomain takeover allows attackers to host malicious "
                                                 "content on your domain, stealing cookies, "
                                                 "phishing users, and damaging reputation.",
                                fix_suggestion=f"Either reclaim the {fingerprint['service']} resource "
                                             f"or remove the dangling DNS record for {subdomain}.",
                                curl_command=f"dig CNAME {subdomain} && curl -I https://{subdomain}"
                            )

        except Exception:
            pass

        return None

    async def _get_cname(self, subdomain: str) -> Optional[str]:
        """Get CNAME record for subdomain."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            pass
        return None

    async def _check_http_fingerprint(self, subdomain: str, fingerprints: List[str]) -> bool:
        """Check if HTTP response matches vulnerable fingerprint."""
        try:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                try:
                    response = await self.client.get(url, follow_redirects=False)
                    response_text = response.text.lower()

                    for fp in fingerprints:
                        if fp.lower() in response_text:
                            return True
                except Exception:
                    continue

        except Exception:
            pass

        return False
