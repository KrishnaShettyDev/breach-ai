"""
BREACH.AI v2 - Cloud Discoverer Module

Cloud asset enumeration for AWS, Azure, and GCP.
"""

import asyncio
import re
from urllib.parse import urlparse

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


# Common S3 bucket name patterns
S3_BUCKET_PATTERNS = [
    "{company}", "{company}-prod", "{company}-production",
    "{company}-dev", "{company}-development", "{company}-staging",
    "{company}-backup", "{company}-backups", "{company}-data",
    "{company}-assets", "{company}-static", "{company}-media",
    "{company}-logs", "{company}-uploads", "{company}-files",
    "{company}-public", "{company}-private", "{company}-internal",
    "{domain}", "{domain}-backup", "{domain}-assets",
]


@register_module
class CloudDiscoverer(ReconModule):
    """
    Cloud Discoverer - Find cloud assets and misconfigurations.

    Discovers:
    - S3 buckets (AWS)
    - Azure Blob Storage containers
    - GCP Storage buckets
    - Exposed cloud services
    - Misconfigured public assets
    """

    info = ModuleInfo(
        name="cloud_discoverer",
        phase=BreachPhase.RECON,
        description="Cloud asset enumeration",
        author="BREACH.AI",
        techniques=["T1580", "T1619"],  # Cloud Infrastructure Discovery
        platforms=["cloud", "aws", "azure", "gcp"],
        requires_access=False,
    )

    async def check(self, config: ModuleConfig) -> bool:
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        parsed = urlparse(config.target)
        domain = parsed.netloc or parsed.path
        if ":" in domain:
            domain = domain.split(":")[0]

        # Extract company name from domain
        company = domain.split(".")[0]

        discovered_assets = []
        public_buckets = []
        cloud_services = []

        # Phase 1: S3 Bucket enumeration
        s3_results = await self._enumerate_s3_buckets(company, domain)
        discovered_assets.extend(s3_results)
        public_buckets.extend([r for r in s3_results if r.get("public")])

        # Phase 2: Azure Blob enumeration
        azure_results = await self._enumerate_azure_blobs(company)
        discovered_assets.extend(azure_results)

        # Phase 3: GCP Storage enumeration
        gcp_results = await self._enumerate_gcp_storage(company)
        discovered_assets.extend(gcp_results)

        # Phase 4: Check for exposed cloud services
        services = await self._check_cloud_services(config.target)
        cloud_services.extend(services)

        # Add evidence
        if discovered_assets:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Discovered {len(discovered_assets)} cloud assets",
                content={
                    "assets": discovered_assets[:20],
                    "public_count": len(public_buckets),
                },
                proves="Cloud infrastructure mapped",
                severity=Severity.INFO,
            )

        if public_buckets:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description="Public cloud storage buckets found",
                content={"buckets": public_buckets},
                proves="Data potentially accessible without authentication",
                severity=Severity.HIGH,
            )

        if cloud_services:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description="Cloud services detected",
                content={"services": cloud_services},
                proves="Cloud infrastructure identified",
                severity=Severity.LOW,
            )

        return self._create_result(
            success=len(discovered_assets) > 0 or len(cloud_services) > 0,
            action="cloud_discovery",
            details=f"Found {len(discovered_assets)} assets, {len(public_buckets)} public",
            data_extracted={
                "cloud_assets": discovered_assets,
                "public_buckets": public_buckets,
                "cloud_services": cloud_services,
            },
            new_targets=[a["url"] for a in discovered_assets if a.get("url")],
            enables_modules=["cloud_intruder"] if public_buckets else [],
        )

    async def _enumerate_s3_buckets(self, company: str, domain: str) -> list[dict]:
        """Enumerate S3 buckets."""
        found = []
        bucket_names = []

        # Generate bucket name variations
        for pattern in S3_BUCKET_PATTERNS:
            name = pattern.replace("{company}", company).replace("{domain}", domain.replace(".", "-"))
            bucket_names.append(name)

        semaphore = asyncio.Semaphore(10)

        async def check_bucket(name: str):
            async with semaphore:
                # Check AWS S3
                url = f"https://{name}.s3.amazonaws.com"
                try:
                    response = await self._safe_request("GET", url, timeout=10)
                    if response:
                        status = response.get("status_code", 0)
                        if status == 200:
                            return {
                                "type": "s3",
                                "name": name,
                                "url": url,
                                "public": True,
                                "listable": "ListBucketResult" in response.get("text", ""),
                            }
                        elif status == 403:
                            return {
                                "type": "s3",
                                "name": name,
                                "url": url,
                                "public": False,
                                "exists": True,
                            }
                except Exception:
                    pass
                return None

        tasks = [check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and isinstance(result, dict):
                found.append(result)

        return found

    async def _enumerate_azure_blobs(self, company: str) -> list[dict]:
        """Enumerate Azure Blob Storage containers."""
        found = []
        container_names = [company, f"{company}data", f"{company}backup", f"{company}public"]

        semaphore = asyncio.Semaphore(5)

        async def check_container(name: str):
            async with semaphore:
                url = f"https://{name}.blob.core.windows.net"
                try:
                    response = await self._safe_request("GET", url, timeout=10)
                    if response and response.get("status_code") in [200, 400, 403]:
                        return {
                            "type": "azure_blob",
                            "name": name,
                            "url": url,
                            "exists": True,
                            "public": response.get("status_code") == 200,
                        }
                except Exception:
                    pass
                return None

        tasks = [check_container(name) for name in container_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and isinstance(result, dict):
                found.append(result)

        return found

    async def _enumerate_gcp_storage(self, company: str) -> list[dict]:
        """Enumerate GCP Storage buckets."""
        found = []
        bucket_names = [company, f"{company}-prod", f"{company}-backup"]

        semaphore = asyncio.Semaphore(5)

        async def check_bucket(name: str):
            async with semaphore:
                url = f"https://storage.googleapis.com/{name}"
                try:
                    response = await self._safe_request("GET", url, timeout=10)
                    if response:
                        status = response.get("status_code", 0)
                        if status in [200, 403]:
                            return {
                                "type": "gcp_storage",
                                "name": name,
                                "url": url,
                                "exists": True,
                                "public": status == 200,
                            }
                except Exception:
                    pass
                return None

        tasks = [check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and isinstance(result, dict):
                found.append(result)

        return found

    async def _check_cloud_services(self, target: str) -> list[dict]:
        """Check for exposed cloud services based on headers and content."""
        services = []

        try:
            response = await self._safe_request("GET", target, timeout=10)
            if response:
                headers = response.get("headers", {})
                text = response.get("text", "")

                # Check for AWS
                if any(h.startswith("x-amz") for h in headers.keys()):
                    services.append({"provider": "aws", "indicator": "x-amz headers"})

                # Check for CloudFront
                if "x-cache" in headers and "cloudfront" in headers.get("x-cache", "").lower():
                    services.append({"provider": "aws_cloudfront", "indicator": "CloudFront cache"})

                # Check for Azure
                if "azure" in str(headers).lower():
                    services.append({"provider": "azure", "indicator": "Azure headers"})

                # Check for GCP
                if "googleapis" in text or "gcp" in str(headers).lower():
                    services.append({"provider": "gcp", "indicator": "Google APIs detected"})

                # Check for Vercel
                if "x-vercel" in headers:
                    services.append({"provider": "vercel", "indicator": "Vercel headers"})

                # Check for Cloudflare
                if "cf-ray" in headers:
                    services.append({"provider": "cloudflare", "indicator": "CF-Ray header"})

        except Exception:
            pass

        return services
