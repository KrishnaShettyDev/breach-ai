"""
BREACH.AI v2 - Cloud Storage Raider

Access and sample cloud storage (S3, Azure Blob, GCS).
Detects sensitive files, misconfigurations, and data exposure.
"""

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from backend.breach.modules.base import (
    DataAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# Sensitive file patterns
SENSITIVE_FILE_PATTERNS = {
    "credentials": [
        r"\.env$",
        r"credentials\.json$",
        r"credentials\.xml$",
        r"\.htpasswd$",
        r"id_rsa$",
        r"id_dsa$",
        r"\.pem$",
        r"\.key$",
        r"\.p12$",
        r"\.pfx$",
        r"service-account.*\.json$",
        r"aws-credentials$",
        r"\.aws/credentials$",
    ],
    "config": [
        r"config\.json$",
        r"config\.yaml$",
        r"config\.yml$",
        r"settings\.json$",
        r"\.config$",
        r"database\.yml$",
        r"secrets\.yml$",
        r"terraform\.tfstate$",
        r"\.tfvars$",
        r"ansible.*\.yml$",
        r"docker-compose\.yml$",
        r"kubernetes.*\.yaml$",
    ],
    "data": [
        r"\.sql$",
        r"\.sqlite$",
        r"\.db$",
        r"\.bak$",
        r"backup.*\.(sql|tar|gz|zip)$",
        r"dump.*\.(sql|tar|gz|zip)$",
        r"export.*\.(csv|json|xlsx)$",
        r"users\.(csv|json|xlsx)$",
        r"customers\.(csv|json|xlsx)$",
        r"passwords\.(txt|csv)$",
    ],
    "source_code": [
        r"\.git/",
        r"\.gitignore$",
        r"\.svn/",
        r"source\.(tar|zip|gz)$",
        r"backup\.(tar|zip|gz)$",
        r"www\.(tar|zip|gz)$",
    ],
    "logs": [
        r"\.log$",
        r"access\.log$",
        r"error\.log$",
        r"debug\.log$",
        r"application\.log$",
    ],
}

# AWS S3 endpoint patterns
S3_ENDPOINTS = {
    "path_style": "https://s3.{region}.amazonaws.com/{bucket}",
    "virtual_hosted": "https://{bucket}.s3.{region}.amazonaws.com",
    "accelerate": "https://{bucket}.s3-accelerate.amazonaws.com",
    "website": "http://{bucket}.s3-website-{region}.amazonaws.com",
}

# Azure Blob endpoint patterns
AZURE_ENDPOINTS = {
    "blob": "https://{account}.blob.core.windows.net/{container}",
    "datalake": "https://{account}.dfs.core.windows.net/{container}",
}

# GCS endpoint patterns
GCS_ENDPOINTS = {
    "storage": "https://storage.googleapis.com/{bucket}",
    "authenticated": "https://storage.cloud.google.com/{bucket}",
    "xml": "https://{bucket}.storage.googleapis.com",
}

# Common bucket names to test
COMMON_BUCKET_PATTERNS = [
    "{company}-backup",
    "{company}-backups",
    "{company}-data",
    "{company}-dev",
    "{company}-development",
    "{company}-prod",
    "{company}-production",
    "{company}-staging",
    "{company}-logs",
    "{company}-assets",
    "{company}-uploads",
    "{company}-files",
    "{company}-storage",
    "{company}-media",
    "{company}-public",
    "{company}-private",
    "{company}-internal",
    "{company}-reports",
    "{company}-exports",
    "{company}-db-backups",
]

# Maximum files to sample
MAX_SAMPLE_FILES = 20
MAX_FILE_SIZE_SAMPLE = 10 * 1024  # 10KB max for file content preview


@register_module
class CloudStorageRaider(DataAccessModule):
    """
    Cloud Storage Raider - Access S3, Azure Blob, and GCS.

    Techniques:
    - Public bucket enumeration
    - Authenticated bucket access
    - Sensitive file detection
    - Misconfiguration exploitation
    - Data sampling and classification
    - SAS token abuse (Azure)
    - Signed URL exploitation
    """

    info = ModuleInfo(
        name="cloud_storage_raider",
        phase=BreachPhase.DATA_ACCESS,
        description="Cloud storage access and data extraction (S3, Azure, GCS)",
        author="BREACH.AI",
        techniques=["T1530", "T1537"],  # Data from Cloud Storage, Transfer to Cloud
        platforms=["aws", "azure", "gcp", "cloud"],
        requires_access=True,
        required_access_level=AccessLevel.CLOUD_USER,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have cloud storage access."""
        has_s3 = bool(
            config.chain_data.get("aws_credentials") or
            config.chain_data.get("s3_buckets")
        )
        has_azure = bool(
            config.chain_data.get("azure_credentials") or
            config.chain_data.get("azure_storage_accounts") or
            config.chain_data.get("azure_sas_token")
        )
        has_gcs = bool(
            config.chain_data.get("gcp_credentials") or
            config.chain_data.get("gcs_buckets")
        )

        return has_s3 or has_azure or has_gcs

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute cloud storage access."""
        self._start_execution()

        accessed_storage = []
        sensitive_files = []
        data_samples = []
        total_files = 0
        total_size = 0

        # Raid AWS S3
        if config.chain_data.get("aws_credentials") or config.chain_data.get("s3_buckets"):
            s3_result = await self._raid_s3(config)
            accessed_storage.extend(s3_result.get("buckets", []))
            sensitive_files.extend(s3_result.get("sensitive_files", []))
            data_samples.extend(s3_result.get("samples", []))
            total_files += s3_result.get("total_files", 0)
            total_size += s3_result.get("total_size", 0)

        # Raid Azure Blob
        if config.chain_data.get("azure_credentials") or config.chain_data.get("azure_storage_accounts"):
            azure_result = await self._raid_azure_blob(config)
            accessed_storage.extend(azure_result.get("containers", []))
            sensitive_files.extend(azure_result.get("sensitive_files", []))
            data_samples.extend(azure_result.get("samples", []))
            total_files += azure_result.get("total_files", 0)
            total_size += azure_result.get("total_size", 0)

        # Raid GCS
        if config.chain_data.get("gcp_credentials") or config.chain_data.get("gcs_buckets"):
            gcs_result = await self._raid_gcs(config)
            accessed_storage.extend(gcs_result.get("buckets", []))
            sensitive_files.extend(gcs_result.get("sensitive_files", []))
            data_samples.extend(gcs_result.get("samples", []))
            total_files += gcs_result.get("total_files", 0)
            total_size += gcs_result.get("total_size", 0)

        # Calculate business impact
        impact = self._calculate_storage_impact(
            total_files, total_size, sensitive_files
        )

        # Add evidence
        for storage in accessed_storage:
            severity = Severity.CRITICAL if storage.get("public") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.DATA_SAMPLE,
                description=f"Accessed {storage['provider']} storage: {storage['name']}",
                content={
                    "provider": storage["provider"],
                    "name": storage["name"],
                    "file_count": storage.get("file_count", 0),
                    "size_bytes": storage.get("size", 0),
                    "public": storage.get("public", False),
                    "sensitive_files_count": storage.get("sensitive_files_count", 0),
                },
                proves=f"Full access to {storage['provider']} storage with {storage.get('file_count', 0)} files",
                severity=severity,
            )

        if sensitive_files:
            self._add_evidence(
                evidence_type=EvidenceType.DATA_SAMPLE,
                description=f"Found {len(sensitive_files)} sensitive files",
                content={
                    "count": len(sensitive_files),
                    "types": list(set(f.get("type") for f in sensitive_files)),
                    "files": [
                        {
                            "name": f.get("name"),
                            "type": f.get("type"),
                            "storage": f.get("storage"),
                        }
                        for f in sensitive_files[:20]
                    ],
                },
                proves="Sensitive files accessible in cloud storage",
                severity=Severity.CRITICAL,
            )

        if data_samples:
            for sample in data_samples[:5]:
                self._add_data_sample_evidence(
                    description=f"Data sample from {sample.get('storage', 'unknown')}",
                    data=sample.get("preview", ""),
                    proves="Actual data is accessible",
                    severity=Severity.HIGH,
                    redact_pii=True,
                )

        # Business impact evidence
        self._add_evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            description="Cloud storage business impact assessment",
            content=impact,
            proves=f"Estimated breach cost: ${impact['total_cost']:,}",
            severity=Severity.CRITICAL,
        )

        return self._create_result(
            success=len(accessed_storage) > 0,
            action="cloud_storage_raid",
            details=f"Accessed {len(accessed_storage)} storage locations, {total_files} files, {len(sensitive_files)} sensitive",
            data_extracted={
                "storage_locations": [s["name"] for s in accessed_storage],
                "total_files": total_files,
                "total_size_bytes": total_size,
                "sensitive_files": len(sensitive_files),
                "business_impact": impact,
            } if accessed_storage else None,
            enables_modules=["evidence_generator"],
        )

    async def _raid_s3(self, config: ModuleConfig) -> dict:
        """Raid AWS S3 buckets."""
        results = {
            "buckets": [],
            "sensitive_files": [],
            "samples": [],
            "total_files": 0,
            "total_size": 0,
        }

        # Get buckets from chain data
        buckets = config.chain_data.get("s3_buckets", [])

        for bucket in buckets:
            bucket_name = bucket if isinstance(bucket, str) else bucket.get("name", "")
            if not bucket_name:
                continue

            bucket_info = {
                "provider": "aws_s3",
                "name": bucket_name,
                "file_count": 0,
                "size": 0,
                "public": False,
                "sensitive_files_count": 0,
            }

            # Get bucket contents from chain data or test access
            bucket_contents = config.chain_data.get(f"s3_contents_{bucket_name}", [])

            if bucket_contents:
                bucket_info["file_count"] = len(bucket_contents)

                for obj in bucket_contents:
                    file_key = obj.get("key", obj.get("Key", ""))
                    file_size = obj.get("size", obj.get("Size", 0))

                    results["total_files"] += 1
                    results["total_size"] += file_size
                    bucket_info["size"] += file_size

                    # Check for sensitive files
                    sensitive_type = self._classify_file(file_key)
                    if sensitive_type:
                        bucket_info["sensitive_files_count"] += 1
                        results["sensitive_files"].append({
                            "name": file_key,
                            "type": sensitive_type,
                            "storage": f"s3://{bucket_name}",
                            "size": file_size,
                        })

            # Check if bucket is public
            bucket_info["public"] = config.chain_data.get(f"s3_public_{bucket_name}", False)

            results["buckets"].append(bucket_info)

            # Get data samples
            if bucket_contents and len(results["samples"]) < MAX_SAMPLE_FILES:
                for obj in bucket_contents[:3]:
                    file_key = obj.get("key", obj.get("Key", ""))
                    preview = obj.get("preview", "")

                    if preview:
                        results["samples"].append({
                            "storage": f"s3://{bucket_name}",
                            "file": file_key,
                            "preview": preview[:MAX_FILE_SIZE_SAMPLE],
                        })

        return results

    async def _raid_azure_blob(self, config: ModuleConfig) -> dict:
        """Raid Azure Blob Storage."""
        results = {
            "containers": [],
            "sensitive_files": [],
            "samples": [],
            "total_files": 0,
            "total_size": 0,
        }

        # Get storage accounts from chain data
        storage_accounts = config.chain_data.get("azure_storage_accounts", [])

        for account in storage_accounts:
            account_name = account.get("name", "")
            containers = account.get("containers", [])

            for container in containers:
                container_name = container.get("name", "")
                if not container_name:
                    continue

                container_info = {
                    "provider": "azure_blob",
                    "name": f"{account_name}/{container_name}",
                    "file_count": 0,
                    "size": 0,
                    "public": container.get("public_access", False),
                    "sensitive_files_count": 0,
                }

                # Get container contents
                blobs = container.get("blobs", [])

                for blob in blobs:
                    blob_name = blob.get("name", "")
                    blob_size = blob.get("size", 0)

                    container_info["file_count"] += 1
                    container_info["size"] += blob_size
                    results["total_files"] += 1
                    results["total_size"] += blob_size

                    # Check for sensitive files
                    sensitive_type = self._classify_file(blob_name)
                    if sensitive_type:
                        container_info["sensitive_files_count"] += 1
                        results["sensitive_files"].append({
                            "name": blob_name,
                            "type": sensitive_type,
                            "storage": f"azure://{account_name}/{container_name}",
                            "size": blob_size,
                        })

                results["containers"].append(container_info)

                # Get data samples
                if blobs and len(results["samples"]) < MAX_SAMPLE_FILES:
                    for blob in blobs[:3]:
                        preview = blob.get("preview", "")
                        if preview:
                            results["samples"].append({
                                "storage": f"azure://{account_name}/{container_name}",
                                "file": blob.get("name", ""),
                                "preview": preview[:MAX_FILE_SIZE_SAMPLE],
                            })

        return results

    async def _raid_gcs(self, config: ModuleConfig) -> dict:
        """Raid Google Cloud Storage."""
        results = {
            "buckets": [],
            "sensitive_files": [],
            "samples": [],
            "total_files": 0,
            "total_size": 0,
        }

        # Get buckets from chain data
        buckets = config.chain_data.get("gcs_buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("name", "") if isinstance(bucket, dict) else bucket
            if not bucket_name:
                continue

            bucket_info = {
                "provider": "gcs",
                "name": bucket_name,
                "file_count": 0,
                "size": 0,
                "public": False,
                "sensitive_files_count": 0,
            }

            # Get bucket contents from chain data
            bucket_contents = config.chain_data.get(f"gcs_contents_{bucket_name}", [])

            if bucket_contents:
                bucket_info["file_count"] = len(bucket_contents)

                for obj in bucket_contents:
                    obj_name = obj.get("name", "")
                    obj_size = obj.get("size", 0)

                    results["total_files"] += 1
                    results["total_size"] += obj_size
                    bucket_info["size"] += obj_size

                    # Check for sensitive files
                    sensitive_type = self._classify_file(obj_name)
                    if sensitive_type:
                        bucket_info["sensitive_files_count"] += 1
                        results["sensitive_files"].append({
                            "name": obj_name,
                            "type": sensitive_type,
                            "storage": f"gs://{bucket_name}",
                            "size": obj_size,
                        })

            # Check if bucket is public
            bucket_info["public"] = bucket.get("public", False) if isinstance(bucket, dict) else False

            results["buckets"].append(bucket_info)

            # Get data samples
            if bucket_contents and len(results["samples"]) < MAX_SAMPLE_FILES:
                for obj in bucket_contents[:3]:
                    preview = obj.get("preview", "")
                    if preview:
                        results["samples"].append({
                            "storage": f"gs://{bucket_name}",
                            "file": obj.get("name", ""),
                            "preview": preview[:MAX_FILE_SIZE_SAMPLE],
                        })

        return results

    def _classify_file(self, filename: str) -> Optional[str]:
        """Classify file as sensitive based on name patterns."""
        filename_lower = filename.lower()

        for category, patterns in SENSITIVE_FILE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, filename_lower):
                    return category

        return None

    def _calculate_storage_impact(
        self,
        total_files: int,
        total_size: int,
        sensitive_files: list
    ) -> dict:
        """Calculate business impact of storage exposure."""
        # Count sensitive file types
        credential_files = sum(1 for f in sensitive_files if f.get("type") == "credentials")
        config_files = sum(1 for f in sensitive_files if f.get("type") == "config")
        data_files = sum(1 for f in sensitive_files if f.get("type") == "data")
        source_files = sum(1 for f in sensitive_files if f.get("type") == "source_code")

        # Calculate costs
        credential_cost = credential_files * 50000  # Major incident per credential file
        config_cost = config_files * 10000  # Config exposure
        data_cost = data_files * 25000  # Data breach
        source_cost = source_files * 75000  # IP theft

        # Storage-based costs
        size_gb = total_size / (1024 * 1024 * 1024)
        storage_cost = int(size_gb * 1000)  # $1000 per GB of exposed data

        # Remediation
        remediation_cost = 25000 if sensitive_files else 5000

        total = credential_cost + config_cost + data_cost + source_cost + storage_cost + remediation_cost

        return {
            "total_files": total_files,
            "total_size_gb": round(size_gb, 2),
            "sensitive_file_counts": {
                "credentials": credential_files,
                "config": config_files,
                "data": data_files,
                "source_code": source_files,
            },
            "credential_exposure_cost": credential_cost,
            "config_exposure_cost": config_cost,
            "data_breach_cost": data_cost,
            "ip_theft_cost": source_cost,
            "storage_exposure_cost": storage_cost,
            "remediation_cost": remediation_cost,
            "total_cost": total,
            "severity": "CRITICAL" if credential_files > 0 else "HIGH" if total > 100000 else "MEDIUM",
        }
