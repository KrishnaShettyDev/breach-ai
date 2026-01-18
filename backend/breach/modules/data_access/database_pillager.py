"""
BREACH.AI v2 - Database Pillager Module

Extract and document database access with safe sampling.
"""

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


# PII field indicators
PII_INDICATORS = [
    "email", "phone", "ssn", "social_security", "password",
    "credit_card", "card_number", "address", "dob", "date_of_birth",
    "passport", "driver_license", "tax_id", "national_id",
]

# Maximum records to sample
MAX_SAMPLE_ROWS = 10


@register_module
class DatabasePillager(DataAccessModule):
    """
    Database Pillager - Access and sample database contents.

    Features:
    - Schema enumeration
    - Table identification
    - Sensitive data detection
    - Safe sampling (max 10 rows)
    - PII redaction in evidence
    - Business impact calculation
    """

    info = ModuleInfo(
        name="database_pillager",
        phase=BreachPhase.DATA_ACCESS,
        description="Database access and safe sampling",
        author="BREACH.AI",
        techniques=["T1530", "T1213"],  # Data from Cloud Storage, Data from Info Repos
        platforms=["database", "cloud", "web"],
        requires_access=True,
        required_access_level=AccessLevel.DATABASE,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have database access."""
        return (
            config.chain_data.get("database_access") or
            config.chain_data.get("supabase_url") or
            config.chain_data.get("sqli_vuln")
        )

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        tables_accessed = []
        data_samples = []
        pii_found = []
        total_records = 0

        # Access via Supabase if available
        if config.chain_data.get("supabase_url"):
            result = await self._pillage_supabase(config)
            tables_accessed.extend(result.get("tables", []))
            data_samples.extend(result.get("samples", []))
            pii_found.extend(result.get("pii", []))
            total_records += result.get("total_records", 0)

        # Access via SQLi if available
        if config.chain_data.get("sqli_vuln"):
            result = await self._pillage_via_sqli(config)
            tables_accessed.extend(result.get("tables", []))
            data_samples.extend(result.get("samples", []))
            pii_found.extend(result.get("pii", []))
            total_records += result.get("total_records", 0)

        # Calculate business impact
        impact = self._calculate_business_impact(total_records, pii_found)

        # Add evidence
        for table in tables_accessed:
            self._add_evidence(
                evidence_type=EvidenceType.DATA_SAMPLE,
                description=f"Accessed table: {table['name']}",
                content={
                    "table": table["name"],
                    "record_count": table["count"],
                    "columns": table.get("columns", []),
                    "pii_columns": table.get("pii_columns", []),
                },
                proves=f"Full access to {table['name']} with {table['count']} records",
                severity=Severity.CRITICAL if table.get("pii_columns") else Severity.HIGH,
            )

        if data_samples:
            for sample in data_samples[:3]:  # Limit to 3 samples
                self._add_data_sample_evidence(
                    description=f"Data sample from {sample.get('table', 'unknown')}",
                    data=sample.get("data", {}),
                    proves="Actual data is accessible",
                    severity=Severity.CRITICAL,
                    redact_pii=True,
                )

        # Business impact evidence
        self._add_evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            description="Business impact assessment",
            content=impact,
            proves=f"Estimated breach cost: ${impact['total_cost']:,}",
            severity=Severity.CRITICAL,
        )

        return self._create_result(
            success=len(tables_accessed) > 0,
            action="database_pillaging",
            details=f"Accessed {len(tables_accessed)} tables, {total_records} records",
            data_extracted={
                "tables": [t["name"] for t in tables_accessed],
                "total_records": total_records,
                "pii_types": list(set(pii_found)),
                "business_impact": impact,
            },
            enables_modules=["evidence_generator"],
        )

    async def _pillage_supabase(self, config: ModuleConfig) -> dict:
        """Pillage data from Supabase."""
        results = {
            "tables": [],
            "samples": [],
            "pii": [],
            "total_records": 0,
        }

        url = config.chain_data.get("supabase_url")
        key = config.chain_data.get("supabase_key")

        if not url or not key:
            return results

        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
        }

        # Test common tables
        tables = ["users", "profiles", "accounts", "orders", "payments", "customers"]

        for table in tables:
            endpoint = f"{url}/rest/v1/{table}?select=*&limit=100"

            try:
                response = await self._safe_request(
                    "GET", endpoint,
                    headers=headers,
                    timeout=15,
                )

                if response and response.get("status_code") == 200:
                    import json
                    data = json.loads(response.get("text", "[]"))

                    if isinstance(data, list) and len(data) > 0:
                        count = len(data)
                        results["total_records"] += count

                        # Analyze columns
                        columns = list(data[0].keys()) if data else []
                        pii_columns = [c for c in columns if any(p in c.lower() for p in PII_INDICATORS)]
                        results["pii"].extend(pii_columns)

                        results["tables"].append({
                            "name": table,
                            "count": count,
                            "columns": columns,
                            "pii_columns": pii_columns,
                        })

                        # Safe sample (max 10 rows)
                        results["samples"].append({
                            "table": table,
                            "data": data[:MAX_SAMPLE_ROWS],
                        })

            except Exception:
                continue

        return results

    async def _pillage_via_sqli(self, config: ModuleConfig) -> dict:
        """Pillage data via SQL injection."""
        # Would use the SQLi vulnerability to extract data
        return {"tables": [], "samples": [], "pii": [], "total_records": 0}

    def _calculate_business_impact(self, record_count: int, pii_types: list) -> dict:
        """Calculate business impact of data exposure."""
        # GDPR fine calculation
        gdpr_per_record = 150 if pii_types else 50
        gdpr_cost = record_count * gdpr_per_record

        # Breach notification costs
        notification_cost = min(record_count * 10, 500000)

        # Legal and remediation
        legal_cost = 100000 if record_count > 1000 else 25000

        # Credit monitoring if PII
        credit_monitoring = record_count * 25 if pii_types else 0

        total = gdpr_cost + notification_cost + legal_cost + credit_monitoring

        return {
            "records_exposed": record_count,
            "pii_types": list(set(pii_types)),
            "gdpr_potential": gdpr_cost,
            "notification_cost": notification_cost,
            "legal_cost": legal_cost,
            "credit_monitoring": credit_monitoring,
            "total_cost": total,
            "severity": "CRITICAL" if total > 1000000 else "HIGH" if total > 100000 else "MEDIUM",
        }
