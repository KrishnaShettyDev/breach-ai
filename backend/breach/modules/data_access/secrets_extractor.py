"""
BREACH.AI v2 - Secrets Extractor Module

Find and document accessible secrets.
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


@register_module
class SecretsExtractor(DataAccessModule):
    """
    Secrets Extractor - Find and document secrets.

    Extracts:
    - API keys and tokens
    - Database credentials
    - Cloud credentials
    - Service account keys
    - Private keys and certificates
    """

    info = ModuleInfo(
        name="secrets_extractor",
        phase=BreachPhase.DATA_ACCESS,
        description="Secret and credential extraction",
        author="BREACH.AI",
        techniques=["T1552.001", "T1552.004"],  # Credentials in Files
        platforms=["web", "cloud", "infrastructure"],
        requires_access=True,
    )

    async def check(self, config: ModuleConfig) -> bool:
        return bool(config.chain_data.get("access_gained"))

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        secrets = []

        # Extract from chain data
        chain_data = config.chain_data

        if chain_data.get("supabase_key"):
            secrets.append({
                "type": "supabase_api_key",
                "source": "client_code",
                "partial_value": chain_data["supabase_key"][:20] + "***",
            })

        if chain_data.get("stripe_pk"):
            secrets.append({
                "type": "stripe_publishable_key",
                "source": "client_code",
                "partial_value": chain_data["stripe_pk"][:15] + "***",
            })

        if chain_data.get("aws_credentials"):
            secrets.append({
                "type": "aws_credentials",
                "source": "ssrf_metadata",
                "partial_value": "AKIA***",
            })

        if chain_data.get("credentials_found"):
            for cred in chain_data["credentials_found"]:
                secrets.append({
                    "type": cred.get("type", "credential"),
                    "source": "credential_harvesting",
                    "partial_value": "***",
                })

        # Add evidence
        if secrets:
            self._add_evidence(
                evidence_type=EvidenceType.CREDENTIAL,
                description=f"Extracted {len(secrets)} secrets",
                content={
                    "count": len(secrets),
                    "types": list(set(s["type"] for s in secrets)),
                },
                proves="Secrets and credentials accessible",
                severity=Severity.CRITICAL,
                redact=True,
            )

        return self._create_result(
            success=len(secrets) > 0,
            action="secrets_extraction",
            details=f"Extracted {len(secrets)} secrets",
            data_extracted={"secrets": secrets},
            enables_modules=["evidence_generator"],
        )
