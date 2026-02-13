"""
BREACH.AI v2 - Evidence Generator Module

Generate undeniable breach evidence.
"""

from datetime import datetime
from typing import Any
import hashlib
import json

from breach.modules.base import (
    ProofModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    Evidence,
    EvidenceType,
    AccessLevel,
    Severity,
)


@register_module
class EvidenceGenerator(ProofModule):
    """
    Evidence Generator - Create undeniable breach proof.

    Generates:
    - Evidence package with all findings
    - Data samples with proper redaction
    - Attack chain visualization
    - Business impact summary
    - Cryptographic proof of access (hash of accessed data)
    """

    info = ModuleInfo(
        name="evidence_generator",
        phase=BreachPhase.PROOF,
        description="Generate breach evidence package",
        author="BREACH.AI",
        techniques=["T1119"],  # Automated Collection
        platforms=["all"],
        requires_access=True,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have evidence to compile."""
        return bool(
            config.chain_data.get("findings") or
            config.chain_data.get("data_accessed") or
            config.chain_data.get("access_gained")
        )

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        # Compile all evidence
        evidence_package = await self._compile_evidence(config)

        # Generate proof summary
        proof_summary = self._generate_proof_summary(evidence_package)

        # Create cryptographic proof
        crypto_proof = self._create_crypto_proof(evidence_package)

        # Add final evidence
        self._add_evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            description="Breach Evidence Package",
            content=proof_summary,
            proves="Complete breach with undeniable evidence",
            severity=Severity.CRITICAL,
        )

        self._add_evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            description="Cryptographic Proof of Access",
            content=crypto_proof,
            proves="Timestamped proof of data access",
            severity=Severity.CRITICAL,
        )

        return self._create_result(
            success=True,
            action="evidence_generation",
            details=f"Generated evidence package with {len(evidence_package['evidence'])} items",
            data_extracted={
                "evidence_package": evidence_package,
                "crypto_proof": crypto_proof,
            },
        )

    async def _compile_evidence(self, config: ModuleConfig) -> dict:
        """Compile all evidence from the breach session."""
        chain_data = config.chain_data

        evidence = []
        attack_chain = []
        data_accessed = []
        credentials_found = []

        # Collect from chain data
        if chain_data.get("evidence"):
            evidence.extend(chain_data["evidence"])

        if chain_data.get("attack_steps"):
            attack_chain = chain_data["attack_steps"]

        if chain_data.get("data_samples"):
            for sample in chain_data["data_samples"]:
                # Redact PII
                redacted = self._redact_sample(sample)
                data_accessed.append(redacted)

        if chain_data.get("credentials_found"):
            for cred in chain_data["credentials_found"]:
                credentials_found.append({
                    "type": cred.get("type", "unknown"),
                    "service": cred.get("service", "unknown"),
                    "source": cred.get("source", "unknown"),
                    # Never include actual credentials
                })

        return {
            "target": config.target,
            "timestamp": datetime.utcnow().isoformat(),
            "highest_access": chain_data.get("highest_access", "none"),
            "evidence": evidence,
            "attack_chain": attack_chain,
            "data_accessed": data_accessed,
            "credentials_count": len(credentials_found),
            "credential_types": list(set(c["type"] for c in credentials_found)),
        }

    def _generate_proof_summary(self, package: dict) -> dict:
        """Generate human-readable proof summary."""
        return {
            "title": "BREACH.AI - Proof of Compromise",
            "target": package["target"],
            "generated_at": package["timestamp"],
            "summary": {
                "highest_access_achieved": package["highest_access"],
                "evidence_items": len(package["evidence"]),
                "attack_chain_steps": len(package["attack_chain"]),
                "data_sources_accessed": len(package["data_accessed"]),
                "credentials_discovered": package["credentials_count"],
            },
            "what_was_accessed": [
                d.get("source", "unknown") for d in package["data_accessed"]
            ],
            "proof_level": self._determine_proof_level(package),
        }

    def _create_crypto_proof(self, package: dict) -> dict:
        """Create cryptographic proof of breach."""
        # Create hash of evidence for non-repudiation
        evidence_str = json.dumps(package, sort_keys=True, default=str)
        evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

        return {
            "type": "sha256",
            "hash": evidence_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "proves": "This hash proves the exact state of evidence at this timestamp",
            "verification": "Hash can be verified against stored evidence package",
        }

    def _redact_sample(self, sample: Any) -> dict:
        """Redact PII from data sample."""
        if isinstance(sample, dict):
            redacted = {}
            pii_keys = ["email", "phone", "ssn", "password", "address", "card"]

            for key, value in sample.items():
                key_lower = key.lower()
                if any(pii in key_lower for pii in pii_keys):
                    if isinstance(value, str) and len(value) > 3:
                        redacted[key] = f"{value[0]}***{value[-1]}"
                    else:
                        redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = value

            return {"source": "database", "data": redacted, "redacted": True}

        return {"source": "unknown", "data": str(sample)[:100], "redacted": False}

    def _determine_proof_level(self, package: dict) -> str:
        """Determine the proof level achieved."""
        access = package.get("highest_access", "none")
        data_count = len(package.get("data_accessed", []))

        if access in ["root", "cloud_admin"] and data_count > 0:
            return "LEVEL 6 - FULL IMPACT PROOF"
        elif access in ["database", "admin"] and data_count > 0:
            return "LEVEL 5 - DATA ACCESS PROOF"
        elif access in ["admin", "cloud_admin"]:
            return "LEVEL 4 - PRIVILEGE PROOF"
        elif access in ["user", "cloud_user"]:
            return "LEVEL 3 - ACCESS PROOF"
        elif package.get("attack_chain"):
            return "LEVEL 2 - EXPLOITATION PROOF"
        elif package.get("evidence"):
            return "LEVEL 1 - EXISTENCE PROOF"
        else:
            return "LEVEL 0 - NO PROOF"
