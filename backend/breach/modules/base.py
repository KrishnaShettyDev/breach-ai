"""
BREACH.AI v2 - Module Base Class

All attack modules inherit from this base class.
Provides standardized structure for the 25 MVP modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import asyncio

from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    Evidence,
    EvidenceType,
    AccessLevel,
    Severity,
)


@dataclass
class ModuleConfig:
    """Configuration for a module execution."""
    target: str = ""
    timeout_seconds: int = 300
    max_retries: int = 3
    aggressive: bool = False

    # Scope limitations
    allowed_hosts: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)

    # Rate limiting
    requests_per_second: int = 10

    # Credentials/tokens to use
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)
    tokens: list[str] = field(default_factory=list)

    # Context from previous modules
    chain_data: dict = field(default_factory=dict)


@dataclass
class ModuleInfo:
    """Metadata about a module."""
    name: str
    phase: BreachPhase
    description: str
    author: str = "BREACH.AI"

    # MITRE ATT&CK techniques
    techniques: list[str] = field(default_factory=list)

    # Platforms this module works on
    platforms: list[str] = field(default_factory=lambda: ["web", "api"])

    # Requirements
    requires_access: bool = False
    required_access_level: AccessLevel = AccessLevel.NONE
    required_tools: list[str] = field(default_factory=list)

    # What this module can provide
    provides_access: bool = False
    max_access_level: AccessLevel = AccessLevel.NONE


class Module(ABC):
    """
    Base class for all BREACH.AI v2 modules.

    Each module follows the pattern:
    1. check() - Can this module run given current context?
    2. run() - Execute the module
    3. cleanup() - Clean up any artifacts (optional)

    Modules are organized by kill chain phase:
    - RECON: subdomain_hunter, port_annihilator, tech_fingerprinter, etc.
    - INITIAL_ACCESS: sqli_destroyer, auth_obliterator, command_injector, etc.
    - FOOTHOLD: shell_stabilizer, persistence_establisher
    - ESCALATION: linux_escalator, container_escaper, aws_escalator, etc.
    - LATERAL: network_spider, credential_harvester, cloud_hopper
    - DATA_ACCESS: database_pillager, secrets_extractor, cloud_storage_raider
    - PROOF: evidence_generator
    """

    # Module metadata - override in subclasses
    info: ModuleInfo = ModuleInfo(
        name="base_module",
        phase=BreachPhase.RECON,
        description="Base module class",
    )

    def __init__(self, http_client=None):
        self.http_client = http_client
        self._start_time: Optional[datetime] = None
        self._evidence: list[Evidence] = []

    @abstractmethod
    async def check(self, config: ModuleConfig) -> bool:
        """
        Check if this module can run with the given configuration.

        Args:
            config: Module configuration including target and context

        Returns:
            True if the module can run, False otherwise
        """
        pass

    @abstractmethod
    async def run(self, config: ModuleConfig) -> ModuleResult:
        """
        Execute the module.

        Args:
            config: Module configuration

        Returns:
            ModuleResult with success status and any findings
        """
        pass

    async def cleanup(self, config: ModuleConfig) -> None:
        """
        Clean up any artifacts created during execution.

        Override in subclasses if cleanup is needed.
        """
        pass

    # Helper methods for modules

    def _start_execution(self):
        """Mark start of execution for timing."""
        self._start_time = datetime.utcnow()
        self._evidence = []

    def _create_result(
        self,
        success: bool,
        action: str = "",
        details: str = "",
        error: str = None,
        access_gained: AccessLevel = None,
        data_extracted: Any = None,
        **kwargs,  # Accept additional params from modules
    ) -> ModuleResult:
        """Create a ModuleResult with timing information."""
        completed_at = datetime.utcnow()
        duration_ms = 0
        if self._start_time:
            duration_ms = int((completed_at - self._start_time).total_seconds() * 1000)

        return ModuleResult(
            success=success,
            module_name=self.info.name,
            phase=self.info.phase,
            action=action,
            details=details,
            error=error,
            access_gained=access_gained,
            evidence=self._evidence.copy(),
            data_extracted=data_extracted,
            started_at=self._start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def _add_evidence(
        self,
        evidence_type: EvidenceType,
        description: str,
        content: Any,
        proves: str = "",
        severity: Severity = Severity.INFO,
        redact: bool = False,
        redaction_notes: str = None,
    ) -> Evidence:
        """Add evidence to the result."""
        evidence = Evidence(
            evidence_type=evidence_type,
            description=description,
            content=content,
            proves=proves,
            action_that_generated=self.info.name,
            phase=self.info.phase,
            severity=severity,
            is_redacted=redact,
            redaction_notes=redaction_notes,
        )
        self._evidence.append(evidence)
        return evidence

    def _add_screenshot_evidence(
        self,
        description: str,
        image_data: bytes,
        proves: str = "",
    ) -> Evidence:
        """Add screenshot evidence."""
        return self._add_evidence(
            evidence_type=EvidenceType.SCREENSHOT,
            description=description,
            content=image_data,
            proves=proves,
            severity=Severity.HIGH,
        )

    def _add_data_sample_evidence(
        self,
        description: str,
        data: Any,
        proves: str = "",
        severity: Severity = Severity.HIGH,
        redact_pii: bool = True,
    ) -> Evidence:
        """Add data sample evidence with optional PII redaction."""
        content = data
        redacted = False

        if redact_pii and isinstance(data, (dict, list)):
            content, redacted = self._redact_pii(data)

        return self._add_evidence(
            evidence_type=EvidenceType.DATA_SAMPLE,
            description=description,
            content=content,
            proves=proves,
            severity=severity,
            redact=redacted,
            redaction_notes="PII fields redacted for safety" if redacted else None,
        )

    def _add_command_output_evidence(
        self,
        command: str,
        output: str,
        proves: str = "",
    ) -> Evidence:
        """Add command output evidence."""
        return self._add_evidence(
            evidence_type=EvidenceType.COMMAND_OUTPUT,
            description=f"Output of: {command}",
            content={"command": command, "output": output},
            proves=proves,
            severity=Severity.HIGH,
        )

    def _redact_pii(self, data: Any, depth: int = 0) -> tuple[Any, bool]:
        """
        Redact PII from data while preserving structure.

        Returns tuple of (redacted_data, was_redacted)
        """
        if depth > 10:  # Prevent infinite recursion
            return data, False

        pii_keys = {
            "email", "phone", "ssn", "social_security", "password",
            "credit_card", "card_number", "cvv", "address", "dob",
            "date_of_birth", "passport", "driver_license", "secret",
            "api_key", "access_token", "refresh_token", "private_key",
        }

        was_redacted = False

        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                key_lower = key.lower().replace("_", "").replace("-", "")
                if any(pii in key_lower for pii in pii_keys):
                    if isinstance(value, str) and len(value) > 3:
                        # Partial redaction - show first and last char
                        result[key] = f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
                        was_redacted = True
                    else:
                        result[key] = "***REDACTED***"
                        was_redacted = True
                else:
                    redacted_value, child_redacted = self._redact_pii(value, depth + 1)
                    result[key] = redacted_value
                    was_redacted = was_redacted or child_redacted
            return result, was_redacted

        elif isinstance(data, list):
            result = []
            for item in data[:10]:  # Limit to 10 items
                redacted_item, child_redacted = self._redact_pii(item, depth + 1)
                result.append(redacted_item)
                was_redacted = was_redacted or child_redacted
            return result, was_redacted

        return data, False

    async def _safe_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[dict]:
        """Make an HTTP request with error handling. Returns dict for modules."""
        if not self.http_client:
            return None

        try:
            response = await self.http_client.request(method, url, **kwargs)
            # Convert HTTPResponse to dict for module compatibility
            return {
                "status_code": response.status_code,
                "text": response.body,
                "headers": response.headers,
                "url": response.url,
                "is_success": response.is_success,
                "elapsed_ms": response.elapsed_ms,
                "cookies": response.cookies,
            }
        except Exception:
            return None


class ReconModule(Module):
    """Base class for reconnaissance modules."""

    info = ModuleInfo(
        name="recon_base",
        phase=BreachPhase.RECON,
        description="Base reconnaissance module",
        requires_access=False,
    )


class InitialAccessModule(Module):
    """Base class for initial access modules."""

    info = ModuleInfo(
        name="initial_access_base",
        phase=BreachPhase.INITIAL_ACCESS,
        description="Base initial access module",
        requires_access=False,
        provides_access=True,
    )


class FootholdModule(Module):
    """Base class for foothold establishment modules."""

    info = ModuleInfo(
        name="foothold_base",
        phase=BreachPhase.FOOTHOLD,
        description="Base foothold module",
        requires_access=True,
        required_access_level=AccessLevel.USER,
    )


class EscalationModule(Module):
    """Base class for privilege escalation modules."""

    info = ModuleInfo(
        name="escalation_base",
        phase=BreachPhase.ESCALATION,
        description="Base escalation module",
        requires_access=True,
        required_access_level=AccessLevel.USER,
        provides_access=True,
    )


class LateralModule(Module):
    """Base class for lateral movement modules."""

    info = ModuleInfo(
        name="lateral_base",
        phase=BreachPhase.LATERAL,
        description="Base lateral movement module",
        requires_access=True,
        required_access_level=AccessLevel.USER,
    )


class DataAccessModule(Module):
    """Base class for data access modules."""

    info = ModuleInfo(
        name="data_access_base",
        phase=BreachPhase.DATA_ACCESS,
        description="Base data access module",
        requires_access=True,
    )


class ProofModule(Module):
    """Base class for proof generation modules."""

    info = ModuleInfo(
        name="proof_base",
        phase=BreachPhase.PROOF,
        description="Base proof generation module",
        requires_access=True,
    )


# Module registry
_MODULE_REGISTRY: dict[str, type[Module]] = {}


def register_module(module_class: type[Module]) -> type[Module]:
    """Decorator to register a module."""
    _MODULE_REGISTRY[module_class.info.name] = module_class
    return module_class


def get_module(name: str) -> Optional[type[Module]]:
    """Get a module class by name."""
    return _MODULE_REGISTRY.get(name)


def get_modules_for_phase(phase: BreachPhase) -> list[type[Module]]:
    """Get all modules for a specific phase."""
    return [
        m for m in _MODULE_REGISTRY.values()
        if m.info.phase == phase
    ]


def get_all_modules() -> dict[str, type[Module]]:
    """Get all registered modules."""
    return _MODULE_REGISTRY.copy()
