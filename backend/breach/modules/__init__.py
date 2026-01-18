"""
BREACH.AI v2 - Attack Modules

25 MVP modules organized by kill chain phase:

RECON (5):
- subdomain_hunter
- port_annihilator
- tech_fingerprinter
- content_discoverer
- cloud_discoverer

INITIAL_ACCESS (8):
- sqli_destroyer
- nosqli_attacker
- command_injector
- auth_obliterator
- file_attacker
- ssrf_exploiter
- cloud_intruder
- service_breaker

ESCALATION (5):
- linux_escalator
- container_escaper
- aws_escalator
- azure_escalator
- gcp_escalator

LATERAL (3):
- network_spider
- credential_harvester
- cloud_hopper

DATA_ACCESS (3):
- database_pillager
- secrets_extractor
- cloud_storage_raider

PROOF (1):
- evidence_generator
"""

from backend.breach.modules.base import (
    Module,
    ModuleConfig,
    ModuleInfo,
    ModuleResult,
    ReconModule,
    InitialAccessModule,
    FootholdModule,
    EscalationModule,
    LateralModule,
    DataAccessModule,
    ProofModule,
    register_module,
    get_module,
    get_modules_for_phase,
    get_all_modules,
)

# Import all modules to trigger registration
from backend.breach.modules import recon
from backend.breach.modules import initial_access
from backend.breach.modules import escalation
from backend.breach.modules import lateral
from backend.breach.modules import data_access
from backend.breach.modules import proof

__all__ = [
    "Module",
    "ModuleConfig",
    "ModuleInfo",
    "ModuleResult",
    "ReconModule",
    "InitialAccessModule",
    "FootholdModule",
    "EscalationModule",
    "LateralModule",
    "DataAccessModule",
    "ProofModule",
    "register_module",
    "get_module",
    "get_modules_for_phase",
    "get_all_modules",
]
