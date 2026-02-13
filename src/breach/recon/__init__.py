"""BREACH.AI Reconnaissance Module"""

from breach.recon.engine import ReconEngine, ReconResult
from breach.recon.dns import DNSEnumerator
from breach.recon.ports import PortScanner
from breach.recon.web import WebCrawler

# Advanced Recon
from breach.recon.recon_warfare import (
    ReconWarfare,
    ReconResult as WarfareResult,
    ReconFinding,
    recon_warfare,
)
from breach.recon.social_engineering import (
    SocialEngineering,
    SocialEngineeringResult,
    Employee,
    EmailPattern,
    social_engineering_recon,
)

__all__ = [
    # Core
    "ReconEngine",
    "ReconResult",
    "DNSEnumerator",
    "PortScanner",
    "WebCrawler",

    # Recon Warfare
    "ReconWarfare",
    "WarfareResult",
    "ReconFinding",
    "recon_warfare",

    # Social Engineering
    "SocialEngineering",
    "SocialEngineeringResult",
    "Employee",
    "EmailPattern",
    "social_engineering_recon",
]
