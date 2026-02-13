"""
BREACH.AI v2 - Reconnaissance Modules

5 MVP Recon Modules:
1. subdomain_hunter - Exhaustive subdomain enumeration
2. port_annihilator - Full port scanning with service identification
3. tech_fingerprinter - Technology stack detection
4. content_discoverer - Directory and file discovery
5. cloud_discoverer - Cloud asset enumeration
"""

from breach.modules.recon.subdomain_hunter import SubdomainHunter
from breach.modules.recon.port_annihilator import PortAnnihilator
from breach.modules.recon.tech_fingerprinter import TechFingerprinter
from breach.modules.recon.content_discoverer import ContentDiscoverer
from breach.modules.recon.cloud_discoverer import CloudDiscoverer

__all__ = [
    "SubdomainHunter",
    "PortAnnihilator",
    "TechFingerprinter",
    "ContentDiscoverer",
    "CloudDiscoverer",
]
