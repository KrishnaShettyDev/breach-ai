"""
BREACH.AI v2 - Lateral Movement Modules

3 MVP Lateral Modules:
1. network_spider - Internal network scanning and pivoting
2. credential_harvester - Extract credentials for further access
3. cloud_hopper - Pivot through cloud resources
"""

from backend.breach.modules.lateral.network_spider import NetworkSpider
from backend.breach.modules.lateral.credential_harvester import CredentialHarvester
from backend.breach.modules.lateral.cloud_hopper import CloudHopper

__all__ = [
    "NetworkSpider",
    "CredentialHarvester",
    "CloudHopper",
]
