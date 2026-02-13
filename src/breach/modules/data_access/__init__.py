"""
BREACH.AI v2 - Data Access Modules

3 MVP Data Access Modules:
1. database_pillager - Database access and sampling
2. secrets_extractor - Extract secrets and sensitive data
3. cloud_storage_raider - Access cloud storage buckets
"""

from breach.modules.data_access.database_pillager import DatabasePillager
from breach.modules.data_access.secrets_extractor import SecretsExtractor
from breach.modules.data_access.cloud_storage_raider import CloudStorageRaider

__all__ = [
    "DatabasePillager",
    "SecretsExtractor",
    "CloudStorageRaider",
]
