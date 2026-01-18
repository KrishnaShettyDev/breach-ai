"""
BREACH.AI v2 - Initial Access Modules

8 MVP Initial Access Modules:
1. sqli_destroyer - SQL injection to database access
2. nosqli_attacker - NoSQL injection attacks
3. command_injector - OS command injection
4. auth_obliterator - Authentication bypass
5. file_attacker - File upload/traversal/LFI
6. ssrf_exploiter - Server-side request forgery
7. cloud_intruder - Cloud misconfiguration exploitation
8. service_breaker - Exposed service exploitation
"""

from backend.breach.modules.initial_access.sqli_destroyer import SQLiDestroyer
from backend.breach.modules.initial_access.nosqli_attacker import NoSQLiAttacker
from backend.breach.modules.initial_access.command_injector import CommandInjector
from backend.breach.modules.initial_access.auth_obliterator import AuthObliterator
from backend.breach.modules.initial_access.file_attacker import FileAttacker
from backend.breach.modules.initial_access.ssrf_exploiter import SSRFExploiter
from backend.breach.modules.initial_access.cloud_intruder import CloudIntruder
from backend.breach.modules.initial_access.service_breaker import ServiceBreaker

__all__ = [
    "SQLiDestroyer",
    "NoSQLiAttacker",
    "CommandInjector",
    "AuthObliterator",
    "FileAttacker",
    "SSRFExploiter",
    "CloudIntruder",
    "ServiceBreaker",
]
