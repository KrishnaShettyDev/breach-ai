"""
BREACH.AI Attack Modules

Core attack modules for comprehensive security assessment.

Imports are lazy to avoid cascading import errors.
Import specific modules directly:
    from backend.breach.attacks.base import BaseAttack, AttackResult
    from backend.breach.attacks.jwt_obliterator import JWTObliterator
    etc.
"""

# Only import the base classes that are known to work
try:
    from backend.breach.attacks.base import BaseAttack, AttackResult
except ImportError:
    BaseAttack = None
    AttackResult = None

__all__ = [
    "BaseAttack",
    "AttackResult",
]
