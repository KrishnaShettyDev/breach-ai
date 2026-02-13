"""
BREACH.AI - God Level Testers
==============================
Attack modules that find REAL vulnerabilities with PROOF.
"""

from .injections import InjectionTester
from .auth import AuthTester
from .idor import IDORTester

__all__ = ["InjectionTester", "AuthTester", "IDORTester"]
