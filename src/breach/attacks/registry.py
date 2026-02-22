"""
BREACH Attack Module Registry (Lean Edition)

Core attack modules only. AI handles the rest.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AttackCategory(str, Enum):
    """Attack module categories."""
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "auth"
    SSRF = "ssrf"
    FILE = "file"


@dataclass
class ModuleInfo:
    """Attack module metadata."""
    name: str
    module_path: str
    class_name: str
    category: AttackCategory
    severity: str
    description: str
    owasp: Optional[str] = None
    cwe: Optional[int] = None


# Core Attack Modules - AI handles the rest
ATTACK_REGISTRY: dict[str, ModuleInfo] = {
    # ==================== INJECTION ====================
    "sqli": ModuleInfo(
        name="SQL Injection",
        module_path="breach.attacks.sqli",
        class_name="SQLInjectionAttack",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="SQL injection (error-based, blind, time-based, UNION)",
        owasp="A03:2021",
        cwe=89,
    ),
    "nosql": ModuleInfo(
        name="NoSQL Injection",
        module_path="breach.attacks.nosql",
        class_name="NoSQLInjectionAttack",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="NoSQL injection (MongoDB, Redis)",
        owasp="A03:2021",
        cwe=943,
    ),
    "cmdi": ModuleInfo(
        name="Command Injection",
        module_path="breach.attacks.injection",
        class_name="CommandInjectionAttack",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="OS command injection and RCE",
        owasp="A03:2021",
        cwe=78,
    ),
    "ssti": ModuleInfo(
        name="Template Injection",
        module_path="breach.attacks.ssti_exploiter",
        class_name="SSTIExploiter",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="Server-side template injection",
        owasp="A03:2021",
        cwe=1336,
    ),

    # ==================== XSS ====================
    "xss": ModuleInfo(
        name="Cross-Site Scripting",
        module_path="breach.attacks.xss",
        class_name="XSSAttack",
        category=AttackCategory.XSS,
        severity="HIGH",
        description="XSS (reflected, stored, DOM-based)",
        owasp="A03:2021",
        cwe=79,
    ),

    # ==================== AUTH ====================
    "auth": ModuleInfo(
        name="Authentication Attacks",
        module_path="breach.attacks.auth",
        class_name="AuthAttack",
        category=AttackCategory.AUTH,
        severity="CRITICAL",
        description="Brute force, credential stuffing, default creds",
        owasp="A07:2021",
        cwe=287,
    ),
    "jwt": ModuleInfo(
        name="JWT Attacks",
        module_path="breach.attacks.jwt_obliterator",
        class_name="JWTObliterator",
        category=AttackCategory.AUTH,
        severity="CRITICAL",
        description="JWT algorithm confusion, key attacks",
        owasp="A07:2021",
        cwe=347,
    ),
    "idor": ModuleInfo(
        name="IDOR",
        module_path="breach.attacks.idor",
        class_name="IDORAttack",
        category=AttackCategory.AUTH,
        severity="HIGH",
        description="Insecure Direct Object Reference",
        owasp="A01:2021",
        cwe=639,
    ),

    # ==================== SSRF ====================
    "ssrf": ModuleInfo(
        name="SSRF",
        module_path="breach.attacks.ssrf",
        class_name="SSRFAttack",
        category=AttackCategory.SSRF,
        severity="CRITICAL",
        description="Server-Side Request Forgery",
        owasp="A10:2021",
        cwe=918,
    ),

    # ==================== FILE ====================
    "lfi": ModuleInfo(
        name="File Attacks",
        module_path="breach.attacks.file_warfare",
        class_name="FileWarfare",
        category=AttackCategory.FILE,
        severity="HIGH",
        description="LFI, RFI, path traversal, file upload",
        owasp="A01:2021",
        cwe=22,
    ),
}


# Category info
CATEGORY_INFO = {
    AttackCategory.INJECTION: {
        "description": "SQL, NoSQL, Command, Template injection",
        "severity": "CRITICAL",
        "modules": ["sqli", "nosql", "cmdi", "ssti"],
    },
    AttackCategory.XSS: {
        "description": "Cross-site scripting attacks",
        "severity": "HIGH",
        "modules": ["xss"],
    },
    AttackCategory.AUTH: {
        "description": "Authentication and authorization attacks",
        "severity": "CRITICAL",
        "modules": ["auth", "jwt", "idor"],
    },
    AttackCategory.SSRF: {
        "description": "Server-side request forgery",
        "severity": "CRITICAL",
        "modules": ["ssrf"],
    },
    AttackCategory.FILE: {
        "description": "File inclusion and upload attacks",
        "severity": "HIGH",
        "modules": ["lfi"],
    },
}


def get_modules_by_category(category: AttackCategory | str) -> list[ModuleInfo]:
    """Get all modules in a category."""
    if isinstance(category, str):
        category = AttackCategory(category)
    return [info for info in ATTACK_REGISTRY.values() if info.category == category]


def get_modules_by_severity(severity: str) -> list[ModuleInfo]:
    """Get all modules with a specific severity."""
    return [info for info in ATTACK_REGISTRY.values() if info.severity == severity.upper()]


def get_all_modules() -> list[ModuleInfo]:
    """Get all registered modules."""
    return list(ATTACK_REGISTRY.values())


def load_module_class(module_info: ModuleInfo):
    """Dynamically load a module class."""
    import importlib
    module = importlib.import_module(module_info.module_path)
    return getattr(module, module_info.class_name)


# Quick access
CRITICAL_MODULES = [k for k, v in ATTACK_REGISTRY.items() if v.severity == "CRITICAL"]
HIGH_MODULES = [k for k, v in ATTACK_REGISTRY.items() if v.severity == "HIGH"]
