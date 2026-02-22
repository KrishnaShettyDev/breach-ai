"""
BREACH Attack Module Registry

Categorized registry of all attack modules for selective scanning.

Usage:
    from breach.attacks.registry import ATTACK_REGISTRY, get_modules_by_category

    # Get all injection modules
    modules = get_modules_by_category("injection")

    # Get all modules
    all_modules = get_all_modules()
"""

from dataclasses import dataclass
from enum import Enum
from typing import Type, Optional


class AttackCategory(str, Enum):
    """Attack module categories."""
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "auth"
    AUTHZ = "authz"
    SSRF = "ssrf"
    API = "api"
    INFRASTRUCTURE = "infrastructure"
    WEB = "web"
    MODERN = "modern"
    BUSINESS = "business"
    RECON = "recon"


@dataclass
class ModuleInfo:
    """Attack module metadata."""
    name: str
    module_path: str
    class_name: str
    category: AttackCategory
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    owasp: Optional[str] = None
    cwe: Optional[int] = None


# Attack Module Registry
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
        description="NoSQL injection (MongoDB, Redis, Cassandra)",
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
        name="Server-Side Template Injection",
        module_path="breach.attacks.ssti_exploiter",
        class_name="SSTIExploiter",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="Template injection (Jinja2, Twig, Freemarker, etc.)",
        owasp="A03:2021",
        cwe=1336,
    ),
    "xxe": ModuleInfo(
        name="XML External Entity",
        module_path="breach.attacks.xxe_destroyer",
        class_name="XXEDestroyer",
        category=AttackCategory.INJECTION,
        severity="HIGH",
        description="XXE injection and XML attacks",
        owasp="A05:2021",
        cwe=611,
    ),
    "injection_arsenal": ModuleInfo(
        name="Injection Arsenal",
        module_path="breach.attacks.injection_arsenal",
        class_name="InjectionArsenal",
        category=AttackCategory.INJECTION,
        severity="CRITICAL",
        description="Advanced injection techniques (LDAP, XPath, Header)",
        owasp="A03:2021",
        cwe=74,
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
    "prototype_pollution": ModuleInfo(
        name="Prototype Pollution",
        module_path="breach.attacks.prototype_pollution",
        class_name="PrototypePollutionAttack",
        category=AttackCategory.XSS,
        severity="HIGH",
        description="JavaScript prototype pollution attacks",
        owasp="A03:2021",
        cwe=1321,
    ),
    "client_side": ModuleInfo(
        name="Client-Side Attacks",
        module_path="breach.attacks.client_side_carnage",
        class_name="ClientSideCarnage",
        category=AttackCategory.XSS,
        severity="MEDIUM",
        description="DOM clobbering, postMessage, client-side attacks",
        owasp="A03:2021",
        cwe=79,
    ),

    # ==================== AUTHENTICATION ====================
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
    "auth_bypass": ModuleInfo(
        name="Auth Bypass",
        module_path="breach.attacks.auth_obliterator",
        class_name="AuthObliterator",
        category=AttackCategory.AUTH,
        severity="CRITICAL",
        description="Authentication bypass techniques",
        owasp="A07:2021",
        cwe=287,
    ),
    "jwt": ModuleInfo(
        name="JWT Attacks",
        module_path="breach.attacks.jwt_obliterator",
        class_name="JWTObliterator",
        category=AttackCategory.AUTH,
        severity="CRITICAL",
        description="JWT algorithm confusion, key attacks, claim manipulation",
        owasp="A07:2021",
        cwe=347,
    ),
    "oauth": ModuleInfo(
        name="OAuth Attacks",
        module_path="breach.attacks.oauth_destroyer",
        class_name="OAuthDestroyer",
        category=AttackCategory.AUTH,
        severity="HIGH",
        description="OAuth flow attacks, token theft, redirect manipulation",
        owasp="A07:2021",
        cwe=287,
    ),
    "saml": ModuleInfo(
        name="SAML Attacks",
        module_path="breach.attacks.saml_destroyer",
        class_name="SAMLDestroyer",
        category=AttackCategory.AUTH,
        severity="CRITICAL",
        description="SAML signature bypass, XML injection",
        owasp="A07:2021",
        cwe=287,
    ),
    "mfa_bypass": ModuleInfo(
        name="MFA Bypass",
        module_path="breach.attacks.mfa_bypass",
        class_name="MFABypass",
        category=AttackCategory.AUTH,
        severity="HIGH",
        description="Multi-factor authentication bypass",
        owasp="A07:2021",
        cwe=287,
    ),
    "password_reset": ModuleInfo(
        name="Password Reset",
        module_path="breach.attacks.password_reset_killer",
        class_name="PasswordResetKiller",
        category=AttackCategory.AUTH,
        severity="HIGH",
        description="Password reset flow vulnerabilities",
        owasp="A07:2021",
        cwe=640,
    ),
    "session": ModuleInfo(
        name="Session Attacks",
        module_path="breach.attacks.session_annihilator",
        class_name="SessionAnnihilator",
        category=AttackCategory.AUTH,
        severity="HIGH",
        description="Session fixation, hijacking, token prediction",
        owasp="A07:2021",
        cwe=384,
    ),

    # ==================== AUTHORIZATION ====================
    "idor": ModuleInfo(
        name="IDOR",
        module_path="breach.attacks.idor",
        class_name="IDORAttack",
        category=AttackCategory.AUTHZ,
        severity="HIGH",
        description="Insecure Direct Object Reference",
        owasp="A01:2021",
        cwe=639,
    ),
    "api_authz": ModuleInfo(
        name="API Authorization",
        module_path="breach.attacks.api_auth_breaker",
        class_name="APIAuthBreaker",
        category=AttackCategory.AUTHZ,
        severity="HIGH",
        description="API authorization bypass, privilege escalation",
        owasp="A01:2021",
        cwe=285,
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

    # ==================== API ====================
    "graphql": ModuleInfo(
        name="GraphQL",
        module_path="breach.attacks.graphql_destroyer",
        class_name="GraphQLDestroyer",
        category=AttackCategory.API,
        severity="HIGH",
        description="GraphQL introspection, injection, DoS, batching",
        owasp="A01:2021",
        cwe=200,
    ),
    "rest_api": ModuleInfo(
        name="REST API",
        module_path="breach.attacks.rest_api_attacker",
        class_name="RESTAPIAttacker",
        category=AttackCategory.API,
        severity="HIGH",
        description="REST API enumeration, mass assignment, BOLA",
        owasp="A01:2021",
        cwe=285,
    ),
    "api_full": ModuleInfo(
        name="API Annihilator",
        module_path="breach.attacks.api_annihilator",
        class_name="APIAnnihilator",
        category=AttackCategory.API,
        severity="HIGH",
        description="Comprehensive API security testing",
        owasp="A01:2021",
        cwe=285,
    ),
    "api_discovery": ModuleInfo(
        name="API Discovery",
        module_path="breach.attacks.api_discovery",
        class_name="APIDiscovery",
        category=AttackCategory.RECON,
        severity="MEDIUM",
        description="API endpoint discovery and enumeration",
        owasp="A01:2021",
        cwe=200,
    ),
    "mobile_api": ModuleInfo(
        name="Mobile API",
        module_path="breach.attacks.mobile_api_attacker",
        class_name="MobileAPIAttacker",
        category=AttackCategory.API,
        severity="HIGH",
        description="Mobile API security testing",
        owasp="A01:2021",
        cwe=285,
    ),
    "websocket": ModuleInfo(
        name="WebSocket",
        module_path="breach.attacks.websocket_destroyer",
        class_name="WebSocketDestroyer",
        category=AttackCategory.API,
        severity="HIGH",
        description="WebSocket injection, hijacking, DoS",
        owasp="A01:2021",
        cwe=285,
    ),

    # ==================== INFRASTRUCTURE ====================
    "cloud": ModuleInfo(
        name="Cloud Attacks",
        module_path="breach.attacks.cloud_destroyer",
        class_name="CloudDestroyer",
        category=AttackCategory.INFRASTRUCTURE,
        severity="CRITICAL",
        description="AWS/Azure/GCP metadata, buckets, IAM, serverless",
        owasp="A05:2021",
        cwe=16,
    ),
    "docker": ModuleInfo(
        name="Docker/Container",
        module_path="breach.attacks.docker_destroyer",
        class_name="DockerDestroyer",
        category=AttackCategory.INFRASTRUCTURE,
        severity="CRITICAL",
        description="Container escapes, Docker API, Kubernetes",
        owasp="A05:2021",
        cwe=16,
    ),
    "subdomain_takeover": ModuleInfo(
        name="Subdomain Takeover",
        module_path="breach.attacks.subdomain_takeover",
        class_name="SubdomainTakeover",
        category=AttackCategory.INFRASTRUCTURE,
        severity="HIGH",
        description="Subdomain takeover detection and exploitation",
        owasp="A05:2021",
        cwe=16,
    ),
    "lotl": ModuleInfo(
        name="Living Off The Land",
        module_path="breach.attacks.living_off_the_land",
        class_name="LivingOffTheLand",
        category=AttackCategory.INFRASTRUCTURE,
        severity="HIGH",
        description="Abuse built-in tools and services",
        owasp="A05:2021",
        cwe=16,
    ),

    # ==================== WEB ====================
    "cors": ModuleInfo(
        name="CORS Misconfiguration",
        module_path="breach.attacks.cors_exploiter",
        class_name="CORSExploiter",
        category=AttackCategory.WEB,
        severity="MEDIUM",
        description="CORS policy bypass and exploitation",
        owasp="A05:2021",
        cwe=346,
    ),
    "cache_poison": ModuleInfo(
        name="Cache Poisoning",
        module_path="breach.attacks.cache_poisoner",
        class_name="CachePoisoner",
        category=AttackCategory.WEB,
        severity="HIGH",
        description="Web cache poisoning attacks",
        owasp="A05:2021",
        cwe=444,
    ),
    "host_header": ModuleInfo(
        name="Host Header Injection",
        module_path="breach.attacks.host_header_injection",
        class_name="HostHeaderInjection",
        category=AttackCategory.WEB,
        severity="MEDIUM",
        description="Host header attacks, password reset poisoning",
        owasp="A05:2021",
        cwe=644,
    ),
    "request_smuggling": ModuleInfo(
        name="Request Smuggling",
        module_path="breach.attacks.request_smuggler",
        class_name="RequestSmuggler",
        category=AttackCategory.WEB,
        severity="HIGH",
        description="HTTP request smuggling (CL.TE, TE.CL)",
        owasp="A05:2021",
        cwe=444,
    ),
    "rate_limit": ModuleInfo(
        name="Rate Limit Bypass",
        module_path="breach.attacks.rate_limit_bypass",
        class_name="RateLimitBypass",
        category=AttackCategory.WEB,
        severity="MEDIUM",
        description="Rate limiting bypass techniques",
        owasp="A04:2021",
        cwe=799,
    ),
    "file_attacks": ModuleInfo(
        name="File Attacks",
        module_path="breach.attacks.file_warfare",
        class_name="FileWarfare",
        category=AttackCategory.WEB,
        severity="HIGH",
        description="File upload, LFI, RFI, path traversal",
        owasp="A01:2021",
        cwe=22,
    ),

    # ==================== MODERN STACK ====================
    "modern_stack": ModuleInfo(
        name="Modern Stack",
        module_path="breach.attacks.modern_stack_destroyer",
        class_name="ModernStackDestroyer",
        category=AttackCategory.MODERN,
        severity="HIGH",
        description="Next.js, React, Vue, Angular specific attacks",
        owasp="A05:2021",
        cwe=16,
    ),

    # ==================== BUSINESS LOGIC ====================
    "business_logic": ModuleInfo(
        name="Business Logic",
        module_path="breach.attacks.business_logic_destroyer",
        class_name="BusinessLogicDestroyer",
        category=AttackCategory.BUSINESS,
        severity="HIGH",
        description="Race conditions, price manipulation, workflow bypass",
        owasp="A04:2021",
        cwe=840,
    ),
}


# Category descriptions for CLI help
CATEGORY_INFO = {
    AttackCategory.INJECTION: {
        "name": "Injection",
        "description": "SQL, NoSQL, Command, SSTI, XXE injection attacks",
        "severity": "CRITICAL",
        "modules": ["sqli", "nosql", "cmdi", "ssti", "xxe", "injection_arsenal"],
    },
    AttackCategory.XSS: {
        "name": "XSS",
        "description": "Cross-site scripting and client-side attacks",
        "severity": "HIGH",
        "modules": ["xss", "prototype_pollution", "client_side"],
    },
    AttackCategory.AUTH: {
        "name": "Authentication",
        "description": "Authentication bypass, JWT, OAuth, SAML, session attacks",
        "severity": "CRITICAL",
        "modules": ["auth", "auth_bypass", "jwt", "oauth", "saml", "mfa_bypass", "password_reset", "session"],
    },
    AttackCategory.AUTHZ: {
        "name": "Authorization",
        "description": "IDOR, privilege escalation, access control bypass",
        "severity": "HIGH",
        "modules": ["idor", "api_authz"],
    },
    AttackCategory.SSRF: {
        "name": "SSRF",
        "description": "Server-side request forgery",
        "severity": "CRITICAL",
        "modules": ["ssrf"],
    },
    AttackCategory.API: {
        "name": "API Security",
        "description": "GraphQL, REST, WebSocket, Mobile API attacks",
        "severity": "HIGH",
        "modules": ["graphql", "rest_api", "api_full", "mobile_api", "websocket"],
    },
    AttackCategory.INFRASTRUCTURE: {
        "name": "Infrastructure",
        "description": "Cloud (AWS/Azure/GCP), Docker, Kubernetes, subdomain takeover",
        "severity": "CRITICAL",
        "modules": ["cloud", "docker", "subdomain_takeover", "lotl"],
    },
    AttackCategory.WEB: {
        "name": "Web Attacks",
        "description": "CORS, cache poisoning, request smuggling, file attacks",
        "severity": "HIGH",
        "modules": ["cors", "cache_poison", "host_header", "request_smuggling", "rate_limit", "file_attacks"],
    },
    AttackCategory.MODERN: {
        "name": "Modern Stack",
        "description": "Next.js, React, Vue, Angular specific vulnerabilities",
        "severity": "HIGH",
        "modules": ["modern_stack"],
    },
    AttackCategory.BUSINESS: {
        "name": "Business Logic",
        "description": "Race conditions, workflow bypass, price manipulation",
        "severity": "HIGH",
        "modules": ["business_logic"],
    },
    AttackCategory.RECON: {
        "name": "Reconnaissance",
        "description": "API discovery, endpoint enumeration",
        "severity": "MEDIUM",
        "modules": ["api_discovery"],
    },
}


def get_modules_by_category(category: AttackCategory | str) -> list[ModuleInfo]:
    """Get all modules in a category."""
    if isinstance(category, str):
        category = AttackCategory(category)

    return [
        info for info in ATTACK_REGISTRY.values()
        if info.category == category
    ]


def get_modules_by_severity(severity: str) -> list[ModuleInfo]:
    """Get all modules with a specific severity."""
    return [
        info for info in ATTACK_REGISTRY.values()
        if info.severity == severity.upper()
    ]


def get_all_modules() -> list[ModuleInfo]:
    """Get all registered modules."""
    return list(ATTACK_REGISTRY.values())


def get_module_by_name(name: str) -> ModuleInfo | None:
    """Get a module by its key name."""
    return ATTACK_REGISTRY.get(name)


def get_category_names() -> list[str]:
    """Get all category names."""
    return [cat.value for cat in AttackCategory]


def load_module_class(module_info: ModuleInfo):
    """Dynamically load a module class."""
    import importlib

    try:
        module = importlib.import_module(module_info.module_path)
        return getattr(module, module_info.class_name)
    except (ImportError, AttributeError) as e:
        raise ImportError(f"Failed to load {module_info.name}: {e}")


# Quick access lists
CRITICAL_MODULES = [k for k, v in ATTACK_REGISTRY.items() if v.severity == "CRITICAL"]
HIGH_MODULES = [k for k, v in ATTACK_REGISTRY.items() if v.severity == "HIGH"]
OWASP_TOP_10_MODULES = [k for k, v in ATTACK_REGISTRY.items() if v.owasp]
