"""
BREACH.AI v2 - Tech Fingerprinter Module

Identify all technologies in use on the target.
"""

import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from breach.modules.base import (
    ReconModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    Severity,
)


# Technology signatures
TECH_SIGNATURES = {
    # Frameworks
    "next.js": [r"_next/static", r"__NEXT_DATA__", r"next-auth"],
    "react": [r"react", r"_reactRootContainer", r"data-reactroot"],
    "vue.js": [r"vue", r"__vue__", r"v-cloak"],
    "angular": [r"ng-version", r"ng-app", r"angular"],
    "express": [r"express", r"x-powered-by:\s*express"],
    "django": [r"csrfmiddlewaretoken", r"django"],
    "rails": [r"rails", r"x-runtime", r"action_dispatch"],
    "laravel": [r"laravel", r"laravel_session"],
    "flask": [r"flask", r"werkzeug"],
    "fastapi": [r"fastapi", r"starlette"],

    # Auth providers
    "clerk": [r"clerk", r"__clerk"],
    "auth0": [r"auth0", r"cdn\.auth0\.com"],
    "firebase_auth": [r"firebaseauth", r"identitytoolkit"],
    "nextauth": [r"next-auth", r"__Secure-next-auth"],
    "supabase_auth": [r"supabase\.auth"],

    # Databases (backend hints)
    "supabase": [r"supabase\.co", r"\.supabase\."],
    "firebase": [r"firebaseio\.com", r"firebase\.google"],
    "mongodb": [r"mongodb", r"mongoose"],
    "postgresql": [r"postgres", r"pg_"],
    "mysql": [r"mysql", r"mysqli"],

    # Cloud/Hosting
    "vercel": [r"vercel", r"\.vercel\.app", r"x-vercel"],
    "netlify": [r"netlify", r"\.netlify\.app"],
    "aws": [r"amazonaws\.com", r"aws-", r"x-amz"],
    "cloudflare": [r"cloudflare", r"cf-ray", r"__cf"],
    "azure": [r"azure", r"\.azurewebsites\.net"],
    "gcp": [r"googleapis", r"\.run\.app"],
    "heroku": [r"heroku", r"\.herokuapp\.com"],

    # Payments
    "stripe": [r"stripe\.com", r"pk_live_", r"pk_test_"],
    "razorpay": [r"razorpay", r"rzp_"],
    "paypal": [r"paypal\.com", r"paypal"],

    # CDN/Analytics
    "google_analytics": [r"google-analytics", r"gtag", r"UA-\d+"],
    "segment": [r"segment\.com", r"analytics\.js"],
    "sentry": [r"sentry\.io", r"sentry"],
    "datadog": [r"datadoghq", r"dd-agent"],

    # CMS
    "wordpress": [r"wp-content", r"wp-includes", r"wordpress"],
    "drupal": [r"drupal", r"sites/default"],
    "shopify": [r"shopify", r"\.myshopify\.com"],

    # Security
    "waf_cloudflare": [r"cf-ray", r"__cf_bm"],
    "waf_aws": [r"x-amzn-waf", r"awswaf"],
    "recaptcha": [r"recaptcha", r"grecaptcha"],
    "hcaptcha": [r"hcaptcha"],
}

# Key patterns to extract
KEY_PATTERNS = {
    "supabase_url": r"https://[a-z0-9]+\.supabase\.co",
    "supabase_key": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "firebase_key": r"AIza[a-zA-Z0-9_-]{35}",
    "stripe_pk": r"pk_(?:live|test)_[a-zA-Z0-9]+",
    "aws_key": r"AKIA[A-Z0-9]{16}",
    "google_api": r"AIza[a-zA-Z0-9_-]{35}",
}


@register_module
class TechFingerprinter(ReconModule):
    """
    Tech Fingerprinter - Comprehensive technology detection.

    Detects:
    - Web frameworks (Next.js, React, Vue, etc.)
    - Backend technologies
    - Authentication providers
    - Database systems
    - Cloud providers
    - CDN/WAF
    - Third-party services
    """

    info = ModuleInfo(
        name="tech_fingerprinter",
        phase=BreachPhase.RECON,
        description="Technology stack detection",
        author="BREACH.AI",
        techniques=["T1592.004"],  # Software Discovery
        platforms=["web"],
        requires_access=False,
    )

    async def check(self, config: ModuleConfig) -> bool:
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        technologies = set()
        extracted_keys = {}
        headers_info = {}

        # Fetch main page and common endpoints
        pages_to_check = [
            "/",
            "/api/health",
            "/api/auth/session",
            "/api/auth/providers",
            "/_next/static/chunks/main.js",
            "/manifest.json",
            "/robots.txt",
        ]

        content = ""
        for page in pages_to_check:
            url = urljoin(config.target, page)
            try:
                response = await self._safe_request("GET", url, timeout=10)
                if response:
                    content += response.get("text", "") + str(response.get("headers", {}))
                    if page == "/":
                        headers_info = response.get("headers", {})
            except Exception:
                pass

        content_lower = content.lower()

        # Detect technologies
        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    technologies.add(tech)
                    break

        # Extract keys
        for key_name, pattern in KEY_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                extracted_keys[key_name] = matches[0]

        # Analyze headers
        header_techs = self._analyze_headers(headers_info)
        technologies.update(header_techs)

        # Add evidence
        tech_list = sorted(list(technologies))
        if tech_list:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description="Technology stack fingerprint",
                content={
                    "technologies": tech_list,
                    "extracted_keys": {k: v[:20] + "..." for k, v in extracted_keys.items()},
                },
                proves="Target technology stack identified",
                severity=Severity.INFO,
            )

        if extracted_keys:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description="API keys and secrets found in client code",
                content=extracted_keys,
                proves="Exposed credentials in frontend",
                severity=Severity.MEDIUM if "aws_key" in extracted_keys else Severity.LOW,
            )

        return self._create_result(
            success=len(technologies) > 0,
            action="tech_fingerprint",
            details=f"Detected {len(technologies)} technologies",
            technologies_detected=tech_list,
            data_extracted={
                "technologies": tech_list,
                "keys": extracted_keys,
            },
            chain_data={
                "supabase_url": extracted_keys.get("supabase_url"),
                "supabase_key": extracted_keys.get("supabase_key"),
                "firebase_key": extracted_keys.get("firebase_key"),
                "stripe_pk": extracted_keys.get("stripe_pk"),
            },
        )

    def _analyze_headers(self, headers: dict) -> set[str]:
        """Analyze HTTP headers for technology hints."""
        techs = set()
        headers_str = str(headers).lower()

        header_hints = {
            "x-powered-by": {
                "express": "express",
                "php": "php",
                "asp.net": "asp.net",
            },
            "server": {
                "nginx": "nginx",
                "apache": "apache",
                "cloudflare": "cloudflare",
                "vercel": "vercel",
            },
            "x-vercel": {"vercel"},
            "cf-ray": {"cloudflare"},
            "x-amz": {"aws"},
        }

        for header_key, tech_map in header_hints.items():
            if header_key in headers_str:
                if isinstance(tech_map, set):
                    techs.update(tech_map)
                else:
                    for keyword, tech in tech_map.items():
                        if keyword in headers_str:
                            techs.add(tech)

        return techs
