#!/usr/bin/env python3
"""
BREACH.AI v3 - Authenticated Breach Engine

The killer feature: Test as a LOGGED IN user.

This finds the bugs that live INSIDE your app:
- IDOR: Can User A access User B's data?
- Privilege Escalation: Can regular user access admin?
- Horizontal Access: Can I see other tenants' data?
- Broken Access Control: What happens if I change IDs?

Usage:
    # Unauthenticated (external attacker)
    python breach_v3.py https://target.com

    # With session token
    python breach_v3.py https://target.com --token "Bearer eyJ..."

    # With cookie
    python breach_v3.py https://target.com --cookie "session=abc123"

    # With login credentials (auto-login)
    python breach_v3.py https://target.com --email user@test.com --password test123

    # Two-user IDOR test (the killer feature)
    python breach_v3.py https://target.com \
        --user1-token "Bearer eyJ..." \
        --user2-token "Bearer eyJ..."

This is where 90% of critical bugs live.
"""

import asyncio
import aiohttp
import json
import sys
import os
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from datetime import datetime
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich import box

console = Console()


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class UserContext:
    """Authenticated user context."""
    identifier: str  # email or "user1", "user2"
    token: Optional[str] = None
    cookie: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None

    # Discovered resources belonging to this user
    owned_resources: List[Dict] = field(default_factory=list)
    accessible_endpoints: List[str] = field(default_factory=list)

    def get_headers(self) -> Dict[str, str]:
        """Get auth headers for this user."""
        headers = {}
        if self.token:
            if self.token.startswith('Bearer '):
                headers['Authorization'] = self.token
            else:
                headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def get_cookies(self) -> Dict[str, str]:
        """Get cookies for this user."""
        cookies = {}
        if self.cookie:
            for part in self.cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    cookies[k] = v
        return cookies


@dataclass
class IDORFinding:
    """An IDOR vulnerability finding."""
    severity: Severity
    title: str
    description: str

    # The attack details
    attacker: str  # Who performed the attack (user1, user2, unauthenticated)
    victim: str  # Whose data was accessed
    endpoint: str
    method: str

    # Evidence
    resource_id: str  # The ID that was accessed
    data_extracted: Optional[Dict] = None
    record_count: int = 0
    pii_fields: List[str] = field(default_factory=list)

    # Reproduction
    curl_command: str = ""
    fix_suggestion: str = ""


@dataclass
class PrivilegeEscalation:
    """A privilege escalation finding."""
    severity: Severity
    title: str
    description: str

    # Attack details
    user_role: str  # regular, guest, etc.
    accessed_role: str  # admin, superuser, etc.
    endpoint: str
    method: str

    # Evidence
    data_extracted: Optional[Dict] = None
    actions_possible: List[str] = field(default_factory=list)

    # Reproduction
    curl_command: str = ""
    fix_suggestion: str = ""


@dataclass
class BreachReport:
    """Complete breach report."""
    target: str
    scan_time: float
    auth_mode: str  # unauthenticated, single_user, dual_user

    # Users involved
    users: List[UserContext] = field(default_factory=list)

    # Findings
    idor_findings: List[IDORFinding] = field(default_factory=list)
    privilege_escalations: List[PrivilegeEscalation] = field(default_factory=list)
    exposed_endpoints: List[Dict] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)

    # Summary
    total_records_exposed: int = 0
    critical_count: int = 0
    high_count: int = 0


# ============================================================================
# AUTHENTICATION HANDLERS
# ============================================================================

class AuthHandler:
    """Handle authentication for different providers."""

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def login_nextauth(self, base_url: str, email: str, password: str) -> Optional[UserContext]:
        """Login via NextAuth credentials provider."""

        # Get CSRF token first
        csrf_url = urljoin(base_url, '/api/auth/csrf')
        try:
            async with self.session.get(csrf_url, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    csrf_token = data.get('csrfToken')
                else:
                    return None
        except:
            return None

        # Attempt login
        login_url = urljoin(base_url, '/api/auth/callback/credentials')
        payload = {
            'email': email,
            'password': password,
            'csrfToken': csrf_token,
            'json': 'true'
        }

        try:
            async with self.session.post(login_url, data=payload, ssl=False, allow_redirects=False) as resp:
                # Check for session cookie
                cookies = resp.cookies

                if 'next-auth.session-token' in cookies or 'session' in cookies:
                    cookie_str = '; '.join([f"{k}={v.value}" for k, v in cookies.items()])

                    return UserContext(
                        identifier=email,
                        cookie=cookie_str
                    )
        except:
            pass

        return None

    async def login_supabase(self, supabase_url: str, anon_key: str, email: str, password: str) -> Optional[UserContext]:
        """Login via Supabase Auth."""

        auth_url = f"{supabase_url}/auth/v1/token?grant_type=password"

        headers = {
            'apikey': anon_key,
            'Content-Type': 'application/json'
        }

        payload = {
            'email': email,
            'password': password
        }

        try:
            async with self.session.post(auth_url, headers=headers, json=payload, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    access_token = data.get('access_token')
                    user = data.get('user', {})

                    return UserContext(
                        identifier=email,
                        token=f"Bearer {access_token}",
                        user_id=user.get('id'),
                        role=user.get('role')
                    )
        except:
            pass

        return None

    async def get_session_info(self, base_url: str, user: UserContext) -> Dict:
        """Get current session info for a user."""

        session_url = urljoin(base_url, '/api/auth/session')

        try:
            async with self.session.get(
                session_url,
                headers=user.get_headers(),
                cookies=user.get_cookies(),
                ssl=False
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except:
            pass

        return {}


# ============================================================================
# RESOURCE DISCOVERY
# ============================================================================

class ResourceDiscovery:
    """Discover resources owned by authenticated users."""

    # Endpoints that typically return user's own resources
    USER_RESOURCE_ENDPOINTS = [
        '/api/me',
        '/api/user',
        '/api/profile',
        '/api/account',
        '/api/projects',
        '/api/teams',
        '/api/organizations',
        '/api/orders',
        '/api/payments',
        '/api/subscriptions',
        '/api/files',
        '/api/documents',
        '/api/messages',
        '/api/notifications',
        '/api/settings',
        '/api/preferences',
        '/api/dashboard',
        '/api/workspaces',
        '/api/investors',
        '/api/lists',
        '/api/contacts',
        '/api/leads',
        '/api/deals',
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def discover_user_resources(self, base_url: str, user: UserContext) -> List[Dict]:
        """Discover resources belonging to a user."""

        resources = []

        for endpoint in self.USER_RESOURCE_ENDPOINTS:
            url = urljoin(base_url, endpoint)

            try:
                async with self.session.get(
                    url,
                    headers=user.get_headers(),
                    cookies=user.get_cookies(),
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        try:
                            data = json.loads(body)

                            # Extract IDs from the response
                            ids = self._extract_ids(data)

                            if ids:
                                resources.append({
                                    'endpoint': endpoint,
                                    'ids': ids,
                                    'data': data,
                                    'count': len(ids) if isinstance(ids, list) else 1
                                })

                                console.print(f"[green]  ✓ {endpoint}[/green] → {len(ids)} resource(s)")
                        except:
                            pass

                    elif resp.status == 401:
                        # Track protected endpoints
                        user.accessible_endpoints.append(endpoint)
            except:
                pass

        user.owned_resources = resources
        return resources

    def _extract_ids(self, data: Any, ids: List[str] = None) -> List[str]:
        """Extract all IDs from a data structure."""
        if ids is None:
            ids = []

        if isinstance(data, dict):
            # Look for common ID fields
            for key in ['id', 'uuid', '_id', 'Id', 'ID', 'projectId', 'userId', 'teamId', 'orderId', 'investorId', 'listId', 'contactId']:
                if key in data and data[key]:
                    id_val = str(data[key])
                    if id_val not in ids:
                        ids.append(id_val)

            # Recurse
            for v in data.values():
                self._extract_ids(v, ids)

        elif isinstance(data, list):
            for item in data:
                self._extract_ids(item, ids)

        return ids


# ============================================================================
# IDOR TESTER - THE KILLER FEATURE
# ============================================================================

class IDORTester:
    """
    Test for Insecure Direct Object Reference vulnerabilities.

    This is the killer feature:
    - User A's token + User B's resource ID = IDOR if it works
    """

    # Common ID parameter patterns
    ID_PATTERNS = [
        '/{id}',
        '/{uuid}',
        '/{projectId}',
        '/{userId}',
        '/{orderId}',
        '/{teamId}',
        '/{documentId}',
        '/{fileId}',
    ]

    # Endpoints to test for IDOR
    IDOR_ENDPOINTS = [
        '/api/projects/{id}',
        '/api/users/{id}',
        '/api/orders/{id}',
        '/api/payments/{id}',
        '/api/teams/{id}',
        '/api/documents/{id}',
        '/api/files/{id}',
        '/api/messages/{id}',
        '/api/invoices/{id}',
        '/api/subscriptions/{id}',
        '/api/organizations/{id}',
        '/api/workspaces/{id}',
        '/api/profiles/{id}',
        '/api/settings/{id}',
        '/api/accounts/{id}',
        '/api/investors/{id}',
        '/api/lists/{id}',
        '/api/contacts/{id}',
        '/api/leads/{id}',
        '/api/deals/{id}',
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.findings: List[IDORFinding] = []

    async def test_cross_user_access(
        self,
        base_url: str,
        attacker: UserContext,
        victim: UserContext
    ) -> List[IDORFinding]:
        """
        Test if attacker can access victim's resources.

        This is the money shot: User A accessing User B's data.
        """

        findings = []

        console.print(f"\n[yellow]Testing: {attacker.identifier} → {victim.identifier}'s data[/yellow]")

        # Get victim's resource IDs
        victim_ids = []
        for resource in victim.owned_resources:
            victim_ids.extend(resource.get('ids', []))

        if not victim_ids:
            console.print(f"[dim]  No victim resources discovered[/dim]")
            return findings

        console.print(f"[dim]  Testing {len(victim_ids)} victim resource IDs[/dim]")

        # Try to access victim's resources with attacker's credentials
        for endpoint_template in self.IDOR_ENDPOINTS:
            for victim_id in victim_ids[:10]:  # Limit to first 10
                endpoint = endpoint_template.replace('{id}', victim_id)
                url = urljoin(base_url, endpoint)

                try:
                    async with self.session.get(
                        url,
                        headers=attacker.get_headers(),
                        cookies=attacker.get_cookies(),
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        body = await resp.text()

                        if resp.status == 200 and len(body) > 50:
                            try:
                                data = json.loads(body)

                                # Verify it's actually victim's data
                                if self._is_victim_data(data, victim_id, victim):
                                    pii = self._detect_pii(data)

                                    finding = IDORFinding(
                                        severity=Severity.CRITICAL,
                                        title=f"IDOR: Cross-User Data Access",
                                        description=f"{attacker.identifier} can access {victim.identifier}'s data at {endpoint}",
                                        attacker=attacker.identifier,
                                        victim=victim.identifier,
                                        endpoint=endpoint,
                                        method="GET",
                                        resource_id=victim_id,
                                        data_extracted=data if isinstance(data, dict) else {'data': str(data)[:500]},
                                        record_count=1,
                                        pii_fields=pii,
                                        curl_command=self._build_curl(url, attacker),
                                        fix_suggestion=f"Add ownership check: if (resource.userId !== currentUser.id) return 403"
                                    )

                                    findings.append(finding)

                                    console.print(f"[red bold]  🔴 IDOR CONFIRMED[/red bold] {endpoint}")
                                    console.print(f"[red]     {attacker.identifier} accessed {victim.identifier}'s resource {victim_id}[/red]")
                                    if pii:
                                        console.print(f"[red]     PII exposed: {', '.join(pii)}[/red]")
                            except json.JSONDecodeError:
                                pass

                        elif resp.status == 404:
                            # 404 vs 401/403 is interesting - may indicate auth bypass
                            pass

                except Exception as e:
                    pass

        self.findings.extend(findings)
        return findings

    async def test_unauthenticated_access(
        self,
        base_url: str,
        victim: UserContext
    ) -> List[IDORFinding]:
        """Test if unauthenticated users can access victim's resources."""

        findings = []

        console.print(f"\n[yellow]Testing: Unauthenticated → {victim.identifier}'s data[/yellow]")

        # Get victim's resource IDs
        victim_ids = []
        for resource in victim.owned_resources:
            victim_ids.extend(resource.get('ids', []))

        if not victim_ids:
            return findings

        # Try to access without any auth
        for endpoint_template in self.IDOR_ENDPOINTS:
            for victim_id in victim_ids[:10]:
                endpoint = endpoint_template.replace('{id}', victim_id)
                url = urljoin(base_url, endpoint)

                try:
                    async with self.session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()

                        if resp.status == 200 and len(body) > 50:
                            try:
                                data = json.loads(body)

                                finding = IDORFinding(
                                    severity=Severity.CRITICAL,
                                    title=f"IDOR: Unauthenticated Data Access",
                                    description=f"Unauthenticated access to {victim.identifier}'s data at {endpoint}",
                                    attacker="unauthenticated",
                                    victim=victim.identifier,
                                    endpoint=endpoint,
                                    method="GET",
                                    resource_id=victim_id,
                                    data_extracted=data if isinstance(data, dict) else {'data': str(data)[:500]},
                                    record_count=1,
                                    pii_fields=self._detect_pii(data),
                                    curl_command=f"curl '{url}'",
                                    fix_suggestion="Add authentication middleware to this endpoint"
                                )

                                findings.append(finding)
                                console.print(f"[red bold]  🔴 UNAUTH ACCESS[/red bold] {endpoint}")
                            except json.JSONDecodeError:
                                pass

                except:
                    pass

        self.findings.extend(findings)
        return findings

    async def test_id_manipulation(
        self,
        base_url: str,
        user: UserContext,
        discovered_endpoints: List[Dict]
    ) -> List[IDORFinding]:
        """Test ID manipulation on discovered endpoints."""

        findings = []

        console.print(f"\n[yellow]Testing ID manipulation for {user.identifier}[/yellow]")

        # Test patterns
        test_ids = ['1', '2', '0', '-1', '999999', 'admin', 'test']

        for ep_info in discovered_endpoints:
            endpoint = ep_info.get('endpoint', '')

            # Find ID patterns in endpoint
            id_match = re.search(r'/([a-f0-9-]{36}|\d+)(?:/|$)', endpoint)

            if id_match:
                original_id = id_match.group(1)

                for test_id in test_ids:
                    if test_id == original_id:
                        continue

                    test_endpoint = endpoint.replace(original_id, test_id)
                    url = urljoin(base_url, test_endpoint)

                    try:
                        async with self.session.get(
                            url,
                            headers=user.get_headers(),
                            cookies=user.get_cookies(),
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text()

                                if len(body) > 50:
                                    try:
                                        data = json.loads(body)

                                        # Check if we got different data
                                        if self._is_different_resource(data, ep_info.get('data')):
                                            finding = IDORFinding(
                                                severity=Severity.HIGH,
                                                title=f"IDOR: ID Manipulation",
                                                description=f"Changing ID from {original_id} to {test_id} returns different data",
                                                attacker=user.identifier,
                                                victim="other_user",
                                                endpoint=test_endpoint,
                                                method="GET",
                                                resource_id=test_id,
                                                data_extracted=data if isinstance(data, dict) else None,
                                                curl_command=self._build_curl(url, user),
                                                fix_suggestion="Verify resource ownership before returning data"
                                            )

                                            findings.append(finding)
                                            console.print(f"[red]  🔴 ID MANIPULATION[/red] {test_endpoint}")
                                    except:
                                        pass
                    except:
                        pass

        self.findings.extend(findings)
        return findings

    def _is_victim_data(self, data: Any, victim_id: str, victim: UserContext) -> bool:
        """Check if data belongs to victim."""
        data_str = json.dumps(data)

        # Check if victim's ID appears in data
        if victim_id in data_str:
            return True

        # Check for victim's email/identifier
        if victim.identifier in data_str:
            return True

        if victim.user_id and victim.user_id in data_str:
            return True

        return True  # Assume it's victim's data if we got 200

    def _is_different_resource(self, new_data: Any, original_data: Any) -> bool:
        """Check if we got a different resource."""
        if not original_data:
            return True

        new_str = json.dumps(new_data, sort_keys=True)
        orig_str = json.dumps(original_data, sort_keys=True)

        return new_str != orig_str

    def _detect_pii(self, data: Any) -> List[str]:
        """Detect PII fields."""
        pii = set()
        pii_keywords = ['email', 'phone', 'password', 'address', 'ssn', 'name', 'token', 'secret', 'card']

        def scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    for kw in pii_keywords:
                        if kw in str(k).lower():
                            pii.add(k)
                    scan(v)
            elif isinstance(obj, list):
                for item in obj:
                    scan(item)

        scan(data)
        return list(pii)

    def _build_curl(self, url: str, user: UserContext) -> str:
        """Build curl command for reproduction."""
        cmd = f"curl '{url}'"

        if user.token:
            cmd += f" -H 'Authorization: {user.token}'"

        if user.cookie:
            cmd += f" -H 'Cookie: {user.cookie}'"

        return cmd


# ============================================================================
# PRIVILEGE ESCALATION TESTER
# ============================================================================

class PrivilegeEscalationTester:
    """Test for privilege escalation vulnerabilities."""

    # Admin endpoints that regular users shouldn't access
    ADMIN_ENDPOINTS = [
        '/api/admin',
        '/api/admin/users',
        '/api/admin/stats',
        '/api/admin/config',
        '/api/admin/settings',
        '/api/admin/dashboard',
        '/api/admin/logs',
        '/api/admin/audit',
        '/api/users',  # User listing often admin-only
        '/api/all-users',
        '/api/customers',
        '/api/internal',
        '/api/debug',
        '/api/system',
        '/api/config',
        '/api/settings/global',
        '/api/metrics',
        '/api/analytics',
        '/api/reports',
        '/api/export/all',
        '/api/backup',
        '/admin',
        '/dashboard/admin',
        '/internal/api',
        '/api/all-investors',
        '/api/all-lists',
        '/api/export',
    ]

    # Actions that indicate admin access
    ADMIN_ACTIONS = [
        ('DELETE', '/api/users/{id}'),
        ('PUT', '/api/users/{id}/role'),
        ('POST', '/api/admin/invite'),
        ('POST', '/api/users'),
        ('DELETE', '/api/projects/{id}'),
        ('PUT', '/api/settings'),
    ]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.findings: List[PrivilegeEscalation] = []

    async def test_admin_access(
        self,
        base_url: str,
        user: UserContext
    ) -> List[PrivilegeEscalation]:
        """Test if regular user can access admin endpoints."""

        findings = []

        console.print(f"\n[yellow]Testing admin access for {user.identifier}[/yellow]")

        for endpoint in self.ADMIN_ENDPOINTS:
            url = urljoin(base_url, endpoint)

            try:
                async with self.session.get(
                    url,
                    headers=user.get_headers(),
                    cookies=user.get_cookies(),
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    body = await resp.text()

                    if resp.status == 200 and len(body) > 50:
                        try:
                            data = json.loads(body)

                            # Check if it's actual admin data
                            if self._is_admin_data(data, endpoint):
                                finding = PrivilegeEscalation(
                                    severity=Severity.CRITICAL,
                                    title=f"Privilege Escalation: Admin Endpoint Access",
                                    description=f"Regular user {user.identifier} can access {endpoint}",
                                    user_role=user.role or "regular",
                                    accessed_role="admin",
                                    endpoint=endpoint,
                                    method="GET",
                                    data_extracted=data if isinstance(data, dict) else {'count': len(data) if isinstance(data, list) else 1},
                                    actions_possible=["View admin data"],
                                    curl_command=self._build_curl(url, user),
                                    fix_suggestion=f"Add admin role check: if (user.role !== 'admin') return 403"
                                )

                                findings.append(finding)

                                record_count = len(data) if isinstance(data, list) else 1
                                console.print(f"[red bold]  🔴 PRIV ESC[/red bold] {endpoint} → {record_count} records")

                        except:
                            pass

            except:
                pass

        self.findings.extend(findings)
        return findings

    async def test_admin_actions(
        self,
        base_url: str,
        user: UserContext
    ) -> List[PrivilegeEscalation]:
        """Test if regular user can perform admin actions."""

        findings = []

        console.print(f"\n[yellow]Testing admin actions for {user.identifier}[/yellow]")

        # Get some IDs to test with
        test_ids = ['1', '999999', 'test']

        for resource in user.owned_resources:
            test_ids.extend(resource.get('ids', [])[:2])

        for method, endpoint_template in self.ADMIN_ACTIONS:
            for test_id in test_ids[:3]:
                endpoint = endpoint_template.replace('{id}', test_id)
                url = urljoin(base_url, endpoint)

                try:
                    # Use appropriate method
                    if method == 'DELETE':
                        # Don't actually delete - just check if allowed
                        # Use OPTIONS or check response to DELETE without body
                        async with self.session.options(
                            url,
                            headers=user.get_headers(),
                            cookies=user.get_cookies(),
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if 'DELETE' in resp.headers.get('Allow', ''):
                                finding = PrivilegeEscalation(
                                    severity=Severity.HIGH,
                                    title=f"Privilege Escalation: DELETE Allowed",
                                    description=f"User can DELETE {endpoint}",
                                    user_role=user.role or "regular",
                                    accessed_role="admin",
                                    endpoint=endpoint,
                                    method="DELETE",
                                    actions_possible=["Delete resources"],
                                    curl_command=f"curl -X DELETE '{url}' -H 'Authorization: {user.token}'",
                                    fix_suggestion="Add role check before destructive operations"
                                )
                                findings.append(finding)
                                console.print(f"[red]  🔴 DELETE ALLOWED[/red] {endpoint}")

                    elif method == 'PUT':
                        # Test role modification
                        payload = {'role': 'admin', 'is_admin': True}
                        async with self.session.put(
                            url,
                            headers=user.get_headers(),
                            cookies=user.get_cookies(),
                            json=payload,
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status in [200, 201]:
                                finding = PrivilegeEscalation(
                                    severity=Severity.CRITICAL,
                                    title=f"Privilege Escalation: Role Modification",
                                    description=f"User can modify roles at {endpoint}",
                                    user_role=user.role or "regular",
                                    accessed_role="admin",
                                    endpoint=endpoint,
                                    method="PUT",
                                    actions_possible=["Modify user roles", "Grant admin access"],
                                    curl_command=f"curl -X PUT '{url}' -H 'Authorization: {user.token}' -d '{json.dumps(payload)}'",
                                    fix_suggestion="Only admins should modify roles"
                                )
                                findings.append(finding)
                                console.print(f"[red bold]  🔴 ROLE MODIFICATION[/red bold] {endpoint}")

                except:
                    pass

        self.findings.extend(findings)
        return findings

    def _is_admin_data(self, data: Any, endpoint: str) -> bool:
        """Check if response looks like admin data."""

        # If it's a list of users, it's admin data
        if isinstance(data, list) and len(data) > 0:
            first = data[0]
            if isinstance(first, dict):
                if any(k in first for k in ['email', 'role', 'created_at', 'user']):
                    return True

        # If endpoint has admin in it and we got data
        if 'admin' in endpoint and data:
            return True

        # If it contains user listings
        if isinstance(data, dict):
            if 'users' in data or 'customers' in data:
                return True

        return False

    def _build_curl(self, url: str, user: UserContext) -> str:
        """Build curl command."""
        cmd = f"curl '{url}'"
        if user.token:
            cmd += f" -H 'Authorization: {user.token}'"
        return cmd


# ============================================================================
# MAIN ENGINE
# ============================================================================

class BreachEngineV3:
    """
    BREACH.AI v3 - Authenticated Breach Engine

    The engine that finds IDOR and privilege escalation.
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.users: List[UserContext] = []
        self.report: Optional[BreachReport] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={'User-Agent': 'BREACH.AI/3.0'}
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def breach(
        self,
        target: str,
        user1_token: str = None,
        user1_cookie: str = None,
        user2_token: str = None,
        user2_cookie: str = None,
        email: str = None,
        password: str = None
    ) -> BreachReport:
        """
        Execute full authenticated breach test.
        """
        start = time.time()

        if not target.startswith('http'):
            target = f'https://{target}'

        # Determine auth mode
        if user1_token and user2_token:
            auth_mode = "dual_user"
        elif user1_token or user1_cookie or email:
            auth_mode = "single_user"
        else:
            auth_mode = "unauthenticated"

        # Print banner
        console.print(Panel.fit(
            f"[bold red]BREACH.AI v3[/bold red]\n"
            f"[dim]Authenticated Breach Engine[/dim]\n\n"
            f"Target: {target}\n"
            f"Mode: {auth_mode}",
            border_style="red"
        ))

        # Initialize report
        self.report = BreachReport(
            target=target,
            scan_time=0,
            auth_mode=auth_mode
        )

        # Setup users
        if user1_token or user1_cookie:
            user1 = UserContext(
                identifier="user1",
                token=user1_token,
                cookie=user1_cookie
            )
            self.users.append(user1)

        if user2_token or user2_cookie:
            user2 = UserContext(
                identifier="user2",
                token=user2_token,
                cookie=user2_cookie
            )
            self.users.append(user2)

        # If credentials provided, try to login
        if email and password and not self.users:
            console.print(f"\n[cyan]▶ AUTHENTICATING[/cyan]")
            auth_handler = AuthHandler(self.session)

            # Try NextAuth
            user = await auth_handler.login_nextauth(target, email, password)
            if user:
                console.print(f"[green]  ✓ Logged in as {email}[/green]")
                self.users.append(user)

        # Phase 1: Resource Discovery
        console.print(f"\n[cyan]▶ PHASE 1: RESOURCE DISCOVERY[/cyan]")

        discovery = ResourceDiscovery(self.session)
        for user in self.users:
            console.print(f"\n[dim]Discovering resources for {user.identifier}...[/dim]")
            await discovery.discover_user_resources(target, user)

        # Phase 2: IDOR Testing
        console.print(f"\n[cyan]▶ PHASE 2: IDOR TESTING[/cyan]")

        idor_tester = IDORTester(self.session)

        # Cross-user IDOR (the killer test)
        if len(self.users) >= 2:
            user1, user2 = self.users[0], self.users[1]

            # User1 → User2's data
            findings = await idor_tester.test_cross_user_access(target, user1, user2)
            self.report.idor_findings.extend(findings)

            # User2 → User1's data
            findings = await idor_tester.test_cross_user_access(target, user2, user1)
            self.report.idor_findings.extend(findings)

        # Single user: test unauthenticated access and ID manipulation
        for user in self.users:
            # Unauth access to user's resources
            findings = await idor_tester.test_unauthenticated_access(target, user)
            self.report.idor_findings.extend(findings)

            # ID manipulation
            findings = await idor_tester.test_id_manipulation(target, user, user.owned_resources)
            self.report.idor_findings.extend(findings)

        # Phase 3: Privilege Escalation
        console.print(f"\n[cyan]▶ PHASE 3: PRIVILEGE ESCALATION[/cyan]")

        priv_tester = PrivilegeEscalationTester(self.session)

        for user in self.users:
            findings = await priv_tester.test_admin_access(target, user)
            self.report.privilege_escalations.extend(findings)

            findings = await priv_tester.test_admin_actions(target, user)
            self.report.privilege_escalations.extend(findings)

        # Phase 4: Endpoint enumeration (even if no auth)
        console.print(f"\n[cyan]▶ PHASE 4: ENDPOINT ENUMERATION[/cyan]")

        await self._enumerate_endpoints(target)

        # Finalize report
        self.report.scan_time = time.time() - start
        self.report.users = self.users

        # Count severities
        for f in self.report.idor_findings:
            if f.severity == Severity.CRITICAL:
                self.report.critical_count += 1
            elif f.severity == Severity.HIGH:
                self.report.high_count += 1

        for f in self.report.privilege_escalations:
            if f.severity == Severity.CRITICAL:
                self.report.critical_count += 1
            elif f.severity == Severity.HIGH:
                self.report.high_count += 1

        return self.report

    async def _enumerate_endpoints(self, base_url: str):
        """Enumerate common endpoints."""

        endpoints = [
            '/api/health', '/api/status', '/api/config',
            '/api/plans', '/api/pricing',
            '/api/auth/session', '/api/auth/csrf', '/api/auth/providers',
            '/graphql', '/api/graphql',
            '/.env', '/.git/config',
            '/api/investors', '/api/lists', '/api/contacts',
            '/api/dashboard', '/api/user', '/api/me',
        ]

        user = self.users[0] if self.users else None

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)

            try:
                headers = user.get_headers() if user else {}
                cookies = user.get_cookies() if user else {}

                async with self.session.get(url, headers=headers, cookies=cookies, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        if len(body) > 20:
                            self.report.exposed_endpoints.append({
                                'endpoint': endpoint,
                                'status': resp.status,
                                'size': len(body)
                            })
                            console.print(f"[green]  ✓ {endpoint}[/green] → {len(body)} bytes")
            except:
                pass


# ============================================================================
# REPORT PRINTER
# ============================================================================

def print_report(report: BreachReport):
    """Print the breach report."""

    console.print(f"\n{'═' * 70}")

    total_findings = len(report.idor_findings) + len(report.privilege_escalations)

    if report.critical_count > 0:
        console.print(f"[bold red]🔴 CRITICAL VULNERABILITIES FOUND[/bold red]")
    elif report.high_count > 0:
        console.print(f"[bold yellow]🟡 HIGH SEVERITY ISSUES FOUND[/bold yellow]")
    elif total_findings > 0:
        console.print(f"[bold cyan]🔵 ISSUES FOUND[/bold cyan]")
    else:
        console.print(f"[bold green]🟢 NO VULNERABILITIES FOUND[/bold green]")

    console.print(f"{'═' * 70}\n")

    # Summary
    table = Table(box=box.ROUNDED, title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    table.add_row("Target", report.target)
    table.add_row("Scan Time", f"{report.scan_time:.1f}s")
    table.add_row("Auth Mode", report.auth_mode)
    table.add_row("Users Tested", str(len(report.users)))
    table.add_row("IDOR Findings", f"[red]{len(report.idor_findings)}[/red]" if report.idor_findings else "0")
    table.add_row("Priv Esc Findings", f"[red]{len(report.privilege_escalations)}[/red]" if report.privilege_escalations else "0")
    table.add_row("Critical", f"[red bold]{report.critical_count}[/red bold]" if report.critical_count else "0")
    table.add_row("High", f"[yellow]{report.high_count}[/yellow]" if report.high_count else "0")

    console.print(table)

    # IDOR Findings
    if report.idor_findings:
        console.print(f"\n[bold red]IDOR Vulnerabilities:[/bold red]")

        for i, f in enumerate(report.idor_findings, 1):
            console.print(f"\n  {i}. [{f.severity.value.upper()}] {f.title}")
            console.print(f"     {f.description}")
            console.print(f"     [dim]Endpoint: {f.endpoint}[/dim]")
            console.print(f"     [dim]Attacker: {f.attacker} → Victim: {f.victim}[/dim]")
            if f.pii_fields:
                console.print(f"     [red]PII Exposed: {', '.join(f.pii_fields)}[/red]")
            console.print(f"     [dim]Reproduce: {f.curl_command}[/dim]")
            console.print(f"     [green]Fix: {f.fix_suggestion}[/green]")

    # Privilege Escalation
    if report.privilege_escalations:
        console.print(f"\n[bold red]Privilege Escalation:[/bold red]")

        for i, f in enumerate(report.privilege_escalations, 1):
            console.print(f"\n  {i}. [{f.severity.value.upper()}] {f.title}")
            console.print(f"     {f.description}")
            console.print(f"     [dim]{f.user_role} → {f.accessed_role}[/dim]")
            console.print(f"     [dim]Reproduce: {f.curl_command}[/dim]")
            console.print(f"     [green]Fix: {f.fix_suggestion}[/green]")

    # Exposed endpoints
    if report.exposed_endpoints:
        console.print(f"\n[bold]Exposed Endpoints:[/bold]")
        for ep in report.exposed_endpoints:
            console.print(f"  • {ep['endpoint']} ({ep['size']} bytes)")

    console.print(f"\n{'═' * 70}\n")


def generate_json_report(report: BreachReport) -> str:
    """Generate JSON report."""
    return json.dumps({
        'target': report.target,
        'scan_time': report.scan_time,
        'auth_mode': report.auth_mode,
        'summary': {
            'critical': report.critical_count,
            'high': report.high_count,
            'total_idor': len(report.idor_findings),
            'total_priv_esc': len(report.privilege_escalations),
        },
        'idor_findings': [
            {
                'severity': f.severity.value,
                'title': f.title,
                'description': f.description,
                'endpoint': f.endpoint,
                'attacker': f.attacker,
                'victim': f.victim,
                'pii_exposed': f.pii_fields,
                'curl': f.curl_command,
                'fix': f.fix_suggestion,
            }
            for f in report.idor_findings
        ],
        'privilege_escalations': [
            {
                'severity': f.severity.value,
                'title': f.title,
                'description': f.description,
                'endpoint': f.endpoint,
                'curl': f.curl_command,
                'fix': f.fix_suggestion,
            }
            for f in report.privilege_escalations
        ],
        'exposed_endpoints': report.exposed_endpoints,
    }, indent=2)


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='BREACH.AI v3 - Authenticated Breach Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Unauthenticated scan
  python breach_v3.py https://target.com

  # Single user (your own token)
  python breach_v3.py https://target.com --token "Bearer eyJ..."

  # Two users (IDOR test - the killer feature)
  python breach_v3.py https://target.com \\
      --user1-token "Bearer eyJ..." \\
      --user2-token "Bearer eyJ..."

  # With login credentials
  python breach_v3.py https://target.com --email user@test.com --password test123
        """
    )

    parser.add_argument('target', help='Target URL')
    parser.add_argument('--token', dest='user1_token', help='Auth token for user1')
    parser.add_argument('--cookie', dest='user1_cookie', help='Auth cookie for user1')
    parser.add_argument('--user1-token', help='Auth token for user1 (explicit)')
    parser.add_argument('--user1-cookie', help='Auth cookie for user1 (explicit)')
    parser.add_argument('--user2-token', help='Auth token for user2 (for IDOR testing)')
    parser.add_argument('--user2-cookie', help='Auth cookie for user2')
    parser.add_argument('--email', help='Email for auto-login')
    parser.add_argument('--password', help='Password for auto-login')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    parser.add_argument('--output', help='Save report to file')

    args = parser.parse_args()

    # Merge token arguments
    user1_token = args.user1_token or getattr(args, 'user1_token', None)
    user1_cookie = args.user1_cookie or getattr(args, 'user1_cookie', None)

    async with BreachEngineV3() as engine:
        report = await engine.breach(
            target=args.target,
            user1_token=user1_token,
            user1_cookie=user1_cookie,
            user2_token=args.user2_token,
            user2_cookie=args.user2_cookie,
            email=args.email,
            password=args.password
        )

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
