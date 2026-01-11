#!/usr/bin/env python3
"""
BREACH.AI - Interactive AI Hacking Agent

This is NOT a scanner. This is an AI that THINKS like a hacker.

It:
1. Analyzes the target
2. Proposes an attack
3. Asks for your permission
4. Executes and analyzes the result
5. Proposes the NEXT attack (never gives up)
6. Chains findings together
7. Proves the breach with real data

Usage:
    export ANTHROPIC_API_KEY=your-key
    python breach_interactive.py https://target.com

The AI will guide you through the attack, asking permission at each step.
Like Claude Code, but for breaking into web apps.
"""

import asyncio
import sys
import os
import json
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Rich for beautiful terminal UI
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import box

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from agents.hacker_brain import PersistentHackerBrain, HackerContext, Finding
from utils.http_client import HTTPClient, HTTPResponse

console = Console()


class BreachAI:
    """
    The Interactive AI Hacking Agent.

    Combines:
    - PersistentHackerBrain (Claude-powered thinking)
    - HTTPClient (real HTTP requests)
    - Rich UI (beautiful terminal interface)
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY required")

        self.brain = PersistentHackerBrain(self.api_key)
        self.http = HTTPClient()
        self.target = None

    async def run(self, target: str):
        """Run the interactive hacking session."""
        self.target = target

        # Banner
        self._print_banner()

        # Initialize
        await self.http._ensure_session()
        context = self.brain.start_session(target)

        try:
            # Phase 1: Recon
            console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
            console.print("[bold cyan]  PHASE 1: RECONNAISSANCE[/bold cyan]")
            console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

            await self._recon(context)

            # Phase 2: Interactive Attack Loop
            console.print(f"\n[bold yellow]{'=' * 60}[/bold yellow]")
            console.print("[bold yellow]  PHASE 2: ATTACK[/bold yellow]")
            console.print(f"[bold yellow]{'=' * 60}[/bold yellow]\n")

            await self._attack_loop(context)

            # Phase 3: Report
            self._print_report(context)

        finally:
            await self.http.close()

    async def _recon(self, context: HackerContext):
        """Initial reconnaissance phase."""
        console.print(f"[cyan][RECON][/cyan] Scanning {self.target}...")

        # Fetch main page
        response = await self.http.get(self.target)

        if response.status_code == 0:
            console.print(f"[red][ERROR][/red] Could not reach target: {response.error}")
            return

        console.print(f"[green][OK][/green] Got response: {response.status_code}")

        body = response.body or ""
        headers = response.headers

        # Detect technologies
        self._detect_tech(context, body, headers)

        # Extract secrets
        self._extract_secrets(context, body)

        # Discover endpoints
        await self._discover_endpoints(context, body)

        # Print summary
        self._print_recon_summary(context)

    def _detect_tech(self, context: HackerContext, body: str, headers: dict):
        """Detect technologies from response."""
        tech_patterns = {
            "Next.js": [r'_next/static', r'__NEXT_DATA__', r'/_next/'],
            "React": [r'react', r'__REACT'],
            "Vue.js": [r'Vue\.', r'__VUE__'],
            "Angular": [r'ng-version', r'angular'],
            "Supabase": [r'supabase\.co', r'@supabase/'],
            "Firebase": [r'firebaseio\.com', r'firebaseapp\.com'],
            "Vercel": [r'vercel', r'\.vercel\.app'],
            "NextAuth": [r'/api/auth/', r'next-auth'],
            "Stripe": [r'stripe\.com', r'pk_live_', r'pk_test_'],
        }

        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    if tech not in context.technologies:
                        context.technologies.append(tech)
                        console.print(f"[green][FOUND][/green] Technology: {tech}")
                    break

        # Check headers
        server = headers.get("server", "").lower()
        if "vercel" in server and "Vercel" not in context.technologies:
            context.technologies.append("Vercel")
            console.print(f"[green][FOUND][/green] Technology: Vercel (from headers)")

        # Detect auth system
        if "NextAuth" in context.technologies or "/api/auth/" in body:
            context.auth_system = "nextauth"
        elif "Supabase" in context.technologies:
            context.auth_system = "supabase"
        elif "Firebase" in context.technologies:
            context.auth_system = "firebase"

    def _extract_secrets(self, context: HackerContext, body: str):
        """Extract secrets from response body."""
        secret_patterns = {
            "supabase_url": r'(https://[a-z0-9]+\.supabase\.co)',
            "supabase_anon_key": r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
            "firebase_url": r'(https://[a-z0-9-]+\.firebaseio\.com)',
            "firebase_api_key": r'AIza[a-zA-Z0-9_-]{35}',
            "aws_access_key": r'(AKIA[0-9A-Z]{16})',
            "stripe_publishable": r'(pk_(?:live|test)_[a-zA-Z0-9]+)',
            "stripe_secret": r'(sk_(?:live|test)_[a-zA-Z0-9]+)',
            "github_token": r'(ghp_[a-zA-Z0-9]{36})',
            "openai_key": r'(sk-[a-zA-Z0-9]{48})',
            "jwt_token": r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        }

        for secret_type, pattern in secret_patterns.items():
            matches = re.findall(pattern, body)
            for match in matches:
                # Avoid duplicates
                existing = [s['value'] for s in context.secrets]
                if match not in existing:
                    context.secrets.append({
                        "type": secret_type,
                        "value": match,
                        "source": "main_page"
                    })

                    # Mask for display
                    masked = match[:20] + "..." if len(match) > 20 else match
                    severity = "red" if "secret" in secret_type or "sk_" in match else "yellow"
                    console.print(f"[{severity}][SECRET][/{severity}] {secret_type}: {masked}")

    async def _discover_endpoints(self, context: HackerContext, body: str):
        """Discover API endpoints."""
        # Common API paths to check
        common_paths = [
            "/api/auth/session", "/api/auth/providers", "/api/auth/csrf",
            "/api/users", "/api/user", "/api/me", "/api/profile",
            "/api/admin", "/api/config", "/api/settings",
            "/api/health", "/api/status", "/api/version",
            "/api/graphql", "/graphql",
            "/.env", "/.env.local", "/.git/config",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/robots.txt", "/sitemap.xml",
            "/api/projects", "/api/teams", "/api/plans",
        ]

        # Extract paths from HTML/JS
        href_matches = re.findall(r'href=["\']([^"\']+)["\']', body)
        src_matches = re.findall(r'src=["\']([^"\']+)["\']', body)
        api_matches = re.findall(r'["\'](/api/[^"\']+)["\']', body)

        discovered = set(common_paths)
        for match in href_matches + src_matches + api_matches:
            if match.startswith('/') and not match.startswith('//'):
                discovered.add(match.split('?')[0])  # Remove query params

        console.print(f"\n[cyan][ENUM][/cyan] Checking {len(discovered)} endpoints...")

        checked = 0
        for path in list(discovered)[:30]:  # Limit to 30
            url = urljoin(self.target, path)
            try:
                resp = await self.http.get(url)
                status = resp.status_code

                # Record endpoint
                endpoint = {
                    "path": path,
                    "url": url,
                    "status": status,
                    "auth": "protected" if status == 401 else "open" if status == 200 else "unknown",
                    "size": len(resp.body) if resp.body else 0
                }
                context.endpoints.append(endpoint)

                # Interesting findings
                if status == 200 and path.startswith('/api/'):
                    console.print(f"[green][OPEN][/green] {path} -> {status} ({endpoint['size']} bytes)")
                elif status == 200 and path in ['/.env', '/.git/config']:
                    console.print(f"[red][CRITICAL][/red] {path} -> EXPOSED!")
                    context.add_finding(Finding(
                        type="vulnerability",
                        severity="critical",
                        title=f"Exposed {path}",
                        details=f"Sensitive file accessible at {path}",
                        evidence=resp.body[:500] if resp.body else None,
                        exploitable=True
                    ))

                checked += 1

            except Exception as e:
                pass

        console.print(f"[cyan][ENUM][/cyan] Checked {checked} endpoints")

    def _print_recon_summary(self, context: HackerContext):
        """Print recon summary."""
        console.print(f"\n[bold]{'-' * 50}[/bold]")
        console.print("[bold]RECON SUMMARY[/bold]")
        console.print(f"[bold]{'-' * 50}[/bold]")

        if context.technologies:
            console.print(f"Technologies: {', '.join(context.technologies)}")
        if context.auth_system:
            console.print(f"Auth System: {context.auth_system}")
        if context.secrets:
            console.print(f"Secrets Found: {len(context.secrets)}")

        open_endpoints = [e for e in context.endpoints if e.get('status') == 200]
        protected_endpoints = [e for e in context.endpoints if e.get('status') == 401]
        console.print(f"Endpoints: {len(open_endpoints)} open, {len(protected_endpoints)} protected")

    async def _attack_loop(self, context: HackerContext):
        """Main interactive attack loop."""
        rounds = 0
        max_rounds = 50

        while rounds < max_rounds:
            rounds += 1

            # Ask the brain what to do next
            console.print(f"\n[bold magenta]{'-' * 60}[/bold magenta]")
            console.print("[bold magenta]BREACH.AI is thinking...[/bold magenta]")
            console.print(f"[bold magenta]{'-' * 60}[/bold magenta]\n")

            try:
                result = await self.brain.think()
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                if not Confirm.ask("Continue?", default=True):
                    break
                continue

            # Handle errors
            if "error" in result:
                console.print(f"[yellow]Brain error: {result.get('error')}[/yellow]")
                if result.get("raw"):
                    console.print(f"[dim]{result['raw'][:500]}[/dim]")
                continue

            # Display thinking
            if result.get("thinking"):
                console.print(Panel(
                    result["thinking"],
                    title="[bold]Thinking[/bold]",
                    border_style="dim"
                ))

            # Get proposal
            proposal = result.get("proposal", {})
            action = proposal.get("action", "")

            # Handle different actions
            if action == "report_breach":
                self._handle_breach_report(context, proposal)
                break

            elif action in ["http_request", "extract_data", "go_deeper"]:
                # Display proposal
                self._display_proposal(proposal)

                # Ask for permission
                choice = Prompt.ask(
                    "\n[bold]Execute this action?[/bold]",
                    choices=["y", "n", "skip", "deeper", "quit"],
                    default="y"
                )

                if choice == "quit":
                    console.print("[yellow]Session ended by user[/yellow]")
                    break

                elif choice == "skip":
                    console.print("[dim]Skipped. Asking for alternative...[/dim]")
                    continue

                elif choice == "deeper":
                    # Ask brain to go deeper on current area
                    technique = proposal.get("technique", "current area")
                    result = await self.brain.go_deeper(technique)
                    continue

                elif choice == "y":
                    # Execute the attack
                    await self._execute_attack(context, proposal)

            elif action == "need_input":
                # Brain needs more info
                user_input = Prompt.ask(proposal.get("description", "What should I focus on?"))
                result = await self.brain.think(user_input)

            else:
                console.print(f"[yellow]Unknown action: {action}[/yellow]")

        if rounds >= max_rounds:
            console.print("[yellow]Max rounds reached[/yellow]")

    def _display_proposal(self, proposal: dict):
        """Display an attack proposal."""
        # Title and description
        technique = proposal.get("technique", "unknown")
        description = proposal.get("description", "")
        confidence = proposal.get("confidence", "medium")

        confidence_color = {"high": "green", "medium": "yellow", "low": "red"}.get(confidence, "white")

        console.print(f"\n[bold]Technique:[/bold] {technique}")
        console.print(f"[bold]Confidence:[/bold] [{confidence_color}]{confidence}[/{confidence_color}]")
        console.print(f"\n{description}")

        # Technical details
        technical = proposal.get("technical", {})
        if technical:
            method = technical.get("method", "GET")
            url = technical.get("url", "")
            headers = technical.get("headers", {})
            body = technical.get("body")

            console.print(f"\n[cyan]{method} {url}[/cyan]")

            if headers:
                for k, v in headers.items():
                    v_display = v[:50] + "..." if len(str(v)) > 50 else v
                    console.print(f"[dim]  {k}: {v_display}[/dim]")

            if body:
                console.print(f"[dim]  Body: {str(body)[:100]}[/dim]")

        # Success indicator
        if proposal.get("success_looks_like"):
            console.print(f"\n[green]Success looks like:[/green] {proposal['success_looks_like']}")

        # Fallback plan
        if proposal.get("if_fails"):
            console.print(f"[yellow]If fails:[/yellow] {proposal['if_fails']}")

    async def _execute_attack(self, context: HackerContext, proposal: dict):
        """Execute an attack and analyze the result."""
        technical = proposal.get("technical", {})
        technique = proposal.get("technique", "unknown")

        method = technical.get("method", "GET")
        url = technical.get("url", "")
        headers = technical.get("headers", {})
        body = technical.get("body")

        if not url:
            console.print("[red]No URL specified[/red]")
            return

        # Execute
        console.print(f"\n[cyan][EXECUTING][/cyan] {method} {url}")

        try:
            if method == "GET":
                response = await self.http.get(url, headers=headers)
            elif method == "POST":
                if isinstance(body, dict):
                    response = await self.http.post(url, headers=headers, json_data=body)
                else:
                    response = await self.http.post(url, headers=headers, data=body)
            elif method == "PUT":
                response = await self.http.put(url, headers=headers, json_data=body)
            elif method == "DELETE":
                response = await self.http.delete(url, headers=headers)
            else:
                response = await self.http.request(method, url, headers=headers)

            status = response.status_code
            resp_body = response.body or ""
            resp_headers = response.headers

            console.print(f"[cyan][RESPONSE][/cyan] {status} ({len(resp_body)} bytes)")

            # Show snippet of response
            if resp_body:
                snippet = resp_body[:500]
                if len(resp_body) > 500:
                    snippet += "..."
                console.print(Panel(snippet, title="Response Preview", border_style="dim"))

            # Analyze with brain
            console.print(f"\n[magenta]Analyzing response...[/magenta]")

            analysis = await self.brain.analyze_response(
                technique=technique,
                request=technical,
                status=status,
                body=resp_body,
                headers=resp_headers
            )

            # Update context based on analysis
            if analysis.get("learned"):
                learned = analysis["learned"]

                if learned.get("vulnerability"):
                    severity = "critical" if "bypass" in learned["vulnerability"].lower() or "access" in learned["vulnerability"].lower() else "high"
                    context.add_finding(Finding(
                        type="vulnerability",
                        severity=severity,
                        title=learned["vulnerability"],
                        details=learned.get("data", ""),
                        evidence=resp_body[:1000],
                        exploitable=True
                    ))
                    console.print(f"[red][VULN][/red] {learned['vulnerability']}")

                if learned.get("data"):
                    console.print(f"[green][DATA][/green] {learned['data'][:200]}")

            # Check for breach indicators
            if status == 200 and len(resp_body) > 100:
                try:
                    data = json.loads(resp_body)
                    if isinstance(data, list) and len(data) > 0:
                        context.data_count = len(data)
                        context.has_data_access = True
                        console.print(f"[red][!] Data access confirmed: {len(data)} records[/red]")
                    elif isinstance(data, dict):
                        if any(k in data for k in ['email', 'users', 'password', 'token', 'secret']):
                            context.has_data_access = True
                            console.print(f"[red][!] Sensitive data in response[/red]")
                except:
                    pass

        except Exception as e:
            console.print(f"[red][ERROR][/red] {e}")

    def _handle_breach_report(self, context: HackerContext, proposal: dict):
        """Handle a breach report from the brain."""
        context.breach_proven = True

        evidence = proposal.get("evidence", {})

        console.print(f"\n[bold red]{'=' * 60}[/bold red]")
        console.print("[bold red]  BREACH CONFIRMED[/bold red]")
        console.print(f"[bold red]{'=' * 60}[/bold red]\n")

        console.print(f"[bold]Vulnerability:[/bold] {evidence.get('vulnerability', 'Unknown')}")
        console.print(f"[bold]Severity:[/bold] [red]{proposal.get('severity', 'critical').upper()}[/red]")
        console.print(f"[bold]Data Exposed:[/bold] {evidence.get('data_exposed', 'Unknown')}")

        if evidence.get("record_count"):
            console.print(f"[bold]Records:[/bold] {evidence['record_count']}")

        if evidence.get("attack_chain"):
            console.print(f"\n[bold]Attack Chain:[/bold]")
            for i, step in enumerate(evidence["attack_chain"], 1):
                console.print(f"  {i}. {step}")

        if evidence.get("sample_data"):
            console.print(f"\n[bold]Sample Data:[/bold]")
            console.print(json.dumps(evidence["sample_data"], indent=2)[:500])

    def _print_report(self, context: HackerContext):
        """Print final report."""
        console.print(f"\n[bold]{'=' * 60}[/bold]")
        console.print("[bold]  FINAL REPORT[/bold]")
        console.print(f"[bold]{'=' * 60}[/bold]\n")

        # Summary table
        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Target", context.target)
        table.add_row("Technologies", ", ".join(context.technologies) or "Unknown")
        table.add_row("Auth System", context.auth_system or "Unknown")
        table.add_row("Secrets Found", str(len(context.secrets)))
        table.add_row("Endpoints Discovered", str(len(context.endpoints)))
        table.add_row("Attack Attempts", str(len(context.attempts)))
        table.add_row("Findings", str(len(context.findings)))

        status = "[red]BREACHED[/red]" if context.breach_proven else "[green]NOT BREACHED[/green]"
        table.add_row("Status", status)

        if context.data_count > 0:
            table.add_row("Data Exposed", f"{context.data_count} records")

        console.print(table)

        # Findings
        if context.findings:
            console.print(f"\n[bold]Findings:[/bold]")
            for finding in context.findings:
                severity_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "dim"
                }.get(finding.severity, "white")

                console.print(f"  [{severity_color}][{finding.severity.upper()}][/{severity_color}] {finding.title}")

        # Summary
        summary = self.brain.get_attack_summary()
        success_rate = (summary["successful_attempts"] / summary["attempts_count"] * 100) if summary["attempts_count"] > 0 else 0
        console.print(f"\n[dim]Success rate: {success_rate:.1f}% ({summary['successful_attempts']}/{summary['attempts_count']} attempts)[/dim]")

    def _print_banner(self):
        """Print the banner."""
        banner = """
[bold red]
    ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
    ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
    ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
    ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                              [/bold red]
[bold white]    Interactive AI Hacking Agent[/bold white]
[dim]    Think. Attack. Prove. Never Give Up.[/dim]
"""
        console.print(banner)


async def main():
    # Check for API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red]ERROR: ANTHROPIC_API_KEY not set[/red]")
        console.print("Run: export ANTHROPIC_API_KEY=your-key")
        sys.exit(1)

    # Get target
    if len(sys.argv) < 2:
        console.print("[red]Usage: python breach_interactive.py <target_url>[/red]")
        console.print("Example: python breach_interactive.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith("http"):
        target = f"https://{target}"

    # Run
    breach = BreachAI()
    await breach.run(target)


if __name__ == "__main__":
    asyncio.run(main())
