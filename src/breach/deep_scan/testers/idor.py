"""
BREACH.AI - IDOR Tester
========================
Tests for Insecure Direct Object Reference vulnerabilities.
"""

import asyncio
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
import aiohttp

from ..payloads import IDOR_PARAMS
from ..spider import DiscoveredEndpoint, SpiderResult
from .injections import Finding


class IDORTester:
    """
    Tests for IDOR vulnerabilities.

    Tests:
    - Direct object references (changing IDs)
    - Cross-user data access
    - Sequential ID enumeration
    - UUID guessing from extracted IDs
    """

    # Patterns that indicate sensitive data
    PII_PATTERNS = [
        (r'"email"\s*:\s*"[^"]+"', 'email'),
        (r'"phone"\s*:\s*"[^"]+"', 'phone'),
        (r'"password"\s*:\s*"[^"]+"', 'password'),
        (r'"ssn"\s*:\s*"[^"]+"', 'ssn'),
        (r'"credit_card"\s*:\s*"[^"]+"', 'credit_card'),
        (r'"address"\s*:\s*"[^"]+"', 'address'),
        (r'"dob"\s*:\s*"[^"]+"', 'date_of_birth'),
        (r'"name"\s*:\s*"[^"]+"', 'name'),
    ]

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        timeout: int = 10,
        concurrent: int = 15,
    ):
        self.session = session
        self.base_url = base_url
        self.timeout = timeout
        self.concurrent = concurrent
        self._semaphore = asyncio.Semaphore(concurrent)
        self.findings: List[Finding] = []

    async def test_all(
        self,
        endpoints: List[DiscoveredEndpoint],
        spider_result: SpiderResult,
        cookies: Dict = None,
        cookies2: Dict = None,  # Second user for cross-user testing
    ) -> List[Finding]:
        """Run all IDOR tests."""
        print(f"\n[IDOR] Testing for Insecure Direct Object References...")

        extracted_ids = spider_result.extracted_ids

        # Phase 1: Test endpoints with ID parameters
        print(f"[IDOR] Testing endpoints with ID parameters using {len(extracted_ids)} extracted IDs...")
        await self._test_id_parameters(endpoints, extracted_ids, cookies)

        # Phase 2: Test sequential ID enumeration
        print(f"[IDOR] Testing sequential ID enumeration...")
        await self._test_sequential_ids(endpoints, cookies)

        # Phase 3: Cross-user IDOR (if second user cookies provided)
        if cookies and cookies2:
            print(f"[IDOR] Testing cross-user data access...")
            await self._test_cross_user(endpoints, cookies, cookies2)

        print(f"\n[IDOR] Found {len(self.findings)} IDOR vulnerabilities")
        return self.findings

    async def _test_id_parameters(
        self,
        endpoints: List[DiscoveredEndpoint],
        extracted_ids: Set[str],
        cookies: Dict = None,
    ):
        """Test endpoints that have ID-like parameters."""

        # Find endpoints with ID parameters
        for ep in endpoints:
            # Check URL for ID patterns
            url_has_id = any(p in ep.url.lower() for p in ['/{id}', '/id/', 'userid', 'accountid', 'orderid'])

            # Check parameters for ID-like names
            id_params = [p for p in (ep.params + ep.body_params) if any(kw in p.lower() for kw in IDOR_PARAMS)]

            if url_has_id or id_params:
                await self._test_endpoint_with_ids(ep, extracted_ids, id_params, cookies)

    async def _test_endpoint_with_ids(
        self,
        endpoint: DiscoveredEndpoint,
        extracted_ids: Set[str],
        id_params: List[str],
        cookies: Dict = None,
    ):
        """Test a specific endpoint with different IDs."""

        # Test with extracted IDs
        test_ids = list(extracted_ids)[:20]

        # Also add some common test IDs
        test_ids.extend(['1', '2', '100', 'admin', 'test'])

        for test_id in test_ids:
            for param in id_params[:3]:  # Limit params
                try:
                    # Build test URL
                    if endpoint.method.upper() == "GET":
                        sep = "&" if "?" in endpoint.url else "?"
                        test_url = f"{endpoint.url}{sep}{param}={test_id}"
                    else:
                        test_url = endpoint.url

                    async with self._semaphore:
                        if endpoint.method.upper() == "GET":
                            async with self.session.get(
                                test_url,
                                cookies=cookies,
                                ssl=False,
                                timeout=self.timeout
                            ) as response:
                                if response.status == 200:
                                    body = await response.text()
                                    await self._check_idor_response(
                                        endpoint.url, param, test_id, body, cookies
                                    )
                        else:
                            async with self.session.post(
                                test_url,
                                data={param: test_id},
                                cookies=cookies,
                                ssl=False,
                                timeout=self.timeout
                            ) as response:
                                if response.status == 200:
                                    body = await response.text()
                                    await self._check_idor_response(
                                        endpoint.url, param, test_id, body, cookies
                                    )

                except:
                    pass

    async def _check_idor_response(
        self,
        url: str,
        param: str,
        test_id: str,
        body: str,
        cookies: Dict = None,
    ):
        """Check if response indicates IDOR vulnerability."""

        # Skip if response is too small or is an error
        if len(body) < 50:
            return

        body_lower = body.lower()
        if any(x in body_lower for x in ['not found', 'error', 'invalid', 'unauthorized', '404']):
            return

        # Check for sensitive data exposure
        pii_found = self._detect_pii(body)
        data_sample = self._extract_data_sample(body)

        if pii_found or (len(body) > 200 and self._looks_like_user_data(body)):
            finding = Finding(
                severity="CRITICAL" if pii_found else "HIGH",
                category="idor",
                title=f"IDOR - Access to Other User's Data via {param}",
                description=f"Can access data belonging to other users by manipulating {param}.",
                endpoint=url,
                method="GET",
                parameter=param,
                payload=test_id,
                raw_response=body[:2000],
                evidence=f"Accessed data for ID: {test_id}",
                data_exposed={
                    "id_accessed": test_id,
                    "pii_fields": pii_found,
                    "sample_data": data_sample,
                },
                business_impact=100000 if pii_found else 50000,
                impact_explanation="Can access any user's data by iterating through IDs. Mass data breach possible.",
                curl_command=f"curl '{url}?{param}={test_id}'",
                steps=[
                    f"1. Identify {param} parameter in request",
                    f"2. Change {param} to different values (e.g., {test_id})",
                    "3. Observe access to other users' data",
                    "4. Enumerate all users to extract complete database",
                ],
                remediation="Always verify the requesting user owns the resource. Use UUIDs instead of sequential IDs. Implement proper authorization checks.",
                cwe_id="CWE-639",
                owasp="A01:2021 – Broken Access Control",
            )
            self.findings.append(finding)

    async def _test_sequential_ids(
        self,
        endpoints: List[DiscoveredEndpoint],
        cookies: Dict = None,
    ):
        """Test for sequential ID enumeration."""

        # Find endpoints that might have numeric IDs in URL path
        url_patterns = [
            r'/users/(\d+)',
            r'/accounts/(\d+)',
            r'/orders/(\d+)',
            r'/documents/(\d+)',
            r'/files/(\d+)',
            r'/api/[^/]+/(\d+)',
        ]

        for ep in endpoints:
            for pattern in url_patterns:
                match = re.search(pattern, ep.url)
                if match:
                    original_id = match.group(1)
                    original_id_int = int(original_id)

                    # Try adjacent IDs
                    test_ids = [
                        str(original_id_int - 1),
                        str(original_id_int + 1),
                        str(original_id_int - 10),
                        str(original_id_int + 10),
                        '1',  # Often admin/first user
                    ]

                    for test_id in test_ids:
                        if test_id == original_id:
                            continue

                        # Replace ID in URL
                        test_url = re.sub(pattern, ep.url[match.start():match.end()].replace(original_id, test_id), ep.url)

                        try:
                            async with self._semaphore:
                                async with self.session.get(
                                    test_url,
                                    cookies=cookies,
                                    ssl=False,
                                    timeout=self.timeout
                                ) as response:
                                    if response.status == 200:
                                        body = await response.text()

                                        if len(body) > 100 and 'not found' not in body.lower():
                                            pii_found = self._detect_pii(body)

                                            if pii_found or self._looks_like_user_data(body):
                                                finding = Finding(
                                                    severity="CRITICAL",
                                                    category="idor",
                                                    title=f"Sequential ID Enumeration",
                                                    description=f"Can enumerate resources by changing sequential ID from {original_id} to {test_id}.",
                                                    endpoint=ep.url,
                                                    method="GET",
                                                    parameter="url_path",
                                                    payload=f"{original_id} -> {test_id}",
                                                    raw_response=body[:2000],
                                                    evidence=f"Accessed different user's data by changing ID to {test_id}",
                                                    data_exposed={
                                                        "original_id": original_id,
                                                        "accessed_id": test_id,
                                                        "pii_fields": pii_found,
                                                    },
                                                    business_impact=120000,
                                                    impact_explanation="Sequential IDs allow enumeration of all users. Can dump entire database.",
                                                    curl_command=f"curl '{test_url}'",
                                                    steps=[
                                                        f"1. Original URL: {ep.url}",
                                                        f"2. Change ID from {original_id} to {test_id}",
                                                        f"3. Access different user's data",
                                                        "4. Script to enumerate all IDs 1 to N",
                                                    ],
                                                    remediation="Use UUIDs instead of sequential IDs. Always verify resource ownership.",
                                                    cwe_id="CWE-639",
                                                    owasp="A01:2021 – Broken Access Control",
                                                )
                                                self.findings.append(finding)
                                                return  # Found one, enough for this endpoint

                        except:
                            pass

    async def _test_cross_user(
        self,
        endpoints: List[DiscoveredEndpoint],
        cookies1: Dict,
        cookies2: Dict,
    ):
        """Test cross-user data access with two different sessions."""

        # Get user 1's data first
        user1_ids = set()

        for ep in endpoints[:20]:  # Limit
            if ep.is_api and not ep.requires_auth:
                continue

            try:
                async with self._semaphore:
                    async with self.session.get(
                        ep.url,
                        cookies=cookies1,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()
                            # Extract IDs from response
                            uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', body, re.I)
                            user1_ids.update(uuids[:10])

            except:
                pass

        if not user1_ids:
            return

        print(f"[IDOR] Found {len(user1_ids)} IDs from user 1, testing with user 2...")

        # Now try to access user 1's resources with user 2's session
        for ep in endpoints:
            if '/api/' not in ep.url:
                continue

            for uid in list(user1_ids)[:10]:
                # Try to access resource
                test_urls = [
                    f"{ep.url}/{uid}",
                    f"{ep.url}?id={uid}",
                    f"{ep.url}?user_id={uid}",
                ]

                for test_url in test_urls:
                    try:
                        async with self._semaphore:
                            async with self.session.get(
                                test_url,
                                cookies=cookies2,  # User 2's session
                                ssl=False,
                                timeout=self.timeout
                            ) as response:
                                if response.status == 200:
                                    body = await response.text()

                                    if len(body) > 100 and uid in body:
                                        pii_found = self._detect_pii(body)

                                        finding = Finding(
                                            severity="CRITICAL",
                                            category="idor",
                                            title="Cross-User Data Access",
                                            description=f"User 2 can access User 1's data. Horizontal privilege escalation.",
                                            endpoint=test_url,
                                            method="GET",
                                            parameter="id",
                                            payload=uid,
                                            raw_response=body[:2000],
                                            evidence=f"User 2 accessed User 1's resource with ID: {uid}",
                                            data_exposed={
                                                "accessed_id": uid,
                                                "pii_fields": pii_found,
                                            },
                                            business_impact=150000,
                                            impact_explanation="Any authenticated user can access any other user's data. Complete data breach.",
                                            curl_command=f"curl -b 'user2_session=...' '{test_url}'",
                                            steps=[
                                                "1. Login as User 1, extract resource IDs",
                                                "2. Login as User 2 (different account)",
                                                f"3. Access User 1's resource: {test_url}",
                                                "4. User 2 sees User 1's data",
                                            ],
                                            remediation="Check resource.user_id === currentUser.id on every request. Use row-level security.",
                                            cwe_id="CWE-639",
                                            owasp="A01:2021 – Broken Access Control",
                                        )
                                        self.findings.append(finding)
                                        return

                    except:
                        pass

    def _detect_pii(self, body: str) -> List[str]:
        """Detect PII in response."""
        found = []

        for pattern, field_name in self.PII_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(field_name)

        return found

    def _extract_data_sample(self, body: str) -> Dict:
        """Extract a sample of data from response."""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                # Return first few keys
                return {k: str(v)[:50] for k, v in list(data.items())[:5]}
            elif isinstance(data, list) and data:
                return {"count": len(data), "sample": str(data[0])[:200]}
        except:
            pass

        return {"raw_sample": body[:200]}

    def _looks_like_user_data(self, body: str) -> bool:
        """Check if response looks like user data."""
        indicators = ['email', 'name', 'user', 'account', 'profile', 'address',
                      'phone', 'order', 'payment', 'subscription']

        body_lower = body.lower()
        matches = sum(1 for ind in indicators if ind in body_lower)

        return matches >= 2
