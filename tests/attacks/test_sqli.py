"""
BREACH SQL Injection Attack Module Tests
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from breach.attacks.sqli import SQLInjectionAttack
from breach.core.memory import Severity


class TestSQLInjectionAttackMetadata:
    """Test SQLi attack module metadata."""

    def test_attack_metadata(self, mock_http_client):
        """Test attack module has correct metadata."""
        attack = SQLInjectionAttack(mock_http_client)

        assert attack.name == "SQL Injection"
        assert attack.attack_type == "sqli"
        assert attack.severity == Severity.CRITICAL
        assert attack.owasp_category == "A03:2021 Injection"
        assert attack.cwe_id == 89

    def test_error_patterns_exist(self, mock_http_client):
        """Test error patterns are defined."""
        attack = SQLInjectionAttack(mock_http_client)

        assert len(attack.error_patterns) > 0
        assert "sql syntax" in [p.lower() for p in attack.error_patterns]

    def test_payloads_exist(self, mock_http_client):
        """Test payloads are defined."""
        attack = SQLInjectionAttack(mock_http_client)

        payloads = attack.get_payloads()
        assert len(payloads) > 0
        assert "'" in payloads  # Basic quote payload
        assert any("UNION" in p for p in payloads)  # Union payloads
        assert any("SLEEP" in p for p in payloads)  # Time-based payloads


class TestSQLInjectionCheck:
    """Test SQLi vulnerability check."""

    @pytest.mark.asyncio
    async def test_check_returns_false_without_parameter(self, mock_http_client):
        """Test check returns false when no parameter provided."""
        attack = SQLInjectionAttack(mock_http_client)

        result = await attack.check("https://example.com/api/users")
        assert result is False

    @pytest.mark.asyncio
    async def test_check_detects_sql_error(
        self, mock_http_client, sqli_error_response
    ):
        """Test check detects SQL error in response."""
        mock_http_client.get = AsyncMock(return_value=sqli_error_response)

        attack = SQLInjectionAttack(mock_http_client)
        result = await attack.check(
            "https://example.com/api/users",
            parameter="id",
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_check_returns_false_for_normal_response(
        self, mock_http_client, normal_response
    ):
        """Test check returns false for normal response."""
        mock_http_client.get = AsyncMock(return_value=normal_response)

        attack = SQLInjectionAttack(mock_http_client)
        result = await attack.check(
            "https://example.com/api/users",
            parameter="id",
        )
        assert result is False


class TestSQLInjectionExploit:
    """Test SQLi exploitation."""

    @pytest.mark.asyncio
    async def test_exploit_returns_failure_without_parameter(self, mock_http_client):
        """Test exploit returns failure when no parameter provided."""
        attack = SQLInjectionAttack(mock_http_client)

        result = await attack.exploit("https://example.com/api/users")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_exploit_success_with_error_based(
        self, mock_http_client, sqli_error_response, mock_response_factory
    ):
        """Test successful error-based SQL injection."""
        # First calls return error (vulnerability confirmed)
        # Later calls return success with data
        responses = [
            sqli_error_response,  # Finding working payload
            sqli_error_response,  # Detect DB type
            mock_response_factory(200, "MySQL 8.0.32"),  # Version extraction
        ]
        mock_http_client.get = AsyncMock(side_effect=responses + [sqli_error_response] * 50)

        attack = SQLInjectionAttack(mock_http_client)
        result = await attack.exploit(
            "https://example.com/api/users",
            parameter="id",
        )
        assert result.success is True
        assert result.attack_type == "sqli"
        assert "SQL Injection" in result.details

    @pytest.mark.asyncio
    async def test_exploit_detects_mysql(
        self, mock_http_client, mock_response_factory
    ):
        """Test MySQL detection."""
        mysql_error = mock_response_factory(
            500,
            "Warning: mysql_query(): You have an error in your SQL syntax"
        )
        mock_http_client.get = AsyncMock(return_value=mysql_error)

        attack = SQLInjectionAttack(mock_http_client)
        result = await attack.exploit(
            "https://example.com/api/users",
            parameter="id",
        )

        if result.success:
            assert result.context.get("db_type") == "mysql"


class TestSQLInjectionPayloads:
    """Test SQLi payload generation."""

    def test_error_payloads_are_safe(self, mock_http_client):
        """Test error payloads don't contain destructive commands."""
        attack = SQLInjectionAttack(mock_http_client)

        dangerous_keywords = ["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT"]

        for payload in attack.ERROR_PAYLOADS:
            for keyword in dangerous_keywords:
                assert keyword not in payload.upper(), (
                    f"Dangerous keyword '{keyword}' found in payload: {payload}"
                )

    def test_time_payloads_use_safe_delays(self, mock_http_client):
        """Test time-based payloads use reasonable delays."""
        attack = SQLInjectionAttack(mock_http_client)

        for payload in attack.TIME_PAYLOADS:
            # Check delays are not too long (max 10 seconds)
            if "SLEEP" in payload.upper():
                assert "SLEEP(10)" not in payload.upper()
            if "DELAY" in payload.upper():
                assert "0:0:10" not in payload


class TestSQLInjectionDetection:
    """Test SQL error pattern detection."""

    def test_detect_mysql_errors(self, mock_http_client):
        """Test MySQL error detection."""
        attack = SQLInjectionAttack(mock_http_client)

        mysql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            "mysql_num_rows() expects parameter",
        ]

        for error in mysql_errors:
            assert attack._detect_error_patterns(error, attack.error_patterns)

    def test_detect_postgresql_errors(self, mock_http_client):
        """Test PostgreSQL error detection."""
        attack = SQLInjectionAttack(mock_http_client)

        pg_errors = [
            "ERROR: unterminated quoted string",
            "pg_query(): Query failed",
        ]

        for error in pg_errors:
            assert attack._detect_error_patterns(error, attack.error_patterns)

    def test_no_false_positives_on_normal_content(self, mock_http_client):
        """Test no false positives on normal content."""
        attack = SQLInjectionAttack(mock_http_client)

        normal_content = [
            "<html><body>Welcome to our website</body></html>",
            "User profile: John Doe",
            "Search results: 0 items found",
        ]

        for content in normal_content:
            assert not attack._detect_error_patterns(content, attack.error_patterns)
