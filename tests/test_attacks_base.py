"""
BREACH Base Attack Module Tests
"""

import pytest
from unittest.mock import AsyncMock

from breach.attacks.base import AttackResult, BaseAttack, InjectionAttack
from breach.core.memory import AccessLevel, Evidence, Severity


class TestAttackResult:
    """Test AttackResult dataclass."""

    def test_attack_result_creation(self):
        """Test creating an attack result."""
        result = AttackResult(
            success=True,
            attack_type="sqli",
            target="https://example.com",
            endpoint="/api/users",
            parameter="id",
            payload="' OR '1'='1",
        )
        assert result.success is True
        assert result.attack_type == "sqli"
        assert result.parameter == "id"

    def test_attack_result_has_evidence_list(self):
        """Test attack result has evidence list."""
        result = AttackResult(
            success=True,
            attack_type="sqli",
            target="https://example.com",
        )
        assert isinstance(result.evidence, list)
        assert len(result.evidence) == 0

    def test_attack_result_with_evidence(self):
        """Test attack result with pre-populated evidence."""
        evidence = Evidence(type="response", data="<html>error</html>")
        result = AttackResult(
            success=True,
            attack_type="xss",
            target="https://example.com",
            evidence=[evidence],
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].type == "response"

    def test_attack_result_context(self):
        """Test attack result context dict."""
        result = AttackResult(
            success=True,
            attack_type="sqli",
            target="https://example.com",
            context={"db_type": "mysql", "columns": 5},
        )
        assert result.context["db_type"] == "mysql"
        assert result.context["columns"] == 5


class TestBaseAttackHelpers:
    """Test BaseAttack helper methods."""

    def test_detect_error_patterns(self, mock_http_client):
        """Test error pattern detection."""
        # Create a concrete implementation for testing
        class TestAttack(InjectionAttack):
            error_patterns = ["error", "warning", "exception"]

            def get_payloads(self):
                return ["test"]

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestAttack(mock_http_client)

        assert attack._detect_error_patterns("An error occurred", attack.error_patterns)
        assert attack._detect_error_patterns("Warning: something", attack.error_patterns)
        assert not attack._detect_error_patterns("Success!", attack.error_patterns)

    def test_extract_data_sample_json(self, mock_http_client):
        """Test extracting JSON data sample."""
        class TestAttack(InjectionAttack):
            error_patterns = []

            def get_payloads(self):
                return []

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestAttack(mock_http_client)

        response = '{"users": [{"id": 1, "name": "test"}]}'
        sample = attack._extract_data_sample(response)

        assert "{" in sample
        assert "users" in sample or "id" in sample

    def test_extract_data_sample_table(self, mock_http_client):
        """Test extracting table data sample."""
        class TestAttack(InjectionAttack):
            error_patterns = []

            def get_payloads(self):
                return []

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestAttack(mock_http_client)

        response = '<html><table><tr><td>User</td><td>Password</td></tr></table></html>'
        sample = attack._extract_data_sample(response)

        assert "<table" in sample.lower()


class TestInjectionAttack:
    """Test InjectionAttack base class."""

    @pytest.mark.asyncio
    async def test_check_requires_parameter(self, mock_http_client):
        """Test check returns false without parameter."""
        class TestInjection(InjectionAttack):
            error_patterns = ["error"]

            def get_payloads(self):
                return ["'"]

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestInjection(mock_http_client)
        result = await attack.check("https://example.com")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_detects_error_pattern(
        self, mock_http_client, mock_response_factory
    ):
        """Test check detects error patterns."""
        error_response = mock_response_factory(500, "SQL error in query")
        mock_http_client.get = AsyncMock(return_value=error_response)

        class TestInjection(InjectionAttack):
            error_patterns = ["sql error"]

            def get_payloads(self):
                return ["'", '"']

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestInjection(mock_http_client)
        result = await attack.check("https://example.com", parameter="id")

        assert result is True

    @pytest.mark.asyncio
    async def test_check_detects_response_size_change(
        self, mock_http_client, mock_response_factory
    ):
        """Test check detects significant response size changes."""
        small_response = mock_response_factory(200, "OK")
        large_response = mock_response_factory(200, "A" * 1000)

        mock_http_client.get = AsyncMock(
            side_effect=[small_response, large_response]
        )

        class TestInjection(InjectionAttack):
            error_patterns = []

            def get_payloads(self):
                return ["'"]

            async def exploit(self, url, parameter=None, method="GET", **kwargs):
                pass

        attack = TestInjection(mock_http_client)
        result = await attack.check("https://example.com", parameter="id")

        assert result is True
