"""
BREACH.AI - Integration Service Unit Tests
==========================================
Test integration services with retry logic and circuit breaker.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

import httpx

from backend.services.integrations import (
    ResilientHTTPClient,
    CircuitState,
    SlackIntegration,
    WebhookIntegration,
    NotificationEvent,
)


class TestResilientHTTPClient:
    """Test resilient HTTP client with retry logic."""

    @pytest.mark.asyncio
    async def test_successful_request(self):
        """Test that successful requests return normally."""
        client = ResilientHTTPClient(max_retries=3)

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.request = AsyncMock(
                return_value=mock_response
            )

            response = await client.request(
                "POST",
                "https://example.com/api",
                "test_service",
            )

            assert response is not None
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_retry_on_server_error(self):
        """Test that server errors trigger retries."""
        client = ResilientHTTPClient(max_retries=2, base_delay=0.01)

        call_count = 0

        async def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = MagicMock()
            if call_count < 3:
                mock_response.status_code = 500
            else:
                mock_response.status_code = 200
            return mock_response

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.request = mock_request

            response = await client.request(
                "POST",
                "https://example.com/api",
                "test_service",
            )

            assert response is not None
            assert response.status_code == 200
            assert call_count == 3  # Original + 2 retries

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens(self):
        """Test that circuit breaker opens after threshold failures."""
        client = ResilientHTTPClient(
            max_retries=0,  # No retries
            circuit_threshold=2,
            circuit_reset_timeout=60,
        )

        async def mock_request(*args, **kwargs):
            raise httpx.ConnectError("Connection failed")

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.request = mock_request

            # First failure
            await client.request("POST", "https://example.com", "fail_service")

            # Second failure - should open circuit
            await client.request("POST", "https://example.com", "fail_service")

            # Circuit should be open
            circuit = client._get_circuit("fail_service")
            assert circuit.state == "open"

            # Third request should be rejected immediately
            response = await client.request("POST", "https://example.com", "fail_service")
            assert response is None

    def test_calculate_delay_with_jitter(self):
        """Test exponential backoff calculation."""
        client = ResilientHTTPClient(base_delay=1.0, max_delay=30.0)

        delay_0 = client._calculate_delay(0)
        delay_1 = client._calculate_delay(1)
        delay_2 = client._calculate_delay(2)

        # Should be roughly exponential (with jitter)
        assert 0.5 < delay_0 < 1.5  # ~1s with jitter
        assert 1.0 < delay_1 < 3.0  # ~2s with jitter
        assert 2.0 < delay_2 < 6.0  # ~4s with jitter

    def test_delay_capped_at_max(self):
        """Test that delay is capped at max_delay."""
        client = ResilientHTTPClient(base_delay=1.0, max_delay=10.0)

        delay = client._calculate_delay(10)  # Would be 1024s without cap

        assert delay <= 12.5  # max_delay + 25% jitter


class TestSlackIntegration:
    """Test Slack integration."""

    @pytest.mark.asyncio
    async def test_send_message_success(self):
        """Test successful Slack message sending."""
        with patch("backend.services.integrations.get_http_client") as mock_get_client:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            slack = SlackIntegration(
                webhook_url="https://hooks.slack.com/test",
            )

            result = await slack._send_message([
                {"type": "section", "text": {"type": "mrkdwn", "text": "Test"}}
            ])

            assert result is True
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_failure(self):
        """Test Slack message sending failure."""
        with patch("backend.services.integrations.get_http_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=None)  # Simulates all retries failed
            mock_get_client.return_value = mock_client

            slack = SlackIntegration(
                webhook_url="https://hooks.slack.com/test",
            )

            result = await slack._send_message([
                {"type": "section", "text": {"type": "mrkdwn", "text": "Test"}}
            ])

            assert result is False


class TestWebhookIntegration:
    """Test generic webhook integration."""

    @pytest.mark.asyncio
    async def test_send_event(self):
        """Test sending webhook event."""
        with patch("backend.services.integrations.get_http_client") as mock_get_client:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            webhook = WebhookIntegration(
                url="https://example.com/webhook",
            )

            result = await webhook.send_event(
                NotificationEvent.SCAN_COMPLETED,
                {"scan_id": "123", "findings": 5},
            )

            assert result is True

    @pytest.mark.asyncio
    async def test_send_event_with_hmac_signature(self):
        """Test webhook with HMAC signature."""
        with patch("backend.services.integrations.get_http_client") as mock_get_client:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            webhook = WebhookIntegration(
                url="https://example.com/webhook",
                secret="mysecret123",
            )

            await webhook.send_event(
                NotificationEvent.CRITICAL_FINDING,
                {"finding_id": "456"},
            )

            # Verify signature header was included
            call_args = mock_client.post.call_args
            headers = call_args.kwargs.get("headers", {})
            assert "X-Breach-Signature" in headers
            assert headers["X-Breach-Signature"].startswith("sha256=")
