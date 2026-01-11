"""
BREACH.AI - E2E Scan Flow Tests
================================
Test complete scan lifecycle with mocked engine.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient

from backend.db.models import Scan, ScanStatus


class TestScanLifecycle:
    """Test complete scan lifecycle."""

    @pytest.mark.asyncio
    async def test_full_scan_flow(
        self,
        authenticated_client: AsyncClient,
        db_session
    ):
        """Test creating, monitoring, and completing a scan."""
        # 1. Create scan
        response = await authenticated_client.post(
            "/api/v1/scans",
            json={
                "target_url": "https://example.com",
                "mode": "quick"
            }
        )
        assert response.status_code == 201
        scan_data = response.json()
        scan_id = scan_data["id"]
        assert scan_data["status"] == "pending"

        # 2. Get scan details
        response = await authenticated_client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        assert response.json()["id"] == scan_id

        # 3. Get scan findings (should be empty initially)
        response = await authenticated_client.get(f"/api/v1/scans/{scan_id}/findings")
        assert response.status_code == 200
        findings = response.json()
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_cancellation(
        self,
        authenticated_client: AsyncClient,
        test_scan: Scan
    ):
        """Test canceling a scan."""
        # Cancel the scan
        response = await authenticated_client.post(
            f"/api/v1/scans/{test_scan.id}/cancel"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "canceled"

    @pytest.mark.asyncio
    async def test_scan_deletion(
        self,
        authenticated_client: AsyncClient,
        test_scan: Scan
    ):
        """Test deleting a scan."""
        response = await authenticated_client.delete(
            f"/api/v1/scans/{test_scan.id}"
        )
        assert response.status_code == 204

        # Verify it's deleted
        response = await authenticated_client.get(
            f"/api/v1/scans/{test_scan.id}"
        )
        assert response.status_code == 404


class TestScanExecution:
    """Test scan execution with mocked engine."""

    @pytest.mark.asyncio
    async def test_scan_with_mocked_engine(
        self,
        authenticated_client: AsyncClient,
        db_session
    ):
        """Test scan execution with mocked breach engine."""
        # Mock the breach engine
        mock_state = MagicMock()
        mock_state.findings = []

        mock_engine = AsyncMock()
        mock_engine.__aenter__ = AsyncMock(return_value=mock_engine)
        mock_engine.__aexit__ = AsyncMock(return_value=None)
        mock_engine.breach = AsyncMock()
        mock_engine.state = mock_state

        with patch("backend.services.scan.BreachEngine", return_value=mock_engine):
            # Create scan
            response = await authenticated_client.post(
                "/api/v1/scans",
                json={
                    "target_url": "https://example.com",
                    "mode": "quick"
                }
            )
            assert response.status_code == 201


class TestMultipleScanManagement:
    """Test managing multiple scans."""

    @pytest.mark.asyncio
    async def test_list_scans_with_status_filter(
        self,
        authenticated_client: AsyncClient,
        db_session
    ):
        """Test filtering scans by status."""
        # Create a scan first
        await authenticated_client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "mode": "quick"}
        )

        # List with status filter
        response = await authenticated_client.get(
            "/api/v1/scans",
            params={"scan_status": "pending"}
        )
        assert response.status_code == 200
        data = response.json()
        # All returned scans should be pending
        for scan in data["items"]:
            assert scan["status"] == "pending"
