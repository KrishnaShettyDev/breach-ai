"""
BREACH.AI - Scans API Integration Tests
========================================
Test scan CRUD endpoints.
"""

import pytest
from httpx import AsyncClient

from backend.db.models import User, Organization, Scan, ScanStatus


class TestScanEndpoints:
    """Test scan API endpoints."""

    @pytest.mark.asyncio
    async def test_create_scan(self, authenticated_client: AsyncClient):
        """Test creating a new scan."""
        response = await authenticated_client.post(
            "/api/v1/scans",
            json={
                "target_url": "https://example.com",
                "mode": "normal"
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert data["target_url"] == "https://example.com/"
        assert data["mode"] == "normal"
        assert data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_create_scan_ssrf_blocked(self, authenticated_client: AsyncClient):
        """Test that SSRF URLs are blocked."""
        response = await authenticated_client.post(
            "/api/v1/scans",
            json={
                "target_url": "http://127.0.0.1/admin",
                "mode": "normal"
            }
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_list_scans(self, authenticated_client: AsyncClient):
        """Test listing scans."""
        response = await authenticated_client.get("/api/v1/scans")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    @pytest.mark.asyncio
    async def test_list_scans_pagination(self, authenticated_client: AsyncClient):
        """Test scan listing pagination."""
        response = await authenticated_client.get(
            "/api/v1/scans",
            params={"page": 1, "per_page": 10}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["per_page"] == 10

    @pytest.mark.asyncio
    async def test_get_scan_not_found(self, authenticated_client: AsyncClient):
        """Test getting a non-existent scan."""
        response = await authenticated_client.get(
            "/api/v1/scans/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_stats(self, authenticated_client: AsyncClient):
        """Test getting scan statistics."""
        response = await authenticated_client.get("/api/v1/scans/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "scans_this_month" in data
        assert "total_findings" in data


class TestTargetEndpoints:
    """Test target API endpoints."""

    @pytest.mark.asyncio
    async def test_create_target(self, authenticated_client: AsyncClient):
        """Test creating a new target."""
        response = await authenticated_client.post(
            "/api/v1/targets",
            json={
                "url": "https://example.com",
                "name": "Example Target"
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Example Target"
        assert "verification_token" in data

    @pytest.mark.asyncio
    async def test_create_target_ssrf_blocked(self, authenticated_client: AsyncClient):
        """Test that SSRF URLs are blocked for targets."""
        response = await authenticated_client.post(
            "/api/v1/targets",
            json={
                "url": "http://localhost/admin",
                "name": "Local Target"
            }
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_list_targets(self, authenticated_client: AsyncClient):
        """Test listing targets."""
        response = await authenticated_client.get("/api/v1/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestHealthEndpoints:
    """Test health check endpoints."""

    @pytest.mark.asyncio
    async def test_health_basic(self, client: AsyncClient):
        """Test basic health endpoint."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_deep(self, client: AsyncClient):
        """Test deep health endpoint."""
        response = await client.get("/health/deep")
        # May be 200 or 503 depending on Redis availability
        assert response.status_code in [200, 503]
        data = response.json()
        assert "status" in data
        assert "checks" in data

    @pytest.mark.asyncio
    async def test_root_endpoint(self, client: AsyncClient):
        """Test root endpoint."""
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "BREACH.AI Enterprise"
        assert "version" in data
