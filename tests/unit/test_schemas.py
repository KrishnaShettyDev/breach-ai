"""
BREACH.AI - Schema Unit Tests
==============================
Test input validation, SSRF protection, and pagination.
"""

import pytest
from pydantic import ValidationError

from backend.schemas.scans import (
    ScanCreate, TargetCreate, ScanMode,
    validate_target_url, is_private_ip,
    PaginationParams, ScanFilterParams
)


class TestSSRFProtection:
    """Test SSRF protection validators."""

    def test_valid_https_url(self):
        """Valid HTTPS URL should pass."""
        url = "https://example.com"
        result = validate_target_url(url)
        assert result == url

    def test_valid_http_url(self):
        """Valid HTTP URL should pass."""
        url = "http://example.com"
        result = validate_target_url(url)
        assert result == url

    def test_blocked_localhost(self):
        """Localhost should be blocked."""
        with pytest.raises(ValueError, match="internal hosts"):
            validate_target_url("http://localhost/test")

    def test_blocked_127_0_0_1(self):
        """127.0.0.1 should be blocked."""
        with pytest.raises(ValueError, match="internal hosts"):
            validate_target_url("http://127.0.0.1/test")

    def test_blocked_aws_metadata(self):
        """AWS metadata endpoint should be blocked."""
        with pytest.raises(ValueError, match="internal hosts"):
            validate_target_url("http://169.254.169.254/latest/meta-data/")

    def test_blocked_private_ip_10(self):
        """10.x.x.x should be blocked."""
        with pytest.raises(ValueError, match="private IP"):
            validate_target_url("http://10.0.0.1/api")

    def test_blocked_private_ip_172(self):
        """172.16.x.x should be blocked."""
        with pytest.raises(ValueError, match="private IP"):
            validate_target_url("http://172.16.0.1/api")

    def test_blocked_private_ip_192(self):
        """192.168.x.x should be blocked."""
        with pytest.raises(ValueError, match="private IP"):
            validate_target_url("http://192.168.1.1/api")

    def test_invalid_protocol(self):
        """Non-HTTP protocols should be blocked."""
        with pytest.raises(ValueError, match="HTTP and HTTPS"):
            validate_target_url("ftp://example.com/file")

    def test_invalid_url_format(self):
        """Invalid URL format should fail."""
        with pytest.raises(ValueError, match="Invalid URL"):
            validate_target_url("not-a-url")

    def test_is_private_ip_loopback(self):
        """Test private IP detection for loopback."""
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.0.0.2") is True

    def test_is_private_ip_10_range(self):
        """Test private IP detection for 10.x range."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_is_private_ip_public(self):
        """Test public IP detection."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False


class TestScanCreate:
    """Test ScanCreate schema validation."""

    def test_valid_scan_create(self):
        """Valid scan creation should work."""
        scan = ScanCreate(
            target_url="https://example.com",
            mode=ScanMode.NORMAL
        )
        assert str(scan.target_url) == "https://example.com/"

    def test_scan_create_ssrf_blocked(self):
        """SSRF URLs should be blocked in ScanCreate."""
        with pytest.raises(ValidationError):
            ScanCreate(
                target_url="http://127.0.0.1/admin",
                mode=ScanMode.NORMAL
            )

    def test_scan_create_modes(self):
        """All scan modes should be valid."""
        for mode in ScanMode:
            scan = ScanCreate(
                target_url="https://example.com",
                mode=mode
            )
            assert scan.mode == mode


class TestTargetCreate:
    """Test TargetCreate schema validation."""

    def test_valid_target_create(self):
        """Valid target creation should work."""
        target = TargetCreate(
            url="https://example.com",
            name="Example Site"
        )
        assert target.name == "Example Site"

    def test_target_create_ssrf_blocked(self):
        """SSRF URLs should be blocked in TargetCreate."""
        with pytest.raises(ValidationError):
            TargetCreate(
                url="http://localhost/admin",
                name="Local Admin"
            )

    def test_target_name_min_length(self):
        """Name should have minimum length."""
        with pytest.raises(ValidationError):
            TargetCreate(
                url="https://example.com",
                name="A"  # Too short
            )


class TestPaginationParams:
    """Test pagination parameter validation."""

    def test_default_pagination(self):
        """Default pagination values should be set."""
        params = PaginationParams()
        assert params.page == 1
        assert params.per_page == 20

    def test_page_min_limit(self):
        """Page number should have minimum of 1."""
        with pytest.raises(ValidationError):
            PaginationParams(page=0)

    def test_page_max_limit(self):
        """Page number should have maximum limit."""
        with pytest.raises(ValidationError):
            PaginationParams(page=1001)

    def test_per_page_max_limit(self):
        """Per page should have maximum limit."""
        with pytest.raises(ValidationError):
            PaginationParams(per_page=101)


class TestScanFilterParams:
    """Test scan filter parameter validation."""

    def test_valid_status_filter(self):
        """Valid status should work."""
        from backend.schemas.scans import ScanStatus
        params = ScanFilterParams(status=ScanStatus.COMPLETED)
        assert params.status == ScanStatus.COMPLETED

    def test_valid_mode_filter(self):
        """Valid mode should work."""
        params = ScanFilterParams(mode=ScanMode.DEEP)
        assert params.mode == ScanMode.DEEP

    def test_optional_filters(self):
        """Filters should be optional."""
        params = ScanFilterParams()
        assert params.status is None
        assert params.mode is None
