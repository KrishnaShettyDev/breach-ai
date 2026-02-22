"""
BREACH Core Module Tests
"""

import pytest
from datetime import datetime

from breach.core.memory import (
    AccessLevel,
    Evidence,
    Finding,
    Endpoint,
    AttackSurface,
    Severity,
)


class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum has expected values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_ordering(self):
        """Test severity can be compared as strings."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        sorted_severities = sorted(severities, key=lambda s: s.value)
        assert Severity.CRITICAL in sorted_severities


class TestAccessLevel:
    """Test AccessLevel enum."""

    def test_access_level_values(self):
        """Test access level enum values."""
        assert AccessLevel.NONE.value == "none"
        assert AccessLevel.READ.value == "read"
        assert AccessLevel.WRITE.value == "write"
        assert AccessLevel.ADMIN.value == "admin"
        assert AccessLevel.SYSTEM.value == "system"


class TestEvidence:
    """Test Evidence dataclass."""

    def test_evidence_creation(self):
        """Test creating evidence."""
        evidence = Evidence(
            type="curl_command",
            data="curl 'https://example.com?id=1' -H 'X-Payload: test'",
        )
        assert evidence.type == "curl_command"
        assert "curl" in evidence.data
        assert isinstance(evidence.timestamp, datetime)

    def test_evidence_with_metadata(self):
        """Test evidence with metadata."""
        evidence = Evidence(
            type="screenshot",
            data="base64_image_data",
            metadata={"format": "png", "width": 1920, "height": 1080},
        )
        assert evidence.metadata["format"] == "png"


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            id="BREACH-001",
            type="sqli",
            severity=Severity.CRITICAL,
            endpoint="https://example.com/api/users",
            parameter="id",
            payload="' OR '1'='1",
            description="SQL Injection vulnerability",
        )
        assert finding.id == "BREACH-001"
        assert finding.type == "sqli"
        assert finding.severity == Severity.CRITICAL
        assert finding.validated is False

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            id="BREACH-002",
            type="xss",
            severity=Severity.HIGH,
            endpoint="https://example.com/search",
            parameter="q",
            validated=True,
        )
        data = finding.to_dict()
        assert data["id"] == "BREACH-002"
        assert data["type"] == "xss"
        assert data["severity"] == "HIGH"
        assert data["validated"] is True

    def test_finding_with_evidence(self):
        """Test finding with evidence attached."""
        evidence = Evidence(type="response", data="<html>error in SQL</html>")
        finding = Finding(
            id="BREACH-003",
            type="sqli",
            severity=Severity.CRITICAL,
            endpoint="https://example.com/api",
            evidence=[evidence],
        )
        assert len(finding.evidence) == 1
        assert finding.evidence[0].type == "response"


class TestEndpoint:
    """Test Endpoint dataclass."""

    def test_endpoint_creation(self):
        """Test creating an endpoint."""
        endpoint = Endpoint(
            url="https://example.com/api/users",
            method="GET",
            parameters=["id", "name"],
        )
        assert endpoint.url == "https://example.com/api/users"
        assert endpoint.method == "GET"
        assert "id" in endpoint.parameters

    def test_endpoint_equality(self):
        """Test endpoint equality comparison."""
        ep1 = Endpoint(url="https://example.com/api", method="GET")
        ep2 = Endpoint(url="https://example.com/api", method="GET")
        ep3 = Endpoint(url="https://example.com/api", method="POST")

        assert ep1 == ep2
        assert ep1 != ep3

    def test_endpoint_hash(self):
        """Test endpoint can be used in sets."""
        ep1 = Endpoint(url="https://example.com/api", method="GET")
        ep2 = Endpoint(url="https://example.com/api", method="GET")
        ep3 = Endpoint(url="https://example.com/other", method="GET")

        endpoints = {ep1, ep2, ep3}
        assert len(endpoints) == 2


class TestAttackSurface:
    """Test AttackSurface dataclass."""

    def test_attack_surface_creation(self):
        """Test creating attack surface."""
        surface = AttackSurface(
            target="https://example.com",
            endpoints=[
                Endpoint(url="https://example.com/api", method="GET"),
                Endpoint(url="https://example.com/login", method="POST"),
            ],
            parameters={"id", "username", "password"},
        )
        assert surface.target == "https://example.com"
        assert len(surface.endpoints) == 2
        assert "username" in surface.parameters
