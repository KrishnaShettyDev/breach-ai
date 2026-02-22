"""
BREACH Test Configuration and Fixtures
"""

import asyncio
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest


@dataclass
class MockHTTPResponse:
    """Mock HTTP response for testing."""

    status_code: int = 200
    body: str = ""
    headers: dict = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {"content-type": "text/html"}

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    client = MagicMock()
    client.get = AsyncMock(return_value=MockHTTPResponse())
    client.post = AsyncMock(return_value=MockHTTPResponse())
    client.request = AsyncMock(return_value=MockHTTPResponse())
    return client


@pytest.fixture
def mock_response_factory():
    """Factory for creating mock responses."""

    def create_response(
        status_code: int = 200,
        body: str = "",
        headers: Optional[dict] = None,
    ) -> MockHTTPResponse:
        return MockHTTPResponse(
            status_code=status_code,
            body=body,
            headers=headers or {"content-type": "text/html"},
        )

    return create_response


@pytest.fixture
def sqli_error_response(mock_response_factory):
    """Response indicating SQL injection vulnerability."""
    return mock_response_factory(
        status_code=500,
        body="You have an error in your SQL syntax near '\\'' at line 1",
    )


@pytest.fixture
def normal_response(mock_response_factory):
    """Normal successful response."""
    return mock_response_factory(
        status_code=200,
        body="<html><body>Welcome to the site</body></html>",
    )


@pytest.fixture
def xss_reflected_response(mock_response_factory):
    """Response with reflected XSS."""
    return mock_response_factory(
        status_code=200,
        body='<html><body>Search results for: <script>alert(1)</script></body></html>',
    )


@pytest.fixture
def sample_target():
    """Sample target URL for testing."""
    return "https://example.com"


@pytest.fixture
def sample_endpoints():
    """Sample discovered endpoints."""
    from breach.core.memory import Endpoint

    return [
        Endpoint(url="https://example.com/api/users", method="GET", parameters=["id"]),
        Endpoint(
            url="https://example.com/api/search", method="GET", parameters=["q", "page"]
        ),
        Endpoint(
            url="https://example.com/api/login",
            method="POST",
            parameters=["username", "password"],
        ),
    ]


@pytest.fixture
def sample_finding():
    """Sample vulnerability finding."""
    from breach.core.memory import AccessLevel, Finding, Severity

    return Finding(
        id="BREACH-001",
        type="sqli",
        severity=Severity.CRITICAL,
        endpoint="https://example.com/api/users?id=1",
        parameter="id",
        payload="' OR '1'='1",
        description="SQL Injection in user lookup endpoint",
        access_level=AccessLevel.READ,
        validated=True,
    )
