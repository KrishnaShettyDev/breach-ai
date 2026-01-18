"""
BREACH.AI - Test Configuration
===============================
Pytest fixtures and configuration for all test types.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment before importing app
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["CLERK_SECRET_KEY"] = "test_clerk_secret_key_12345"
os.environ["STRIPE_SECRET_KEY"] = "test_stripe_secret_key_12345"
os.environ["CORS_ORIGINS"] = "http://localhost:3000"
os.environ["ENVIRONMENT"] = "test"
os.environ["DEBUG"] = "true"
os.environ["REDIS_URL"] = ""  # Disable Redis for tests (use in-memory rate limiting)

from backend.db.database import Base
from backend.db.models import User, Organization, OrganizationMember, UserRole, Scan, ScanStatus, ScanMode


# ===========================================
# Event Loop Configuration
# ===========================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for session scope."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ===========================================
# Database Fixtures
# ===========================================

@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create async engine for testing with in-memory SQLite."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for testing."""
    async_session_factory = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    async with async_session_factory() as session:
        yield session
        await session.rollback()


# ===========================================
# User and Organization Fixtures
# ===========================================

@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        id=uuid4(),
        email="test@breach.ai",
        name="Test User",
        clerk_id=f"user_{uuid4().hex[:20]}",
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_organization(db_session: AsyncSession) -> Organization:
    """Create a test organization."""
    org = Organization(
        id=uuid4(),
        name="Test Organization",
        slug=f"test-org-{uuid4().hex[:8]}",
        subscription_tier="free",
        max_scans_per_month=10,
        max_targets=3,
        max_team_members=2,
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def test_member(
    db_session: AsyncSession,
    test_user: User,
    test_organization: Organization
) -> tuple[User, Organization]:
    """Create a user with organization membership."""
    member = OrganizationMember(
        organization_id=test_organization.id,
        user_id=test_user.id,
        role=UserRole.OWNER,
    )
    db_session.add(member)
    await db_session.commit()
    return test_user, test_organization


@pytest_asyncio.fixture
async def test_scan(
    db_session: AsyncSession,
    test_member: tuple[User, Organization]
) -> Scan:
    """Create a test scan."""
    user, org = test_member
    scan = Scan(
        id=uuid4(),
        organization_id=org.id,
        created_by=user.id,
        target_url="https://example.com",
        mode=ScanMode.NORMAL,
        status=ScanStatus.PENDING,
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return scan


# ===========================================
# HTTP Client Fixtures
# ===========================================

@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create async HTTP client for API testing."""
    from backend.api.server import app
    from backend.db.database import get_db

    # Override database dependency
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    # Use ASGITransport for newer httpx versions
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authenticated_client(
    client: AsyncClient,
    test_member: tuple[User, Organization]
) -> AsyncClient:
    """Create authenticated client with mocked auth."""
    from backend.api.deps import get_current_user

    user, org = test_member

    # Override auth dependency
    from backend.api.server import app

    async def override_auth():
        return (user, org)

    app.dependency_overrides[get_current_user] = override_auth

    yield client

    del app.dependency_overrides[get_current_user]


# ===========================================
# Mock Fixtures
# ===========================================

@pytest.fixture
def mock_clerk_token():
    """Return a mock Clerk token for testing."""
    return "test_clerk_token_" + uuid4().hex


@pytest.fixture
def mock_api_key():
    """Return a mock API key for testing."""
    return "breach_test_" + uuid4().hex[:32]


# ===========================================
# Utility Functions
# ===========================================

def make_uuid():
    """Generate a new UUID."""
    return uuid4()


def make_email():
    """Generate a unique test email."""
    return f"test_{uuid4().hex[:8]}@breach.ai"


def make_url():
    """Generate a test URL."""
    return f"https://test-{uuid4().hex[:8]}.example.com"
