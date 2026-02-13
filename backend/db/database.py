"""
BREACH.AI - Database Configuration
===================================
Database connection with SQLAlchemy async support.
Supports both PostgreSQL (production) and SQLite (development).
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from backend.config import settings

# Database URL from config
DATABASE_URL = settings.database_url

# Handle SQLite for development
if DATABASE_URL.startswith("sqlite://") and "+aiosqlite" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://")

# Engine configuration
engine_kwargs = {
    "echo": settings.debug,
}

# PostgreSQL-specific settings
if DATABASE_URL.startswith("postgresql"):
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
        "pool_recycle": 1800,  # Recycle connections after 30 minutes
    })
# SQLite-specific settings - use NullPool to avoid connection sharing issues
elif "sqlite" in DATABASE_URL:
    from sqlalchemy.pool import NullPool
    engine_kwargs.update({
        "poolclass": NullPool,
        "connect_args": {"check_same_thread": False},
    })

engine = create_async_engine(DATABASE_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions.
    Use for background tasks or non-dependency injection contexts.
    """
    session = AsyncSessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections."""
    await engine.dispose()


async def check_db_health() -> dict:
    """
    Check database health and return pool statistics.

    Returns:
        dict with pool stats and connection status
    """
    try:
        async with AsyncSessionLocal() as session:
            # Execute a simple query to verify connection
            result = await session.execute(text("SELECT 1"))
            result.scalar()

        # Get pool statistics (only for PostgreSQL with pool)
        pool_stats = {}
        if hasattr(engine.pool, 'size'):
            pool_stats = {
                "pool_size": engine.pool.size(),
                "checked_in": engine.pool.checkedin(),
                "checked_out": engine.pool.checkedout(),
                "overflow": engine.pool.overflow(),
                "invalid": engine.pool.invalidatedcount() if hasattr(engine.pool, 'invalidatedcount') else 0,
            }

        return {
            "connected": True,
            "database_type": "postgresql" if "postgresql" in DATABASE_URL else "sqlite",
            **pool_stats
        }

    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }
