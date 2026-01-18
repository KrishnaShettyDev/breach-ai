"""
BREACH.AI - Learning Engine Integration Tests
==============================================
Test learning engine and brain memory functionality.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import (
    User, Organization, Target, BrainMemory
)
from backend.services.learning import LearningEngine, AttackStrategy


class TestLearningEngine:
    """Test learning engine operations."""

    @pytest.mark.asyncio
    async def test_store_knowledge(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test storing learned knowledge."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
        )
        db_session.add(target)
        await db_session.commit()

        engine = LearningEngine(db_session)

        # Store technology knowledge
        memory = await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="nginx",
            value={"name": "nginx", "version": "1.24"},
            confidence=0.9,
        )

        assert memory is not None
        assert memory.memory_type == "technology"
        assert memory.confidence == 0.9

    @pytest.mark.asyncio
    async def test_store_knowledge_updates_existing(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test that storing same knowledge updates confidence."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
        )
        db_session.add(target)
        await db_session.commit()

        engine = LearningEngine(db_session)

        # Store first time
        memory1 = await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="nginx",
            value={"name": "nginx"},
            confidence=0.7,
        )

        original_confidence = memory1.confidence

        # Store again (should update)
        memory2 = await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="nginx",
            value={"name": "nginx"},
            confidence=0.7,
        )

        # Confidence should have increased
        assert memory2.confidence > original_confidence
        assert memory2.access_count >= 1

    @pytest.mark.asyncio
    async def test_get_knowledge(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test retrieving learned knowledge."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
        )
        db_session.add(target)
        await db_session.commit()

        engine = LearningEngine(db_session)

        # Store some knowledge
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="nginx",
            value={"name": "nginx"},
        )
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="endpoint",
            key="/api/users",
            value={"path": "/api/users"},
        )

        # Get all knowledge
        all_knowledge = await engine.get_knowledge(target.id, min_confidence=0.0)
        assert len(all_knowledge) == 2

        # Get filtered by type
        tech_only = await engine.get_knowledge(
            target.id,
            knowledge_type="technology",
            min_confidence=0.0,
        )
        assert len(tech_only) == 1
        assert tech_only[0].memory_type == "technology"

    @pytest.mark.asyncio
    async def test_generate_attack_strategy(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test generating attack strategy from learned data."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
        )
        db_session.add(target)
        await db_session.commit()

        engine = LearningEngine(db_session)

        # Store various knowledge types
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="django",
            value={"name": "Django"},
        )
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="endpoint",
            key="/admin",
            value={"path": "/admin"},
        )
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="vulnerability_hotspot",
            key="/api/login",
            value={"endpoint": "/api/login", "severity": "high"},
        )
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="module_effectiveness",
            key="sql_injection",
            value={"module": "sql_injection", "effective": True, "findings_count": 3},
        )

        strategy = await engine.generate_attack_strategy(target.id)

        assert isinstance(strategy, AttackStrategy)
        assert strategy.target_id == target.id
        assert "Django" in strategy.known_technologies
        assert "/admin" in strategy.known_endpoints
        assert "/api/login" in strategy.vulnerability_hotspots
        assert "sql_injection" in strategy.priority_modules
        # Has hotspots, should recommend deep scan
        assert strategy.recommended_depth == "deep"

    @pytest.mark.asyncio
    async def test_get_learning_stats(
        self,
        db_session: AsyncSession,
        test_member: tuple[User, Organization]
    ):
        """Test getting learning statistics."""
        user, org = test_member

        target = Target(
            id=uuid4(),
            organization_id=org.id,
            url="https://example.com",
            name="Test Target",
        )
        db_session.add(target)
        await db_session.commit()

        engine = LearningEngine(db_session)

        # Store some knowledge
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="nginx",
            value={"name": "nginx"},
        )
        await engine.store_knowledge(
            target_id=target.id,
            knowledge_type="technology",
            key="python",
            value={"name": "Python"},
        )

        stats = await engine.get_learning_stats(target.id)

        assert stats["total_memories"] == 2
        assert "technology" in stats["by_type"]
        assert stats["by_type"]["technology"] == 2
        assert stats["avg_confidence"] > 0


class TestLearningAPI:
    """Test learning API endpoints."""

    @pytest.mark.asyncio
    async def test_get_learning_stats_no_target(
        self,
        authenticated_client: AsyncClient
    ):
        """Test getting stats without target ID returns org stats."""
        response = await authenticated_client.get("/api/v1/learning/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_targets" in data
        assert "total_memories" in data
