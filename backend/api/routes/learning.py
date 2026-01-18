"""
BREACH.AI - Learning Engine API Routes
======================================

API endpoints for viewing and managing the AI learning engine.
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.api.deps import get_current_user
from backend.services.learning import LearningEngine, apply_learning_to_scan

router = APIRouter(prefix="/learning", tags=["Learning Engine"])


# ============== Request/Response Models ==============

class LearningStatsResponse(BaseModel):
    """Learning statistics for a target."""
    target_id: str
    total_memories: int
    by_type: dict
    avg_confidence: float
    oldest_memory: Optional[str]
    newest_memory: Optional[str]


class OrganizationLearningStats(BaseModel):
    """Organization-wide learning statistics."""
    total_targets: int
    targets_with_learning: int
    total_memories: int
    avg_memories_per_target: float


class MemoryItem(BaseModel):
    """A single memory/knowledge item."""
    id: str
    memory_type: str
    key: str
    value: dict
    confidence: float
    access_count: int
    created_at: str
    last_accessed: str
    expires_at: str


class AttackStrategyResponse(BaseModel):
    """Optimized attack strategy for a target."""
    target_id: str
    priority_modules: List[str]
    skip_modules: List[str]
    known_technologies: List[str]
    known_endpoints: List[str]
    known_parameters: List[str]
    vulnerability_hotspots: List[str]
    recommended_depth: str


class RetestItem(BaseModel):
    """A vulnerability to retest."""
    finding_id: str
    title: str
    severity: str
    category: str
    endpoint: Optional[str]
    last_found: str
    test_payload: Optional[str]


class KnowledgeExport(BaseModel):
    """Full knowledge export for a target."""
    target_id: str
    target_url: Optional[str]
    export_date: str
    stats: LearningStatsResponse
    strategy: AttackStrategyResponse
    memories: List[MemoryItem]
    retest_items: List[RetestItem]


# ============== Endpoints ==============

@router.get("/stats/{target_id}", response_model=LearningStatsResponse)
async def get_learning_stats(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get learning statistics for a specific target.

    Returns counts of learned patterns, technologies, endpoints, etc.
    """
    user, org = current

    engine = LearningEngine(db)
    stats = await engine.get_learning_stats(target_id)

    return LearningStatsResponse(
        target_id=str(target_id),
        **stats
    )


@router.get("/stats", response_model=OrganizationLearningStats)
async def get_org_learning_stats(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get learning statistics for the entire organization.

    Shows aggregate learning across all targets.
    """
    user, org = current

    engine = LearningEngine(db)
    stats = await engine.get_organization_learning_stats(org.id)

    return OrganizationLearningStats(**stats)


@router.get("/strategy/{target_id}", response_model=AttackStrategyResponse)
async def get_attack_strategy(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get the AI-generated attack strategy for a target.

    Returns prioritized modules, known technologies, and vulnerability hotspots
    based on past scans. This is what makes subsequent scans smarter.
    """
    user, org = current

    engine = LearningEngine(db)
    strategy = await engine.generate_attack_strategy(target_id)

    return AttackStrategyResponse(
        target_id=str(strategy.target_id),
        priority_modules=strategy.priority_modules,
        skip_modules=strategy.skip_modules,
        known_technologies=strategy.known_technologies,
        known_endpoints=strategy.known_endpoints,
        known_parameters=strategy.known_parameters,
        vulnerability_hotspots=strategy.vulnerability_hotspots,
        recommended_depth=strategy.recommended_depth,
    )


@router.get("/retest/{target_id}", response_model=List[RetestItem])
async def get_retest_items(
    target_id: UUID,
    max_age_days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get vulnerabilities that should be retested.

    Returns critical and high severity findings from recent scans
    that should be verified in the next scan.
    """
    user, org = current

    engine = LearningEngine(db)
    items = await engine.get_vulnerabilities_to_retest(target_id, max_age_days)

    return [RetestItem(**item) for item in items]


@router.post("/retest/{target_id}/{finding_id}")
async def mark_retest_result(
    target_id: UUID,
    finding_id: UUID,
    status: str = Query(..., pattern="^(fixed|still_vulnerable|not_testable)$"),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Mark the result of a vulnerability retest.

    Status options:
    - fixed: Vulnerability has been remediated
    - still_vulnerable: Vulnerability still exists
    - not_testable: Cannot verify (e.g., endpoint removed)
    """
    user, org = current

    engine = LearningEngine(db)
    await engine.mark_vulnerability_status(target_id, finding_id, status)

    return {"status": "recorded", "finding_id": str(finding_id), "result": status}


@router.get("/export/{target_id}", response_model=KnowledgeExport)
async def export_knowledge(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Export all learned knowledge for a target.

    Returns a comprehensive export including:
    - Statistics
    - Attack strategy
    - All memory items
    - Retest items

    Useful for backup, transfer, or analysis.
    """
    import json
    from datetime import datetime
    from sqlalchemy import select
    from backend.db.models import Target

    user, org = current

    engine = LearningEngine(db)

    # Get target info
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()

    # Get all data
    stats = await engine.get_learning_stats(target_id)
    strategy = await engine.generate_attack_strategy(target_id)
    memories = await engine.get_knowledge(target_id, min_confidence=0.0)
    retest_items = await engine.get_vulnerabilities_to_retest(target_id, max_age_days=90)

    # Convert memories to response format
    memory_items = []
    for mem in memories:
        try:
            value = json.loads(mem.value) if isinstance(mem.value, str) else mem.value
        except json.JSONDecodeError:
            value = {"raw": mem.value}

        memory_items.append(MemoryItem(
            id=str(mem.id),
            memory_type=mem.memory_type,
            key=mem.key,
            value=value,
            confidence=mem.confidence,
            access_count=mem.access_count,
            created_at=mem.created_at.isoformat(),
            last_accessed=mem.last_accessed.isoformat() if mem.last_accessed else mem.created_at.isoformat(),
            expires_at=mem.expires_at.isoformat() if mem.expires_at else "",
        ))

    return KnowledgeExport(
        target_id=str(target_id),
        target_url=target.url if target else None,
        export_date=datetime.utcnow().isoformat(),
        stats=LearningStatsResponse(target_id=str(target_id), **stats),
        strategy=AttackStrategyResponse(
            target_id=str(strategy.target_id),
            priority_modules=strategy.priority_modules,
            skip_modules=strategy.skip_modules,
            known_technologies=strategy.known_technologies,
            known_endpoints=strategy.known_endpoints,
            known_parameters=strategy.known_parameters,
            vulnerability_hotspots=strategy.vulnerability_hotspots,
            recommended_depth=strategy.recommended_depth,
        ),
        memories=memory_items,
        retest_items=[RetestItem(**item) for item in retest_items],
    )


@router.post("/decay/{target_id}")
async def trigger_knowledge_decay(
    target_id: UUID,
    decay_factor: float = Query(default=0.95, ge=0.5, le=0.99),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Trigger knowledge decay for a target.

    Reduces confidence of old, unused knowledge. This helps the
    learning engine prioritize recent, relevant patterns.
    """
    user, org = current

    engine = LearningEngine(db)
    await engine.decay_knowledge(target_id, decay_factor)

    return {"status": "decay_applied", "target_id": str(target_id), "factor": decay_factor}


@router.delete("/clear/{target_id}")
async def clear_knowledge(
    target_id: UUID,
    knowledge_type: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Clear learned knowledge for a target.

    Optionally filter by knowledge_type:
    - technology
    - endpoint
    - parameter
    - vulnerability_hotspot
    - successful_attack
    - module_effectiveness

    Use with caution - this removes learned patterns.
    """
    from sqlalchemy import delete
    from backend.db.models import BrainMemory

    user, org = current

    query = delete(BrainMemory).where(BrainMemory.target_id == target_id)
    if knowledge_type:
        query = query.where(BrainMemory.memory_type == knowledge_type)

    result = await db.execute(query)
    await db.commit()

    return {
        "status": "cleared",
        "target_id": str(target_id),
        "knowledge_type": knowledge_type or "all",
        "items_removed": result.rowcount,
    }
