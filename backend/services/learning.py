"""
BREACH.AI - Database-Backed Learning Engine
============================================

NOTE: This is the DATABASE-BACKED learning engine for API/multi-instance mode.
      For the FILE-BASED learning engine used in CLI mode, see:
      backend/breach/core/learning_engine.py

This module stores learning data in the database (BrainMemory table) which allows:
- Shared learning across multiple instances
- Per-target/per-organization learning
- Persistence across server restarts
- Integration with the API for viewing learning stats

The core/learning_engine.py is used for real-time attack optimization during scans.
This service is used for API-level learning statistics and cross-session persistence.

Features:
- Learns from successful attacks
- Remembers application-specific patterns
- Tracks vulnerability patterns per target
- Automatic retesting of previously found vulnerabilities
- Attack strategy optimization based on past results
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Set
from uuid import UUID
import json
import hashlib

import structlog
from sqlalchemy import select, update, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import (
    BrainMemory, Target, Finding, Scan,
    Organization, Severity
)

logger = structlog.get_logger(__name__)


@dataclass
class LearnedPattern:
    """A pattern learned from previous scans."""
    pattern_type: str  # "vulnerability", "endpoint", "parameter", "technology"
    pattern_value: str
    confidence: float  # 0.0 to 1.0
    occurrences: int
    last_seen: datetime
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStrategy:
    """Optimized attack strategy for a target."""
    target_id: UUID
    priority_modules: List[str]  # Modules that worked before
    skip_modules: List[str]      # Modules that never find anything
    known_technologies: List[str]
    known_endpoints: List[str]
    known_parameters: List[str]
    vulnerability_hotspots: List[str]  # Endpoints with past vulns
    recommended_depth: str  # quick/normal/deep


class LearningEngine:
    """
    Cross-session learning engine.

    Stores and retrieves knowledge about:
    - Target-specific patterns
    - Successful attack vectors
    - Application technology stacks
    - Endpoint/parameter discovery
    - Vulnerability trends
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ============== Knowledge Storage ==============

    async def store_knowledge(
        self,
        target_id: UUID,
        knowledge_type: str,
        key: str,
        value: Any,
        confidence: float = 1.0,
        ttl_days: int = 90
    ) -> BrainMemory:
        """
        Store a piece of learned knowledge.

        Args:
            target_id: Target this knowledge applies to
            knowledge_type: Category (technology, endpoint, parameter, vulnerability, attack_result)
            key: Unique identifier within the type
            value: The knowledge data
            confidence: Confidence level (0.0 to 1.0)
            ttl_days: How long to keep this knowledge
        """
        # Create unique memory key
        memory_key = self._make_key(target_id, knowledge_type, key)

        # Check if exists
        existing = await self._get_memory(memory_key)

        if existing:
            # Update existing
            existing.value = json.dumps(value) if not isinstance(value, str) else value
            existing.confidence = min(1.0, existing.confidence + 0.1)  # Increase confidence
            existing.access_count += 1
            existing.last_accessed = datetime.utcnow()
            existing.expires_at = datetime.utcnow() + timedelta(days=ttl_days)
            await self.db.commit()
            return existing
        else:
            # Create new
            memory = BrainMemory(
                target_id=target_id,
                memory_type=knowledge_type,
                key=memory_key,
                value=json.dumps(value) if not isinstance(value, str) else value,
                confidence=confidence,
                expires_at=datetime.utcnow() + timedelta(days=ttl_days),
            )
            self.db.add(memory)
            await self.db.commit()
            await self.db.refresh(memory)
            return memory

    async def get_knowledge(
        self,
        target_id: UUID,
        knowledge_type: str = None,
        min_confidence: float = 0.5
    ) -> List[BrainMemory]:
        """Retrieve learned knowledge for a target."""
        query = select(BrainMemory).where(
            BrainMemory.target_id == target_id,
            BrainMemory.confidence >= min_confidence,
            BrainMemory.expires_at > datetime.utcnow(),
        )

        if knowledge_type:
            query = query.where(BrainMemory.memory_type == knowledge_type)

        result = await self.db.execute(query)
        memories = list(result.scalars().all())

        # Update access counts
        for memory in memories:
            memory.access_count += 1
            memory.last_accessed = datetime.utcnow()

        await self.db.commit()
        return memories

    async def decay_knowledge(self, target_id: UUID, decay_factor: float = 0.95):
        """
        Decay confidence of old knowledge.

        Knowledge that isn't reinforced slowly loses confidence.
        """
        cutoff = datetime.utcnow() - timedelta(days=30)

        await self.db.execute(
            update(BrainMemory)
            .where(
                BrainMemory.target_id == target_id,
                BrainMemory.last_accessed < cutoff,
                BrainMemory.confidence > 0.1,
            )
            .values(confidence=BrainMemory.confidence * decay_factor)
        )
        await self.db.commit()

    # ============== Learning from Scans ==============

    async def learn_from_scan(
        self,
        scan_id: UUID,
        target_id: UUID,
        findings: List[Finding],
        discovered_data: Dict[str, Any]
    ):
        """
        Learn from a completed scan.

        Extracts and stores:
        - Technologies detected
        - Endpoints found
        - Parameters discovered
        - Vulnerability patterns
        - Module effectiveness
        """
        logger.info("learning_from_scan", scan_id=str(scan_id), target_id=str(target_id))

        # Learn technologies
        for tech in discovered_data.get("technologies", []):
            await self.store_knowledge(
                target_id=target_id,
                knowledge_type="technology",
                key=tech.get("name", str(tech)),
                value={
                    "name": tech.get("name"),
                    "version": tech.get("version"),
                    "confidence": tech.get("confidence", 0.8),
                },
                confidence=tech.get("confidence", 0.8),
            )

        # Learn endpoints
        for endpoint in discovered_data.get("endpoints", []):
            await self.store_knowledge(
                target_id=target_id,
                knowledge_type="endpoint",
                key=endpoint.get("path", str(endpoint)),
                value={
                    "path": endpoint.get("path"),
                    "method": endpoint.get("method", "GET"),
                    "parameters": endpoint.get("parameters", []),
                    "auth_required": endpoint.get("auth_required", False),
                },
            )

        # Learn parameters
        for param in discovered_data.get("parameters", []):
            await self.store_knowledge(
                target_id=target_id,
                knowledge_type="parameter",
                key=param,
                value={"name": param},
            )

        # Learn from findings (vulnerability patterns)
        for finding in findings:
            # Store vulnerability location
            if finding.affected_endpoint:
                await self.store_knowledge(
                    target_id=target_id,
                    knowledge_type="vulnerability_hotspot",
                    key=finding.affected_endpoint,
                    value={
                        "endpoint": finding.affected_endpoint,
                        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        "category": finding.category,
                        "finding_id": str(finding.id),
                    },
                    confidence=1.0,
                    ttl_days=180,  # Keep vulnerability locations longer
                )

            # Store attack vector
            await self.store_knowledge(
                target_id=target_id,
                knowledge_type="successful_attack",
                key=f"{finding.category}_{finding.affected_endpoint}",
                value={
                    "category": finding.category,
                    "module": finding.attack_module if hasattr(finding, 'attack_module') else None,
                    "endpoint": finding.affected_endpoint,
                    "parameters": finding.affected_parameters if hasattr(finding, 'affected_parameters') else [],
                },
                confidence=1.0,
            )

        # Learn module effectiveness
        for module_name, result in discovered_data.get("module_results", {}).items():
            found_vulns = result.get("findings_count", 0)
            await self.store_knowledge(
                target_id=target_id,
                knowledge_type="module_effectiveness",
                key=module_name,
                value={
                    "module": module_name,
                    "findings_count": found_vulns,
                    "effective": found_vulns > 0,
                    "last_run": datetime.utcnow().isoformat(),
                },
                confidence=0.9 if found_vulns > 0 else 0.5,
            )

        logger.info(
            "learning_complete",
            scan_id=str(scan_id),
            technologies=len(discovered_data.get("technologies", [])),
            endpoints=len(discovered_data.get("endpoints", [])),
            findings=len(findings),
        )

    # ============== Strategy Generation ==============

    async def generate_attack_strategy(self, target_id: UUID) -> AttackStrategy:
        """
        Generate an optimized attack strategy based on learned knowledge.

        This is what makes subsequent scans smarter and faster.
        """
        # Get all knowledge for this target
        all_knowledge = await self.get_knowledge(target_id, min_confidence=0.3)

        # Categorize
        technologies = []
        endpoints = []
        parameters = []
        hotspots = []
        effective_modules = []
        ineffective_modules = []

        for memory in all_knowledge:
            try:
                value = json.loads(memory.value) if isinstance(memory.value, str) else memory.value
            except json.JSONDecodeError:
                value = {"raw": memory.value}

            if memory.memory_type == "technology":
                technologies.append(value.get("name", str(value)))

            elif memory.memory_type == "endpoint":
                endpoints.append(value.get("path", str(value)))

            elif memory.memory_type == "parameter":
                parameters.append(value.get("name", str(value)))

            elif memory.memory_type == "vulnerability_hotspot":
                hotspots.append(value.get("endpoint", str(value)))

            elif memory.memory_type == "module_effectiveness":
                if value.get("effective"):
                    effective_modules.append(value.get("module"))
                elif memory.confidence < 0.4:
                    ineffective_modules.append(value.get("module"))

        # Determine recommended depth
        if hotspots:
            recommended_depth = "deep"  # Known vulnerabilities, worth deep scanning
        elif technologies:
            recommended_depth = "normal"  # Know the stack, normal scan
        else:
            recommended_depth = "quick"  # Unknown target, quick first

        strategy = AttackStrategy(
            target_id=target_id,
            priority_modules=list(set(effective_modules)),
            skip_modules=list(set(ineffective_modules)),
            known_technologies=list(set(technologies)),
            known_endpoints=list(set(endpoints))[:100],  # Limit size
            known_parameters=list(set(parameters))[:200],
            vulnerability_hotspots=list(set(hotspots)),
            recommended_depth=recommended_depth,
        )

        logger.info(
            "strategy_generated",
            target_id=str(target_id),
            priority_modules=len(strategy.priority_modules),
            known_endpoints=len(strategy.known_endpoints),
            hotspots=len(strategy.vulnerability_hotspots),
            recommended_depth=strategy.recommended_depth,
        )

        return strategy

    # ============== Regression Testing ==============

    async def get_vulnerabilities_to_retest(
        self,
        target_id: UUID,
        max_age_days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get previously found vulnerabilities that should be retested.

        This implements MindFort's "automatic retesting" feature.
        """
        cutoff = datetime.utcnow() - timedelta(days=max_age_days)

        # Get recent findings for this target
        result = await self.db.execute(
            select(Finding)
            .join(Scan)
            .where(
                Scan.target_id == target_id,
                Finding.created_at >= cutoff,
                Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
            )
            .order_by(Finding.severity.desc())
            .limit(20)
        )

        findings = result.scalars().all()

        retest_items = []
        for finding in findings:
            retest_items.append({
                "finding_id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "category": finding.category,
                "endpoint": finding.affected_endpoint,
                "last_found": finding.created_at.isoformat(),
                "test_payload": finding.evidence if hasattr(finding, 'evidence') else None,
            })

        return retest_items

    async def mark_vulnerability_status(
        self,
        target_id: UUID,
        finding_id: UUID,
        status: str,  # "fixed", "still_vulnerable", "not_testable"
    ):
        """Mark the retest status of a vulnerability."""
        await self.store_knowledge(
            target_id=target_id,
            knowledge_type="retest_result",
            key=str(finding_id),
            value={
                "finding_id": str(finding_id),
                "status": status,
                "tested_at": datetime.utcnow().isoformat(),
            },
            ttl_days=90,
        )

    # ============== Analytics ==============

    async def get_learning_stats(self, target_id: UUID) -> Dict[str, Any]:
        """Get learning statistics for a target."""
        knowledge = await self.get_knowledge(target_id, min_confidence=0.0)

        stats = {
            "total_memories": len(knowledge),
            "by_type": {},
            "avg_confidence": 0.0,
            "oldest_memory": None,
            "newest_memory": None,
        }

        if knowledge:
            for memory in knowledge:
                t = memory.memory_type
                if t not in stats["by_type"]:
                    stats["by_type"][t] = 0
                stats["by_type"][t] += 1

            stats["avg_confidence"] = sum(m.confidence for m in knowledge) / len(knowledge)
            stats["oldest_memory"] = min(m.created_at for m in knowledge).isoformat()
            stats["newest_memory"] = max(m.created_at for m in knowledge).isoformat()

        return stats

    async def get_organization_learning_stats(
        self,
        organization_id: UUID
    ) -> Dict[str, Any]:
        """Get learning statistics across all targets in an organization."""
        # Get all targets
        result = await self.db.execute(
            select(Target).where(Target.organization_id == organization_id)
        )
        targets = result.scalars().all()

        total_memories = 0
        targets_with_learning = 0

        for target in targets:
            knowledge = await self.get_knowledge(target.id, min_confidence=0.0)
            if knowledge:
                total_memories += len(knowledge)
                targets_with_learning += 1

        return {
            "total_targets": len(targets),
            "targets_with_learning": targets_with_learning,
            "total_memories": total_memories,
            "avg_memories_per_target": total_memories / len(targets) if targets else 0,
        }

    # ============== Helpers ==============

    def _make_key(self, target_id: UUID, knowledge_type: str, key: str) -> str:
        """Create a unique key for memory storage."""
        raw = f"{target_id}:{knowledge_type}:{key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    async def _get_memory(self, memory_key: str) -> Optional[BrainMemory]:
        """Get a specific memory by key."""
        result = await self.db.execute(
            select(BrainMemory).where(BrainMemory.key == memory_key)
        )
        return result.scalar_one_or_none()


# ============== Integration with Scan Service ==============

async def apply_learning_to_scan(
    db: AsyncSession,
    target_id: UUID,
    scan_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Apply learned knowledge to enhance a scan.

    Called before starting a scan to optimize it based on past learning.
    """
    engine = LearningEngine(db)
    strategy = await engine.generate_attack_strategy(target_id)

    # Enhance config with learned data
    enhanced_config = {**scan_config}

    # Add known endpoints to seed the crawler
    if strategy.known_endpoints:
        enhanced_config["seed_endpoints"] = strategy.known_endpoints[:50]

    # Add known parameters to test
    if strategy.known_parameters:
        enhanced_config["known_parameters"] = strategy.known_parameters[:100]

    # Prioritize modules that found vulnerabilities before
    if strategy.priority_modules:
        enhanced_config["priority_modules"] = strategy.priority_modules

    # Skip modules that never find anything for this target
    if strategy.skip_modules:
        enhanced_config["skip_modules"] = strategy.skip_modules

    # Focus on known hotspots
    if strategy.vulnerability_hotspots:
        enhanced_config["hotspots"] = strategy.vulnerability_hotspots

    # Get items to retest
    retest_items = await engine.get_vulnerabilities_to_retest(target_id)
    if retest_items:
        enhanced_config["retest_vulnerabilities"] = retest_items

    # Override depth recommendation if not explicitly set
    if "mode" not in scan_config:
        enhanced_config["recommended_mode"] = strategy.recommended_depth

    logger.info(
        "learning_applied",
        target_id=str(target_id),
        seed_endpoints=len(enhanced_config.get("seed_endpoints", [])),
        hotspots=len(enhanced_config.get("hotspots", [])),
        retest_items=len(enhanced_config.get("retest_vulnerabilities", [])),
    )

    return enhanced_config
