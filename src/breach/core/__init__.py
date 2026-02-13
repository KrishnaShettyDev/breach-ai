"""BREACH.AI Core Components"""

from breach.core.memory import (
    Memory,
    Finding,
    Severity,
    AccessLevel,
    Credential,
    AttackSurface,
)
from breach.core.scheduler import AttackScheduler, ScheduledAttack
from breach.core.learning_engine import (
    LearningEngine,
    LearningData,
    AttackPattern,
    TechnologyProfile,
    WAFProfile,
    TargetHistory,
    get_learning_engine,
    learn_attack,
    learn_vulnerability,
    predict_vulns,
    get_best_attacks,
    prioritize_attacks,
    get_waf_bypasses,
    get_learning_stats,
)

__all__ = [
    # Memory
    "Memory",
    "Finding",
    "Severity",
    "AccessLevel",
    "Credential",
    "AttackSurface",

    # Scheduler
    "AttackScheduler",
    "ScheduledAttack",

    # Learning Engine
    "LearningEngine",
    "LearningData",
    "AttackPattern",
    "TechnologyProfile",
    "WAFProfile",
    "TargetHistory",
    "get_learning_engine",
    "learn_attack",
    "learn_vulnerability",
    "predict_vulns",
    "get_best_attacks",
    "prioritize_attacks",
    "get_waf_bypasses",
    "get_learning_stats",
]
