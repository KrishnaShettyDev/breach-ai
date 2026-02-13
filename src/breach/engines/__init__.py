"""
BREACH.AI - Unified Engine Architecture
=======================================

Provides a unified interface for all scan modes:
- quick: Fast reconnaissance + common vulnerabilities
- deep: Comprehensive injection testing
- proven: Proof-by-exploitation (only reports exploited vulns)
- chaos: All 60+ attack modules
"""

from .base import BaseEngine, ScanConfig, ScanResult, Finding
from .quick import QuickEngine
from .deep import DeepEngine
from .proven import ProvenEngine
from .chaos import ChaosEngine

__all__ = [
    "BaseEngine",
    "ScanConfig",
    "ScanResult",
    "Finding",
    "QuickEngine",
    "DeepEngine",
    "ProvenEngine",
    "ChaosEngine",
]


def get_engine(mode: str) -> type:
    """Get engine class for the given mode."""
    engines = {
        "quick": QuickEngine,
        "deep": DeepEngine,
        "proven": ProvenEngine,
        "chaos": ChaosEngine,
    }
    if mode not in engines:
        raise ValueError(f"Unknown mode: {mode}. Available: {list(engines.keys())}")
    return engines[mode]
