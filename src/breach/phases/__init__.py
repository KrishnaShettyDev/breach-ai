"""
BREACH v3.1 - Phase Architecture
=================================

Shannon-style 4-phase penetration testing:

Phase 1: Reconnaissance - Map the attack surface
Phase 2: Vulnerability Analysis - Generate hypotheses (parallel)
Phase 3: Exploitation - Prove vulnerabilities (parallel)
Phase 4: Reporting - Generate deliverables

Each phase is independent and produces structured output
for the next phase.
"""

from .phase1_recon import ReconPhase, ReconResult
from .phase2_analysis import AnalysisPhase, AnalysisResult, Hypothesis
from .phase3_exploit import ExploitPhase, ExploitResult, ValidatedFinding
from .phase4_report import ReportPhase, ReportResult

__all__ = [
    "ReconPhase",
    "ReconResult",
    "AnalysisPhase",
    "AnalysisResult",
    "Hypothesis",
    "ExploitPhase",
    "ExploitResult",
    "ValidatedFinding",
    "ReportPhase",
    "ReportResult",
]
