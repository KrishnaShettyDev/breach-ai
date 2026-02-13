"""
BREACH.AI - Autonomous Security Assessment Engine
==================================================

An AI-powered security testing framework that:
- Discovers attack surfaces automatically
- Chains vulnerabilities for maximum impact
- Extracts data as proof of concept
- Generates comprehensive reports

Modules:
--------
- core: Core engine components (memory, scheduler, agent)
- attacks: Attack modules (IDOR, SQLi, XSS, Auth bypass, etc.)
- recon: Reconnaissance modules (DNS, ports, web fingerprinting)
- modules: V2 killchain modules (61 total attack modules)
- agents: AI brain and decision-making engines
- utils: HTTP client, helpers, logging
- report: Report generation
- recommendations: Fix recommendations database (45+ vulnerability types)

Quick Start:
------------
    from breach.breach import BrutalAssessment, run_brutal_assessment

    # Run a complete security assessment
    results = await run_brutal_assessment("https://target.com")

CLI Usage:
----------
    breach assess https://target.com --brutal --output ./reports
"""

__version__ = "5.0.0"
__author__ = "BREACH.AI"

# Main exports - use try/except for flexible imports
try:
    from .brutal_assessment import (
        BrutalAssessment,
        AssessmentResults,
        Finding,
        run_brutal_assessment,
    )
except ImportError:
    # Module may not be fully installed
    BrutalAssessment = None
    AssessmentResults = None
    Finding = None
    run_brutal_assessment = None

__all__ = [
    "BrutalAssessment",
    "AssessmentResults",
    "Finding",
    "run_brutal_assessment",
    "__version__",
]
