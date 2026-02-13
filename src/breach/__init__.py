"""
BREACH v3.1 - Autonomous Security Scanner
==========================================

Shannon-style security assessment with proof-by-exploitation.

Uses the Claude Agent SDK for autonomous multi-turn security testing.

Modules:
--------
- ai: Claude Agent SDK integration
- phases: 4-phase pentest (recon, analysis, exploit, report)
- workflow: Orchestration engine
- attacks: Attack payloads and patterns
- exploitation: Proof-of-concept generation
- recon: Reconnaissance tools
- report: Report generation

Quick Start:
------------
    from breach.workflow import WorkflowConfig, WorkflowEngine

    config = WorkflowConfig(target="https://target.com")
    async with WorkflowEngine(config) as engine:
        result = await engine.run()

CLI Usage:
----------
    breach scan https://target.com
    breach scan https://target.com --repo ./myapp  # with source
    breach scan https://target.com --no-browser    # skip XSS validation
"""

__version__ = "3.1.0"
__author__ = "BREACH Team"

# Main exports
from .workflow import WorkflowConfig, WorkflowEngine, WorkflowResult
from .ai import BreachAgent, AgentResult, AGENT_SDK_AVAILABLE

__all__ = [
    # Workflow
    "WorkflowConfig",
    "WorkflowEngine",
    "WorkflowResult",
    # Agent
    "BreachAgent",
    "AgentResult",
    "AGENT_SDK_AVAILABLE",
    # Meta
    "__version__",
]
