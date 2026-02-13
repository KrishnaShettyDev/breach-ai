"""
BREACH.AI Agents Module
=======================

AI-powered autonomous security assessment agents.

Available Agents:
- SmartBreachAgent: Methodology-focused (harvest IDs, test IDOR, chain findings)
- SaaSBreachAgent: Discovery-first (discovers stack, adapts attacks)
"""

from .smart_agent import SmartBreachAgent
from .saas_agent import SaaSBreachAgent

__all__ = [
    "SmartBreachAgent",
    "SaaSBreachAgent",
]
