"""
BREACH v3.1 - AI Module (Claude Agent SDK)
==========================================

Uses the official Claude Agent SDK - the same harness powering Claude Code.

Features:
- Multi-turn autonomous execution
- Built-in tools (Bash, Read, Write, WebFetch)
- Custom security testing tools via MCP
- Streaming responses
- Checkpointing support
"""

from .agent import (
    BreachAgent,
    ClaudeAgent,  # Backward compatible alias
    AgentResult,
    AgentTurn,
    AgentState,
    create_security_tools_server,
    AGENT_SDK_AVAILABLE,
)
from .prompts import PromptManager

__all__ = [
    # Main agent
    "BreachAgent",
    "ClaudeAgent",
    "AgentResult",
    "AgentTurn",
    "AgentState",
    # Tools
    "create_security_tools_server",
    # Utils
    "PromptManager",
    "AGENT_SDK_AVAILABLE",
]
