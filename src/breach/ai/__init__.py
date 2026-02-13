"""
BREACH v3.0 - AI Module
========================

Claude Agent integration following Shannon's architecture.
Uses Claude as an AUTONOMOUS AGENT, not a chatbot.

Key differences from v2.x:
- Multi-turn conversations (up to 1000 turns)
- Tool use with MCP-style integration
- Checkpoint/retry support
- Structured output
"""

from .agent import ClaudeAgent, AgentResult
from .tools import Tool, BrowserTool, HTTPTool, SourceTool
from .prompts import PromptManager

__all__ = [
    "ClaudeAgent",
    "AgentResult",
    "Tool",
    "BrowserTool",
    "HTTPTool",
    "SourceTool",
    "PromptManager",
]
