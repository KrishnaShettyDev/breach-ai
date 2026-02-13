"""
BREACH v3.0 - Claude Autonomous Agent
======================================

Shannon-style Claude integration using Claude as an autonomous agent.

Key features:
- Multi-turn execution (not single API calls)
- Tool use with function calling
- Checkpoint/rollback support
- Structured output
- Audit logging
"""

import asyncio
import json
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from .tools import Tool, ToolResult
from .prompts import PromptManager


class AgentState(str, Enum):
    """Agent execution state."""
    IDLE = "idle"
    RUNNING = "running"
    WAITING_TOOL = "waiting_tool"
    COMPLETED = "completed"
    FAILED = "failed"
    CHECKPOINTED = "checkpointed"


@dataclass
class AgentTurn:
    """Single turn in agent conversation."""
    turn_number: int
    role: str  # user, assistant, tool
    content: str
    tool_calls: List[Dict] = field(default_factory=list)
    tool_results: List[Dict] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tokens_used: int = 0


@dataclass
class AgentResult:
    """Result of agent execution."""
    success: bool
    output: str
    structured_output: Dict = field(default_factory=dict)

    # Execution stats
    turns_used: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    duration_seconds: float = 0.0

    # History
    conversation: List[AgentTurn] = field(default_factory=list)

    # Errors
    error: Optional[str] = None
    error_type: Optional[str] = None

    # Checkpointing
    checkpoint_id: Optional[str] = None
    can_resume: bool = False


class ClaudeAgent:
    """
    Autonomous Claude Agent.

    Unlike v2.x which made single API calls, this agent:
    - Runs multi-turn conversations (up to max_turns)
    - Uses tools via function calling
    - Supports checkpointing for retry
    - Produces structured output

    This mirrors Shannon's claude-executor.ts approach.
    """

    # Pricing per 1M tokens (Claude 3.5 Sonnet)
    INPUT_COST_PER_1M = 3.00
    OUTPUT_COST_PER_1M = 15.00

    def __init__(
        self,
        model: str = "claude-sonnet-4-5-20250929",
        max_turns: int = 100,
        max_tokens: int = 64000,
        tools: List[Tool] = None,
        system_prompt: str = None,
        audit_dir: Path = None,
        on_turn: Callable[[AgentTurn], None] = None,
        on_tool_call: Callable[[str, Dict], None] = None,
    ):
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("anthropic package required. Install: pip install anthropic")

        self.model = model
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.tools = tools or []
        self.system_prompt = system_prompt
        self.audit_dir = audit_dir
        self.on_turn = on_turn
        self.on_tool_call = on_tool_call

        self._client = anthropic.Anthropic()
        self._state = AgentState.IDLE
        self._conversation: List[Dict] = []
        self._turns: List[AgentTurn] = []
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    @property
    def state(self) -> AgentState:
        return self._state

    def _build_tools_schema(self) -> List[Dict]:
        """Build Anthropic tools schema from Tool objects."""
        return [tool.to_anthropic_schema() for tool in self.tools]

    async def run(
        self,
        task: str,
        context: Dict = None,
        checkpoint: str = None,
    ) -> AgentResult:
        """
        Run the agent on a task.

        Args:
            task: The task description
            context: Additional context (recon results, etc.)
            checkpoint: Resume from checkpoint ID

        Returns:
            AgentResult with output and stats
        """
        start_time = time.time()
        self._state = AgentState.RUNNING

        # Build initial message
        user_message = self._build_task_message(task, context)

        # Initialize conversation
        if checkpoint:
            self._load_checkpoint(checkpoint)
        else:
            self._conversation = []
            self._turns = []

        self._conversation.append({"role": "user", "content": user_message})

        try:
            # Main agent loop
            for turn_num in range(self.max_turns):
                # Make API call
                response = await self._call_claude()

                # Track tokens
                self._total_input_tokens += response.usage.input_tokens
                self._total_output_tokens += response.usage.output_tokens

                # Process response
                assistant_message = response.content

                # Create turn record
                turn = AgentTurn(
                    turn_number=turn_num,
                    role="assistant",
                    content=self._extract_text(assistant_message),
                    tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                )

                # Check for tool use
                tool_calls = [block for block in assistant_message if block.type == "tool_use"]

                if tool_calls:
                    turn.tool_calls = [
                        {"name": tc.name, "input": tc.input, "id": tc.id}
                        for tc in tool_calls
                    ]

                    # Add assistant message to conversation
                    self._conversation.append({
                        "role": "assistant",
                        "content": assistant_message
                    })

                    # Execute tools
                    self._state = AgentState.WAITING_TOOL
                    tool_results = await self._execute_tools(tool_calls)
                    turn.tool_results = tool_results

                    # Add tool results to conversation
                    self._conversation.append({
                        "role": "user",
                        "content": tool_results
                    })

                    self._state = AgentState.RUNNING

                else:
                    # No tool use - agent is done
                    self._conversation.append({
                        "role": "assistant",
                        "content": assistant_message
                    })

                self._turns.append(turn)

                if self.on_turn:
                    self.on_turn(turn)

                # Check stop condition
                if response.stop_reason == "end_turn" and not tool_calls:
                    break

                # Checkpoint periodically
                if turn_num > 0 and turn_num % 10 == 0:
                    self._save_checkpoint(turn_num)

            # Success
            self._state = AgentState.COMPLETED

            # Extract final output
            final_output = self._extract_text(assistant_message)
            structured = self._extract_structured_output(final_output)

            return AgentResult(
                success=True,
                output=final_output,
                structured_output=structured,
                turns_used=len(self._turns),
                total_tokens=self._total_input_tokens + self._total_output_tokens,
                cost_usd=self._calculate_cost(),
                duration_seconds=time.time() - start_time,
                conversation=self._turns,
            )

        except anthropic.APIError as e:
            self._state = AgentState.FAILED
            self._save_checkpoint(len(self._turns))

            return AgentResult(
                success=False,
                output="",
                error=str(e),
                error_type="api_error",
                turns_used=len(self._turns),
                total_tokens=self._total_input_tokens + self._total_output_tokens,
                cost_usd=self._calculate_cost(),
                duration_seconds=time.time() - start_time,
                can_resume=True,
                checkpoint_id=self._checkpoint_id,
            )

        except Exception as e:
            self._state = AgentState.FAILED

            return AgentResult(
                success=False,
                output="",
                error=str(e),
                error_type="execution_error",
                turns_used=len(self._turns),
                duration_seconds=time.time() - start_time,
            )

    async def _call_claude(self) -> Any:
        """Make API call to Claude."""
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": self._conversation,
        }

        if self.system_prompt:
            kwargs["system"] = self.system_prompt

        if self.tools:
            kwargs["tools"] = self._build_tools_schema()

        return self._client.messages.create(**kwargs)

    async def _execute_tools(self, tool_calls: List) -> List[Dict]:
        """Execute tool calls and return results."""
        results = []

        for tc in tool_calls:
            tool_name = tc.name
            tool_input = tc.input
            tool_id = tc.id

            if self.on_tool_call:
                self.on_tool_call(tool_name, tool_input)

            # Find matching tool
            tool = next((t for t in self.tools if t.name == tool_name), None)

            if tool:
                try:
                    result = await tool.execute(tool_input)
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result.output if isinstance(result, ToolResult) else str(result),
                    })
                except Exception as e:
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": f"Error executing tool: {e}",
                        "is_error": True,
                    })
            else:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": f"Unknown tool: {tool_name}",
                    "is_error": True,
                })

        return results

    def _build_task_message(self, task: str, context: Dict = None) -> str:
        """Build the initial task message."""
        message = f"# Task\n\n{task}\n"

        if context:
            message += "\n# Context\n\n"
            message += json.dumps(context, indent=2, default=str)

        message += "\n\n# Instructions\n\n"
        message += "1. Analyze the task and available context\n"
        message += "2. Use the available tools to accomplish the task\n"
        message += "3. Report your findings with evidence\n"
        message += "4. If you cannot complete the task, explain why\n"

        return message

    def _extract_text(self, content: Any) -> str:
        """Extract text from message content."""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [block.text for block in content if hasattr(block, 'text')]
            return "\n".join(texts)
        return str(content)

    def _extract_structured_output(self, text: str) -> Dict:
        """Try to extract structured output from text."""
        # Look for JSON blocks
        import re
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass

        # Look for findings
        findings = []
        finding_pattern = r'\*\*(\w+)\*\*.*?endpoint[:\s]+([^\n]+)'
        for match in re.finditer(finding_pattern, text, re.IGNORECASE):
            findings.append({
                "type": match.group(1),
                "endpoint": match.group(2).strip(),
            })

        if findings:
            return {"findings": findings}

        return {}

    def _calculate_cost(self) -> float:
        """Calculate USD cost of execution."""
        input_cost = (self._total_input_tokens / 1_000_000) * self.INPUT_COST_PER_1M
        output_cost = (self._total_output_tokens / 1_000_000) * self.OUTPUT_COST_PER_1M
        return input_cost + output_cost

    def _save_checkpoint(self, turn_num: int):
        """Save checkpoint for resume."""
        if not self.audit_dir:
            return

        checkpoint_dir = self.audit_dir / "checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self._checkpoint_id = hashlib.sha256(
            f"{time.time()}{turn_num}".encode()
        ).hexdigest()[:12]

        checkpoint_file = checkpoint_dir / f"checkpoint_{self._checkpoint_id}.json"
        checkpoint_file.write_text(json.dumps({
            "conversation": self._conversation,
            "turns": [t.__dict__ for t in self._turns],
            "input_tokens": self._total_input_tokens,
            "output_tokens": self._total_output_tokens,
        }, default=str))

        self._state = AgentState.CHECKPOINTED

    def _load_checkpoint(self, checkpoint_id: str):
        """Load from checkpoint."""
        if not self.audit_dir:
            return

        checkpoint_file = self.audit_dir / "checkpoints" / f"checkpoint_{checkpoint_id}.json"
        if checkpoint_file.exists():
            data = json.loads(checkpoint_file.read_text())
            self._conversation = data["conversation"]
            self._total_input_tokens = data["input_tokens"]
            self._total_output_tokens = data["output_tokens"]
