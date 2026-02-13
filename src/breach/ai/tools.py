"""
BREACH v3.0 - Agent Tools
==========================

Tool definitions for Claude Agent.
These are the capabilities the agent can use during execution.

Follows Shannon's MCP-style tool integration.
"""

import asyncio
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, quote

import aiohttp


@dataclass
class ToolResult:
    """Result of tool execution."""
    success: bool
    output: str
    data: Dict = field(default_factory=dict)
    error: Optional[str] = None
    screenshot: Optional[bytes] = None


class Tool(ABC):
    """Base class for agent tools."""

    name: str
    description: str
    parameters: Dict

    @abstractmethod
    async def execute(self, params: Dict) -> ToolResult:
        """Execute the tool with given parameters."""
        pass

    def to_anthropic_schema(self) -> Dict:
        """Convert to Anthropic tool schema."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": [k for k, v in self.parameters.items() if v.get("required", False)],
            }
        }


class HTTPTool(Tool):
    """
    HTTP request tool for the agent.

    Allows the agent to make HTTP requests to test endpoints.
    """

    name = "http_request"
    description = """Make an HTTP request to a URL.
    Use this to test endpoints, send payloads, and observe responses.
    Returns the response body, headers, and status code."""

    parameters = {
        "url": {
            "type": "string",
            "description": "The URL to request",
            "required": True,
        },
        "method": {
            "type": "string",
            "description": "HTTP method (GET, POST, PUT, DELETE)",
            "default": "GET",
        },
        "headers": {
            "type": "object",
            "description": "Request headers",
        },
        "body": {
            "type": "string",
            "description": "Request body for POST/PUT",
        },
        "params": {
            "type": "object",
            "description": "URL query parameters",
        },
        "cookies": {
            "type": "object",
            "description": "Cookies to send",
        },
        "timeout": {
            "type": "integer",
            "description": "Timeout in seconds",
            "default": 30,
        },
    }

    def __init__(self, session: aiohttp.ClientSession = None):
        self._session = session
        self._owns_session = session is None

    async def execute(self, params: Dict) -> ToolResult:
        url = params["url"]
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body")
        query_params = params.get("params", {})
        cookies = params.get("cookies", {})
        timeout = params.get("timeout", 30)

        # Create session if needed
        if not self._session:
            self._session = aiohttp.ClientSession()

        try:
            # Build URL with params
            if query_params:
                sep = "&" if "?" in url else "?"
                param_str = "&".join(f"{k}={quote(str(v))}" for k, v in query_params.items())
                url = f"{url}{sep}{param_str}"

            # Make request
            async with self._session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                cookies=cookies,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                body_text = await response.text()

                return ToolResult(
                    success=True,
                    output=f"Status: {response.status}\n\nHeaders:\n{json.dumps(dict(response.headers), indent=2)}\n\nBody:\n{body_text[:5000]}",
                    data={
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body_text,
                        "url": str(response.url),
                    }
                )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                output=f"Request timed out after {timeout}s",
                error="timeout",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output=f"Request failed: {e}",
                error=str(e),
            )


class BrowserTool(Tool):
    """
    Browser automation tool using Playwright.

    For XSS validation, JavaScript execution, screenshot capture.
    """

    name = "browser"
    description = """Control a browser to test vulnerabilities.
    Use this for XSS testing (verify JS execution), CSRF testing,
    clickjacking, and capturing screenshots as proof."""

    parameters = {
        "action": {
            "type": "string",
            "description": "Action: navigate, execute_js, screenshot, get_cookies, click",
            "required": True,
        },
        "url": {
            "type": "string",
            "description": "URL to navigate to",
        },
        "script": {
            "type": "string",
            "description": "JavaScript to execute",
        },
        "selector": {
            "type": "string",
            "description": "CSS selector for click action",
        },
        "wait_for": {
            "type": "string",
            "description": "Wait for selector or 'networkidle'",
        },
    }

    def __init__(self):
        self._browser = None
        self._page = None

    async def _ensure_browser(self):
        """Ensure browser is initialized."""
        if self._browser is None:
            try:
                from playwright.async_api import async_playwright
                pw = await async_playwright().start()
                self._browser = await pw.chromium.launch(headless=True)
                self._page = await self._browser.new_page()
            except ImportError:
                raise ImportError("Playwright required. Install: pip install playwright && playwright install")

    async def execute(self, params: Dict) -> ToolResult:
        action = params["action"]

        await self._ensure_browser()

        try:
            if action == "navigate":
                url = params["url"]
                wait_for = params.get("wait_for", "networkidle")

                await self._page.goto(url, wait_until=wait_for, timeout=30000)

                return ToolResult(
                    success=True,
                    output=f"Navigated to {url}\nTitle: {await self._page.title()}\nURL: {self._page.url}",
                    data={
                        "url": self._page.url,
                        "title": await self._page.title(),
                    }
                )

            elif action == "execute_js":
                script = params["script"]
                result = await self._page.evaluate(script)

                return ToolResult(
                    success=True,
                    output=f"JavaScript executed. Result: {json.dumps(result, default=str)}",
                    data={"result": result},
                )

            elif action == "screenshot":
                screenshot = await self._page.screenshot(full_page=True)

                return ToolResult(
                    success=True,
                    output=f"Screenshot captured ({len(screenshot)} bytes)",
                    screenshot=screenshot,
                )

            elif action == "get_cookies":
                cookies = await self._page.context.cookies()

                return ToolResult(
                    success=True,
                    output=f"Cookies: {json.dumps(cookies, indent=2)}",
                    data={"cookies": cookies},
                )

            elif action == "click":
                selector = params["selector"]
                await self._page.click(selector, timeout=5000)

                return ToolResult(
                    success=True,
                    output=f"Clicked element: {selector}",
                )

            elif action == "get_content":
                content = await self._page.content()

                return ToolResult(
                    success=True,
                    output=f"Page content ({len(content)} chars):\n{content[:3000]}...",
                    data={"content": content},
                )

            else:
                return ToolResult(
                    success=False,
                    output=f"Unknown action: {action}",
                    error="unknown_action",
                )

        except Exception as e:
            return ToolResult(
                success=False,
                output=f"Browser action failed: {e}",
                error=str(e),
            )

    async def close(self):
        """Close browser."""
        if self._browser:
            await self._browser.close()


class SourceTool(Tool):
    """
    Source code analysis tool.

    For white-box testing - analyze application source code.
    """

    name = "analyze_source"
    description = """Analyze source code for vulnerabilities.
    Use this to find dangerous sinks, trace data flows,
    and identify potential injection points."""

    parameters = {
        "action": {
            "type": "string",
            "description": "Action: search, read_file, find_sinks, trace_dataflow",
            "required": True,
        },
        "pattern": {
            "type": "string",
            "description": "Search pattern (regex)",
        },
        "file_path": {
            "type": "string",
            "description": "File to read",
        },
        "source": {
            "type": "string",
            "description": "Data source for tracing",
        },
        "sink_type": {
            "type": "string",
            "description": "Sink type: sqli, xss, cmdi, ssrf",
        },
    }

    # Dangerous sinks by vulnerability type
    SINKS = {
        "sqli": [
            r'execute\s*\(',
            r'cursor\.execute',
            r'raw\s*\(',
            r'query\s*\(',
            r'\$\w+\s*=\s*["\']SELECT',
        ],
        "xss": [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'\.html\s*\(',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
        ],
        "cmdi": [
            r'exec\s*\(',
            r'system\s*\(',
            r'popen\s*\(',
            r'subprocess\.',
            r'os\.system',
            r'shell_exec',
        ],
        "ssrf": [
            r'requests\.(get|post)\s*\(',
            r'urllib\.',
            r'fetch\s*\(',
            r'axios\.',
            r'curl_exec',
        ],
    }

    def __init__(self, repo_path: str = None):
        self.repo_path = repo_path

    async def execute(self, params: Dict) -> ToolResult:
        action = params["action"]

        if action == "search":
            pattern = params["pattern"]
            return await self._search(pattern)

        elif action == "read_file":
            file_path = params["file_path"]
            return await self._read_file(file_path)

        elif action == "find_sinks":
            sink_type = params.get("sink_type", "all")
            return await self._find_sinks(sink_type)

        elif action == "trace_dataflow":
            source = params["source"]
            return await self._trace_dataflow(source)

        else:
            return ToolResult(
                success=False,
                output=f"Unknown action: {action}",
                error="unknown_action",
            )

    async def _search(self, pattern: str) -> ToolResult:
        """Search for pattern in source code."""
        if not self.repo_path:
            return ToolResult(
                success=False,
                output="No repository configured",
                error="no_repo",
            )

        import subprocess
        try:
            result = subprocess.run(
                ["grep", "-rn", "-E", pattern, self.repo_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            matches = result.stdout.strip().split("\n")[:50]  # Limit results

            return ToolResult(
                success=True,
                output=f"Found {len(matches)} matches:\n" + "\n".join(matches),
                data={"matches": matches},
            )

        except Exception as e:
            return ToolResult(
                success=False,
                output=f"Search failed: {e}",
                error=str(e),
            )

    async def _read_file(self, file_path: str) -> ToolResult:
        """Read a source file."""
        from pathlib import Path

        if not self.repo_path:
            return ToolResult(success=False, output="No repo", error="no_repo")

        full_path = Path(self.repo_path) / file_path

        if not full_path.exists():
            return ToolResult(
                success=False,
                output=f"File not found: {file_path}",
                error="not_found",
            )

        try:
            content = full_path.read_text()
            return ToolResult(
                success=True,
                output=f"File: {file_path}\n\n{content[:10000]}",
                data={"content": content},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output=f"Failed to read: {e}",
                error=str(e),
            )

    async def _find_sinks(self, sink_type: str) -> ToolResult:
        """Find dangerous sinks in codebase."""
        if not self.repo_path:
            return ToolResult(success=False, output="No repo", error="no_repo")

        findings = []

        types_to_check = [sink_type] if sink_type != "all" else self.SINKS.keys()

        for stype in types_to_check:
            patterns = self.SINKS.get(stype, [])
            for pattern in patterns:
                result = await self._search(pattern)
                if result.success and result.data.get("matches"):
                    findings.extend([
                        {"type": stype, "pattern": pattern, "match": m}
                        for m in result.data["matches"]
                    ])

        return ToolResult(
            success=True,
            output=f"Found {len(findings)} potential sinks:\n" +
                   "\n".join(f"[{f['type']}] {f['match']}" for f in findings[:30]),
            data={"sinks": findings},
        )

    async def _trace_dataflow(self, source: str) -> ToolResult:
        """Trace data flow from source."""
        # Simplified data flow tracing
        search_result = await self._search(source)

        if not search_result.success:
            return search_result

        # Find where the source variable is used
        flows = []
        for match in search_result.data.get("matches", []):
            # Check if it flows to a sink
            for sink_type, patterns in self.SINKS.items():
                for pattern in patterns:
                    if re.search(pattern, match):
                        flows.append({
                            "source": source,
                            "sink_type": sink_type,
                            "location": match,
                        })

        return ToolResult(
            success=True,
            output=f"Data flow analysis for '{source}':\n" +
                   f"Found {len(flows)} potential flows to dangerous sinks:\n" +
                   "\n".join(f"  - {f['sink_type']}: {f['location']}" for f in flows[:20]),
            data={"flows": flows},
        )


class SQLiTool(Tool):
    """
    SQL Injection testing tool.

    Specialized tool for SQLi exploitation.
    """

    name = "sqli_test"
    description = """Test for SQL injection vulnerabilities.
    Sends payloads and analyzes responses for SQL errors,
    time delays, or data extraction."""

    parameters = {
        "url": {
            "type": "string",
            "description": "Target URL",
            "required": True,
        },
        "parameter": {
            "type": "string",
            "description": "Parameter to test",
            "required": True,
        },
        "method": {
            "type": "string",
            "description": "HTTP method",
            "default": "GET",
        },
        "payload_type": {
            "type": "string",
            "description": "Payload type: error, time, union, boolean",
            "default": "error",
        },
    }

    # SQLi payloads by type
    PAYLOADS = {
        "error": [
            "'",
            "\"",
            "' OR '1'='1",
            "1' AND '1'='1",
            "1 AND 1=1",
        ],
        "time": [
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
        ],
        "boolean": [
            "' AND 1=1--",
            "' AND 1=2--",
        ],
    }

    SQL_ERRORS = [
        "sql syntax",
        "mysql",
        "postgres",
        "sqlite",
        "ora-",
        "microsoft",
        "syntax error",
        "unclosed quotation",
    ]

    def __init__(self, session: aiohttp.ClientSession = None):
        self._session = session

    async def execute(self, params: Dict) -> ToolResult:
        url = params["url"]
        parameter = params["parameter"]
        method = params.get("method", "GET")
        payload_type = params.get("payload_type", "error")

        if not self._session:
            self._session = aiohttp.ClientSession()

        payloads = self.PAYLOADS.get(payload_type, self.PAYLOADS["error"])
        results = []

        for payload in payloads:
            try:
                start_time = asyncio.get_event_loop().time()

                if method == "GET":
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{parameter}={quote(payload)}"
                    async with self._session.get(test_url, ssl=False, timeout=15) as resp:
                        body = await resp.text()
                        status = resp.status
                else:
                    async with self._session.post(url, data={parameter: payload}, ssl=False, timeout=15) as resp:
                        body = await resp.text()
                        status = resp.status

                elapsed = asyncio.get_event_loop().time() - start_time

                # Check for SQL errors
                error_found = any(e in body.lower() for e in self.SQL_ERRORS)

                # Check for time delay
                time_delay = elapsed > 4.5

                result = {
                    "payload": payload,
                    "status": status,
                    "error_based": error_found,
                    "time_based": time_delay,
                    "elapsed": elapsed,
                }

                if error_found or time_delay:
                    result["vulnerable"] = True
                    result["evidence"] = body[:500] if error_found else f"Time delay: {elapsed:.2f}s"

                results.append(result)

            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e),
                })

        # Determine if vulnerable
        vulnerable = any(r.get("vulnerable") for r in results)

        output = f"SQLi Test Results for {parameter}:\n\n"
        for r in results:
            status = "[VULNERABLE]" if r.get("vulnerable") else "[OK]"
            output += f"{status} {r['payload']}\n"
            if r.get("evidence"):
                output += f"    Evidence: {r['evidence'][:100]}\n"

        return ToolResult(
            success=True,
            output=output,
            data={
                "vulnerable": vulnerable,
                "results": results,
            }
        )
