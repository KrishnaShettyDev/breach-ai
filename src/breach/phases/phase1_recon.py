"""
BREACH v3.1 - Phase 1: Reconnaissance
======================================

Map the attack surface before testing.

This phase:
1. Discovers endpoints
2. Identifies parameters
3. Detects technologies
4. Analyzes source code (if available)
5. Produces structured recon results
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from breach.ai import BreachAgent, AGENT_SDK_AVAILABLE
from breach.ai.prompts import PromptManager


@dataclass
class Endpoint:
    """Discovered endpoint."""
    url: str
    method: str
    parameters: List[str] = field(default_factory=list)
    source: str = ""  # Where it was discovered
    requires_auth: bool = False


@dataclass
class Technology:
    """Detected technology."""
    name: str
    version: Optional[str] = None
    category: str = ""  # framework, server, language, etc.
    confidence: float = 1.0


@dataclass
class ReconResult:
    """Result of reconnaissance phase."""
    target: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0

    # Discovered items
    endpoints: List[Endpoint] = field(default_factory=list)
    parameters: Set[str] = field(default_factory=set)
    technologies: List[Technology] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)

    # Source analysis (if available)
    source_analyzed: bool = False
    data_flows: List[Dict] = field(default_factory=list)
    sinks_found: List[Dict] = field(default_factory=list)

    # Stats
    pages_crawled: int = 0
    total_parameters: int = 0

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "endpoints": [
                {"url": e.url, "method": e.method, "parameters": e.parameters}
                for e in self.endpoints
            ],
            "parameters": list(self.parameters),
            "technologies": [
                {"name": t.name, "version": t.version, "category": t.category}
                for t in self.technologies
            ],
            "js_files": self.js_files,
            "source_analyzed": self.source_analyzed,
            "pages_crawled": self.pages_crawled,
        }


class ReconPhase:
    """
    Phase 1: Reconnaissance.

    Maps the attack surface through:
    - Web crawling
    - JavaScript analysis
    - Technology fingerprinting
    - Source code analysis (optional)
    """

    # Common parameters to look for
    INTERESTING_PARAMS = {
        "id", "user_id", "user", "uid", "username",
        "email", "password", "pass", "pwd",
        "q", "query", "search", "s",
        "url", "uri", "path", "file", "page",
        "redirect", "next", "return", "goto",
        "cmd", "exec", "command",
        "template", "tpl", "view",
        "callback", "jsonp", "cb",
    }

    # Technology signatures
    TECH_SIGNATURES = {
        "X-Powered-By": {
            "PHP": ("PHP", "language"),
            "Express": ("Express.js", "framework"),
            "ASP.NET": ("ASP.NET", "framework"),
        },
        "Server": {
            "nginx": ("nginx", "server"),
            "Apache": ("Apache", "server"),
            "cloudflare": ("Cloudflare", "cdn"),
        },
        "body": {
            "wp-content": ("WordPress", "cms"),
            "drupal": ("Drupal", "cms"),
            "react": ("React", "framework"),
            "vue": ("Vue.js", "framework"),
            "angular": ("Angular", "framework"),
            "next": ("Next.js", "framework"),
            "nuxt": ("Nuxt.js", "framework"),
        }
    }

    def __init__(
        self,
        use_ai: bool = True,
        use_browser: bool = False,
        repo_path: Path = None,
        max_pages: int = 100,
        timeout: int = 30,
        audit_dir: Path = None,
        on_progress: Callable[[str], None] = None,
    ):
        self.use_ai = use_ai
        self.use_browser = use_browser
        self.repo_path = repo_path
        self.max_pages = max_pages
        self.timeout = timeout
        self.audit_dir = audit_dir
        self.on_progress = on_progress or (lambda x: None)

        self._session: Optional[aiohttp.ClientSession] = None
        self._visited: Set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"User-Agent": "BREACH/3.0 Recon"},
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def run(
        self,
        target: str,
        cookies: Dict[str, str] = None,
    ) -> ReconResult:
        """
        Run reconnaissance on target.

        Args:
            target: Target URL
            cookies: Session cookies for authenticated recon

        Returns:
            ReconResult with discovered endpoints, parameters, technologies
        """
        start_time = time.time()
        result = ReconResult(target=target)

        self.on_progress("Starting reconnaissance...")

        # Normalize target URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        result.target = target

        # Phase 1a: Traditional crawling
        self.on_progress("Crawling website...")
        await self._crawl(target, result, cookies)

        # Phase 1b: Technology detection
        self.on_progress("Detecting technologies...")
        await self._detect_technologies(target, result, cookies)

        # Phase 1c: JavaScript analysis
        self.on_progress("Analyzing JavaScript files...")
        await self._analyze_javascript(result, cookies)

        # Phase 1d: Source code analysis (if available)
        if self.repo_path and self.repo_path.exists():
            self.on_progress("Analyzing source code...")
            await self._analyze_source_code(result)
            result.source_analyzed = True

        # Phase 1e: AI-powered recon (if enabled)
        if self.use_ai:
            self.on_progress("Running AI-powered reconnaissance...")
            await self._ai_recon(target, result, cookies)

        # Finalize
        result.completed_at = datetime.utcnow()
        result.duration_seconds = time.time() - start_time
        result.total_parameters = len(result.parameters)

        self.on_progress(f"Reconnaissance complete: {len(result.endpoints)} endpoints, {len(result.parameters)} parameters")

        return result

    async def _crawl(
        self,
        start_url: str,
        result: ReconResult,
        cookies: Dict[str, str],
    ):
        """Crawl the website to discover endpoints."""
        base_domain = urlparse(start_url).netloc
        await self._queue.put(start_url)

        while not self._queue.empty() and len(self._visited) < self.max_pages:
            url = await self._queue.get()

            if url in self._visited:
                continue

            self._visited.add(url)

            try:
                async with self._session.get(url, cookies=cookies) as response:
                    if response.status != 200:
                        continue

                    body = await response.text()
                    result.pages_crawled += 1

                    # Parse HTML
                    soup = BeautifulSoup(body, "lxml")

                    # Extract links
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)

                        if urlparse(full_url).netloc == base_domain:
                            if full_url not in self._visited:
                                await self._queue.put(full_url)

                    # Extract forms
                    for form in soup.find_all("form"):
                        action = form.get("action", url)
                        method = form.get("method", "GET").upper()
                        full_action = urljoin(url, action)

                        params = []
                        for inp in form.find_all(["input", "textarea", "select"]):
                            name = inp.get("name")
                            if name:
                                params.append(name)
                                result.parameters.add(name)

                        result.endpoints.append(Endpoint(
                            url=full_action,
                            method=method,
                            parameters=params,
                            source="form",
                        ))

                    # Extract URL parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            if "=" in param:
                                name = param.split("=")[0]
                                result.parameters.add(name)

                    # Extract JS files
                    for script in soup.find_all("script", src=True):
                        js_url = urljoin(url, script["src"])
                        if js_url not in result.js_files:
                            result.js_files.append(js_url)

            except Exception as e:
                pass  # Continue crawling

    async def _detect_technologies(
        self,
        target: str,
        result: ReconResult,
        cookies: Dict[str, str],
    ):
        """Detect technologies from headers and body."""
        try:
            async with self._session.get(target, cookies=cookies) as response:
                headers = dict(response.headers)
                body = await response.text()

                # Check headers
                for header, signatures in self.TECH_SIGNATURES.items():
                    if header == "body":
                        continue

                    value = headers.get(header, "")
                    for sig, (name, category) in signatures.items():
                        if sig.lower() in value.lower():
                            # Try to extract version
                            version_match = re.search(rf"{sig}[/\s]*([\d.]+)", value, re.I)
                            version = version_match.group(1) if version_match else None

                            result.technologies.append(Technology(
                                name=name,
                                version=version,
                                category=category,
                            ))

                # Check body
                body_lower = body.lower()
                for sig, (name, category) in self.TECH_SIGNATURES["body"].items():
                    if sig in body_lower:
                        result.technologies.append(Technology(
                            name=name,
                            category=category,
                            confidence=0.8,
                        ))

        except Exception:
            pass

    async def _analyze_javascript(
        self,
        result: ReconResult,
        cookies: Dict[str, str],
    ):
        """Analyze JavaScript files for endpoints and parameters."""
        for js_url in result.js_files[:20]:  # Limit to 20 files
            try:
                async with self._session.get(js_url, cookies=cookies) as response:
                    if response.status != 200:
                        continue

                    js_content = await response.text()

                    # Find API endpoints
                    api_patterns = [
                        r'["\'](/api/[^"\']+)["\']',
                        r'["\'](/v\d+/[^"\']+)["\']',
                        r'fetch\s*\(\s*["\']([^"\']+)["\']',
                        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                    ]

                    for pattern in api_patterns:
                        for match in re.finditer(pattern, js_content):
                            path = match.group(1)
                            full_url = urljoin(result.target, path)

                            # Check if not already found
                            existing = [e.url for e in result.endpoints]
                            if full_url not in existing:
                                result.endpoints.append(Endpoint(
                                    url=full_url,
                                    method="GET",
                                    source="javascript",
                                ))

                    # Find parameters
                    param_patterns = [
                        r'params\s*[=:]\s*\{([^}]+)\}',
                        r'data\s*[=:]\s*\{([^}]+)\}',
                    ]

                    for pattern in param_patterns:
                        for match in re.finditer(pattern, js_content):
                            params_str = match.group(1)
                            param_names = re.findall(r'["\']?(\w+)["\']?\s*:', params_str)
                            for name in param_names:
                                if name.lower() in self.INTERESTING_PARAMS or len(name) > 2:
                                    result.parameters.add(name)

            except Exception:
                pass

    async def _analyze_source_code(self, result: ReconResult):
        """Analyze source code for vulnerabilities."""
        if not self.repo_path:
            return

        source_tool = SourceTool(repo_path=str(self.repo_path))

        # Find dangerous sinks
        sinks_result = await source_tool._find_sinks("all")
        if sinks_result.success:
            result.sinks_found = sinks_result.data.get("sinks", [])

        # Find API routes
        route_patterns = [
            r'@(app|router)\.(get|post|put|delete)\s*\(["\']([^"\']+)',
            r'router\.(get|post|put|delete)\s*\(["\']([^"\']+)',
        ]

        for pattern in route_patterns:
            search_result = await source_tool._search(pattern)
            if search_result.success:
                for match in search_result.data.get("matches", []):
                    route_match = re.search(pattern, match)
                    if route_match:
                        method = route_match.group(2).upper() if route_match.lastindex >= 2 else "GET"
                        path = route_match.group(3) if route_match.lastindex >= 3 else route_match.group(2)
                        result.endpoints.append(Endpoint(
                            url=urljoin(result.target, path),
                            method=method,
                            source="source_code",
                        ))

    async def _ai_recon(
        self,
        target: str,
        result: ReconResult,
        cookies: Dict[str, str],
    ):
        """Use AI agent for enhanced recon."""
        prompts = PromptManager()

        tools = [
            HTTPTool(session=self._session),
        ]

        if self.use_browser:
            tools.append(BrowserTool())

        if self.repo_path:
            tools.append(SourceTool(repo_path=str(self.repo_path)))

        agent = ClaudeAgent(
            max_turns=20,
            tools=tools,
            system_prompt="You are a security researcher performing reconnaissance.",
            audit_dir=self.audit_dir,
        )

        prompt = prompts.get_recon_prompt(
            target=target,
            has_source=self.repo_path is not None,
        )

        # Save prompt for reproducibility
        if self.audit_dir:
            prompts.save_prompt("phase1_recon", prompt, self.audit_dir)

        agent_result = await agent.run(
            task=prompt,
            context={
                "current_endpoints": len(result.endpoints),
                "current_parameters": len(result.parameters),
                "technologies": [t.name for t in result.technologies],
            },
        )

        # Extract AI findings
        if agent_result.success and agent_result.structured_output:
            ai_data = agent_result.structured_output

            # Add discovered endpoints
            for ep in ai_data.get("endpoints", []):
                if isinstance(ep, dict):
                    existing_urls = [e.url for e in result.endpoints]
                    if ep.get("url") and ep["url"] not in existing_urls:
                        result.endpoints.append(Endpoint(
                            url=ep["url"],
                            method=ep.get("method", "GET"),
                            parameters=ep.get("parameters", []),
                            source="ai_recon",
                        ))

            # Add parameters
            for param in ai_data.get("parameters", []):
                if isinstance(param, str):
                    result.parameters.add(param)
