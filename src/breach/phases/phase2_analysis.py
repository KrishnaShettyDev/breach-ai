"""
BREACH v3.1 - Phase 2: Vulnerability Analysis
===============================================

Parallel vulnerability hypothesis generation.

This phase spawns specialized agents for each OWASP category
to analyze endpoints and generate exploitation hypotheses.

NO EXPLOITATION YET - only analysis and hypothesis generation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from breach.ai import BreachAgent, AGENT_SDK_AVAILABLE
from breach.ai.prompts import PromptManager
from .phase1_recon import ReconResult, Endpoint


@dataclass
class Hypothesis:
    """Vulnerability hypothesis to test in Phase 3."""
    id: str
    vuln_type: str  # sqli, xss, ssrf, cmdi, auth
    endpoint: str
    parameter: str
    payload: str
    confidence: float  # 0.0 to 1.0
    rationale: str
    source: str  # Which agent generated this
    priority: int = 0  # Higher = test first


@dataclass
class AnalysisResult:
    """Result of vulnerability analysis phase."""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0

    # Hypotheses generated
    hypotheses: List[Hypothesis] = field(default_factory=list)
    total_hypotheses: int = 0

    # By type
    sqli_hypotheses: int = 0
    xss_hypotheses: int = 0
    ssrf_hypotheses: int = 0
    cmdi_hypotheses: int = 0
    auth_hypotheses: int = 0

    # Stats
    endpoints_analyzed: int = 0
    agents_run: int = 0

    def to_dict(self) -> Dict:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_hypotheses": self.total_hypotheses,
            "by_type": {
                "sqli": self.sqli_hypotheses,
                "xss": self.xss_hypotheses,
                "ssrf": self.ssrf_hypotheses,
                "cmdi": self.cmdi_hypotheses,
                "auth": self.auth_hypotheses,
            },
            "hypotheses": [
                {
                    "id": h.id,
                    "vuln_type": h.vuln_type,
                    "endpoint": h.endpoint,
                    "parameter": h.parameter,
                    "confidence": h.confidence,
                }
                for h in self.hypotheses
            ],
        }


class VulnAgent:
    """Base class for OWASP-specialized vulnerability agents."""

    VULN_TYPE: str = ""
    DESCRIPTION: str = ""

    # Payloads for initial testing
    PAYLOADS: List[str] = []

    # Patterns that indicate vulnerability
    INDICATORS: List[str] = []

    def __init__(
        self,
        target: str,
        endpoints: List[Endpoint],
        recon_result: ReconResult,
        repo_path: Path = None,
        audit_dir: Path = None,
    ):
        self.target = target
        self.endpoints = endpoints
        self.recon_result = recon_result
        self.repo_path = repo_path
        self.audit_dir = audit_dir

    async def analyze(self) -> List[Hypothesis]:
        """Analyze endpoints and generate hypotheses."""
        raise NotImplementedError


class SQLiAgent(VulnAgent):
    """SQL Injection analysis agent."""

    VULN_TYPE = "sqli"
    DESCRIPTION = "SQL Injection"

    PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1 UNION SELECT NULL--",
    ]

    INDICATORS = [
        "sql syntax",
        "mysql",
        "postgres",
        "sqlite",
        "ora-",
        "unclosed quotation",
    ]

    # Parameters likely to be SQL injectable
    TARGET_PARAMS = {
        "id", "user_id", "uid", "product_id", "item_id",
        "category", "sort", "order", "limit", "offset",
        "search", "query", "q", "filter",
    }

    async def analyze(self) -> List[Hypothesis]:
        hypotheses = []
        hypothesis_id = 0

        for endpoint in self.endpoints:
            # Check parameters
            for param in endpoint.parameters:
                param_lower = param.lower()

                # High priority: known SQLi-prone params
                if param_lower in self.TARGET_PARAMS or "id" in param_lower:
                    confidence = 0.7
                    priority = 10
                else:
                    confidence = 0.3
                    priority = 1

                # Check source code for SQL usage
                if self.recon_result.source_analyzed:
                    for sink in self.recon_result.sinks_found:
                        if sink.get("type") == "sqli":
                            if param in sink.get("match", ""):
                                confidence = 0.9
                                priority = 20

                # Generate hypothesis for each payload
                for payload in self.PAYLOADS[:3]:  # Top 3 payloads
                    hypothesis_id += 1
                    hypotheses.append(Hypothesis(
                        id=f"sqli_{hypothesis_id}",
                        vuln_type=self.VULN_TYPE,
                        endpoint=endpoint.url,
                        parameter=param,
                        payload=payload,
                        confidence=confidence,
                        rationale=f"Parameter '{param}' may be used in SQL query",
                        source="sqli_agent",
                        priority=priority,
                    ))

        return hypotheses


class XSSAgent(VulnAgent):
    """Cross-Site Scripting analysis agent."""

    VULN_TYPE = "xss"
    DESCRIPTION = "Cross-Site Scripting"

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
    ]

    INDICATORS = [
        "script",
        "onerror",
        "onclick",
        "javascript:",
    ]

    TARGET_PARAMS = {
        "q", "query", "search", "s",
        "name", "user", "username",
        "comment", "message", "content",
        "callback", "redirect", "url",
    }

    async def analyze(self) -> List[Hypothesis]:
        hypotheses = []
        hypothesis_id = 0

        for endpoint in self.endpoints:
            for param in endpoint.parameters:
                param_lower = param.lower()

                if param_lower in self.TARGET_PARAMS or "name" in param_lower:
                    confidence = 0.6
                    priority = 10
                else:
                    confidence = 0.2
                    priority = 1

                # Check source for XSS sinks
                if self.recon_result.source_analyzed:
                    for sink in self.recon_result.sinks_found:
                        if sink.get("type") == "xss":
                            if param in sink.get("match", ""):
                                confidence = 0.85
                                priority = 20

                for payload in self.PAYLOADS[:2]:
                    hypothesis_id += 1
                    hypotheses.append(Hypothesis(
                        id=f"xss_{hypothesis_id}",
                        vuln_type=self.VULN_TYPE,
                        endpoint=endpoint.url,
                        parameter=param,
                        payload=payload,
                        confidence=confidence,
                        rationale=f"Parameter '{param}' may be reflected in response",
                        source="xss_agent",
                        priority=priority,
                    ))

        return hypotheses


class SSRFAgent(VulnAgent):
    """Server-Side Request Forgery analysis agent."""

    VULN_TYPE = "ssrf"
    DESCRIPTION = "Server-Side Request Forgery"

    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://localhost:22",
        "http://[::1]:80",
    ]

    TARGET_PARAMS = {
        "url", "uri", "path", "file", "page",
        "src", "href", "link", "redirect",
        "callback", "proxy", "fetch", "load",
    }

    async def analyze(self) -> List[Hypothesis]:
        hypotheses = []
        hypothesis_id = 0

        for endpoint in self.endpoints:
            for param in endpoint.parameters:
                param_lower = param.lower()

                if param_lower in self.TARGET_PARAMS or "url" in param_lower:
                    confidence = 0.7
                    priority = 15

                    for payload in self.PAYLOADS:
                        hypothesis_id += 1
                        hypotheses.append(Hypothesis(
                            id=f"ssrf_{hypothesis_id}",
                            vuln_type=self.VULN_TYPE,
                            endpoint=endpoint.url,
                            parameter=param,
                            payload=payload,
                            confidence=confidence,
                            rationale=f"Parameter '{param}' accepts URL-like input",
                            source="ssrf_agent",
                            priority=priority,
                        ))

        return hypotheses


class CMDiAgent(VulnAgent):
    """Command Injection analysis agent."""

    VULN_TYPE = "cmdi"
    DESCRIPTION = "Command Injection"

    PAYLOADS = [
        "; id",
        "| id",
        "$(id)",
        "`id`",
        "; cat /etc/passwd",
    ]

    TARGET_PARAMS = {
        "cmd", "command", "exec", "run",
        "ping", "host", "ip", "domain",
        "file", "filename", "path",
    }

    async def analyze(self) -> List[Hypothesis]:
        hypotheses = []
        hypothesis_id = 0

        for endpoint in self.endpoints:
            for param in endpoint.parameters:
                param_lower = param.lower()

                if param_lower in self.TARGET_PARAMS:
                    confidence = 0.7
                    priority = 20  # High priority - critical if found

                    for payload in self.PAYLOADS[:3]:
                        hypothesis_id += 1
                        hypotheses.append(Hypothesis(
                            id=f"cmdi_{hypothesis_id}",
                            vuln_type=self.VULN_TYPE,
                            endpoint=endpoint.url,
                            parameter=param,
                            payload=payload,
                            confidence=confidence,
                            rationale=f"Parameter '{param}' may be passed to system command",
                            source="cmdi_agent",
                            priority=priority,
                        ))

        return hypotheses


class AuthAgent(VulnAgent):
    """Authentication/Authorization analysis agent."""

    VULN_TYPE = "auth"
    DESCRIPTION = "Broken Authentication"

    PAYLOADS = [
        "' OR '1'='1' --",  # SQLi auth bypass
        "admin' --",
        '{"$ne": null}',  # NoSQL
        "admin",  # Default creds
    ]

    async def analyze(self) -> List[Hypothesis]:
        hypotheses = []
        hypothesis_id = 0

        for endpoint in self.endpoints:
            url_lower = endpoint.url.lower()

            # Check if it's an auth endpoint
            if any(x in url_lower for x in ["login", "signin", "auth", "session"]):
                for param in endpoint.parameters:
                    if any(x in param.lower() for x in ["user", "pass", "email", "pwd"]):
                        for payload in self.PAYLOADS:
                            hypothesis_id += 1
                            hypotheses.append(Hypothesis(
                                id=f"auth_{hypothesis_id}",
                                vuln_type=self.VULN_TYPE,
                                endpoint=endpoint.url,
                                parameter=param,
                                payload=payload,
                                confidence=0.5,
                                rationale=f"Auth endpoint with '{param}' parameter",
                                source="auth_agent",
                                priority=15,
                            ))

        return hypotheses


class AnalysisPhase:
    """
    Phase 2: Vulnerability Analysis.

    Runs specialized agents in PARALLEL to analyze endpoints
    and generate exploitation hypotheses.
    """

    # Agent classes to run
    AGENTS = [
        SQLiAgent,
        XSSAgent,
        SSRFAgent,
        CMDiAgent,
        AuthAgent,
    ]

    def __init__(
        self,
        use_ai: bool = True,
        repo_path: Path = None,
        audit_dir: Path = None,
        on_progress: Callable[[str], None] = None,
    ):
        self.use_ai = use_ai
        self.repo_path = repo_path
        self.audit_dir = audit_dir
        self.on_progress = on_progress or (lambda x: None)

    async def run(
        self,
        target: str,
        recon_result: ReconResult,
    ) -> AnalysisResult:
        """
        Run parallel vulnerability analysis.

        Args:
            target: Target URL
            recon_result: Results from Phase 1

        Returns:
            AnalysisResult with hypotheses for Phase 3
        """
        start_time = time.time()
        result = AnalysisResult()

        self.on_progress("Starting parallel vulnerability analysis...")

        # Create agent instances
        agents = [
            AgentClass(
                target=target,
                endpoints=recon_result.endpoints,
                recon_result=recon_result,
                repo_path=self.repo_path,
                audit_dir=self.audit_dir,
            )
            for AgentClass in self.AGENTS
        ]

        # Run agents in parallel
        self.on_progress(f"Running {len(agents)} specialized agents in parallel...")

        tasks = [agent.analyze() for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect hypotheses
        for agent, agent_result in zip(agents, results):
            if isinstance(agent_result, Exception):
                self.on_progress(f"Agent {agent.VULN_TYPE} failed: {agent_result}")
                continue

            for hypothesis in agent_result:
                result.hypotheses.append(hypothesis)

                # Update counters
                if hypothesis.vuln_type == "sqli":
                    result.sqli_hypotheses += 1
                elif hypothesis.vuln_type == "xss":
                    result.xss_hypotheses += 1
                elif hypothesis.vuln_type == "ssrf":
                    result.ssrf_hypotheses += 1
                elif hypothesis.vuln_type == "cmdi":
                    result.cmdi_hypotheses += 1
                elif hypothesis.vuln_type == "auth":
                    result.auth_hypotheses += 1

            result.agents_run += 1

        # Sort by priority
        result.hypotheses.sort(key=lambda h: (-h.priority, -h.confidence))
        result.total_hypotheses = len(result.hypotheses)
        result.endpoints_analyzed = len(recon_result.endpoints)

        # AI-enhanced analysis (if enabled)
        if self.use_ai and result.hypotheses:
            self.on_progress("Running AI-enhanced analysis...")
            await self._ai_analysis(target, recon_result, result)

        # Finalize
        result.completed_at = datetime.utcnow()
        result.duration_seconds = time.time() - start_time

        self.on_progress(f"Analysis complete: {result.total_hypotheses} hypotheses generated")

        return result

    async def _ai_analysis(
        self,
        target: str,
        recon_result: ReconResult,
        result: AnalysisResult,
    ):
        """Use AI to refine and prioritize hypotheses."""
        # This would use Claude to analyze the hypotheses
        # and potentially generate new ones based on patterns
        pass
