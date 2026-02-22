"""
BREACH - Source Code Analysis
=============================

Multi-language data flow analysis for white-box testing.
"""

from breach.source.dataflow import (
    DataFlowAnalyzer,
    DataFlowGraph,
    TaintedFlow,
    TaintSource,
    TaintSink,
    FlowAnalysisResult,
)
from breach.source.languages import (
    LanguageAnalyzer,
    PythonAnalyzer,
    JavaScriptAnalyzer,
    GoAnalyzer,
    JavaAnalyzer,
    PHPAnalyzer,
    RubyAnalyzer,
)

__all__ = [
    # Core
    "DataFlowAnalyzer",
    "DataFlowGraph",
    "TaintedFlow",
    "TaintSource",
    "TaintSink",
    "FlowAnalysisResult",
    # Languages
    "LanguageAnalyzer",
    "PythonAnalyzer",
    "JavaScriptAnalyzer",
    "GoAnalyzer",
    "JavaAnalyzer",
    "PHPAnalyzer",
    "RubyAnalyzer",
]
