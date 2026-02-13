"""
BREACH.AI - Base Engine
=======================

Abstract base class for all scan engines.
Provides unified interface for scan configuration, execution, and results.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    A security finding/vulnerability.

    Unified structure used across all engines.
    """
    # Basic info
    title: str
    severity: Severity
    vulnerability_type: str

    # Location
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None

    # Details
    description: str = ""
    payload: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Impact
    business_impact: float = 0.0
    impact_explanation: str = ""

    # Exploitation proof (for proven mode)
    is_exploited: bool = False
    exploitation_proof: Dict[str, Any] = field(default_factory=dict)
    exploitation_confidence: float = 0.0
    proof_type: str = ""

    # Reproduction
    curl_command: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    poc_script: str = ""

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "vulnerability_type": self.vulnerability_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "description": self.description,
            "payload": self.payload[:200] if self.payload else "",
            "evidence": self.evidence,
            "business_impact": self.business_impact,
            "is_exploited": self.is_exploited,
            "exploitation_confidence": self.exploitation_confidence,
            "curl_command": self.curl_command,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ScanConfig:
    """
    Unified scan configuration.

    Used by all engines for consistent configuration.
    """
    # Target
    target: str

    # Authentication
    cookie: Optional[str] = None
    cookie2: Optional[str] = None  # For IDOR testing
    token: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    # Scan control
    timeout_minutes: int = 30
    rate_limit: int = 50
    parallel: int = 5

    # Module selection
    modules: Optional[List[str]] = None
    skip_modules: Optional[List[str]] = None
    exclude_paths: List[str] = field(default_factory=list)

    # Features
    ai_enabled: bool = False
    browser_enabled: bool = False

    # Proxy
    proxy: Optional[str] = None

    # Verbosity
    verbose: bool = False

    def get_cookies_dict(self) -> Optional[Dict[str, str]]:
        """Parse cookie string to dict."""
        if not self.cookie:
            return None
        cookies = {}
        for part in self.cookie.split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def get_cookies2_dict(self) -> Optional[Dict[str, str]]:
        """Parse second cookie string to dict."""
        if not self.cookie2:
            return None
        cookies = {}
        for part in self.cookie2.split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies


@dataclass
class ScanResult:
    """
    Unified scan result.

    Returned by all engines with consistent structure.
    """
    # Target
    target: str
    mode: str

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: int = 0

    # Findings
    findings: List[Finding] = field(default_factory=list)

    # Statistics
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    requests_made: int = 0

    # Exploitation stats (for proven mode)
    exploitation_attempts: int = 0
    successful_exploits: int = 0
    false_positives_filtered: int = 0

    # Business impact
    total_business_impact: float = 0.0

    # Error info
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH])

    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.LOW])

    @property
    def info_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.INFO])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "total_business_impact": self.total_business_impact,
            },
            "statistics": {
                "endpoints_discovered": self.endpoints_discovered,
                "endpoints_tested": self.endpoints_tested,
                "requests_made": self.requests_made,
                "exploitation_attempts": self.exploitation_attempts,
                "successful_exploits": self.successful_exploits,
                "false_positives_filtered": self.false_positives_filtered,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


class BaseEngine(ABC):
    """
    Abstract base class for all scan engines.

    Provides unified interface and common functionality.
    """

    MODE: str = "base"
    DESCRIPTION: str = "Base engine"

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(target=config.target, mode=self.MODE)

        # Callbacks
        self._progress_callbacks: List[Callable[[int, str], None]] = []
        self._finding_callbacks: List[Callable[[Finding], None]] = []

    def on_progress(self, callback: Callable[[int, str], None]):
        """Register progress callback (percent, message)."""
        self._progress_callbacks.append(callback)

    def on_finding(self, callback: Callable[[Finding], None]):
        """Register finding callback."""
        self._finding_callbacks.append(callback)

    async def _emit_progress(self, percent: int, message: str):
        """Emit progress to all callbacks."""
        for cb in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(percent, message)
                else:
                    cb(percent, message)
            except Exception:
                pass

    async def _emit_finding(self, finding: Finding):
        """Emit finding to all callbacks."""
        for cb in self._finding_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(finding)
                else:
                    cb(finding)
            except Exception:
                pass

    @abstractmethod
    async def scan(self) -> ScanResult:
        """
        Execute the scan.

        Must be implemented by subclasses.
        """
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, *args):
        """Async context manager exit."""
        await self.cleanup()

    async def initialize(self):
        """Initialize engine resources. Override in subclass if needed."""
        pass

    async def cleanup(self):
        """Cleanup engine resources. Override in subclass if needed."""
        pass
