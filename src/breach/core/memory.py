"""
BREACH Core Memory Types
========================

Data structures for findings, evidence, and attack tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AccessLevel(str, Enum):
    """Access level achieved through exploitation."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    SYSTEM = "system"


@dataclass
class Evidence:
    """Proof of exploitation."""
    type: str  # screenshot, response, curl_command, etc.
    data: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A validated security finding."""
    id: str
    type: str  # sqli, xss, ssrf, etc.
    severity: Severity
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    curl_command: Optional[str] = None
    access_level: AccessLevel = AccessLevel.NONE
    cvss_score: Optional[float] = None
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "curl_command": self.curl_command,
            "access_level": self.access_level.value,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "validated": self.validated,
        }


@dataclass
class Endpoint:
    """A discovered endpoint."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    requires_auth: bool = False
    content_type: Optional[str] = None

    def __hash__(self):
        return hash((self.url, self.method))

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return self.url == other.url and self.method == other.method


@dataclass
class AttackSurface:
    """The discovered attack surface of a target."""
    target: str
    endpoints: List[Endpoint] = field(default_factory=list)
    parameters: Set[str] = field(default_factory=set)
    technologies: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)

    def add_endpoint(self, endpoint: Endpoint):
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
            self.parameters.update(endpoint.parameters)


@dataclass
class Memory:
    """Session memory for tracking state."""
    target: str
    attack_surface: AttackSurface = None
    findings: List[Finding] = field(default_factory=list)
    attempted_attacks: List[Dict] = field(default_factory=list)
    session_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.attack_surface is None:
            self.attack_surface = AttackSurface(target=self.target)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def get_findings_by_type(self, vuln_type: str) -> List[Finding]:
        return [f for f in self.findings if f.type == vuln_type]

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
