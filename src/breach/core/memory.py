"""
BREACH.AI - Memory System

Central storage for findings, credentials, attack surface, and scan state.
This is the "brain's memory" - everything discovered during a scan.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from breach.utils.helpers import generate_id


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __gt__(self, other):
        return not self.__lt__(other) and self != other


class AccessLevel(Enum):
    """Levels of access achieved."""
    NONE = "none"
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    ROOT = "root"
    DATABASE = "database"
    CLOUD = "cloud"

    def __lt__(self, other):
        order = [AccessLevel.NONE, AccessLevel.ANONYMOUS, AccessLevel.USER,
                 AccessLevel.ADMIN, AccessLevel.DATABASE, AccessLevel.CLOUD, AccessLevel.ROOT]
        return order.index(self) < order.index(other)

    def __ge__(self, other):
        return not self.__lt__(other)

    def __gt__(self, other):
        return not self.__lt__(other) and self != other


@dataclass
class Evidence:
    """Evidence of successful exploitation."""
    type: str  # screenshot, data_sample, request_response, poc_script
    description: str
    content: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "description": self.description,
            "content": str(self.content)[:1000] if self.content else None,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Finding:
    """A security finding/vulnerability."""
    id: str
    title: str
    vuln_type: str
    severity: Severity
    target: str

    # Details
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    details: str = ""

    # Evidence
    evidence: list[Evidence] = field(default_factory=list)
    request: Optional[str] = None
    response: Optional[str] = None

    # Impact
    access_gained: Optional[AccessLevel] = None
    data_exposed: Optional[str] = None

    # Metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    verified: bool = False
    false_positive: bool = False

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def add_evidence(self, evidence_type: str, description: str, content: Any):
        """Add evidence to this finding."""
        self.evidence.append(Evidence(
            type=evidence_type,
            description=description,
            content=content,
        ))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload": self.payload,
            "details": self.details,
            "evidence": [e.to_dict() for e in self.evidence],
            "access_gained": self.access_gained.value if self.access_gained else None,
            "data_exposed": self.data_exposed,
            "discovered_at": self.discovered_at.isoformat(),
            "verified": self.verified,
            "remediation": self.remediation,
            "references": self.references,
        }

    @classmethod
    def create(
        cls,
        title: str,
        vuln_type: str,
        severity: Severity,
        target: str,
        **kwargs
    ) -> "Finding":
        """Factory method to create a finding."""
        return cls(
            id=generate_id("VULN"),
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            target=target,
            **kwargs
        )


@dataclass
class Credential:
    """A discovered credential."""
    id: str
    username: str
    password: Optional[str] = None
    password_hash: Optional[str] = None
    service: str = ""
    source: str = ""  # Where it was found
    valid: Optional[bool] = None  # Has it been tested?
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "password": "***REDACTED***" if self.password else None,
            "password_hash": self.password_hash[:20] + "..." if self.password_hash else None,
            "service": self.service,
            "source": self.source,
            "valid": self.valid,
        }

    @classmethod
    def create(cls, username: str, password: str = None, **kwargs) -> "Credential":
        return cls(
            id=generate_id("CRED"),
            username=username,
            password=password,
            **kwargs
        )


@dataclass
class Token:
    """A discovered authentication token."""
    id: str
    token_type: str  # jwt, api_key, session, bearer, etc.
    value: str
    service: str = ""
    source: str = ""
    valid: Optional[bool] = None
    expires_at: Optional[datetime] = None
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "token_type": self.token_type,
            "value": self.value[:20] + "..." if len(self.value) > 20 else self.value,
            "service": self.service,
            "source": self.source,
            "valid": self.valid,
        }


@dataclass
class Endpoint:
    """A discovered endpoint."""
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    requires_auth: bool = False
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "requires_auth": self.requires_auth,
            "content_type": self.content_type,
            "technologies": self.technologies,
        }


@dataclass
class AttackSurface:
    """The mapped attack surface of a target."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    open_ports: list[dict] = field(default_factory=list)
    sensitive_files: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)

    def add_subdomain(self, subdomain: str):
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)

    def add_endpoint(self, endpoint: Endpoint):
        # Avoid duplicates
        existing_urls = [e.url for e in self.endpoints]
        if endpoint.url not in existing_urls:
            self.endpoints.append(endpoint)

    def add_parameter(self, endpoint: str, param_name: str, param_type: str = "query"):
        self.parameters.append({
            "endpoint": endpoint,
            "name": param_name,
            "type": param_type,
        })

    def add_technology(self, tech: str):
        if tech.lower() not in [t.lower() for t in self.technologies]:
            self.technologies.append(tech)

    def add_port(self, port: int, service: str = "", banner: str = ""):
        self.open_ports.append({
            "port": port,
            "service": service,
            "banner": banner,
        })

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "subdomains": self.subdomains,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "parameters": self.parameters,
            "technologies": self.technologies,
            "open_ports": self.open_ports,
            "sensitive_files": self.sensitive_files,
            "forms": self.forms,
        }


@dataclass
class AccessMilestone:
    """Record of when access level was achieved."""
    level: AccessLevel
    achieved_at: datetime
    method: str  # How was this access gained
    finding_id: Optional[str] = None


class Memory:
    """
    Central memory for the breach agent.

    Stores:
    - Findings (vulnerabilities discovered)
    - Credentials and tokens
    - Attack surface mapping
    - Failed attack attempts (to avoid repeating)
    - Access milestones
    """

    def __init__(self, target: str = ""):
        self.target = target
        self.findings: list[Finding] = []
        self.credentials: list[Credential] = []
        self.tokens: list[Token] = []
        self.attack_surface = AttackSurface(target=target)
        self.failed_attacks: set[str] = set()
        self.access_milestones: list[AccessMilestone] = []

        # Stats
        self.total_attacks = 0
        self.start_time = datetime.utcnow()

    def add_finding(self, finding: Finding):
        """Add a finding to memory."""
        # Check for duplicates
        for existing in self.findings:
            if (existing.vuln_type == finding.vuln_type and
                existing.endpoint == finding.endpoint and
                existing.parameter == finding.parameter):
                # Update existing finding with new evidence if available
                if finding.evidence:
                    existing.evidence.extend(finding.evidence)
                return existing

        self.findings.append(finding)
        return finding

    def add_credential(self, credential: Credential):
        """Add a credential to memory."""
        # Check for duplicates
        for existing in self.credentials:
            if existing.username == credential.username and existing.service == credential.service:
                # Update if we now have the password
                if credential.password and not existing.password:
                    existing.password = credential.password
                return existing

        self.credentials.append(credential)
        return credential

    def add_token(self, token: Token):
        """Add a token to memory."""
        # Check for duplicates by value
        for existing in self.tokens:
            if existing.value == token.value:
                return existing

        self.tokens.append(token)
        return token

    def add_failed_attack(self, attack_signature: str):
        """Record a failed attack to avoid repeating."""
        self.failed_attacks.add(attack_signature)
        self.total_attacks += 1

    def was_attack_tried(self, attack_signature: str) -> bool:
        """Check if an attack was already tried."""
        return attack_signature in self.failed_attacks

    def record_access_milestone(self, level: AccessLevel, method: str = "", finding_id: str = None):
        """Record when a new access level was achieved."""
        # Only record if this is a new level
        existing_levels = [m.level for m in self.access_milestones]
        if level not in existing_levels:
            self.access_milestones.append(AccessMilestone(
                level=level,
                achieved_at=datetime.utcnow(),
                method=method,
                finding_id=finding_id,
            ))

    def get_highest_access(self) -> AccessLevel:
        """Get the highest access level achieved."""
        if not self.access_milestones:
            return AccessLevel.NONE
        return max(m.level for m in self.access_milestones)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> list[Finding]:
        """Get critical and high severity findings."""
        return [f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]

    def get_credentials_for_service(self, service: str) -> list[Credential]:
        """Get credentials for a specific service."""
        return [c for c in self.credentials if c.service.lower() == service.lower()]

    def severity_counts(self) -> dict:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        """Export memory to dictionary."""
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "credentials": [c.to_dict() for c in self.credentials],
            "tokens": [t.to_dict() for t in self.tokens],
            "attack_surface": self.attack_surface.to_dict(),
            "failed_attacks_count": len(self.failed_attacks),
            "total_attacks": self.total_attacks,
            "highest_access": self.get_highest_access().value,
            "severity_counts": self.severity_counts(),
        }

    def summary(self) -> str:
        """Generate a text summary of memory."""
        counts = self.severity_counts()
        return (
            f"Target: {self.target}\n"
            f"Findings: {len(self.findings)} total "
            f"({counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low)\n"
            f"Credentials: {len(self.credentials)}\n"
            f"Tokens: {len(self.tokens)}\n"
            f"Endpoints: {len(self.attack_surface.endpoints)}\n"
            f"Subdomains: {len(self.attack_surface.subdomains)}\n"
            f"Access Level: {self.get_highest_access().value}\n"
            f"Attack Attempts: {self.total_attacks}"
        )
