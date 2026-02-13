"""
BREACH.AI v2 - Kill Chain Architecture

The 7-phase kill chain that transforms BREACH.AI from a scanner to a breach prover.

Phases:
1. RECON - Deep reconnaissance and attack surface mapping
2. INITIAL_ACCESS - Gain first foothold via vulnerabilities
3. FOOTHOLD - Stabilize access and establish persistence
4. ESCALATION - Escalate privileges to root/admin
5. LATERAL - Move through the network/cloud
6. DATA_ACCESS - Access and sample sensitive data
7. PROOF - Generate undeniable evidence of breach
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


class BreachPhase(Enum):
    """The 7 phases of the kill chain."""
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    FOOTHOLD = "foothold"
    ESCALATION = "escalation"
    LATERAL = "lateral"
    DATA_ACCESS = "data_access"
    PROOF = "proof"

    @property
    def display_name(self) -> str:
        return {
            BreachPhase.RECON: "Reconnaissance",
            BreachPhase.INITIAL_ACCESS: "Initial Access",
            BreachPhase.FOOTHOLD: "Establish Foothold",
            BreachPhase.ESCALATION: "Privilege Escalation",
            BreachPhase.LATERAL: "Lateral Movement",
            BreachPhase.DATA_ACCESS: "Data Access",
            BreachPhase.PROOF: "Proof Generation",
        }[self]

    @property
    def order(self) -> int:
        return list(BreachPhase).index(self)

    def __lt__(self, other):
        return self.order < other.order

    def __le__(self, other):
        return self.order <= other.order


class DecisionMode(Enum):
    """Brain decision modes based on current state."""
    EXPLORATION = "exploration"      # Wide search, many options
    EXPLOITATION = "exploitation"    # Deep focus on promising vector
    ESCALATION = "escalation"        # Focus on privilege increase
    COLLECTION = "collection"        # Evidence gathering


class AccessLevel(Enum):
    """Levels of access achieved during breach."""
    NONE = "none"
    ANONYMOUS = "anonymous"          # Unauthenticated access
    USER = "user"                    # Authenticated as regular user
    PRIVILEGED_USER = "privileged_user"  # User with elevated permissions
    ADMIN = "admin"                  # Administrative access
    DATABASE = "database"            # Direct database access
    CLOUD_USER = "cloud_user"        # Cloud identity assumed
    CLOUD_ADMIN = "cloud_admin"      # Cloud admin privileges
    SYSTEM = "system"                # System-level access
    ROOT = "root"                    # Full root/domain admin

    @property
    def severity_weight(self) -> int:
        """Weight for calculating breach severity."""
        return {
            AccessLevel.NONE: 0,
            AccessLevel.ANONYMOUS: 1,
            AccessLevel.USER: 2,
            AccessLevel.PRIVILEGED_USER: 3,
            AccessLevel.ADMIN: 5,
            AccessLevel.DATABASE: 6,
            AccessLevel.CLOUD_USER: 4,
            AccessLevel.CLOUD_ADMIN: 7,
            AccessLevel.SYSTEM: 8,
            AccessLevel.ROOT: 10,
        }[self]

    def __lt__(self, other):
        return self.severity_weight < other.severity_weight

    def __le__(self, other):
        return self.severity_weight <= other.severity_weight

    def __gt__(self, other):
        return self.severity_weight > other.severity_weight

    def __ge__(self, other):
        return self.severity_weight >= other.severity_weight


class EvidenceType(Enum):
    """Types of evidence that prove breach."""
    SCREENSHOT = "screenshot"
    COMMAND_OUTPUT = "command_output"
    DATA_SAMPLE = "data_sample"
    FILE_CONTENT = "file_content"
    NETWORK_CAPTURE = "network_capture"
    API_RESPONSE = "api_response"
    CREDENTIAL = "credential"
    TOKEN = "token"


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __lt__(self, other):
        return self.weight < other.weight


@dataclass
class Evidence:
    """Proof of breach - the undeniable evidence."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType = EvidenceType.API_RESPONSE
    description: str = ""
    proves: str = ""  # What does this prove?

    # Content
    content: Any = None
    content_type: str = "text/plain"
    content_hash: Optional[str] = None

    # Context
    action_that_generated: str = ""
    target_system: str = ""
    phase: Optional[BreachPhase] = None

    # Safety
    is_redacted: bool = False
    redaction_notes: Optional[str] = None

    severity: Severity = Severity.INFO
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "description": self.description,
            "proves": self.proves,
            "content_preview": str(self.content)[:500] if self.content else None,
            "content_type": self.content_type,
            "action_that_generated": self.action_that_generated,
            "target_system": self.target_system,
            "phase": self.phase.value if self.phase else None,
            "is_redacted": self.is_redacted,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ModuleResult:
    """Result from a module execution."""
    success: bool
    module_name: str
    phase: BreachPhase

    # What happened
    action: str = ""
    details: str = ""
    error: Optional[str] = None

    # What we gained
    access_gained: Optional[AccessLevel] = None
    evidence: list[Evidence] = field(default_factory=list)
    data_extracted: Optional[Any] = None
    credentials_found: list[dict] = field(default_factory=list)
    tokens_found: list[dict] = field(default_factory=list)

    # What we learned
    new_targets: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    technologies_detected: list[str] = field(default_factory=list)

    # For chaining
    enables_modules: list[str] = field(default_factory=list)
    chain_data: dict = field(default_factory=dict)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "module_name": self.module_name,
            "phase": self.phase.value,
            "action": self.action,
            "details": self.details,
            "error": self.error,
            "access_gained": self.access_gained.value if self.access_gained else None,
            "evidence_count": len(self.evidence),
            "credentials_found": len(self.credentials_found),
            "tokens_found": len(self.tokens_found),
            "new_targets": self.new_targets,
            "new_endpoints": len(self.new_endpoints),
            "technologies_detected": self.technologies_detected,
            "enables_modules": self.enables_modules,
            "duration_ms": self.duration_ms,
        }


@dataclass
class BreachStep:
    """A single step in the breach chain."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    sequence_num: int = 0
    phase: BreachPhase = BreachPhase.RECON

    # What was attempted
    module_name: str = ""
    action: str = ""
    target: str = ""
    parameters: dict = field(default_factory=dict)

    # AI reasoning
    reasoning: str = ""
    expected_outcome: str = ""
    if_fails: str = ""

    # Result
    success: bool = False
    result: Optional[ModuleResult] = None
    error: Optional[str] = None

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "sequence_num": self.sequence_num,
            "phase": self.phase.value,
            "module_name": self.module_name,
            "action": self.action,
            "target": self.target,
            "reasoning": self.reasoning,
            "expected_outcome": self.expected_outcome,
            "success": self.success,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class BreachSession:
    """A complete breach session - runs for hours/days."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""

    # Status
    current_phase: BreachPhase = BreachPhase.RECON
    decision_mode: DecisionMode = DecisionMode.EXPLORATION
    is_running: bool = False
    is_complete: bool = False

    # Configuration
    config: dict = field(default_factory=dict)
    timeout_hours: int = 24
    scope: list[str] = field(default_factory=list)
    rules_of_engagement: dict = field(default_factory=dict)

    # Progress
    steps: list[BreachStep] = field(default_factory=list)
    current_step: int = 0

    # Results
    breach_achieved: bool = False
    highest_access: AccessLevel = AccessLevel.NONE
    systems_compromised: list[str] = field(default_factory=list)
    evidence_collected: list[Evidence] = field(default_factory=list)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_activity_at: Optional[datetime] = None

    def add_step(self, step: BreachStep):
        """Add a step to the session."""
        step.session_id = self.id
        step.sequence_num = len(self.steps) + 1
        self.steps.append(step)
        self.current_step = step.sequence_num
        self.last_activity_at = datetime.utcnow()

    def update_access(self, new_access: AccessLevel):
        """Update highest access level."""
        if new_access > self.highest_access:
            self.highest_access = new_access

    def add_evidence(self, evidence: Evidence):
        """Add evidence to collection."""
        self.evidence_collected.append(evidence)

    def get_steps_for_phase(self, phase: BreachPhase) -> list[BreachStep]:
        """Get all steps for a specific phase."""
        return [s for s in self.steps if s.phase == phase]

    def get_successful_steps(self) -> list[BreachStep]:
        """Get all successful steps."""
        return [s for s in self.steps if s.success]

    def get_duration_seconds(self) -> float:
        """Get session duration in seconds."""
        if not self.started_at:
            return 0
        end = self.completed_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "current_phase": self.current_phase.value,
            "decision_mode": self.decision_mode.value,
            "is_running": self.is_running,
            "is_complete": self.is_complete,
            "breach_achieved": self.breach_achieved,
            "highest_access": self.highest_access.value,
            "systems_compromised": self.systems_compromised,
            "steps_count": len(self.steps),
            "evidence_count": len(self.evidence_collected),
            "duration_seconds": self.get_duration_seconds(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class BrainDecision:
    """A decision made by the AI brain."""
    module_name: str
    action: str
    target: str
    parameters: dict = field(default_factory=dict)

    # Reasoning
    reasoning: str = ""
    expected_outcome: str = ""
    if_fails: str = ""

    # Priority
    priority: int = 5  # 1-10
    phase: BreachPhase = BreachPhase.RECON
    decision_mode: DecisionMode = DecisionMode.EXPLORATION

    # For custom actions
    requires_custom_script: bool = False
    custom_script: Optional[str] = None

    def to_step(self) -> BreachStep:
        """Convert decision to a breach step."""
        return BreachStep(
            phase=self.phase,
            module_name=self.module_name,
            action=self.action,
            target=self.target,
            parameters=self.parameters,
            reasoning=self.reasoning,
            expected_outcome=self.expected_outcome,
            if_fails=self.if_fails,
        )


# Chain mapping - what phases enable what
PHASE_CHAINS = {
    BreachPhase.RECON: [BreachPhase.INITIAL_ACCESS],
    BreachPhase.INITIAL_ACCESS: [BreachPhase.FOOTHOLD, BreachPhase.DATA_ACCESS],
    BreachPhase.FOOTHOLD: [BreachPhase.ESCALATION, BreachPhase.LATERAL],
    BreachPhase.ESCALATION: [BreachPhase.LATERAL, BreachPhase.DATA_ACCESS],
    BreachPhase.LATERAL: [BreachPhase.ESCALATION, BreachPhase.DATA_ACCESS],
    BreachPhase.DATA_ACCESS: [BreachPhase.PROOF],
    BreachPhase.PROOF: [],
}


def can_transition_to(current: BreachPhase, target: BreachPhase) -> bool:
    """Check if we can transition from current phase to target phase."""
    # Can always go to proof if we have access
    if target == BreachPhase.PROOF:
        return current >= BreachPhase.INITIAL_ACCESS

    # Check allowed transitions
    return target in PHASE_CHAINS.get(current, [])
