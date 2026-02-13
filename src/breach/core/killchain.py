"""
BREACH Kill Chain Types
=======================

Attack chain tracking for multi-stage exploits.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum


class KillChainPhase(str, Enum):
    """Cyber kill chain phases."""
    RECON = "reconnaissance"
    WEAPONIZE = "weaponization"
    DELIVER = "delivery"
    EXPLOIT = "exploitation"
    INSTALL = "installation"
    COMMAND = "command_and_control"
    ACTION = "actions_on_objectives"


class BreachPhase(str, Enum):
    """BREACH testing phases."""
    RECON = "reconnaissance"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


@dataclass
class KillChainStep:
    """A single step in the kill chain."""
    phase: KillChainPhase
    technique: str
    description: str
    evidence: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    success: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BreachStep:
    """A single step in a breach session."""
    name: str
    phase: str
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    success: bool = False
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "phase": self.phase,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
        }


@dataclass
class BreachSession:
    """A complete breach testing session."""
    target: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    kill_chain: Optional["KillChain"] = None
    findings: List[Any] = field(default_factory=list)
    attack_surface: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Any):
        self.findings.append(finding)

    def complete(self):
        self.completed_at = datetime.utcnow()

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings_count": len(self.findings),
            "kill_chain": self.kill_chain.to_dict() if self.kill_chain else None,
        }


@dataclass
class KillChain:
    """Complete attack kill chain."""
    target: str
    steps: List[KillChainStep] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    final_impact: str = ""

    def add_step(self, step: KillChainStep):
        self.steps.append(step)

    def get_successful_steps(self) -> List[KillChainStep]:
        return [s for s in self.steps if s.success]

    def get_phases_reached(self) -> List[KillChainPhase]:
        return list(set(s.phase for s in self.steps if s.success))

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "steps": [
                {
                    "phase": s.phase.value,
                    "technique": s.technique,
                    "description": s.description,
                    "success": s.success,
                }
                for s in self.steps
            ],
            "phases_reached": [p.value for p in self.get_phases_reached()],
            "final_impact": self.final_impact,
        }
