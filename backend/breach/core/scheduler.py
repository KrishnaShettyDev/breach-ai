"""
BREACH.AI - Attack Scheduler

Intelligent scheduling and prioritization of attacks.
Decides what to attack next based on likelihood of success and potential impact.
"""

import heapq
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from backend.breach.core.memory import AttackSurface, Finding, Severity
from backend.breach.utils.helpers import generate_id


class AttackCategory(Enum):
    """Categories of attacks."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    XSS = "xss"
    SSRF = "ssrf"
    FILE = "file"
    INFRASTRUCTURE = "infrastructure"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class ScheduledAttack:
    """An attack scheduled for execution."""
    id: str
    name: str
    attack_type: str
    category: AttackCategory
    target: str

    # Targeting
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    method: str = "GET"

    # Priority (higher = more important)
    priority: int = 50
    reasoning: str = ""

    # Attack configuration
    payloads: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    # State
    scheduled_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed, skipped

    # For heap comparison
    def __lt__(self, other):
        # Higher priority first (negate for min-heap)
        return self.priority > other.priority

    def signature(self) -> str:
        """Generate unique signature for this attack."""
        return f"{self.attack_type}:{self.endpoint}:{self.parameter}:{self.method}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "attack_type": self.attack_type,
            "category": self.category.value,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "priority": self.priority,
            "reasoning": self.reasoning,
            "status": self.status,
        }

    @classmethod
    def create(
        cls,
        name: str,
        attack_type: str,
        category: AttackCategory,
        target: str,
        **kwargs
    ) -> "ScheduledAttack":
        return cls(
            id=generate_id("ATK"),
            name=name,
            attack_type=attack_type,
            category=category,
            target=target,
            **kwargs
        )


class AttackScheduler:
    """
    Intelligent attack scheduler.

    Prioritizes attacks based on:
    - Likelihood of success (based on recon data)
    - Potential impact (critical vulns first)
    - Attack surface coverage
    - Previous findings (chain attacks)
    """

    # Priority weights for different factors
    WEIGHTS = {
        "technology_match": 20,   # Attack matches detected technology
        "sensitive_endpoint": 15,  # Endpoint looks sensitive
        "has_parameters": 10,      # Endpoint has injectable parameters
        "admin_path": 25,          # Path contains admin/api/internal
        "file_exposure": 30,       # Sensitive file detected
        "low_hanging": 20,         # Common/easy vulnerabilities
        "chain_potential": 15,     # Can chain with existing finding
    }

    # Patterns for sensitive endpoints
    SENSITIVE_PATTERNS = [
        "admin", "api", "internal", "debug", "test", "dev",
        "login", "auth", "user", "account", "profile",
        "upload", "file", "download", "export", "import",
        "config", "settings", "backup", "database", "db",
        "graphql", "rest", "v1", "v2", "private",
    ]

    def __init__(self):
        self._queue: list[ScheduledAttack] = []
        self._completed: list[ScheduledAttack] = []
        self._skipped: set[str] = set()
        self.total_scheduled = 0

    def prioritize(self, attack_surface: AttackSurface, findings: list[Finding] = None):
        """
        Generate prioritized attack queue from attack surface.

        Args:
            attack_surface: Mapped attack surface
            findings: Existing findings to inform chaining
        """
        findings = findings or []

        # Generate attacks for each endpoint
        for endpoint in attack_surface.endpoints:
            attacks = self._generate_attacks_for_endpoint(
                endpoint,
                attack_surface.technologies,
                findings
            )
            for attack in attacks:
                self.schedule(attack)

        # Add infrastructure attacks for sensitive files
        for sensitive_file in attack_surface.sensitive_files:
            self._schedule_file_attacks(sensitive_file, attack_surface.target)

        # Add port-based attacks
        for port_info in attack_surface.open_ports:
            self._schedule_port_attacks(port_info, attack_surface.target)

    def _generate_attacks_for_endpoint(
        self,
        endpoint: Any,
        technologies: list[str],
        findings: list[Finding]
    ) -> list[ScheduledAttack]:
        """Generate attacks for a single endpoint."""
        attacks = []
        url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
        params = endpoint.parameters if hasattr(endpoint, 'parameters') else []

        base_priority = 50

        # Check for sensitive patterns
        url_lower = url.lower()
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in url_lower:
                base_priority += self.WEIGHTS["sensitive_endpoint"]
                break

        # Check for admin paths
        if any(p in url_lower for p in ["admin", "internal", "api", "debug"]):
            base_priority += self.WEIGHTS["admin_path"]

        # SQL Injection attacks (if parameters exist)
        if params:
            for param in params:
                attacks.append(ScheduledAttack.create(
                    name=f"SQL Injection on {param}",
                    attack_type="sqli",
                    category=AttackCategory.INJECTION,
                    target=url,
                    endpoint=url,
                    parameter=param,
                    priority=base_priority + self.WEIGHTS["has_parameters"],
                    reasoning=f"Testing parameter {param} for SQL injection",
                ))

                attacks.append(ScheduledAttack.create(
                    name=f"XSS on {param}",
                    attack_type="xss",
                    category=AttackCategory.XSS,
                    target=url,
                    endpoint=url,
                    parameter=param,
                    priority=base_priority + self.WEIGHTS["has_parameters"] - 5,
                    reasoning=f"Testing parameter {param} for XSS",
                ))

        # SSRF attacks (URL parameters)
        url_params = [p for p in params if any(
            kw in p.lower() for kw in ["url", "link", "src", "href", "path", "file", "redirect"]
        )]
        for param in url_params:
            attacks.append(ScheduledAttack.create(
                name=f"SSRF via {param}",
                attack_type="ssrf",
                category=AttackCategory.SSRF,
                target=url,
                endpoint=url,
                parameter=param,
                priority=base_priority + 25,
                reasoning=f"Parameter {param} looks like it might accept URLs",
            ))

        # Auth bypass attempts
        if any(kw in url_lower for kw in ["login", "auth", "signin", "session"]):
            attacks.append(ScheduledAttack.create(
                name=f"Auth bypass on {url}",
                attack_type="auth_bypass",
                category=AttackCategory.AUTHENTICATION,
                target=url,
                endpoint=url,
                priority=base_priority + 20,
                reasoning="Authentication endpoint detected",
            ))

        # IDOR tests (if numeric IDs in URL)
        import re
        if re.search(r'/\d+', url) or any(
            p for p in params if any(kw in p.lower() for kw in ["id", "uid", "user", "account"])
        ):
            attacks.append(ScheduledAttack.create(
                name=f"IDOR test on {url}",
                attack_type="idor",
                category=AttackCategory.ACCESS_CONTROL,
                target=url,
                endpoint=url,
                priority=base_priority + 15,
                reasoning="Endpoint contains ID references",
            ))

        # Technology-specific attacks
        for tech in technologies:
            tech_lower = tech.lower()

            if tech_lower == "php":
                attacks.append(ScheduledAttack.create(
                    name=f"PHP LFI on {url}",
                    attack_type="lfi",
                    category=AttackCategory.FILE,
                    target=url,
                    endpoint=url,
                    priority=base_priority + self.WEIGHTS["technology_match"],
                    reasoning="PHP detected - testing for LFI",
                ))

            if tech_lower in ["express", "node", "nodejs"]:
                attacks.append(ScheduledAttack.create(
                    name=f"Prototype pollution on {url}",
                    attack_type="prototype_pollution",
                    category=AttackCategory.INJECTION,
                    target=url,
                    endpoint=url,
                    priority=base_priority + self.WEIGHTS["technology_match"],
                    reasoning="Node.js detected - testing for prototype pollution",
                ))

            if tech_lower in ["jinja", "jinja2", "flask", "django"]:
                attacks.append(ScheduledAttack.create(
                    name=f"SSTI on {url}",
                    attack_type="ssti",
                    category=AttackCategory.INJECTION,
                    target=url,
                    endpoint=url,
                    priority=base_priority + self.WEIGHTS["technology_match"] + 10,
                    reasoning="Template engine detected - testing for SSTI",
                ))

        return attacks

    def _schedule_file_attacks(self, file_path: str, target: str):
        """Schedule attacks for exposed sensitive files."""
        file_lower = file_path.lower()
        priority = 80  # High priority for sensitive files

        if ".git" in file_lower:
            self.schedule(ScheduledAttack.create(
                name=f"Git repository extraction",
                attack_type="git_dump",
                category=AttackCategory.FILE,
                target=target,
                endpoint=file_path,
                priority=priority + self.WEIGHTS["file_exposure"],
                reasoning="Exposed .git directory found",
            ))

        if ".env" in file_lower:
            self.schedule(ScheduledAttack.create(
                name=f"Environment file extraction",
                attack_type="env_dump",
                category=AttackCategory.FILE,
                target=target,
                endpoint=file_path,
                priority=priority + self.WEIGHTS["file_exposure"],
                reasoning="Exposed .env file found",
            ))

        if any(kw in file_lower for kw in ["backup", ".sql", ".bak", ".old"]):
            self.schedule(ScheduledAttack.create(
                name=f"Backup file extraction",
                attack_type="backup_dump",
                category=AttackCategory.FILE,
                target=target,
                endpoint=file_path,
                priority=priority + self.WEIGHTS["file_exposure"],
                reasoning="Backup file detected",
            ))

    def _schedule_port_attacks(self, port_info: dict, target: str):
        """Schedule attacks for open ports."""
        port = port_info.get("port")
        service = port_info.get("service", "").lower()

        # Database ports
        if port in [3306, 5432, 1433, 27017, 6379]:
            self.schedule(ScheduledAttack.create(
                name=f"Database attack on port {port}",
                attack_type="database_attack",
                category=AttackCategory.INFRASTRUCTURE,
                target=target,
                endpoint=f"{target}:{port}",
                priority=90,
                reasoning=f"Database port {port} exposed",
                config={"port": port, "service": service},
            ))

        # Admin interfaces
        if port in [8080, 8443, 9090, 9200, 5601]:
            self.schedule(ScheduledAttack.create(
                name=f"Admin interface on port {port}",
                attack_type="admin_interface",
                category=AttackCategory.AUTHENTICATION,
                target=target,
                endpoint=f"{target}:{port}",
                priority=85,
                reasoning=f"Potential admin interface on port {port}",
                config={"port": port},
            ))

    def schedule(self, attack: ScheduledAttack):
        """Add an attack to the queue."""
        # Skip if already scheduled with same signature
        sig = attack.signature()
        if sig in self._skipped:
            return

        heapq.heappush(self._queue, attack)
        self.total_scheduled += 1

    def get_next(self) -> Optional[ScheduledAttack]:
        """Get the next highest priority attack."""
        while self._queue:
            attack = heapq.heappop(self._queue)
            sig = attack.signature()

            if sig in self._skipped:
                continue

            attack.status = "running"
            attack.started_at = datetime.utcnow()
            return attack

        return None

    def complete(self, attack: ScheduledAttack, success: bool = False):
        """Mark an attack as completed."""
        attack.status = "completed" if success else "failed"
        attack.completed_at = datetime.utcnow()
        self._completed.append(attack)

        # Skip similar attacks if successful
        if success:
            self._skipped.add(attack.signature())

    def skip(self, attack_signature: str):
        """Skip an attack (don't run it)."""
        self._skipped.add(attack_signature)

    def get_initial_attacks(self, limit: int = 20) -> list[ScheduledAttack]:
        """Get initial batch of attacks to start with."""
        attacks = []
        for _ in range(min(limit, len(self._queue))):
            attack = self.get_next()
            if attack:
                attacks.append(attack)
        return attacks

    def pending_count(self) -> int:
        """Number of attacks still pending."""
        return len(self._queue)

    def completed_count(self) -> int:
        """Number of completed attacks."""
        return len(self._completed)

    def success_count(self) -> int:
        """Number of successful attacks."""
        return sum(1 for a in self._completed if a.status == "completed")

    def stats(self) -> dict:
        """Get scheduler statistics."""
        return {
            "total_scheduled": self.total_scheduled,
            "pending": self.pending_count(),
            "completed": self.completed_count(),
            "successful": self.success_count(),
            "skipped": len(self._skipped),
        }

    def adjust_priorities(self, findings: list[Finding]):
        """
        Adjust attack priorities based on new findings.

        If we find a vulnerability, prioritize similar attacks on other endpoints.
        """
        for finding in findings:
            # Boost priority for same attack type on different endpoints
            for attack in self._queue:
                if attack.attack_type == finding.vuln_type:
                    attack.priority += 10

            # If we found credentials, boost auth-related attacks
            if finding.vuln_type in ["credential_exposure", "auth_bypass"]:
                for attack in self._queue:
                    if attack.category == AttackCategory.AUTHENTICATION:
                        attack.priority += 20

        # Re-heapify after priority changes
        heapq.heapify(self._queue)
