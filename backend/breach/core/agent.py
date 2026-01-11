"""
BREACH.AI - Core Agent Loop

The main orchestration engine that runs the autonomous security assessment.
This is the brain that coordinates reconnaissance, attacks, and reporting.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from backend.breach.attacks.engine import AttackEngine
from backend.breach.core.enhanced_brain import EnhancedAgentBrain
from backend.breach.core.memory import AccessLevel, Memory
from backend.breach.core.scheduler import AttackScheduler
from backend.breach.recon.engine import ReconEngine
from backend.breach.report.generator import ReportGenerator
from backend.breach.utils.http import HTTPClient
from backend.breach.utils.logger import logger


class AgentState(Enum):
    """Current state of the breach agent."""
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"
    ATTACKING = "attacking"
    ESCALATING = "escalating"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanConfig:
    """Configuration for a breach scan."""
    target_url: str
    max_duration_hours: int = 24
    parallel_attacks: int = 5
    aggressive_mode: bool = True
    include_infrastructure: bool = True
    include_cloud: bool = True
    stop_on_critical: bool = False

    # Scope limitations
    allowed_domains: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    rate_limit_rps: int = 50


@dataclass
class ScanResult:
    """Result of a breach scan."""
    target: str
    start_time: datetime
    end_time: datetime
    state: AgentState
    findings: list
    access_achieved: AccessLevel

    # Timing metrics
    time_to_first_finding: Optional[timedelta] = None
    time_to_initial_access: Optional[timedelta] = None
    time_to_admin: Optional[timedelta] = None
    time_to_full_compromise: Optional[timedelta] = None

    # Stats
    total_requests: int = 0
    endpoints_discovered: int = 0
    attack_attempts: int = 0
    successful_attacks: int = 0

    def severity_counts(self) -> dict:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class BreachAgent:
    """
    The autonomous breach agent.

    This is the main class that orchestrates the entire security assessment.
    It uses Claude to make intelligent decisions about what to attack next,
    how to chain vulnerabilities, and when to escalate.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.state = AgentState.INITIALIZING
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Core components
        self.brain = EnhancedAgentBrain()
        self.memory = Memory(target=config.target_url)
        self.scheduler = AttackScheduler()
        self.recon = ReconEngine()
        self.attack_engine: Optional[AttackEngine] = None
        self.reporter = ReportGenerator()
        self.http_client: Optional[HTTPClient] = None

        # Runtime state
        self._running = False
        self._current_access = AccessLevel.NONE

    async def run(self) -> ScanResult:
        """
        Execute the full breach assessment.

        This is the main entry point that runs the complete attack cycle:
        1. Reconnaissance - Gather information about the target
        2. Attack - Systematically try to find vulnerabilities
        3. Escalate - Chain vulnerabilities for deeper access
        4. Report - Generate brutal evidence report
        """
        self.start_time = datetime.utcnow()
        self._running = True
        deadline = self.start_time + timedelta(hours=self.config.max_duration_hours)

        logger.banner()
        logger.info(f"Starting breach assessment of {self.config.target_url}")
        logger.info(f"Max duration: {self.config.max_duration_hours} hours")
        logger.info(f"Deadline: {deadline.isoformat()}")

        # Initialize HTTP client
        self.http_client = HTTPClient(
            base_url=self.config.target_url,
            rate_limit=self.config.rate_limit_rps,
        )

        # Initialize attack engine
        self.attack_engine = AttackEngine(http_client=self.http_client)

        try:
            # Phase 1: Reconnaissance
            await self._run_reconnaissance()

            # Phase 2: Main attack loop
            await self._run_attack_loop(deadline)

            # Phase 3: Post-exploitation (if we got access)
            if self._current_access >= AccessLevel.USER:
                await self._run_post_exploitation()

            self.state = AgentState.COMPLETED

        except Exception as e:
            logger.error(f"Agent failed with error: {e}")
            self.state = AgentState.FAILED
            raise

        finally:
            self._running = False
            self.end_time = datetime.utcnow()
            if self.http_client:
                await self.http_client.close()

        # Phase 4: Generate report
        return await self._generate_report()

    async def _run_reconnaissance(self):
        """Phase 1: Reconnaissance"""
        self.state = AgentState.RECONNAISSANCE
        logger.phase_start("PHASE 1: RECONNAISSANCE")

        # Run full recon
        recon_results = await self.recon.run_full_recon(self.config.target_url)

        # Store findings
        for finding in recon_results.findings:
            self.memory.add_finding(finding)

            if finding.severity.value in ["critical", "high"]:
                logger.finding(finding.severity.value, finding.title, finding.target)

        # Update attack surface
        self.memory.attack_surface = recon_results.attack_surface

        logger.info(f"Recon complete. Attack surface:")
        logger.info(f"  - Subdomains: {len(recon_results.attack_surface.subdomains)}")
        logger.info(f"  - Endpoints: {len(recon_results.attack_surface.endpoints)}")
        logger.info(f"  - Technologies: {recon_results.attack_surface.technologies}")

        # Prioritize attack plan based on recon
        self.scheduler.prioritize(recon_results.attack_surface, self.memory.findings)

    async def _run_attack_loop(self, deadline: datetime):
        """Phase 2: Main Attack Loop"""
        self.state = AgentState.ATTACKING
        logger.phase_start("PHASE 2: ATTACK LOOP")

        attack_queue = asyncio.Queue()

        # Initial attack queue from scheduler
        for attack in self.scheduler.get_initial_attacks():
            await attack_queue.put(attack)

        # Parallel attack workers
        workers = [
            asyncio.create_task(self._attack_worker(attack_queue, deadline, i))
            for i in range(self.config.parallel_attacks)
        ]

        # Main decision loop
        while datetime.utcnow() < deadline and self._running:
            # Check if we've achieved full compromise
            if self._current_access >= AccessLevel.ROOT:
                logger.info("Full compromise achieved. Continuing for completeness...")
                if self.config.stop_on_critical:
                    break

            # Ask brain what to try next
            context = self._build_context()
            next_actions = await self.brain.decide_next_actions(context)

            for action in next_actions:
                # Handle custom script actions
                if action.requires_custom_script:
                    result = await self.brain.execute_custom_script_action(action, context)
                    if result and result.success:
                        logger.info(f"Custom script succeeded: {result.output[:100]}...")
                else:
                    await attack_queue.put(action)

            # Check for possible vulnerability chains
            if len(self.memory.findings) >= 2:
                chain_action = await self.brain.generate_chain_attack(
                    self.memory.findings, context
                )
                if chain_action:
                    await attack_queue.put(chain_action)

            # Brief pause to avoid spinning
            await asyncio.sleep(1)

            # Check if all work is done
            if attack_queue.empty() and all(w.done() for w in workers):
                logger.info("All attacks exhausted")
                break

        # Cancel workers
        for worker in workers:
            worker.cancel()

        logger.phase_end("ATTACK LOOP", {
            "attempts": self.memory.total_attacks,
            "findings": len(self.memory.findings),
        })

    async def _attack_worker(self, queue: asyncio.Queue, deadline: datetime, worker_id: int):
        """Worker that executes attacks from the queue."""
        while datetime.utcnow() < deadline and self._running:
            try:
                # Get next attack with timeout
                attack = await asyncio.wait_for(queue.get(), timeout=5)

                logger.debug(f"Worker {worker_id}: Executing {attack.name}")

                # Convert AttackAction to ScheduledAttack if needed
                from backend.breach.core.scheduler import ScheduledAttack, AttackCategory

                if hasattr(attack, 'attack_type'):
                    scheduled = ScheduledAttack.create(
                        name=attack.name,
                        attack_type=attack.attack_type,
                        category=AttackCategory.INJECTION,  # Default
                        target=attack.target,
                        endpoint=attack.parameters.get('endpoint'),
                        parameter=attack.parameters.get('parameter'),
                        priority=attack.priority,
                    )
                else:
                    scheduled = attack

                # Execute the attack
                result = await self.attack_engine.execute(scheduled)

                # Process result
                if result and result.success:
                    logger.attack_success(scheduled.attack_type, result.details[:50] if result.details else "")

                    # Store finding
                    finding = result.to_finding()
                    self.memory.add_finding(finding)

                    # Update access level
                    if result.access_gained:
                        self._update_access(result.access_gained)

                    # Ask brain for follow-up attacks
                    follow_ups = await self.brain.get_follow_up_attacks(result)
                    for follow_up in follow_ups:
                        await queue.put(follow_up)
                else:
                    self.memory.add_failed_attack(f"{scheduled.attack_type}:{scheduled.endpoint}")

                queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Worker {worker_id} error: {e}")
                continue

    async def _run_post_exploitation(self):
        """Phase 3: Post-Exploitation"""
        self.state = AgentState.POST_EXPLOITATION
        logger.phase_start("PHASE 3: POST-EXPLOITATION")

        # Ask brain what to demonstrate
        context = self._build_context()
        post_ex_plan = await self.brain.plan_post_exploitation(context)

        for action in post_ex_plan:
            logger.info(f"Demonstrating: {action.description}")

            # Execute post-exploitation using scripting capability
            if action.action_type == "data_extraction":
                result = await self.brain.scripting.extract_breach_evidence(
                    access_type=action.parameters.get("system", "database"),
                    system=action.parameters.get("table", "unknown"),
                    credentials=context.get("credentials", {}),
                    context=context
                )

                if result and result.data_extracted:
                    self.memory.add_finding(
                        self.memory.findings[0].__class__.create(
                            title=f"Data Extraction: {action.name}",
                            vuln_type="data_extraction",
                            severity=self.memory.findings[0].severity.__class__.HIGH,
                            target=self.config.target_url,
                            details=action.description,
                            data_exposed=str(result.data_extracted)[:500],
                        )
                    )

        logger.phase_end("POST-EXPLOITATION")

    async def _generate_report(self) -> ScanResult:
        """Phase 4: Report Generation"""
        self.state = AgentState.REPORTING
        logger.phase_start("PHASE 4: GENERATING REPORT")

        # Calculate timing metrics
        time_to_first = None
        time_to_access = None
        time_to_admin = None
        time_to_root = None

        if self.memory.findings:
            first_finding = min(self.memory.findings, key=lambda f: f.discovered_at)
            time_to_first = first_finding.discovered_at - self.start_time

        for milestone in self.memory.access_milestones:
            duration = milestone.achieved_at - self.start_time
            if milestone.level == AccessLevel.USER and not time_to_access:
                time_to_access = duration
            elif milestone.level == AccessLevel.ADMIN and not time_to_admin:
                time_to_admin = duration
            elif milestone.level == AccessLevel.ROOT and not time_to_root:
                time_to_root = duration

        result = ScanResult(
            target=self.config.target_url,
            start_time=self.start_time,
            end_time=self.end_time,
            state=self.state,
            findings=self.memory.findings,
            access_achieved=self._current_access,
            time_to_first_finding=time_to_first,
            time_to_initial_access=time_to_access,
            time_to_admin=time_to_admin,
            time_to_full_compromise=time_to_root,
            total_requests=self.http_client.request_count if self.http_client else 0,
            endpoints_discovered=len(self.memory.attack_surface.endpoints),
            attack_attempts=self.memory.total_attacks,
            successful_attacks=len(self.memory.findings),
        )

        # Generate the brutal report
        await self.reporter.generate(result, self.memory)

        logger.phase_end("REPORT GENERATION")

        return result

    def _build_context(self) -> dict:
        """Build context for brain decisions."""
        return {
            "target": self.config.target_url,
            "current_access": self._current_access.value,
            "findings": [f.to_dict() for f in self.memory.findings[-20:]],
            "failed_attacks": list(self.memory.failed_attacks)[-50:],
            "attack_surface": self.memory.attack_surface.to_dict(),
            "elapsed_time": (datetime.utcnow() - self.start_time).total_seconds(),
            "credentials": {c.service: [{"username": c.username}] for c in self.memory.credentials},
            "access_tokens": [t.to_dict() for t in self.memory.tokens],
        }

    def _update_access(self, new_access: AccessLevel):
        """Update access level and record milestone."""
        if new_access > self._current_access:
            logger.info(f"ACCESS ESCALATED: {self._current_access.value} -> {new_access.value}")
            self._current_access = new_access
            self.memory.record_access_milestone(new_access)

    def stop(self):
        """Stop the agent gracefully."""
        logger.info("Stop requested. Finishing current attacks...")
        self._running = False


async def run_breach(target_url: str, **kwargs) -> ScanResult:
    """
    Convenience function to run a breach assessment.

    Usage:
        result = await run_breach("https://target.com", max_duration_hours=12)
    """
    config = ScanConfig(target_url=target_url, **kwargs)
    agent = BreachAgent(config)
    return await agent.run()
