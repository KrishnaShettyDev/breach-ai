"""
BREACH.AI v2 - Kill Chain Orchestrator

The main engine that runs the 7-phase kill chain.
This is the brain that coordinates the entire breach assessment.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional
import json

from anthropic import Anthropic

from breach.core.killchain import (
    BreachPhase,
    BreachSession,
    BreachStep,
    BrainDecision,
    DecisionMode,
    ModuleResult,
    AccessLevel,
    Evidence,
    can_transition_to,
)
from breach.modules.base import (
    Module,
    ModuleConfig,
    get_module,
    get_modules_for_phase,
)
from breach.utils.logger import logger


# Brain prompts for decision making
BRAIN_SYSTEM_PROMPT = """You are the AI brain of BREACH.AI v2 - an autonomous security breach proving system.

Your job is NOT to find vulnerabilities. Your job is to PROVE BREACHES.

Think like a real attacker:
- Methodical, patient, and relentless
- Every action moves toward the goal: PROVE TOTAL COMPROMISE
- Chain vulnerabilities together for deeper access
- Never give up after a few failures - real attackers try hundreds of things

KILL CHAIN PHASES:
1. RECON - Map the attack surface exhaustively
2. INITIAL_ACCESS - Get first foothold via any vulnerability
3. FOOTHOLD - Stabilize access, establish persistence
4. ESCALATION - Escalate to root/admin
5. LATERAL - Move through systems to reach crown jewels
6. DATA_ACCESS - Access and sample sensitive data
7. PROOF - Generate undeniable evidence

Your decisions must follow this chain. Each phase enables the next."""

BRAIN_DECISION_PROMPT = """CURRENT STATE:
Target: {target}
Phase: {phase}
Access Level: {access_level}
Time Elapsed: {elapsed_time}

WHAT WE KNOW:
{attack_surface}

WHAT WORKED:
{successes}

WHAT FAILED (don't repeat):
{failures}

CREDENTIALS/TOKENS:
{credentials}

AVAILABLE MODULES:
{available_modules}

GOAL: Achieve complete breach with proof.
Current Objective: {objective}

TASK: Decide the next action.

Consider:
1. What's the highest-value thing to try?
2. What attack chains might work?
3. What haven't we tried?
4. How can we leverage existing access?

Respond with JSON:
{{
  "module_name": "the module to run",
  "action": "what to do",
  "target": "specific target",
  "parameters": {{}},
  "reasoning": "why this is the best next step",
  "expected_outcome": "what we expect to gain",
  "if_fails": "what to try next"
}}"""


class KillChainOrchestrator:
    """
    The Kill Chain Orchestrator - runs the 7-phase breach.

    This is the main class that:
    1. Manages breach sessions
    2. Coordinates module execution
    3. Uses Claude for intelligent decision-making
    4. Tracks progress through the kill chain
    5. Generates final breach report
    """

    def __init__(self, http_client=None, model: str = "claude-sonnet-4-20250514", api_key: str = None):
        self.http_client = http_client
        self.model = model
        self.session: Optional[BreachSession] = None

        # Initialize Anthropic client with explicit key or from environment
        import os
        effective_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not effective_key:
            logger.warning(
                "No ANTHROPIC_API_KEY found. ChainBreaker mode requires an Anthropic API key. "
                "Set it in your .env file or environment."
            )
        self.client = Anthropic(api_key=effective_key) if effective_key else None

        # Phase tracking for smarter transitions
        self._phase_start_time: Optional[datetime] = None
        self._modules_tried_this_phase: set = set()
        self._consecutive_same_module: int = 0
        self._last_module: str = ""

        # Cumulative discoveries (across all results in phase)
        self._total_endpoints_found: int = 0
        self._total_targets_found: int = 0
        self._total_technologies_found: int = 0

    async def run_breach(
        self,
        target: str,
        timeout_hours: int = 24,
        scope: list[str] = None,
        rules: dict = None,
    ) -> BreachSession:
        """
        Run a complete breach assessment.

        This is the main entry point that runs the full kill chain.
        """
        # Check if Anthropic client is available
        if not self.client:
            raise RuntimeError(
                "ChainBreaker mode requires ANTHROPIC_API_KEY. "
                "Please set it in your .env file or environment:\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )

        # Initialize session
        self.session = BreachSession(
            target=target,
            timeout_hours=timeout_hours,
            scope=scope or [target],
            rules_of_engagement=rules or {},
            started_at=datetime.utcnow(),
            is_running=True,
        )

        deadline = self.session.started_at + timedelta(hours=timeout_hours)

        logger.info(f"Starting breach of {target}")
        logger.info(f"Timeout: {timeout_hours} hours, Deadline: {deadline}")

        try:
            # Phase 1: Reconnaissance
            await self._run_phase(BreachPhase.RECON, deadline)

            # Phase 2: Initial Access
            if self._should_continue(deadline):
                await self._run_phase(BreachPhase.INITIAL_ACCESS, deadline)

            # Phase 3: Foothold (if we got access)
            if self._should_continue(deadline) and self.session.highest_access > AccessLevel.ANONYMOUS:
                await self._run_phase(BreachPhase.FOOTHOLD, deadline)

            # Phase 4: Escalation
            if self._should_continue(deadline) and self.session.highest_access >= AccessLevel.USER:
                await self._run_phase(BreachPhase.ESCALATION, deadline)

            # Phase 5: Lateral Movement
            if self._should_continue(deadline) and self.session.highest_access >= AccessLevel.USER:
                await self._run_phase(BreachPhase.LATERAL, deadline)

            # Phase 6: Data Access
            if self._should_continue(deadline) and self.session.highest_access >= AccessLevel.USER:
                await self._run_phase(BreachPhase.DATA_ACCESS, deadline)

            # Phase 7: Proof Generation
            if len(self.session.evidence_collected) > 0:
                await self._run_phase(BreachPhase.PROOF, deadline)

            # Mark complete
            self.session.is_complete = True
            self.session.breach_achieved = self.session.highest_access >= AccessLevel.DATABASE

        except Exception as e:
            logger.error(f"Breach failed: {e}")
            self.session.is_complete = True

        finally:
            self.session.is_running = False
            self.session.completed_at = datetime.utcnow()

        logger.info(f"Breach complete. Access: {self.session.highest_access.value}")
        logger.info(f"Evidence items: {len(self.session.evidence_collected)}")

        return self.session

    async def _run_phase(self, phase: BreachPhase, deadline: datetime):
        """Run a single phase of the kill chain."""
        logger.info(f"=== PHASE: {phase.display_name} ===")
        self.session.current_phase = phase

        # Reset phase tracking
        self._phase_start_time = datetime.utcnow()
        self._modules_tried_this_phase = set()
        self._consecutive_same_module = 0
        self._last_module = ""
        self._total_endpoints_found = 0
        self._total_targets_found = 0
        self._total_technologies_found = 0

        # Get modules for this phase
        modules = get_modules_for_phase(phase)

        if not modules:
            logger.warning(f"No modules available for {phase.value}")
            return

        # Determine decision mode
        self.session.decision_mode = self._get_decision_mode(phase)

        # Phase time limits (in seconds)
        phase_time_limits = {
            BreachPhase.RECON: 300,        # 5 min max for recon
            BreachPhase.INITIAL_ACCESS: 600,  # 10 min
            BreachPhase.FOOTHOLD: 300,
            BreachPhase.ESCALATION: 600,
            BreachPhase.LATERAL: 600,
            BreachPhase.DATA_ACCESS: 300,
            BreachPhase.PROOF: 180,
        }
        max_phase_time = phase_time_limits.get(phase, 600)

        # Run until phase complete or timeout
        max_attempts = 20 if phase == BreachPhase.RECON else 50
        attempts = 0

        while attempts < max_attempts and self._should_continue(deadline):
            attempts += 1

            # Check phase time limit
            phase_elapsed = (datetime.utcnow() - self._phase_start_time).total_seconds()
            if phase_elapsed > max_phase_time:
                logger.info(f"Phase time limit reached ({max_phase_time}s), advancing...")
                break

            # Force variety: if same module 3 times in a row, exclude it
            excluded_modules = set()
            if self._consecutive_same_module >= 3:
                excluded_modules.add(self._last_module)
                logger.debug(f"Forcing variety, excluding {self._last_module}")

            # Get brain decision with variety hints
            decision = await self._get_brain_decision(phase, modules, excluded_modules)

            if not decision:
                # No more ideas, move to next phase
                logger.info("AI brain has no more ideas for this phase")
                break

            # Track module variety
            if decision.module_name == self._last_module:
                self._consecutive_same_module += 1
            else:
                self._consecutive_same_module = 0
            self._last_module = decision.module_name
            self._modules_tried_this_phase.add(decision.module_name)

            # Execute the decision
            result = await self._execute_decision(decision)

            # Process result
            if result:
                await self._process_result(result, decision)

                # Track cumulative discoveries
                if result.new_endpoints:
                    self._total_endpoints_found += len(result.new_endpoints)
                if result.new_targets:
                    self._total_targets_found += len(result.new_targets)
                if result.technologies_detected:
                    self._total_technologies_found += len(result.technologies_detected)

                # Check if we should transition to next phase
                if self._should_advance_phase(phase, result):
                    break

            # Brief pause
            await asyncio.sleep(0.1)

            # Auto-advance if we've tried all modules at least once
            if len(self._modules_tried_this_phase) >= len(modules):
                logger.info(f"All {len(modules)} modules tried, advancing phase")
                break

        logger.info(f"Phase {phase.value} complete. Steps: {len(self.session.get_steps_for_phase(phase))}, "
                   f"Modules tried: {len(self._modules_tried_this_phase)}")

    async def _get_brain_decision(
        self, phase: BreachPhase, modules: list[type[Module]], excluded_modules: set = None
    ) -> Optional[BrainDecision]:
        """Get next action from the AI brain."""
        excluded_modules = excluded_modules or set()

        # Filter out excluded modules
        available_modules = [m for m in modules if m.info.name not in excluded_modules]
        if not available_modules:
            available_modules = modules  # Fall back to all if all excluded

        # Build context with variety hints
        context = self._build_context(phase, available_modules)

        # Add variety hints to prompt
        variety_hint = ""
        if self._modules_tried_this_phase:
            tried = ", ".join(self._modules_tried_this_phase)
            not_tried = [m.info.name for m in available_modules if m.info.name not in self._modules_tried_this_phase]
            if not_tried:
                variety_hint = f"\n\nIMPORTANT: You've already tried: {tried}\nConsider trying: {', '.join(not_tried[:3])}"

        prompt = BRAIN_DECISION_PROMPT.format(**context) + variety_hint

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                system=BRAIN_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            content = response.content[0].text

            # Parse JSON response
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])

                module_name = data.get("module_name", "")

                # If AI chose excluded module, pick a random untried one
                if module_name in excluded_modules:
                    untried = [m.info.name for m in available_modules if m.info.name not in self._modules_tried_this_phase]
                    if untried:
                        module_name = untried[0]
                        logger.debug(f"Overriding AI choice to enforce variety: {module_name}")

                return BrainDecision(
                    module_name=module_name,
                    action=data.get("action", ""),
                    target=data.get("target", self.session.target),
                    parameters=data.get("parameters", {}),
                    reasoning=data.get("reasoning", ""),
                    expected_outcome=data.get("expected_outcome", ""),
                    if_fails=data.get("if_fails", ""),
                    phase=phase,
                    decision_mode=self.session.decision_mode,
                )

        except Exception as e:
            logger.debug(f"Brain decision failed: {e}")

        return None

    async def _execute_decision(self, decision: BrainDecision) -> Optional[ModuleResult]:
        """Execute a brain decision."""
        # Get the module
        module_class = get_module(decision.module_name)

        if not module_class:
            logger.debug(f"Module not found: {decision.module_name}")
            return None

        # Instantiate module
        module = module_class(http_client=self.http_client)

        # Build config
        config = ModuleConfig(
            target=decision.target or self.session.target,
            cookies={},
            headers={},
            chain_data=self._get_chain_data(),
        )

        # Check if module can run
        if not await module.check(config):
            logger.debug(f"Module check failed: {decision.module_name}")
            return None

        # Create step
        step = decision.to_step()
        step.started_at = datetime.utcnow()
        self.session.add_step(step)

        try:
            # Execute module
            result = await module.run(config)

            # Update step
            step.success = result.success
            step.result = result
            step.completed_at = datetime.utcnow()
            step.duration_ms = result.duration_ms

            if result.success:
                logger.info(f"✓ {decision.module_name}: {result.details[:50]}")
            else:
                logger.debug(f"✗ {decision.module_name}: {result.error or 'failed'}")

            return result

        except Exception as e:
            step.error = str(e)
            step.completed_at = datetime.utcnow()
            logger.debug(f"Module execution failed: {e}")
            return None

        finally:
            # Cleanup
            try:
                await module.cleanup(config)
            except Exception:
                pass

    async def _process_result(self, result: ModuleResult, decision: BrainDecision):
        """Process module result."""
        # Update access level
        if result.access_gained:
            self.session.update_access(result.access_gained)

        # Collect evidence
        for evidence in result.evidence:
            self.session.add_evidence(evidence)

        # Track compromised systems
        if result.access_gained and result.access_gained >= AccessLevel.USER:
            target = decision.target or self.session.target
            if target not in self.session.systems_compromised:
                self.session.systems_compromised.append(target)

    def _build_context(self, phase: BreachPhase, modules: list[type[Module]]) -> dict:
        """Build context for brain decision."""
        successful_steps = self.session.get_successful_steps()
        failed_steps = [s for s in self.session.steps if not s.success]

        # Get chain data for context
        chain_data = self._get_chain_data()

        return {
            "target": self.session.target,
            "phase": phase.display_name,
            "access_level": self.session.highest_access.value,
            "elapsed_time": f"{self.session.get_duration_seconds():.0f} seconds",
            "attack_surface": json.dumps(chain_data.get("attack_surface", {}), indent=2)[:1000],
            "successes": "\n".join(
                f"- {s.module_name}: {s.result.details[:50] if s.result else 'success'}"
                for s in successful_steps[-10:]
            ) or "None yet",
            "failures": "\n".join(
                f"- {s.module_name}: {s.error or 'failed'}"
                for s in failed_steps[-10:]
            ) or "None",
            "credentials": json.dumps(chain_data.get("credentials", {}), indent=2)[:500],
            "available_modules": "\n".join(
                f"- {m.info.name}: {m.info.description}"
                for m in modules
            ),
            "objective": self._get_phase_objective(phase),
        }

    def _get_chain_data(self) -> dict:
        """Get accumulated data from the breach chain."""
        chain_data = {
            "attack_surface": {},
            "credentials": {},
            "tokens": [],
            "access_gained": self.session.highest_access.value,
            "findings": [],
            "data_samples": [],
        }

        # Accumulate from successful steps
        for step in self.session.get_successful_steps():
            if step.result:
                result = step.result

                # Accumulate new targets
                if result.new_targets:
                    chain_data.setdefault("new_targets", []).extend(result.new_targets)

                # Accumulate endpoints
                if result.new_endpoints:
                    chain_data.setdefault("endpoints", []).extend(result.new_endpoints)

                # Accumulate technologies
                if result.technologies_detected:
                    chain_data.setdefault("technologies", []).extend(result.technologies_detected)

                # Accumulate credentials
                if result.credentials_found:
                    chain_data.setdefault("credentials_found", []).extend(result.credentials_found)

                # Accumulate tokens
                if result.tokens_found:
                    chain_data["tokens"].extend(result.tokens_found)

                # Accumulate chain data from modules
                if result.chain_data:
                    chain_data.update(result.chain_data)

                # Accumulate data extracted
                if result.data_extracted:
                    chain_data.setdefault("data_extracted", []).append(result.data_extracted)

        return chain_data

    def _get_phase_objective(self, phase: BreachPhase) -> str:
        """Get the objective for a phase."""
        objectives = {
            BreachPhase.RECON: "Map the complete attack surface - subdomains, endpoints, technologies",
            BreachPhase.INITIAL_ACCESS: "Get first foothold - any vulnerability that gives access",
            BreachPhase.FOOTHOLD: "Stabilize access and gather more information",
            BreachPhase.ESCALATION: "Escalate to higher privileges - admin, root, or cloud admin",
            BreachPhase.LATERAL: "Move to other systems and services",
            BreachPhase.DATA_ACCESS: "Access sensitive data - databases, files, secrets",
            BreachPhase.PROOF: "Generate undeniable evidence of complete breach",
        }
        return objectives.get(phase, "Continue breach")

    def _get_decision_mode(self, phase: BreachPhase) -> DecisionMode:
        """Get decision mode for a phase."""
        if phase == BreachPhase.RECON:
            return DecisionMode.EXPLORATION
        elif phase in [BreachPhase.INITIAL_ACCESS, BreachPhase.FOOTHOLD]:
            return DecisionMode.EXPLOITATION
        elif phase == BreachPhase.ESCALATION:
            return DecisionMode.ESCALATION
        else:
            return DecisionMode.COLLECTION

    def _should_continue(self, deadline: datetime) -> bool:
        """Check if we should continue the breach."""
        return (
            datetime.utcnow() < deadline and
            self.session.is_running
        )

    def _should_advance_phase(self, current: BreachPhase, result: ModuleResult) -> bool:
        """Check if we should advance to the next phase."""
        # Recon complete after sufficient cumulative discovery
        if current == BreachPhase.RECON:
            # Advance if we've found enough attack surface
            has_endpoints = self._total_endpoints_found >= 5
            has_targets = self._total_targets_found >= 3
            has_tech = self._total_technologies_found >= 2

            # Or if this specific result was very successful
            big_result = (
                (result.new_endpoints and len(result.new_endpoints) > 10) or
                (result.new_targets and len(result.new_targets) > 5)
            )

            # Or if we have any attack surface at all after trying multiple modules
            minimal_surface = (
                len(self._modules_tried_this_phase) >= 3 and
                (self._total_endpoints_found > 0 or self._total_targets_found > 0)
            )

            return has_endpoints or has_targets or has_tech or big_result or minimal_surface

        # Initial access complete when we get access
        if current == BreachPhase.INITIAL_ACCESS:
            return result.access_gained is not None

        # Foothold - advance after any successful persistence
        if current == BreachPhase.FOOTHOLD:
            return result.success and len(self._modules_tried_this_phase) >= 2

        # Escalation complete when we reach high access
        if current == BreachPhase.ESCALATION:
            return result.access_gained and result.access_gained >= AccessLevel.ADMIN

        # Lateral - advance after finding new systems
        if current == BreachPhase.LATERAL:
            return (result.new_targets and len(result.new_targets) > 0) or len(self._modules_tried_this_phase) >= 2

        # Data access complete when we have samples
        if current == BreachPhase.DATA_ACCESS:
            return result.data_extracted is not None

        # Proof - always complete after running
        if current == BreachPhase.PROOF:
            return result.success

        return False

    def stop(self):
        """Stop the breach gracefully."""
        if self.session:
            self.session.is_running = False
            logger.info("Breach stop requested")


async def run_breach(target: str, **kwargs) -> BreachSession:
    """Convenience function to run a breach."""
    orchestrator = KillChainOrchestrator()
    return await orchestrator.run_breach(target, **kwargs)
