"""
BREACH.AI - Enhanced Agent Brain with Scripting

The brain now has the power to write custom scripts when needed.
This makes the agent truly autonomous - it can adapt to ANY situation.
"""

import json
from dataclasses import dataclass
from typing import Optional

from anthropic import Anthropic

from breach.agents.script_generator import (
    ScriptGenerator,
    ScriptingCapability,
    ScriptResult,
)
from breach.core.memory import AccessLevel, Finding
from breach.utils.logger import logger


@dataclass
class AttackAction:
    """An attack action decided by the brain."""
    name: str
    attack_type: str
    target: str
    parameters: dict
    priority: int
    reasoning: str
    requires_custom_script: bool = False
    script_goal: Optional[str] = None


@dataclass
class PostExAction:
    """A post-exploitation action."""
    name: str
    description: str
    action_type: str
    parameters: dict


# Enhanced system prompt that knows about scripting
ENHANCED_SYSTEM_PROMPT = """You are the brain of BREACH.AI, an autonomous security assessment agent.

Your job is to think like a real attacker - methodical, patient, and relentless.

YOU HAVE SPECIAL POWERS:
1. Standard Attacks: Pre-built modules for common vulnerabilities
2. **Custom Script Generation**: When standard attacks fail, you can request CUSTOM SCRIPTS
   - Use this when WAFs block payloads
   - Use this when you need unique exploitation techniques
   - Use this when you need to chain vulnerabilities
   - Use this when you need custom data extraction

CURRENT CONTEXT:
- Target: {target}
- Current Access Level: {current_access}
- Time Elapsed: {elapsed_time} seconds
- Findings So Far: {findings_count}
- Failed Attempts: {failed_count}

ATTACK SURFACE:
{attack_surface}

RECENT FINDINGS:
{recent_findings}

FAILED ATTACKS (these didn't work with standard payloads):
{failed_attacks}

CREDENTIALS/TOKENS FOUND:
{credentials}

YOUR TASK:
Decide the next best attacks. You can:
1. Use standard attack modules
2. Request CUSTOM SCRIPTS for complex situations

For custom scripts, set:
- requires_custom_script: true
- script_goal: "what the script should accomplish"

OUTPUT FORMAT:
Return a JSON array:
[
  {{
    "name": "Human readable name",
    "attack_type": "sqli|xss|ssrf|auth_bypass|custom_script|etc",
    "target": "URL or endpoint",
    "parameters": {{"param": "value"}},
    "priority": 1-10,
    "reasoning": "Why this attack now",
    "requires_custom_script": false,
    "script_goal": null
  }}
]

WHEN TO USE CUSTOM SCRIPTS:
- After 2+ failed attempts on same endpoint (WAF likely blocking)
- When you find credentials but need custom extraction logic
- When you want to chain multiple vulns into one attack
- When the target uses unusual protocols/formats
- When you need a clean PoC for the report

Return 3-5 attacks, ordered by priority."""


FOLLOW_UP_PROMPT = """A vulnerability was discovered. What should we try next?

VULNERABILITY:
Type: {vuln_type}
Target: {target}
Details: {details}
Access Gained: {access_gained}
Data Retrieved: {data_sample}

What follow-up attacks can leverage this finding?
Consider:
1. Using any credentials/tokens found
2. Accessing internal resources via SSRF
3. Escalating privileges
4. Moving laterally
5. Extracting more data

Return as JSON array of attack actions."""


CHAIN_ANALYSIS_PROMPT = """Analyze these vulnerabilities and determine if they can be chained together:

FINDINGS:
{findings}

CURRENT ACCESS: {current_access}

Can any of these be chained to achieve greater access?
For example:
- SSRF + exposed internal service = internal access
- XSS + CSRF = account takeover
- Info disclosure + auth bypass = full access

If yes, return:
{{
    "can_chain": true,
    "chain": ["finding_id_1", "finding_id_2"],
    "goal": "what the chain achieves",
    "explanation": "how to chain them"
}}

If no meaningful chain exists:
{{
    "can_chain": false
}}"""


class EnhancedAgentBrain:
    """
    The enhanced Claude-powered decision engine with scripting capability.

    This brain can:
    1. Decide what attacks to run
    2. Request custom scripts when standard attacks fail
    3. Chain vulnerabilities together
    4. Generate PoC scripts for reports
    """

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic()
        self.model = model
        self.decision_history = []

        # Scripting capability
        self.scripting = ScriptingCapability()
        self.script_generator = ScriptGenerator(model=model)

        # Track what's been tried
        self.failed_standard_attacks: dict[str, list[str]] = {}

    async def decide_next_actions(self, context: dict) -> list[AttackAction]:
        """Decide the next attacks, potentially including custom scripts."""
        prompt = ENHANCED_SYSTEM_PROMPT.format(
            target=context["target"],
            current_access=context["current_access"],
            elapsed_time=int(context["elapsed_time"]),
            findings_count=len(context["findings"]),
            failed_count=len(context["failed_attacks"]),
            attack_surface=self._format_attack_surface(context["attack_surface"]),
            recent_findings=self._format_findings(context["findings"]),
            failed_attacks=self._format_failed(context["failed_attacks"]),
            credentials=self._format_credentials(context.get("credentials", {})),
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            content = response.content[0].text
            actions = self._parse_actions(content)

            # Log decisions
            for action in actions:
                if action.requires_custom_script:
                    logger.info(f"Brain decided: CUSTOM SCRIPT - {action.script_goal}")
                else:
                    logger.debug(f"Brain decided: {action.name} (priority: {action.priority})")

            self.decision_history.append({
                "context_summary": f"Access: {context['current_access']}, Findings: {len(context['findings'])}",
                "actions": [a.name for a in actions],
                "custom_scripts_requested": sum(1 for a in actions if a.requires_custom_script)
            })

            return actions

        except Exception as e:
            logger.error(f"Brain decision failed: {e}")
            return []

    async def handle_attack_failure(
        self,
        action: AttackAction,
        error: str,
        response: str,
        context: dict
    ) -> Optional[AttackAction]:
        """Handle a failed attack by potentially generating a custom script."""
        # Track this failure
        key = f"{action.target}:{action.parameters.get('endpoint', '')}"
        if key not in self.failed_standard_attacks:
            self.failed_standard_attacks[key] = []
        self.failed_standard_attacks[key].append(action.attack_type)

        # If multiple failures on same endpoint, try custom script
        if len(self.failed_standard_attacks[key]) >= 2:
            logger.info(f"Multiple failures on {key}. Generating custom script...")

            return AttackAction(
                name=f"Custom script for {action.attack_type}",
                attack_type="custom_script",
                target=action.target,
                parameters={
                    **action.parameters,
                    "original_attack": action.attack_type,
                    "failed_attempts": self.failed_standard_attacks[key],
                    "last_response": response[:1000]
                },
                priority=9,
                reasoning=f"Standard {action.attack_type} attacks failed. Generating custom bypass.",
                requires_custom_script=True,
                script_goal=f"Bypass protections and exploit {action.attack_type} vulnerability"
            )

        return None

    async def execute_custom_script_action(
        self,
        action: AttackAction,
        context: dict
    ) -> Optional[ScriptResult]:
        """Execute an action that requires a custom script."""
        if not action.requires_custom_script:
            return None

        params = action.parameters

        # Determine script type and generate
        if params.get("original_attack"):
            # This is a retry after failure
            result = await self.scripting.handle_failed_attack(
                attack_type=params["original_attack"],
                target=action.target,
                endpoint=params.get("endpoint", "/"),
                parameter=params.get("name", "unknown"),
                payload=params.get("last_payload", ""),
                response=params.get("last_response", ""),
                context=context
            )
            return result

        elif action.attack_type == "chain_exploit":
            # Chain multiple vulnerabilities
            return await self.scripting.create_exploit_chain(
                vulnerabilities=params.get("vulnerabilities", []),
                goal=action.script_goal,
                context=context
            )

        elif action.attack_type == "data_extraction":
            # Extract data for evidence
            return await self.scripting.extract_breach_evidence(
                access_type=params.get("access_type", "database"),
                system=params.get("system", "unknown"),
                credentials=context.get("credentials", {}),
                context=context
            )

        else:
            # Generic custom script
            logger.info(f"Generating generic custom script: {action.script_goal}")

            script = await self.script_generator.generate_exploitation_script(
                target=action.target,
                vuln_type=params.get("vuln_type", "unknown"),
                endpoint=params.get("endpoint", "/"),
                parameter=params.get("parameter", "unknown"),
                current_payload=params.get("payload", ""),
                response=params.get("response", ""),
                context=context
            )

            if script.code and not script.error:
                return await self.script_generator.execute_script(script, context)

        return None

    async def generate_chain_attack(
        self,
        findings: list[Finding],
        context: dict
    ) -> Optional[AttackAction]:
        """Analyze findings and see if we can chain them into a bigger attack."""
        if len(findings) < 2:
            return None

        prompt = CHAIN_ANALYSIS_PROMPT.format(
            findings=json.dumps([f.to_dict() for f in findings], indent=2),
            current_access=context.get('current_access', 'none')
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            result = json.loads(response.content[0].text)

            if result.get("can_chain"):
                logger.info(f"Chain attack possible: {result['goal']}")

                chain_findings = [
                    f.to_dict() for f in findings
                    if f.id in result.get("chain", [])
                ]

                return AttackAction(
                    name=f"Exploit Chain: {result['goal']}",
                    attack_type="chain_exploit",
                    target=context.get("target", ""),
                    parameters={
                        "vulnerabilities": chain_findings,
                        "explanation": result.get("explanation", "")
                    },
                    priority=10,
                    reasoning=result.get("explanation", ""),
                    requires_custom_script=True,
                    script_goal=result.get("goal", "")
                )

        except Exception as e:
            logger.debug(f"Chain analysis failed: {e}")

        return None

    async def get_follow_up_attacks(self, vuln_result) -> list[AttackAction]:
        """Get follow-up attacks based on a newly discovered vulnerability."""
        prompt = FOLLOW_UP_PROMPT.format(
            vuln_type=vuln_result.attack_type,
            target=vuln_result.target,
            details=vuln_result.details,
            access_gained=vuln_result.access_gained or "None",
            data_sample=vuln_result.data_sample[:500] if vuln_result.data_sample else "None",
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )

            return self._parse_actions(response.content[0].text)

        except Exception as e:
            logger.error(f"Follow-up decision failed: {e}")
            return []

    async def plan_post_exploitation(self, context: dict) -> list[PostExAction]:
        """Plan post-exploitation to demonstrate impact."""
        if context.get("current_access") in ["admin", "root", "database"]:
            logger.info("High access achieved. Planning data extraction...")

            return [
                PostExAction(
                    name="Extract user data sample",
                    description="Extract sample user records as proof",
                    action_type="data_extraction",
                    parameters={"system": "database", "table": "users"}
                ),
                PostExAction(
                    name="Enumerate sensitive tables",
                    description="Find all tables with sensitive data",
                    action_type="enumeration",
                    parameters={"system": "database"}
                ),
                PostExAction(
                    name="Extract credentials",
                    description="Find stored credentials/API keys",
                    action_type="credential_harvest",
                    parameters={"system": "database"}
                ),
            ]

        return []

    async def generate_report_scripts(self, findings: list[Finding]) -> list:
        """Generate clean PoC scripts for the final report."""
        return await self.scripting.generate_report_pocs(
            [f.to_dict() for f in findings]
        )

    def _parse_actions(self, content: str) -> list[AttackAction]:
        """Parse Claude's response into AttackAction objects."""
        try:
            start = content.find('[')
            end = content.rfind(']') + 1
            if start == -1 or end == 0:
                return []

            json_str = content[start:end]
            actions_data = json.loads(json_str)

            actions = []
            for data in actions_data:
                actions.append(AttackAction(
                    name=data.get("name", "Unknown"),
                    attack_type=data.get("attack_type", "unknown"),
                    target=data.get("target", ""),
                    parameters=data.get("parameters", {}),
                    priority=data.get("priority", 5),
                    reasoning=data.get("reasoning", ""),
                    requires_custom_script=data.get("requires_custom_script", False),
                    script_goal=data.get("script_goal"),
                ))

            actions.sort(key=lambda a: a.priority, reverse=True)
            return actions

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse brain response: {e}")
            return []

    def _format_attack_surface(self, surface: dict) -> str:
        """Format attack surface for prompt."""
        lines = []
        if surface.get("subdomains"):
            lines.append(f"Subdomains ({len(surface['subdomains'])}): {', '.join(surface['subdomains'][:10])}")
        if surface.get("endpoints"):
            lines.append(f"Endpoints ({len(surface['endpoints'])}): {', '.join(str(e)[:50] for e in surface['endpoints'][:10])}")
        if surface.get("technologies"):
            lines.append(f"Technologies: {', '.join(surface['technologies'])}")
        return "\n".join(lines) if lines else "Not yet mapped"

    def _format_findings(self, findings: list) -> str:
        """Format recent findings for prompt."""
        if not findings:
            return "None yet"
        lines = []
        for f in findings[-10:]:
            lines.append(f"- [{f.get('severity', 'unknown')}] {f.get('title', 'Unknown')}: {f.get('target', '')}")
        return "\n".join(lines)

    def _format_failed(self, failed: list) -> str:
        """Format failed attacks to avoid repeating."""
        if not failed:
            return "None"
        return "\n".join(f"- {f}" for f in list(failed)[-20:])

    def _format_credentials(self, creds: dict) -> str:
        """Format found credentials."""
        if not creds:
            return "None found"
        lines = []
        if isinstance(creds, dict):
            for service, cred_list in creds.items():
                if isinstance(cred_list, list):
                    for cred in cred_list:
                        lines.append(f"- {service}: {cred.get('username', 'N/A')} / {'*' * 8}")
        return "\n".join(lines) if lines else "None found"
