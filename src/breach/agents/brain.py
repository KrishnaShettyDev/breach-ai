"""
BREACH.AI - Agent Brain

The decision-making engine powered by Claude.
This is what makes BREACH.AI intelligent - it reasons about what to attack next,
how to chain vulnerabilities, and when to escalate.
"""

import json
from typing import Optional
from dataclasses import dataclass

from anthropic import Anthropic

from .memory import AccessLevel, Finding
from ..utils.logger import logger


@dataclass
class AttackAction:
    """An attack action decided by the brain."""
    name: str
    attack_type: str
    target: str
    parameters: dict
    priority: int
    reasoning: str
    
    
@dataclass  
class PostExAction:
    """A post-exploitation action."""
    name: str
    description: str
    action_type: str
    parameters: dict


SYSTEM_PROMPT = """You are the brain of BREACH.AI, a security assessment agent.

IMPORTANT RULES:
- Only suggest attacks for endpoints that ACTUALLY EXIST in the attack surface
- Do NOT hallucinate or make up endpoints that weren't discovered
- Do NOT suggest attacks without a clear, verifiable target
- Focus on real vulnerabilities, not theoretical ones
- Every attack MUST have a concrete target URL from the discovered endpoints

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

FAILED ATTACKS (avoid repeating):
{failed_attacks}

CREDENTIALS/TOKENS FOUND:
{credentials}

YOUR TASK:
Decide the next best attacks to try. Think step by step:

1. What have we learned from successful attacks?
2. What new attack vectors do successful findings open up?
3. What high-value targets haven't we tried yet?
4. How can we chain existing findings for deeper access?

RULES:
- Be methodical - don't randomly guess
- Prioritize attacks that could escalate access
- If you found credentials, USE THEM
- If you found an internal endpoint via SSRF, EXPLORE IT
- Don't repeat failed attacks unless with different parameters
- Think about lateral movement and pivoting
- Always go for maximum impact

OUTPUT FORMAT:
Return a JSON array of attack actions:
[
  {
    "name": "Human readable name",
    "attack_type": "sqli|xss|ssrf|auth_bypass|etc",
    "target": "URL or endpoint",
    "parameters": {"param": "value"},
    "priority": 1-10,
    "reasoning": "Why this attack now"
  }
]

Return 3-5 attacks, ordered by priority."""


FOLLOW_UP_PROMPT = """A vulnerability was just discovered. Analyze it and suggest follow-up attacks.

VULNERABILITY FOUND:
Type: {vuln_type}
Target: {target}
Details: {details}
Access Gained: {access_gained}
Data Retrieved: {data_sample}

CURRENT CONTEXT:
{context}

Think about:
1. How can we leverage this vulnerability for deeper access?
2. What new attack surface does this open up?
3. Are there credentials or tokens we can extract/use?
4. Can we chain this with other findings?

Return follow-up attacks as JSON array."""


POST_EX_PROMPT = """We have achieved {access_level} access. Plan post-exploitation to demonstrate maximum impact.

CURRENT ACCESS:
- Level: {access_level}
- Method: {access_method}
- Credentials/Tokens: {credentials}

GOAL: Prove the severity of the breach with undeniable evidence.

Plan actions to:
1. Extract sample data (users, transactions, secrets)
2. Demonstrate further access (internal systems, cloud)
3. Prove persistence capability (without actually persisting)
4. Show business impact (what an attacker could do)

Return as JSON array of post-exploitation actions:
[
  {
    "name": "Action name",
    "description": "What we're demonstrating",
    "action_type": "data_extraction|lateral_movement|privilege_escalation|impact_demo",
    "parameters": {}
  }
]"""


class AgentBrain:
    """
    The Claude-powered decision engine.
    
    This class handles all the intelligent decision-making:
    - What to attack next
    - How to chain vulnerabilities  
    - When and how to escalate
    - Post-exploitation planning
    """
    
    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic()
        self.model = model
        self.decision_history = []
        
    async def decide_next_actions(self, context: dict) -> list[AttackAction]:
        """
        Decide the next attacks to try based on current context.

        Args:
            context: Current state including findings, access level, attack surface

        Returns:
            List of AttackAction objects to execute
        """
        # Format the prompt with context
        prompt = SYSTEM_PROMPT.format(
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
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            # Parse the response
            content = response.content[0].text
            actions = self._parse_actions(content)

            # VALIDATE: Filter out hallucinated attacks
            valid_actions = self._validate_actions(actions, context)

            # Log decisions
            for action in valid_actions:
                logger.debug(f"Brain decided: {action.name} (priority: {action.priority})")
                logger.debug(f"  Reasoning: {action.reasoning}")

            if len(valid_actions) < len(actions):
                logger.warning(f"Filtered {len(actions) - len(valid_actions)} hallucinated attacks")

            self.decision_history.append({
                "context_summary": f"Access: {context['current_access']}, Findings: {len(context['findings'])}",
                "actions": [a.name for a in valid_actions]
            })

            return valid_actions

        except Exception as e:
            logger.error(f"Brain decision failed: {e}")
            return []

    def _validate_actions(self, actions: list[AttackAction], context: dict) -> list[AttackAction]:
        """
        Validate suggested actions against the actual attack surface.
        Filters out hallucinated endpoints and unrealistic attacks.
        """
        valid_actions = []

        # Get known endpoints from attack surface
        attack_surface = context.get("attack_surface", {})
        known_endpoints = set(attack_surface.get("endpoints", []))
        target_base = context.get("target", "")

        valid_attack_types = {
            "sqli", "xss", "ssrf", "cmdi", "lfi", "nosql", "ssti", "xxe",
            "auth_bypass", "idor", "jwt_attack", "csrf", "open_redirect",
            "sensitive_file", "path_traversal", "header_injection"
        }

        for action in actions:
            # 1. Check attack type is valid
            if action.attack_type.lower() not in valid_attack_types:
                logger.debug(f"Filtered invalid attack type: {action.attack_type}")
                continue

            # 2. Check target is not empty
            if not action.target or action.target.strip() == "":
                logger.debug(f"Filtered empty target: {action.name}")
                continue

            # 3. Check target is related to our target (not a completely different domain)
            from urllib.parse import urlparse
            try:
                target_host = urlparse(target_base).netloc
                action_host = urlparse(action.target).netloc

                # Allow if it's the same domain or subdomain
                if action_host and not (
                    action_host == target_host or
                    action_host.endswith("." + target_host) or
                    action.target.startswith("/")  # Relative path
                ):
                    logger.debug(f"Filtered off-target attack: {action.target} (target: {target_host})")
                    continue
            except:
                pass  # If parsing fails, let it through for now

            # 4. For endpoints not in known list, lower priority
            if known_endpoints and action.target not in known_endpoints:
                if not any(ep in action.target or action.target in ep for ep in known_endpoints):
                    # Significantly lower priority for unverified endpoints
                    action.priority = min(action.priority, 3)
                    logger.debug(f"Lowered priority for unverified endpoint: {action.target}")

            # 5. Check parameters make sense for attack type
            if action.attack_type in ["sqli", "xss", "cmdi", "lfi"]:
                if not action.parameters:
                    # These attacks need parameters - lower priority
                    action.priority = min(action.priority, 2)

            valid_actions.append(action)

        return valid_actions
    
    async def get_follow_up_attacks(self, vuln_result) -> list[AttackAction]:
        """
        Get follow-up attacks based on a newly discovered vulnerability.
        
        When we find a vulnerability, the brain analyzes it and suggests
        ways to leverage it for deeper access.
        """
        prompt = FOLLOW_UP_PROMPT.format(
            vuln_type=vuln_result.attack_type,
            target=vuln_result.target,
            details=vuln_result.details,
            access_gained=vuln_result.access_gained or "None",
            data_sample=vuln_result.data_sample[:500] if vuln_result.data_sample else "None",
            context=json.dumps(vuln_result.context, indent=2),
        )
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            content = response.content[0].text
            return self._parse_actions(content)
            
        except Exception as e:
            logger.error(f"Follow-up decision failed: {e}")
            return []
    
    async def plan_post_exploitation(self, context: dict) -> list[PostExAction]:
        """
        Plan post-exploitation actions to demonstrate impact.
        
        Once we have access, we need to prove how bad it is.
        """
        prompt = POST_EX_PROMPT.format(
            access_level=context["current_access"],
            access_method=context.get("access_method", "Unknown"),
            credentials=self._format_credentials(context.get("credentials", {})),
        )
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            content = response.content[0].text
            return self._parse_post_ex_actions(content)
            
        except Exception as e:
            logger.error(f"Post-ex planning failed: {e}")
            return []
    
    async def analyze_finding(self, finding: Finding) -> dict:
        """
        Deep analysis of a finding - severity, impact, chaining potential.
        """
        prompt = f"""Analyze this security finding:

Type: {finding.vuln_type}
Target: {finding.target}
Details: {finding.details}
Evidence: {finding.evidence[:1000] if finding.evidence else 'None'}

Provide:
1. True severity (not just CVSS, actual business impact)
2. Exploitation difficulty (1-10)
3. Potential for chaining with other vulns
4. What an attacker would do with this
5. Remediation priority

Return as JSON."""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return json.loads(response.content[0].text)
            
        except Exception as e:
            logger.error(f"Finding analysis failed: {e}")
            return {}
    
    def _parse_actions(self, content: str) -> list[AttackAction]:
        """Parse Claude's response into AttackAction objects."""
        try:
            # Find JSON in response
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
                ))
            
            # Sort by priority
            actions.sort(key=lambda a: a.priority, reverse=True)
            return actions
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse brain response: {e}")
            return []
    
    def _parse_post_ex_actions(self, content: str) -> list[PostExAction]:
        """Parse post-exploitation actions from response."""
        try:
            start = content.find('[')
            end = content.rfind(']') + 1
            if start == -1 or end == 0:
                return []
                
            json_str = content[start:end]
            actions_data = json.loads(json_str)
            
            return [
                PostExAction(
                    name=data.get("name", "Unknown"),
                    description=data.get("description", ""),
                    action_type=data.get("action_type", "unknown"),
                    parameters=data.get("parameters", {}),
                )
                for data in actions_data
            ]
            
        except json.JSONDecodeError:
            return []
    
    def _format_attack_surface(self, surface: dict) -> str:
        """Format attack surface for prompt."""
        lines = []
        
        if surface.get("subdomains"):
            lines.append(f"Subdomains ({len(surface['subdomains'])}): {', '.join(surface['subdomains'][:10])}")
            
        if surface.get("endpoints"):
            lines.append(f"Endpoints ({len(surface['endpoints'])}): {', '.join(surface['endpoints'][:10])}")
            
        if surface.get("technologies"):
            lines.append(f"Technologies: {', '.join(surface['technologies'])}")
            
        if surface.get("open_ports"):
            lines.append(f"Open Ports: {surface['open_ports']}")
            
        return "\n".join(lines) if lines else "Not yet mapped"
    
    def _format_findings(self, findings: list) -> str:
        """Format recent findings for prompt."""
        if not findings:
            return "None yet"
            
        lines = []
        for f in findings[-10:]:  # Last 10
            lines.append(f"- [{f.get('severity', 'unknown')}] {f.get('title', 'Unknown')}: {f.get('target', '')}")
        return "\n".join(lines)
    
    def _format_failed(self, failed: list) -> str:
        """Format failed attacks to avoid repeating."""
        if not failed:
            return "None"
        return "\n".join(f"- {f}" for f in failed[-20:])  # Last 20
    
    def _format_credentials(self, creds: dict) -> str:
        """Format found credentials."""
        if not creds:
            return "None found"
            
        lines = []
        for service, cred_list in creds.items():
            for cred in cred_list:
                lines.append(f"- {service}: {cred.get('username', 'N/A')} / {'*' * 8}")
        return "\n".join(lines) if lines else "None found"
