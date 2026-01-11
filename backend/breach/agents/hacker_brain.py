"""
BREACH.AI - Persistent Hacker Brain

This is NOT a scanner brain. This is a HACKER brain.

A scanner: "Auth returned 401. Secure. Moving on."
A hacker: "Auth returned 401. What auth system? What else can I try?
          Let me try 50 more things before I give up."

This brain:
1. NEVER gives up on first failure
2. CHAINS findings together
3. REMEMBERS everything it learned
4. THINKS DEEP about each response
5. ASKS for permission but PROPOSES aggressive next steps
6. KNOWS real 2024/2025 attack techniques
"""

import asyncio
import json
import re
import os
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    import anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False

import aiohttp


class AttackPhase(Enum):
    """Current phase of the attack."""
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    PROVE = "prove"
    COMPLETE = "complete"


@dataclass
class Finding:
    """Something we discovered."""
    type: str  # tech, secret, endpoint, vulnerability, breach
    severity: str  # info, low, medium, high, critical
    title: str
    details: str
    evidence: Any = None
    exploitable: bool = False
    exploited: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AttackAttempt:
    """Record of an attack we tried."""
    technique: str
    target: str
    request: Dict
    response_status: int
    response_body: str
    success: bool
    finding: Optional[Finding] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HackerContext:
    """
    Everything the hacker brain knows.
    This is the persistent memory that grows throughout the session.
    """
    target: str
    phase: AttackPhase = AttackPhase.RECON

    # What we learned
    technologies: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    endpoints: List[Dict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    # What we tried
    attempts: List[AttackAttempt] = field(default_factory=list)
    failed_techniques: List[str] = field(default_factory=list)

    # Attack state
    auth_system: Optional[str] = None  # nextauth, supabase, firebase, jwt, session
    has_auth_bypass: bool = False
    has_data_access: bool = False
    has_write_access: bool = False
    breach_proven: bool = False

    # Extracted proof
    extracted_data: List[Dict] = field(default_factory=list)
    data_count: int = 0

    def add_finding(self, finding: Finding):
        """Add a finding and update state."""
        self.findings.append(finding)

        if finding.severity == "critical" and finding.exploited:
            self.breach_proven = True

    def add_attempt(self, attempt: AttackAttempt):
        """Record an attack attempt."""
        self.attempts.append(attempt)
        if not attempt.success:
            self.failed_techniques.append(attempt.technique)

    def get_untried_techniques(self, all_techniques: List[str]) -> List[str]:
        """Get techniques we haven't tried yet."""
        return [t for t in all_techniques if t not in self.failed_techniques]

    def to_prompt_context(self) -> str:
        """Convert context to string for Claude."""
        parts = []

        parts.append(f"## Target: {self.target}")
        parts.append(f"## Phase: {self.phase.value}")

        if self.technologies:
            parts.append(f"## Technologies Detected\n{', '.join(self.technologies)}")

        if self.auth_system:
            parts.append(f"## Auth System: {self.auth_system}")

        if self.secrets:
            secret_list = "\n".join([f"- [{s['type']}] {s['value'][:50]}..." for s in self.secrets[:10]])
            parts.append(f"## Secrets Found ({len(self.secrets)})\n{secret_list}")

        if self.endpoints:
            endpoint_list = "\n".join([
                f"- {e['path']} -> {e.get('status', '?')} ({e.get('auth', 'unknown')})"
                for e in self.endpoints[:20]
            ])
            parts.append(f"## Endpoints Discovered ({len(self.endpoints)})\n{endpoint_list}")

        if self.findings:
            finding_list = "\n".join([
                f"- [{f.severity.upper()}] {f.title}" + (" [EXPLOITED]" if f.exploited else "")
                for f in self.findings[-10:]
            ])
            parts.append(f"## Findings ({len(self.findings)})\n{finding_list}")

        if self.attempts:
            recent = self.attempts[-5:]
            attempt_list = "\n".join([
                f"- {a.technique}: {'SUCCESS' if a.success else 'FAIL'} ({a.response_status})"
                for a in recent
            ])
            parts.append(f"## Recent Attempts\n{attempt_list}")

        if self.failed_techniques:
            parts.append(f"## Failed Techniques: {', '.join(self.failed_techniques[-20:])}")

        # Current state
        state = []
        if self.has_auth_bypass:
            state.append("[+] Auth Bypass")
        if self.has_data_access:
            state.append("[+] Data Access")
        if self.has_write_access:
            state.append("[+] Write Access")
        if self.breach_proven:
            state.append("[+] BREACH PROVEN")

        if state:
            parts.append(f"## Current State\n{', '.join(state)}")

        if self.data_count > 0:
            parts.append(f"## Data Extracted: {self.data_count} records")

        return "\n\n".join(parts)


# The system prompt that makes Claude think like a persistent hacker
HACKER_SYSTEM_PROMPT = """You are BREACH.AI, an elite penetration tester AI.

You are NOT a scanner. You are a HACKER. The difference:

SCANNER: "Got 401. Secure. Moving on."
HACKER: "Got 401. Interesting. What auth system? Let me try 50 more things."

## Your Mindset

1. NEVER GIVE UP after one failure
2. Every response teaches you something
3. Chain small findings into big breaches
4. Think like an attacker, not an auditor
5. 401 is information, not a stop sign

## Your Knowledge (2024-2025 Real Attacks)

### Authentication Bypass Techniques

**NextAuth / Auth.js:**
- Check /api/auth/providers for OAuth config
- Check /api/auth/csrf for token leakage
- Try /api/auth/session with manipulated cookies
- Test /api/auth/callback/* for open redirect
- JWT none algorithm attack
- CSRF token reuse across sessions

**Supabase Auth:**
- anon key + direct PostgREST = RLS bypass
- /rest/v1/{table}?select=* with just anon key
- /auth/v1/admin/* endpoints
- gotrue endpoints: /auth/v1/token, /auth/v1/user
- Storage bucket enumeration: /storage/v1/bucket/{name}

**Firebase Auth:**
- /.json returns entire database if open
- Try /users.json, /data.json, /messages.json
- Check /__/firebase/init.json for config
- Firestore: /v1/projects/{id}/databases/(default)/documents/{collection}

**JWT Attacks:**
- Algorithm confusion: Change RS256 to HS256
- None algorithm: {"alg": "none"}
- Weak secret brute force: Try common secrets
- Claim tampering: Change user_id, role, is_admin
- Signature stripping
- Key confusion attacks

### Framework-Specific Attacks

**Next.js (CVE-2025-29927):**
- Header: x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
- Bypasses ALL middleware - try on /admin, /dashboard, /api/*
- Check for exposed source maps: /_next/static/chunks/*.js.map

**Vercel/Serverless:**
- /_logs, /_src exposure
- Function timeout abuse
- Cold start timing attacks

### API Exploitation

**IDOR Patterns:**
- /api/users/1 -> try /api/users/2
- UUID enumeration from other endpoints
- Negative IDs: /api/users/-1
- Zero ID: /api/users/0
- Large ID: /api/users/999999
- Try IDs found in other responses

**Mass Assignment:**
- Add role: "admin" to POST/PUT body
- Add is_admin: true
- Add permissions: ["all"]

**GraphQL:**
- Introspection: {__schema{types{name}}}
- Batching attacks for auth bypass
- Nested query DoS

### Information to Extract

When you find access, ALWAYS try to extract:
1. User emails (prove PII exposure)
2. Password hashes (prove critical breach)
3. API keys / tokens (prove secret exposure)
4. Admin users (prove privilege data)
5. Record counts (prove scale)

## Response Format

ALWAYS respond with this JSON structure:

```json
{
  "thinking": "Your detailed reasoning. What did you learn? What does this mean? What should you try next and WHY?",

  "learned": {
    "technology": "any new tech detected",
    "auth_system": "if identified",
    "vulnerability": "if found",
    "data": "what data you can see"
  },

  "proposal": {
    "action": "http_request|extract_data|report_breach|go_deeper|need_input",
    "technique": "name of technique (e.g., 'supabase_rls_bypass', 'nextjs_middleware_bypass')",
    "description": "Human-readable: What I want to do and WHY this is worth trying",
    "confidence": "high|medium|low",
    "technical": {
      "method": "GET|POST|PUT|DELETE",
      "url": "exact URL",
      "headers": {},
      "body": null
    },
    "success_looks_like": "What response indicates vulnerability",
    "if_fails": "What I'll try next if this doesn't work"
  }
}
```

When breach is proven:
```json
{
  "thinking": "...",
  "learned": {...},
  "proposal": {
    "action": "report_breach",
    "severity": "critical",
    "title": "Brief title",
    "evidence": {
      "vulnerability": "what the vuln is",
      "data_exposed": "what data was accessible",
      "record_count": 12345,
      "sample_data": {...},
      "attack_chain": ["step1", "step2", "step3"]
    }
  }
}
```

## Critical Rules

1. ONE action at a time - human must approve
2. Be SPECIFIC - exact URLs, exact headers
3. EXPLAIN your reasoning - teach the human
4. When something fails, IMMEDIATELY suggest what to try next
5. CHAIN findings - use data from one endpoint to attack another
6. NEVER say "secure" after one failed attempt
7. ALWAYS have a "if_fails" plan
8. Extract PROOF - don't just say "vulnerable", show the data
"""


class PersistentHackerBrain:
    """
    The brain that thinks like a real hacker.

    Key differences from a scanner:
    1. Maintains context across all attempts
    2. Never gives up after one failure
    3. Chains findings together
    4. Proposes next steps even on failure
    5. Knows when to go deeper vs move on
    """

    def __init__(self, api_key: str = None):
        """Initialize the hacker brain."""
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY required")

        # Use SDK if available, otherwise raw API
        if HAS_ANTHROPIC_SDK:
            self.client = anthropic.Anthropic(api_key=self.api_key)
        else:
            self.client = None

        self.context: Optional[HackerContext] = None
        self.conversation: List[Dict] = []

    def start_session(self, target: str) -> HackerContext:
        """Start a new hacking session."""
        self.context = HackerContext(target=target)
        self.conversation = []
        return self.context

    async def think(self, user_message: str = None) -> Dict:
        """
        Ask the hacker brain to think about the current situation.

        Returns the brain's analysis and proposal.
        """
        if not self.context:
            raise ValueError("No active session. Call start_session first.")

        # Build the message
        context_str = self.context.to_prompt_context()

        if user_message:
            full_message = f"{context_str}\n\n## User Message\n{user_message}"
        else:
            full_message = f"{context_str}\n\nWhat should I try next?"

        # Call Claude
        response = await self._call_claude(full_message)

        # Parse the response
        return self._parse_response(response)

    async def analyze_response(
        self,
        technique: str,
        request: Dict,
        status: int,
        body: str,
        headers: Dict
    ) -> Dict:
        """
        Analyze an HTTP response and decide what to do next.

        This is where the "never give up" logic lives.
        """
        if not self.context:
            raise ValueError("No active session")

        # Record the attempt
        attempt = AttackAttempt(
            technique=technique,
            target=request.get("url", ""),
            request=request,
            response_status=status,
            response_body=body[:5000],  # Truncate for context
            success=self._is_success(status, body, technique)
        )
        self.context.add_attempt(attempt)

        # Build analysis prompt
        prompt = f"""I just tried: {technique}

Request:
{json.dumps(request, indent=2)}

Response:
- Status: {status}
- Headers: {json.dumps(dict(list(headers.items())[:15]), indent=2)}
- Body ({len(body)} bytes):
{body[:3000]}{"..." if len(body) > 3000 else ""}

Analyze this response:
1. What did I learn?
2. Is this a vulnerability? (be specific about evidence)
3. What should I try NEXT? (never give up after one attempt)
4. How can I chain this with what I already know?

Remember: {status} status code is INFORMATION, not a final answer."""

        response = await self._call_claude(prompt)
        result = self._parse_response(response)

        # Update context based on analysis
        if result.get("learned"):
            learned = result["learned"]
            if learned.get("technology"):
                if learned["technology"] not in self.context.technologies:
                    self.context.technologies.append(learned["technology"])
            if learned.get("auth_system"):
                self.context.auth_system = learned["auth_system"]

        return result

    async def go_deeper(self, area: str) -> Dict:
        """
        Ask the brain to go deeper on a specific area.

        Use when surface-level attacks fail.
        """
        prompt = f"""I want to go DEEPER on: {area}

Surface-level attacks haven't worked. Time to get creative.

Think about:
1. Edge cases and bypasses
2. Chaining with other findings
3. Alternative paths to the same goal
4. Less common techniques
5. What would a real attacker try next?

Don't suggest things I've already tried: {self.context.failed_techniques[-20:]}

Give me your most creative, aggressive (but legal) approach."""

        return await self.think(prompt)

    async def chain_attack(self, finding1: str, finding2: str) -> Dict:
        """
        Ask the brain to chain two findings together.
        """
        prompt = f"""I have two findings I want to CHAIN together:

Finding 1: {finding1}
Finding 2: {finding2}

How can I combine these to escalate the attack?
What new attack paths does this combination open up?"""

        return await self.think(prompt)

    def _is_success(self, status: int, body: str, technique: str) -> bool:
        """Determine if a response indicates success."""
        # Success indicators
        if status == 200:
            # Check for actual data vs empty response
            if len(body) > 100:
                # Check it's not an error message
                error_indicators = ["error", "unauthorized", "forbidden", "not found", "denied"]
                body_lower = body.lower()[:500]
                if not any(ind in body_lower for ind in error_indicators):
                    return True

        # Some techniques succeed on other codes
        if technique in ["supabase_rls_bypass", "firebase_open_db"]:
            if status == 200 and body and body not in ["null", "[]", "{}"]:
                return True

        return False

    async def _call_claude(self, message: str) -> str:
        """Call Claude API."""
        # Add to conversation
        self.conversation.append({"role": "user", "content": message})

        if HAS_ANTHROPIC_SDK and self.client:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=HACKER_SYSTEM_PROMPT,
                messages=self.conversation
            )
            assistant_message = response.content[0].text
        else:
            # Fallback to raw API
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 4096,
                        "system": HACKER_SYSTEM_PROMPT,
                        "messages": self.conversation,
                    },
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        raise Exception(f"Claude API error: {error}")

                    data = await resp.json()
                    assistant_message = data["content"][0]["text"]

        # Add to conversation
        self.conversation.append({"role": "assistant", "content": assistant_message})

        # Keep conversation manageable (last 20 exchanges)
        if len(self.conversation) > 40:
            self.conversation = self.conversation[-40:]

        return assistant_message

    def _parse_response(self, response: str) -> Dict:
        """Parse Claude's JSON response."""
        # Try to extract JSON from response
        try:
            # Look for JSON block
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                # Try to find JSON object
                match = re.search(r'\{[\s\S]*\}', response)
                if match:
                    json_str = match.group()
                else:
                    return {"raw": response, "error": "No JSON found"}

            return json.loads(json_str)

        except json.JSONDecodeError as e:
            return {"raw": response, "error": f"JSON parse error: {e}"}

    def get_attack_summary(self) -> Dict:
        """Get a summary of the attack session."""
        if not self.context:
            return {}

        return {
            "target": self.context.target,
            "phase": self.context.phase.value,
            "technologies": self.context.technologies,
            "auth_system": self.context.auth_system,
            "findings_count": len(self.context.findings),
            "attempts_count": len(self.context.attempts),
            "successful_attempts": len([a for a in self.context.attempts if a.success]),
            "failed_techniques": len(self.context.failed_techniques),
            "has_auth_bypass": self.context.has_auth_bypass,
            "has_data_access": self.context.has_data_access,
            "has_write_access": self.context.has_write_access,
            "breach_proven": self.context.breach_proven,
            "data_extracted": self.context.data_count,
        }


# Convenience functions for the main breach.py

async def create_hacker_brain(api_key: str = None) -> PersistentHackerBrain:
    """Create a new hacker brain instance."""
    return PersistentHackerBrain(api_key)
