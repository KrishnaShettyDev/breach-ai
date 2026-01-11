"""
BREACH.AI - API Annihilator

THE MASTER API DESTRUCTION ENGINE

Modern applications ARE APIs. This module destroys them all:
- REST API Attacker: BOLA, mass assignment, rate limits
- GraphQL Destroyer: Introspection, injection, DoS
- API Auth Breaker: Key leakage, broken auth
- WebSocket Destroyer: Hijacking, injection
- API Discovery: Full attack surface mapping

"Modern apps are APIs. We own them."
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from backend.breach.attacks.api_auth_breaker import APIAuthBreaker
from backend.breach.attacks.api_discovery import APIDiscovery
from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.attacks.graphql_destroyer import GraphQLDestroyer
from backend.breach.attacks.rest_api_attacker import RESTAPIAttacker
from backend.breach.attacks.websocket_destroyer import WebSocketDestroyer
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.http import HTTPClient
from backend.breach.utils.logger import logger


class APIAttackPhase(Enum):
    """Phases of API annihilation."""
    DISCOVERY = "discovery"
    REST_ATTACKS = "rest_attacks"
    GRAPHQL_ATTACKS = "graphql_attacks"
    AUTH_ATTACKS = "auth_attacks"
    WEBSOCKET_ATTACKS = "websocket_attacks"
    EXPLOITATION = "exploitation"


@dataclass
class APIAnnihilatorResult:
    """Result of API annihilation campaign."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    phase: APIAttackPhase = APIAttackPhase.DISCOVERY
    findings: list[AttackResult] = field(default_factory=list)
    access_achieved: AccessLevel = AccessLevel.NONE

    # Discovery stats
    endpoints_found: int = 0
    api_types: list[str] = field(default_factory=list)  # rest, graphql, websocket

    # Attack stats
    rest_attacks: int = 0
    graphql_attacks: int = 0
    auth_attacks: int = 0
    websocket_attacks: int = 0

    # Extracted data
    api_keys: list[str] = field(default_factory=list)
    exposed_data: list[str] = field(default_factory=list)

    def total_attacks(self) -> int:
        return (
            self.rest_attacks + self.graphql_attacks +
            self.auth_attacks + self.websocket_attacks
        )

    def critical_findings(self) -> list[AttackResult]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def summary(self) -> str:
        return f"""
API ANNIHILATOR RESULTS
========================
Target: {self.target}
Duration: {self.end_time - self.start_time if self.end_time else 'ongoing'}
Access Achieved: {self.access_achieved.value.upper()}

API Types Found: {', '.join(self.api_types) or 'None'}
Endpoints Discovered: {self.endpoints_found}

Total Attacks: {self.total_attacks()}
- REST: {self.rest_attacks}
- GraphQL: {self.graphql_attacks}
- Auth: {self.auth_attacks}
- WebSocket: {self.websocket_attacks}

Findings: {len(self.findings)}
- Critical: {len([f for f in self.findings if f.severity == Severity.CRITICAL])}
- High: {len([f for f in self.findings if f.severity == Severity.HIGH])}
- Medium: {len([f for f in self.findings if f.severity == Severity.MEDIUM])}

API Keys Found: {len(self.api_keys)}
Data Exposed: {len(self.exposed_data)}
"""


class APIAnnihilator(BaseAttack):
    """
    THE API ANNIHILATOR

    Master API attack orchestrator that runs ALL API attacks
    in an intelligent sequence to maximize exploitation.

    Attack Sequence:
    1. DISCOVERY - Map the entire API attack surface
    2. REST ATTACKS - BOLA, mass assignment, rate limits
    3. GRAPHQL ATTACKS - Introspection, injection, DoS
    4. AUTH ATTACKS - Key leakage, broken auth
    5. WEBSOCKET ATTACKS - Hijacking, injection
    6. EXPLOITATION - Chain findings for maximum impact
    """

    name = "API Annihilator"
    attack_type = "api_annihilator"
    description = "Master API attack orchestrator"
    severity = Severity.CRITICAL
    owasp_category = "API Security"
    cwe_id = 284

    def __init__(self, http_client: Optional[HTTPClient] = None):
        super().__init__(http_client)

        # Attack modules
        self.api_discovery: Optional[APIDiscovery] = None
        self.rest_attacker: Optional[RESTAPIAttacker] = None
        self.graphql_destroyer: Optional[GraphQLDestroyer] = None
        self.auth_breaker: Optional[APIAuthBreaker] = None
        self.websocket_destroyer: Optional[WebSocketDestroyer] = None

        # State
        self.result: Optional[APIAnnihilatorResult] = None
        self.detected_api_types: set[str] = set()

    def get_payloads(self) -> list[str]:
        return []

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has APIs."""
        response = await self.http_client.get(url)

        api_indicators = [
            "api", "json", "graphql", "rest", "websocket",
            "ws://", "wss://", "endpoint", "bearer", "oauth",
        ]

        body_lower = response.body.lower()
        content_type = response.headers.get("Content-Type", "").lower()

        return (
            any(ind in body_lower for ind in api_indicators) or
            "application/json" in content_type
        )

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Run the full API annihilation campaign."""
        result = self._create_result(False, url, parameter)

        # Initialize campaign result
        self.result = APIAnnihilatorResult(
            target=url,
            start_time=datetime.utcnow(),
        )

        # Initialize attack modules
        self._initialize_modules()

        logger.info("=" * 60)
        logger.info("  API ANNIHILATOR - COMMENCING ATTACK")
        logger.info("=" * 60)

        try:
            # Phase 1: Discovery
            await self._phase_discovery(url)

            # Phase 2: REST API Attacks
            if "rest" in self.detected_api_types:
                await self._phase_rest_attacks(url)

            # Phase 3: GraphQL Attacks
            if "graphql" in self.detected_api_types:
                await self._phase_graphql_attacks(url)

            # Phase 4: API Auth Attacks
            await self._phase_auth_attacks(url)

            # Phase 5: WebSocket Attacks
            if "websocket" in self.detected_api_types:
                await self._phase_websocket_attacks(url)

            # Phase 6: Exploitation
            await self._phase_exploitation(url)

        except Exception as e:
            logger.error(f"API Annihilator error: {e}")

        # Finalize
        self.result.end_time = datetime.utcnow()
        self.result.api_types = list(self.detected_api_types)

        # Build final result
        if self.result.findings:
            result.success = True
            result.access_gained = self.result.access_achieved

            critical = self.result.critical_findings()
            if critical:
                result.details = f"API ANNIHILATED: {critical[0].details}"
                result.payload = critical[0].payload
            else:
                result.details = f"Found {len(self.result.findings)} API vulnerabilities"

            for finding in self.result.findings:
                for evidence in finding.evidence:
                    result.add_evidence(
                        evidence.get("type", "unknown"),
                        evidence.get("description", ""),
                        evidence.get("data", "")
                    )

        logger.info("=" * 60)
        logger.info("  API ANNIHILATOR - CAMPAIGN COMPLETE")
        logger.info(self.result.summary())
        logger.info("=" * 60)

        return result

    def _initialize_modules(self):
        """Initialize all attack modules."""
        self.api_discovery = APIDiscovery(self.http_client)
        self.rest_attacker = RESTAPIAttacker(self.http_client)
        self.graphql_destroyer = GraphQLDestroyer(self.http_client)
        self.auth_breaker = APIAuthBreaker(self.http_client)
        self.websocket_destroyer = WebSocketDestroyer(self.http_client)

    async def _phase_discovery(self, url: str):
        """Phase 1: API Discovery."""
        self.result.phase = APIAttackPhase.DISCOVERY
        logger.info("[API] Phase 1: DISCOVERY")

        # Run API discovery
        discovery_result = await self.api_discovery.exploit(url)

        if discovery_result.success:
            self.result.findings.append(discovery_result)

            # Parse discovery data
            if discovery_result.data_sample:
                try:
                    import json
                    data = json.loads(discovery_result.data_sample)
                    self.result.endpoints_found = data.get("endpoints", 0)
                except:
                    pass

        # Detect API types
        if await self.rest_attacker.check(url):
            self.detected_api_types.add("rest")

        if await self.graphql_destroyer.check(url):
            self.detected_api_types.add("graphql")

        if await self.websocket_destroyer.check(url):
            self.detected_api_types.add("websocket")

        logger.info(f"[API] Detected types: {self.detected_api_types}")

    async def _phase_rest_attacks(self, url: str):
        """Phase 2: REST API Attacks."""
        self.result.phase = APIAttackPhase.REST_ATTACKS
        logger.info("[API] Phase 2: REST API ATTACKS")

        try:
            rest_result = await self.rest_attacker.exploit(url)
            self.result.rest_attacks += 1

            if rest_result.success:
                self.result.findings.append(rest_result)
                self._update_access(rest_result.access_gained)

                # Check for BOLA (most critical)
                if "bola" in rest_result.details.lower():
                    logger.finding("critical", "BOLA/IDOR", rest_result.details)
                else:
                    logger.finding("high", "REST API vulnerability", rest_result.details)

        except Exception as e:
            logger.debug(f"REST attack error: {e}")

    async def _phase_graphql_attacks(self, url: str):
        """Phase 3: GraphQL Attacks."""
        self.result.phase = APIAttackPhase.GRAPHQL_ATTACKS
        logger.info("[API] Phase 3: GRAPHQL DESTRUCTION")

        try:
            graphql_result = await self.graphql_destroyer.exploit(url)
            self.result.graphql_attacks += 1

            if graphql_result.success:
                self.result.findings.append(graphql_result)
                self._update_access(graphql_result.access_gained)

                logger.finding("high", "GraphQL vulnerability", graphql_result.details)

        except Exception as e:
            logger.debug(f"GraphQL attack error: {e}")

    async def _phase_auth_attacks(self, url: str):
        """Phase 4: API Auth Attacks."""
        self.result.phase = APIAttackPhase.AUTH_ATTACKS
        logger.info("[API] Phase 4: API AUTH BREAKING")

        try:
            auth_result = await self.auth_breaker.exploit(url)
            self.result.auth_attacks += 1

            if auth_result.success:
                self.result.findings.append(auth_result)
                self._update_access(auth_result.access_gained)

                # Extract API keys if found
                if auth_result.payload and len(auth_result.payload) > 10:
                    self.result.api_keys.append(auth_result.payload)

                logger.finding("critical", "API Auth vulnerability", auth_result.details)

        except Exception as e:
            logger.debug(f"Auth attack error: {e}")

    async def _phase_websocket_attacks(self, url: str):
        """Phase 5: WebSocket Attacks."""
        self.result.phase = APIAttackPhase.WEBSOCKET_ATTACKS
        logger.info("[API] Phase 5: WEBSOCKET DESTRUCTION")

        try:
            ws_result = await self.websocket_destroyer.exploit(url)
            self.result.websocket_attacks += 1

            if ws_result.success:
                self.result.findings.append(ws_result)
                self._update_access(ws_result.access_gained)

                logger.finding("high", "WebSocket vulnerability", ws_result.details)

        except Exception as e:
            logger.debug(f"WebSocket attack error: {e}")

    async def _phase_exploitation(self, url: str):
        """Phase 6: Chain findings for exploitation."""
        self.result.phase = APIAttackPhase.EXPLOITATION
        logger.info("[API] Phase 6: EXPLOITATION & CHAINING")

        if not self.result.findings:
            return

        # Look for attack chains
        chains = self._identify_attack_chains()

        for chain in chains:
            logger.info(f"[API] Attack chain: {chain['description']}")

            if chain['access'] > self.result.access_achieved:
                self._update_access(chain['access'])

    def _identify_attack_chains(self) -> list[dict]:
        """Identify possible attack chains."""
        chains = []

        finding_types = set()
        for f in self.result.findings:
            for e in f.evidence:
                finding_types.add(e.get("type", ""))

        # Chain 1: API Key + BOLA = Full data access
        if "api_key_leak" in finding_types and "api_bola" in finding_types:
            chains.append({
                "description": "API Key + BOLA = Full database access",
                "access": AccessLevel.DATABASE,
            })

        # Chain 2: GraphQL introspection + injection
        if "graphql_introspection" in finding_types:
            chains.append({
                "description": "GraphQL schema + targeted injection",
                "access": AccessLevel.USER,
            })

        # Chain 3: Auth bypass + BOLA
        if "api_auth_bypass" in finding_types and "api_bola" in finding_types:
            chains.append({
                "description": "Auth bypass + BOLA = Account takeover",
                "access": AccessLevel.ADMIN,
            })

        # Chain 4: WebSocket hijacking
        if "ws_cswsh" in finding_types:
            chains.append({
                "description": "WebSocket hijacking = Real-time data theft",
                "access": AccessLevel.USER,
            })

        return chains

    def _update_access(self, new_access: Optional[AccessLevel]):
        """Update access level if new is higher."""
        if new_access and new_access > self.result.access_achieved:
            logger.info(f"[API] ACCESS ESCALATED: {self.result.access_achieved.value} -> {new_access.value}")
            self.result.access_achieved = new_access


async def annihilate_api(url: str, http_client: Optional[HTTPClient] = None) -> APIAnnihilatorResult:
    """
    Convenience function to annihilate an API.

    Usage:
        result = await annihilate_api("https://api.target.com")
        print(result.summary())
    """
    annihilator = APIAnnihilator(http_client)
    await annihilator.exploit(url)
    return annihilator.result
