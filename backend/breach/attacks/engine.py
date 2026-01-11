"""
BREACH.AI - Attack Engine

Main orchestrator for executing attacks.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Type

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import Finding, Severity
from backend.breach.core.scheduler import ScheduledAttack
from backend.breach.utils.http import HTTPClient
from backend.breach.utils.logger import logger


@dataclass
class AttackConfig:
    """Configuration for attack execution."""
    timeout: float = 30.0
    rate_limit: int = 50
    max_payloads: int = 50
    verify_findings: bool = True
    extract_evidence: bool = True


class AttackEngine:
    """
    Main attack orchestration engine.

    Manages:
    - Attack module loading
    - Attack execution
    - Result verification
    - Evidence extraction
    """

    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        config: Optional[AttackConfig] = None
    ):
        self.config = config or AttackConfig()
        self.http_client = http_client
        self._own_client = False

        # Attack modules registry
        self._attack_modules: dict[str, Type[BaseAttack]] = {}

        # Stats
        self.request_count = 0
        self.attacks_executed = 0
        self.successful_attacks = 0

        # Register built-in attack modules
        self._register_builtin_attacks()

    def _register_builtin_attacks(self):
        """Register built-in attack modules."""
        try:
            from backend.breach.attacks.sqli import SQLInjectionAttack
            self.register_attack("sqli", SQLInjectionAttack)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.xss import XSSAttack
            self.register_attack("xss", XSSAttack)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.ssrf import SSRFAttack
            self.register_attack("ssrf", SSRFAttack)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.auth import AuthBypassAttack
            self.register_attack("auth_bypass", AuthBypassAttack)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.idor import IDORAttack
            self.register_attack("idor", IDORAttack)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.injection import CommandInjectionAttack, SSTIAttack
            self.register_attack("command_injection", CommandInjectionAttack)
            self.register_attack("ssti", SSTIAttack)
        except ImportError:
            pass

        # === AUTH OBLITERATOR MODULES ===
        # Comprehensive authentication attack suite

        try:
            from backend.breach.attacks.jwt_obliterator import JWTObliterator
            self.register_attack("jwt_attack", JWTObliterator)
            self.register_attack("jwt", JWTObliterator)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.oauth_destroyer import OAuthDestroyer
            self.register_attack("oauth_attack", OAuthDestroyer)
            self.register_attack("oauth", OAuthDestroyer)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.session_annihilator import SessionAnnihilator
            self.register_attack("session_attack", SessionAnnihilator)
            self.register_attack("session", SessionAnnihilator)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.password_reset_killer import PasswordResetKiller
            self.register_attack("password_reset_attack", PasswordResetKiller)
            self.register_attack("password_reset", PasswordResetKiller)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.mfa_bypass import MFABypass
            self.register_attack("mfa_bypass", MFABypass)
            self.register_attack("mfa", MFABypass)
            self.register_attack("2fa", MFABypass)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.saml_destroyer import SAMLDestroyer
            self.register_attack("saml_attack", SAMLDestroyer)
            self.register_attack("saml", SAMLDestroyer)
            self.register_attack("sso", SAMLDestroyer)
        except ImportError:
            pass

        # === API ANNIHILATOR MODULES ===
        # Comprehensive API attack suite

        try:
            from backend.breach.attacks.api_discovery import APIDiscovery
            self.register_attack("api_discovery", APIDiscovery)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.graphql_destroyer import GraphQLDestroyer
            self.register_attack("graphql_attack", GraphQLDestroyer)
            self.register_attack("graphql", GraphQLDestroyer)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.rest_api_attacker import RESTAPIAttacker
            self.register_attack("rest_api_attack", RESTAPIAttacker)
            self.register_attack("rest", RESTAPIAttacker)
            self.register_attack("bola", RESTAPIAttacker)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.api_auth_breaker import APIAuthBreaker
            self.register_attack("api_auth_attack", APIAuthBreaker)
            self.register_attack("api_auth", APIAuthBreaker)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.websocket_destroyer import WebSocketDestroyer
            self.register_attack("websocket_attack", WebSocketDestroyer)
            self.register_attack("websocket", WebSocketDestroyer)
            self.register_attack("ws", WebSocketDestroyer)
        except ImportError:
            pass

        # === MASTER ORCHESTRATORS ===

        try:
            from backend.breach.attacks.auth_obliterator import AuthObliterator
            self.register_attack("auth_obliterator", AuthObliterator)
        except ImportError:
            pass

        try:
            from backend.breach.attacks.api_annihilator import APIAnnihilator
            self.register_attack("api_annihilator", APIAnnihilator)
        except ImportError:
            pass

        # === CLOUD DESTROYER MODULES ===
        # Cloud infrastructure attack suite

        try:
            from backend.breach.attacks.cloud_destroyer import (
                CloudDestroyer,
                CloudMetadataSSRF,
                S3BucketAttacker,
            )
            self.register_attack("cloud_destroyer", CloudDestroyer)
            self.register_attack("cloud", CloudDestroyer)
            self.register_attack("cloud_metadata", CloudMetadataSSRF)
            self.register_attack("metadata_ssrf", CloudMetadataSSRF)
            self.register_attack("s3_attack", S3BucketAttacker)
            self.register_attack("s3", S3BucketAttacker)
            self.register_attack("bucket", S3BucketAttacker)
        except ImportError:
            pass

        # === INJECTION ARSENAL MODULES ===
        # Comprehensive injection attack suite

        try:
            from backend.breach.attacks.injection_arsenal import (
                InjectionArsenal,
                AdvancedSQLiAttack,
                NoSQLInjectionAttack,
                LDAPInjectionAttack,
                XPathInjectionAttack,
                CommandInjectionAdvanced,
                SSTIAdvancedAttack,
                ELInjectionAttack,
            )
            self.register_attack("injection_arsenal", InjectionArsenal)
            self.register_attack("advanced_sqli", AdvancedSQLiAttack)
            self.register_attack("sqli_advanced", AdvancedSQLiAttack)
            self.register_attack("nosqli", NoSQLInjectionAttack)
            self.register_attack("nosql", NoSQLInjectionAttack)
            self.register_attack("mongodb", NoSQLInjectionAttack)
            self.register_attack("ldapi", LDAPInjectionAttack)
            self.register_attack("ldap", LDAPInjectionAttack)
            self.register_attack("xpathi", XPathInjectionAttack)
            self.register_attack("xpath", XPathInjectionAttack)
            self.register_attack("cmdi_advanced", CommandInjectionAdvanced)
            self.register_attack("os_command", CommandInjectionAdvanced)
            self.register_attack("ssti_advanced", SSTIAdvancedAttack)
            self.register_attack("template", SSTIAdvancedAttack)
            self.register_attack("el_injection", ELInjectionAttack)
            self.register_attack("expression", ELInjectionAttack)
        except ImportError:
            pass

        # === FILE WARFARE MODULES ===
        # File-based attack suite

        try:
            from backend.breach.attacks.file_warfare import (
                FileWarfare,
                PathTraversalAttack,
                FileInclusionAttack,
                FileUploadAttack,
            )
            self.register_attack("file_warfare", FileWarfare)
            self.register_attack("file", FileWarfare)
            self.register_attack("path_traversal", PathTraversalAttack)
            self.register_attack("lfi", FileInclusionAttack)
            self.register_attack("rfi", FileInclusionAttack)
            self.register_attack("file_inclusion", FileInclusionAttack)
            self.register_attack("file_upload", FileUploadAttack)
            self.register_attack("upload", FileUploadAttack)
        except ImportError:
            pass

        # === CLIENT-SIDE CARNAGE MODULES ===
        # Client-side attack suite

        try:
            from backend.breach.attacks.client_side_carnage import (
                ClientSideCarnage,
                DOMXSSHunter,
                PrototypePollutionHunter,
            )
            self.register_attack("client_side", ClientSideCarnage)
            self.register_attack("client_carnage", ClientSideCarnage)
            self.register_attack("dom_xss", DOMXSSHunter)
            self.register_attack("domxss", DOMXSSHunter)
            self.register_attack("prototype_pollution", PrototypePollutionHunter)
            self.register_attack("proto_pollution", PrototypePollutionHunter)
        except ImportError:
            pass

        # === BUSINESS LOGIC DESTROYER MODULES ===
        # Business logic attack suite

        try:
            from backend.breach.attacks.business_logic_destroyer import (
                BusinessLogicDestroyer,
                RaceConditionAttack,
                PriceManipulationAttack,
            )
            self.register_attack("business_logic", BusinessLogicDestroyer)
            self.register_attack("logic", BusinessLogicDestroyer)
            self.register_attack("race_condition", RaceConditionAttack)
            self.register_attack("race", RaceConditionAttack)
            self.register_attack("toctou", RaceConditionAttack)
            self.register_attack("price_manipulation", PriceManipulationAttack)
            self.register_attack("price", PriceManipulationAttack)
        except ImportError:
            pass

        # === LIVING OFF THE LAND ===
        # LOLBins/LOLBas attack simulation

        try:
            from backend.breach.attacks.living_off_the_land import (
                LivingOffTheLand,
                LOLTechnique,
                LOLPayload,
                OSType,
                LOLCategory,
            )
            # LOL module is a technique library, not a BaseAttack
            # Registered for reference but used differently
            self._lol_module = LivingOffTheLand()
        except ImportError:
            self._lol_module = None

        # === DOCKER DESTROYER ===
        # Container security attack suite

        try:
            from backend.breach.attacks.docker_destroyer import DockerDestroyer
            self.register_attack("docker", DockerDestroyer)
            self.register_attack("docker_destroyer", DockerDestroyer)
            self.register_attack("container", DockerDestroyer)
            self.register_attack("container_escape", DockerDestroyer)
        except ImportError:
            pass

        # === MOBILE API ATTACKER ===
        # Mobile application API attack suite

        try:
            from backend.breach.attacks.mobile_api_attacker import MobileAPIAttacker
            self.register_attack("mobile", MobileAPIAttacker)
            self.register_attack("mobile_api", MobileAPIAttacker)
            self.register_attack("ios", MobileAPIAttacker)
            self.register_attack("android", MobileAPIAttacker)
        except ImportError:
            pass

        # === MODERN STACK DESTROYER ===
        # Vibe-coder stack attacks (Next.js, Supabase, Firebase, Vercel, etc.)

        try:
            from backend.breach.attacks.modern_stack_destroyer import ModernStackDestroyer
            self.register_attack("modern_stack", ModernStackDestroyer)
            self.register_attack("nextjs", ModernStackDestroyer)
            self.register_attack("supabase", ModernStackDestroyer)
            self.register_attack("firebase", ModernStackDestroyer)
            self.register_attack("vercel", ModernStackDestroyer)
            self.register_attack("vibe_code", ModernStackDestroyer)
        except ImportError:
            pass

        # === AI CODE ANALYZER ===
        # Vulnerabilities in AI-generated code (Cursor, v0, Bolt, ChatGPT, etc.)

        try:
            from backend.breach.attacks.ai_code_analyzer import AICodeAnalyzer
            self.register_attack("ai_code", AICodeAnalyzer)
            self.register_attack("cursor", AICodeAnalyzer)
            self.register_attack("v0", AICodeAnalyzer)
            self.register_attack("bolt", AICodeAnalyzer)
            self.register_attack("vibe_coder", AICodeAnalyzer)
        except ImportError:
            pass

    def get_lol_techniques(self, os_type: str = "linux") -> list:
        """Get Living Off The Land techniques."""
        if not self._lol_module:
            return []
        from backend.breach.attacks.living_off_the_land import OSType
        os_enum = OSType.LINUX if os_type.lower() == "linux" else OSType.WINDOWS
        return self._lol_module.get_all_techniques(os_enum)

    def register_attack(self, attack_type: str, attack_class: Type[BaseAttack]):
        """Register an attack module."""
        self._attack_modules[attack_type] = attack_class
        logger.debug(f"Registered attack module: {attack_type}")

    async def initialize(self, base_url: str):
        """Initialize the attack engine."""
        if not self.http_client:
            self.http_client = HTTPClient(
                base_url=base_url,
                timeout=self.config.timeout,
                rate_limit=self.config.rate_limit,
            )
            self._own_client = True

    async def close(self):
        """Clean up resources."""
        if self._own_client and self.http_client:
            await self.http_client.close()

    async def execute(self, scheduled_attack: ScheduledAttack) -> Optional[AttackResult]:
        """
        Execute a scheduled attack.

        Args:
            scheduled_attack: The attack to execute

        Returns:
            AttackResult if vulnerability found, None otherwise
        """
        attack_type = scheduled_attack.attack_type
        target = scheduled_attack.target
        endpoint = scheduled_attack.endpoint or target
        parameter = scheduled_attack.parameter
        method = scheduled_attack.method

        self.attacks_executed += 1

        # Get attack module
        attack_class = self._attack_modules.get(attack_type)
        if not attack_class:
            logger.debug(f"Unknown attack type: {attack_type}")
            return None

        # Create attack instance
        attack = attack_class(self.http_client)

        logger.attack_start(attack_type, f"{endpoint}?{parameter}" if parameter else endpoint)

        try:
            # Execute attack
            start_time = datetime.utcnow()

            result = await attack.run(
                url=endpoint,
                parameter=parameter,
                method=method,
                **scheduled_attack.config
            )

            duration = (datetime.utcnow() - start_time).total_seconds() * 1000

            if result:
                result.duration_ms = duration
                self.successful_attacks += 1

                # Verify finding if configured
                if self.config.verify_findings:
                    result = await self._verify_finding(attack, result)

                # Extract additional evidence if configured
                if self.config.extract_evidence and result.success:
                    result = await self._extract_evidence(attack, result)

                logger.attack_success(attack_type, result.details[:100] if result.details else "")

            return result

        except Exception as e:
            logger.debug(f"Attack execution error: {e}")
            return None

    async def execute_batch(
        self,
        attacks: list[ScheduledAttack],
        max_concurrent: int = 5
    ) -> list[AttackResult]:
        """
        Execute multiple attacks concurrently.

        Args:
            attacks: List of attacks to execute
            max_concurrent: Maximum concurrent attacks

        Returns:
            List of successful attack results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def run_with_semaphore(attack: ScheduledAttack) -> Optional[AttackResult]:
            async with semaphore:
                return await self.execute(attack)

        tasks = [run_with_semaphore(attack) for attack in attacks]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in task_results:
            if isinstance(result, AttackResult) and result.success:
                results.append(result)

        return results

    async def _verify_finding(
        self,
        attack: BaseAttack,
        result: AttackResult
    ) -> AttackResult:
        """
        Verify a finding by re-testing with the same payload.
        """
        if not result.payload or not result.endpoint:
            return result

        # Re-send the payload
        response = await attack._send_payload(
            result.endpoint,
            result.parameter,
            result.payload,
            result.method,
        )

        # Check if we get the same result
        if attack._detect_error_patterns(response.body, attack.error_patterns):
            result.verified = True
            result.add_evidence(
                "verification",
                "Vulnerability verified with repeated test",
                f"Payload: {result.payload}"
            )

        return result

    async def _extract_evidence(
        self,
        attack: BaseAttack,
        result: AttackResult
    ) -> AttackResult:
        """
        Extract additional evidence for the finding.
        """
        # Capture request/response
        if result.endpoint and result.payload and result.parameter:
            result.request = f"{result.method} {result.endpoint}?{result.parameter}={result.payload}"

        # For data extraction attacks, try to get a sample
        if result.data_sample:
            result.add_evidence(
                "data_sample",
                "Sample of extracted data",
                result.data_sample[:1000]
            )

        return result

    async def execute_post_ex(self, action: Any) -> Any:
        """
        Execute a post-exploitation action.

        Args:
            action: PostExAction from the brain

        Returns:
            Result with evidence
        """
        # This is a placeholder - actual implementation would depend on
        # what access we have and what we want to demonstrate
        @dataclass
        class PostExResult:
            success: bool = False
            evidence: Optional[Any] = None

        return PostExResult()

    def get_available_attacks(self) -> list[str]:
        """Get list of available attack types."""
        return list(self._attack_modules.keys())

    def stats(self) -> dict:
        """Get attack engine statistics."""
        return {
            "attacks_executed": self.attacks_executed,
            "successful_attacks": self.successful_attacks,
            "success_rate": self.successful_attacks / max(1, self.attacks_executed),
            "available_modules": len(self._attack_modules),
            "requests_made": self.http_client.request_count if self.http_client else 0,
        }
