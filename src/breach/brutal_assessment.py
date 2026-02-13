"""
BREACH.AI - Brutal One-Time Assessment

Complete security breach assessment for consulting engagements.
Runs ALL 60+ attack modules in optimized order.
Generates comprehensive report with evidence and fix recommendations.

Usage:
    assessment = BrutalAssessment(target="https://example.com")
    results = await assessment.run()
    report = assessment.generate_report()
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import traceback

# V2 Killchain Modules
from breach.modules.base import (
    ModuleConfig,
    get_all_modules as get_v2_modules,
)
from breach.core.killchain import (
    BreachPhase,
    Evidence,
    EvidenceType,
    Severity,
    AccessLevel,
)

# V1 Attack Modules
from breach.attacks.sqli import SQLInjectionAttack
from breach.attacks.nosql import NoSQLInjectionAttack
from breach.attacks.xss import XSSAttack
from breach.attacks.ssrf import SSRFAttack
from breach.attacks.injection import CommandInjectionAttack, SSTIAttack, XXEAttack
from breach.attacks.auth import AuthBypassAttack
from breach.attacks.jwt_obliterator import JWTObliterator
from breach.attacks.oauth_destroyer import OAuthDestroyer
from breach.attacks.mfa_bypass import MFABypass
from breach.attacks.session_annihilator import SessionAnnihilator
from breach.attacks.password_reset_killer import PasswordResetKiller
from breach.attacks.saml_destroyer import SAMLDestroyer
from breach.attacks.api_auth_breaker import APIAuthBreaker
from breach.attacks.idor import IDORAttack
from breach.attacks.api_discovery import APIDiscovery
from breach.attacks.rest_api_attacker import RESTAPIAttacker
from breach.attacks.graphql_destroyer import GraphQLDestroyer
from breach.attacks.websocket_destroyer import WebSocketDestroyer
from breach.attacks.mobile_api_attacker import MobileAPIAttacker
from breach.attacks.business_logic_destroyer import BusinessLogicDestroyer
from breach.attacks.client_side_carnage import ClientSideCarnage
from breach.attacks.modern_stack_destroyer import ModernStackDestroyer
from breach.attacks.cloud_destroyer import CloudDestroyer
from breach.attacks.docker_destroyer import DockerDestroyer
from breach.attacks.file_warfare import FileWarfare
from breach.attacks.ai_code_analyzer import AICodeAnalyzer
from breach.attacks.api_annihilator import APIAnnihilator
from breach.attacks.injection_arsenal import InjectionArsenal
from breach.attacks.living_off_the_land import LivingOffTheLand
from breach.attacks.base import AttackResult

# V1 Recon Modules
from breach.recon.dns import DNSEnumerator
from breach.recon.ports import PortScanner
from breach.recon.web import WebCrawler, CrawlResult
from breach.recon.recon_warfare import ReconWarfare
from breach.recon.social_engineering import SocialEngineering

# HTTP Client
from breach.utils.http import HTTPClient

# Fix Recommendations Database
from breach.recommendations import get_recommendation, ALL_RECOMMENDATIONS


class AssessmentPhase(Enum):
    """Assessment phases for brutal one-time assessment."""
    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    API_ATTACKS = "api_attacks"
    CLOUD_INFRA = "cloud_infrastructure"
    LATERAL_DATA = "lateral_and_data"
    PROOF = "proof_generation"


@dataclass
class Finding:
    """A security finding from the assessment."""
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: List[Evidence]
    affected_component: str
    attack_module: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    business_impact: Optional[str] = None
    recommendation: Optional[str] = None
    fix_guidance: Optional[str] = None
    prevention: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def enrich_with_recommendation(self, vuln_type: str):
        """Enrich finding with recommendation data."""
        rec = get_recommendation(vuln_type)
        if rec:
            self.cwe_id = self.cwe_id or rec.get("cwe_id")
            self.business_impact = self.business_impact or rec.get("impact")
            self.recommendation = self.recommendation or rec.get("title")
            self.fix_guidance = rec.get("fix")
            self.prevention = rec.get("prevention")
            self.references = self.references or rec.get("references", [])


@dataclass
class AssessmentResults:
    """Complete results from a brutal assessment."""
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: int = 0

    # Findings by severity
    critical_findings: List[Finding] = field(default_factory=list)
    high_findings: List[Finding] = field(default_factory=list)
    medium_findings: List[Finding] = field(default_factory=list)
    low_findings: List[Finding] = field(default_factory=list)
    info_findings: List[Finding] = field(default_factory=list)

    # Module execution stats
    modules_executed: int = 0
    modules_successful: int = 0
    modules_failed: int = 0
    module_results: Dict[str, Any] = field(default_factory=dict)

    # Evidence collection
    all_evidence: List[Evidence] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    data_samples: List[Dict] = field(default_factory=list)

    # Business impact
    risk_score: int = 0  # 0-100
    estimated_breach_cost: int = 0
    compliance_issues: List[str] = field(default_factory=list)

    # Access levels achieved
    max_access_level: AccessLevel = AccessLevel.NONE
    access_chain: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return (
            len(self.critical_findings) +
            len(self.high_findings) +
            len(self.medium_findings) +
            len(self.low_findings) +
            len(self.info_findings)
        )

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export."""
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_findings": self.total_findings,
                "critical": len(self.critical_findings),
                "high": len(self.high_findings),
                "medium": len(self.medium_findings),
                "low": len(self.low_findings),
                "info": len(self.info_findings),
                "risk_score": self.risk_score,
                "estimated_breach_cost": self.estimated_breach_cost,
                "max_access_level": self.max_access_level.value,
            },
            "modules": {
                "executed": self.modules_executed,
                "successful": self.modules_successful,
                "failed": self.modules_failed,
            },
            "findings": {
                "critical": [self._finding_to_dict(f) for f in self.critical_findings],
                "high": [self._finding_to_dict(f) for f in self.high_findings],
                "medium": [self._finding_to_dict(f) for f in self.medium_findings],
                "low": [self._finding_to_dict(f) for f in self.low_findings],
                "info": [self._finding_to_dict(f) for f in self.info_findings],
            },
            "access_chain": self.access_chain,
            "compliance_issues": self.compliance_issues,
        }

    def _finding_to_dict(self, finding: Finding) -> Dict:
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "category": finding.category,
            "description": finding.description,
            "affected_component": finding.affected_component,
            "attack_module": finding.attack_module,
            "cwe_id": finding.cwe_id,
            "cvss_score": finding.cvss_score,
            "business_impact": finding.business_impact,
            "recommendation": finding.recommendation,
            "reproduction_steps": finding.reproduction_steps,
            "timestamp": finding.timestamp.isoformat(),
        }


class BrutalAssessment:
    """
    Brutal One-Time Security Assessment.

    Runs ALL 60+ attack modules against the target:
    - 31 V1 Attack Modules
    - 25 V2 Killchain Modules
    - 7 Recon Modules

    Generates comprehensive evidence and recommendations.
    """

    def __init__(
        self,
        target: str,
        scope: List[str] = None,
        exclude: List[str] = None,
        aggressive: bool = True,
        timeout_per_module: int = 300,
        max_concurrent: int = 5,
        http_client: HTTPClient = None,
    ):
        self.target = target.rstrip("/")
        self.scope = scope or [target]
        self.exclude = exclude or []
        self.aggressive = aggressive
        self.timeout_per_module = timeout_per_module
        self.max_concurrent = max_concurrent

        # Create HTTPClient if not provided
        self.http_client = http_client or HTTPClient(
            base_url=self.target,
            timeout=float(timeout_per_module),
            rate_limit=50,
            max_retries=2,
        )
        self._own_http_client = http_client is None  # Track if we need to close it

        self.results = AssessmentResults(
            target=target,
            started_at=datetime.utcnow(),
        )

        # Chain data passed between modules
        self.chain_data: Dict[str, Any] = {}

        # Discovery data - populated during recon phase
        self.discovered_endpoints: List[Dict] = []  # URLs with parameters
        self.discovered_forms: List[Dict] = []       # Forms with inputs
        self.discovered_params: List[str] = []       # Parameter names found

        # Module execution order
        self._v1_attack_modules = self._get_v1_attack_modules()
        self._v1_recon_modules = self._get_v1_recon_modules()
        self._v2_modules = get_v2_modules()

        # Finding counter
        self._finding_counter = 0

    def _get_v1_attack_modules(self) -> List[tuple]:
        """Get all V1 attack modules with metadata."""
        return [
            # Injection Attacks (parameter-based)
            ("sqli", SQLInjectionAttack, "injection", "SQL Injection", True),
            ("nosql", NoSQLInjectionAttack, "injection", "NoSQL Injection", True),
            ("cmdi", CommandInjectionAttack, "injection", "Command Injection", True),
            ("ssti", SSTIAttack, "injection", "Server-Side Template Injection", True),
            ("xxe", XXEAttack, "injection", "XML External Entity", False),
            ("injection_arsenal", InjectionArsenal, "injection", "Full Injection Arsenal", False),

            # Web Vulnerabilities (parameter-based)
            ("xss", XSSAttack, "web", "Cross-Site Scripting", True),
            ("ssrf", SSRFAttack, "web", "Server-Side Request Forgery", True),
            ("idor", IDORAttack, "web", "Insecure Direct Object Reference", True),
            ("file_warfare", FileWarfare, "web", "File Upload/Traversal", False),

            # Authentication Attacks (URL-based, no param needed)
            ("auth", AuthBypassAttack, "authentication", "Authentication Bypass", False),
            ("jwt", JWTObliterator, "authentication", "JWT Attacks", False),
            ("oauth", OAuthDestroyer, "authentication", "OAuth/OIDC Attacks", False),
            ("mfa", MFABypass, "authentication", "MFA Bypass", False),
            ("session", SessionAnnihilator, "authentication", "Session Attacks", False),
            ("password_reset", PasswordResetKiller, "authentication", "Password Reset Abuse", False),
            ("saml", SAMLDestroyer, "authentication", "SAML Attacks", False),
            ("api_auth", APIAuthBreaker, "authentication", "API Auth Bypass", False),

            # API Attacks (URL-based)
            ("api_discovery", APIDiscovery, "api", "API Discovery", False),
            ("rest_api", RESTAPIAttacker, "api", "REST API Attacks", False),
            ("graphql", GraphQLDestroyer, "api", "GraphQL Attacks", False),
            ("websocket", WebSocketDestroyer, "api", "WebSocket Attacks", False),
            ("mobile_api", MobileAPIAttacker, "api", "Mobile API Attacks", False),
            ("api_annihilator", APIAnnihilator, "api", "Full API Attack Suite", False),

            # Application Logic (URL-based)
            ("business_logic", BusinessLogicDestroyer, "logic", "Business Logic Flaws", False),
            ("client_side", ClientSideCarnage, "logic", "Client-Side Attacks", False),
            ("modern_stack", ModernStackDestroyer, "logic", "Modern Stack Attacks", False),

            # Cloud & Infrastructure (URL-based)
            ("cloud", CloudDestroyer, "cloud", "Cloud Infrastructure Attacks", False),
            ("docker", DockerDestroyer, "cloud", "Docker/Container Attacks", False),
            ("living_off_land", LivingOffTheLand, "cloud", "Living Off The Land", False),

            # Code Analysis (URL-based)
            ("ai_code", AICodeAnalyzer, "analysis", "AI Code Analysis", False),
        ]

    def _get_v1_recon_modules(self) -> List[tuple]:
        """Get all V1 recon modules."""
        return [
            ("dns_recon", DNSEnumerator, "recon", "DNS Reconnaissance"),
            ("port_scan", PortScanner, "recon", "Port Scanning"),
            ("web_recon", WebCrawler, "recon", "Web Technology Fingerprinting"),
            ("recon_warfare", ReconWarfare, "recon", "Advanced Reconnaissance"),
            ("social_eng", SocialEngineering, "recon", "Social Engineering Recon"),
        ]

    async def run(self) -> AssessmentResults:
        """
        Execute the brutal assessment.
        Runs all 60+ modules in optimized order.
        """
        print(f"\n{'='*60}")
        print(f"BREACH.AI - BRUTAL ASSESSMENT")
        print(f"Target: {self.target}")
        print(f"Modules: {len(self._v1_attack_modules) + len(self._v1_recon_modules) + len(self._v2_modules)}")
        print(f"{'='*60}\n")

        try:
            # Phase 1: Reconnaissance
            print("\n[PHASE 1] RECONNAISSANCE")
            print("-" * 40)
            await self._run_recon_phase()

            # Phase 2: Initial Access Attacks
            print("\n[PHASE 2] INITIAL ACCESS ATTACKS")
            print("-" * 40)
            await self._run_initial_access_phase()

            # Phase 3: API & Application Attacks
            print("\n[PHASE 3] API & APPLICATION ATTACKS")
            print("-" * 40)
            await self._run_api_attacks_phase()

            # Phase 4: Cloud & Infrastructure
            print("\n[PHASE 4] CLOUD & INFRASTRUCTURE")
            print("-" * 40)
            await self._run_cloud_infra_phase()

            # Phase 5: Lateral Movement & Data Access
            print("\n[PHASE 5] LATERAL MOVEMENT & DATA ACCESS")
            print("-" * 40)
            await self._run_lateral_data_phase()

            # Phase 6: Proof & Evidence Generation
            print("\n[PHASE 6] PROOF & EVIDENCE")
            print("-" * 40)
            await self._run_proof_phase()

        except Exception as e:
            print(f"\n[ERROR] Assessment failed: {e}")
            traceback.print_exc()
        finally:
            # Clean up HTTPClient if we created it
            if self._own_http_client and self.http_client:
                try:
                    await self.http_client.close()
                except Exception:
                    pass

        # Finalize results
        self.results.completed_at = datetime.utcnow()
        self.results.duration_seconds = int(
            (self.results.completed_at - self.results.started_at).total_seconds()
        )

        # Calculate risk score and business impact
        self._calculate_risk_score()
        self._calculate_business_impact()

        # Print summary
        self._print_summary()

        return self.results

    async def _run_recon_phase(self):
        """Run reconnaissance modules and discover attack surface."""
        # Step 1: Web Crawling for endpoint/parameter discovery
        print("  [discovery] Crawling target for endpoints and parameters...")
        try:
            crawler = WebCrawler(
                http_client=self.http_client,
                max_depth=3,
                max_pages=100,
            )
            crawl_result = await asyncio.wait_for(
                crawler.crawl(self.target),
                timeout=120  # 2 min max for crawling
            )

            # Store discovered data
            for endpoint in crawl_result.endpoints:
                if endpoint.parameters:
                    self.discovered_endpoints.append({
                        "url": endpoint.url,
                        "method": endpoint.method,
                        "parameters": endpoint.parameters,
                    })

            for form in crawl_result.forms:
                self.discovered_forms.append(form)
                # Extract parameter names from forms
                for inp in form.get("inputs", []):
                    if inp.get("name"):
                        self.discovered_params.append(inp["name"])

            # Add parameters found in content
            for param in crawl_result.parameters:
                if param.get("name"):
                    self.discovered_params.append(param["name"])

            # Deduplicate
            self.discovered_params = list(set(self.discovered_params))

            print(f"  [discovery] Found {len(crawl_result.endpoints)} endpoints, "
                  f"{len(self.discovered_forms)} forms, {len(self.discovered_params)} params")

            # Store in chain data for other modules
            self.chain_data["endpoints"] = [e.url for e in crawl_result.endpoints]
            self.chain_data["forms"] = self.discovered_forms
            self.chain_data["parameters"] = self.discovered_params
            self.chain_data["api_endpoints"] = crawl_result.api_endpoints

        except asyncio.TimeoutError:
            print("  [discovery] Crawling timed out, continuing with basic attacks")
        except Exception as e:
            print(f"  [discovery] Crawling failed: {str(e)[:50]}, continuing...")

        # Step 2: Run other V1 Recon modules
        for name, module_class, category, description in self._v1_recon_modules:
            if module_class == WebCrawler:
                continue  # Already ran
            await self._run_v1_recon_module(name, module_class, category, description)

        # Step 3: V2 Recon modules
        v2_recon = [m for m in self._v2_modules.values()
                    if m.info.phase == BreachPhase.RECON]
        for module_class in v2_recon:
            await self._run_v2_module(module_class)

    async def _run_initial_access_phase(self):
        """Run initial access attack modules."""
        # V1 Injection and web vulnerability modules
        injection_modules = [
            m for m in self._v1_attack_modules
            if m[2] in ["injection", "web", "authentication"]
        ]
        for module_tuple in injection_modules:
            await self._run_v1_module(module_tuple)

        # V2 Initial Access modules
        v2_initial = [m for m in self._v2_modules.values()
                      if m.info.phase == BreachPhase.INITIAL_ACCESS]
        for module_class in v2_initial:
            await self._run_v2_module(module_class)

    async def _run_api_attacks_phase(self):
        """Run API and application attack modules."""
        api_modules = [
            m for m in self._v1_attack_modules
            if m[2] in ["api", "logic"]
        ]
        for module_tuple in api_modules:
            await self._run_v1_module(module_tuple)

    async def _run_cloud_infra_phase(self):
        """Run cloud and infrastructure attack modules."""
        cloud_modules = [
            m for m in self._v1_attack_modules
            if m[2] in ["cloud", "analysis"]
        ]
        for module_tuple in cloud_modules:
            await self._run_v1_module(module_tuple)

        # V2 Escalation modules
        v2_escalation = [m for m in self._v2_modules.values()
                         if m.info.phase == BreachPhase.ESCALATION]
        for module_class in v2_escalation:
            await self._run_v2_module(module_class)

    async def _run_lateral_data_phase(self):
        """Run lateral movement and data access modules."""
        # V2 Lateral modules
        v2_lateral = [m for m in self._v2_modules.values()
                      if m.info.phase == BreachPhase.LATERAL]
        for module_class in v2_lateral:
            await self._run_v2_module(module_class)

        # V2 Data Access modules
        v2_data = [m for m in self._v2_modules.values()
                   if m.info.phase == BreachPhase.DATA_ACCESS]
        for module_class in v2_data:
            await self._run_v2_module(module_class)

    async def _run_proof_phase(self):
        """Run proof and evidence generation modules."""
        v2_proof = [m for m in self._v2_modules.values()
                    if m.info.phase == BreachPhase.PROOF]
        for module_class in v2_proof:
            await self._run_v2_module(module_class)

    async def _run_v1_recon_module(
        self,
        name: str,
        module_class: type,
        category: str,
        description: str
    ):
        """Execute a V1 recon module (different interface than attack modules)."""
        self.results.modules_executed += 1
        print(f"  [{name}] {description}...", end=" ", flush=True)

        try:
            # Extract target hostname for DNS/port modules
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            hostname = parsed.netloc or parsed.path
            if ":" in hostname:
                hostname = hostname.split(":")[0]

            # Recon modules have different interfaces - handle each type
            if module_class == DNSEnumerator:
                module = module_class(timeout=30.0)
                # DNSEnumerator has enumerate_subdomains()
                result = await asyncio.wait_for(
                    module.enumerate_subdomains(hostname),
                    timeout=self.timeout_per_module
                )
            elif module_class == PortScanner:
                module = module_class(timeout=2.0, max_concurrent=50)
                # PortScanner has scan_ports()
                common_ports = [21, 22, 80, 443, 3306, 5432, 8080, 8443, 27017]
                result = await asyncio.wait_for(
                    module.scan_ports(hostname, common_ports),
                    timeout=self.timeout_per_module
                )
            elif module_class == WebCrawler:
                module = module_class(http_client=self.http_client)
                result = await asyncio.wait_for(
                    module.crawl(self.target),
                    timeout=self.timeout_per_module
                )
            elif module_class == ReconWarfare:
                module = module_class(http_client=self.http_client)
                # ReconWarfare has full_recon()
                result = await asyncio.wait_for(
                    module.full_recon(self.target),
                    timeout=self.timeout_per_module
                )
            elif module_class == SocialEngineering:
                module = module_class(http_client=self.http_client)
                # SocialEngineering has full_osint()
                result = await asyncio.wait_for(
                    module.full_osint(hostname),
                    timeout=self.timeout_per_module
                )
            else:
                # Try generic approach
                try:
                    module = module_class(http_client=self.http_client)
                except TypeError:
                    try:
                        module = module_class()
                    except TypeError:
                        print("[skip: constructor]")
                        self.results.module_results[name] = {"status": "skipped"}
                        return

                # Try various method names
                if hasattr(module, 'full_recon'):
                    result = await asyncio.wait_for(
                        module.full_recon(self.target),
                        timeout=self.timeout_per_module
                    )
                elif hasattr(module, 'full_osint'):
                    result = await asyncio.wait_for(
                        module.full_osint(hostname),
                        timeout=self.timeout_per_module
                    )
                elif hasattr(module, 'enumerate_subdomains'):
                    result = await asyncio.wait_for(
                        module.enumerate_subdomains(hostname),
                        timeout=self.timeout_per_module
                    )
                elif hasattr(module, 'scan_ports'):
                    result = await asyncio.wait_for(
                        module.scan_ports(hostname, [80, 443]),
                        timeout=self.timeout_per_module
                    )
                elif hasattr(module, 'crawl'):
                    result = await asyncio.wait_for(
                        module.crawl(self.target),
                        timeout=self.timeout_per_module
                    )
                elif hasattr(module, 'run'):
                    result = await asyncio.wait_for(
                        module.run(self.target),
                        timeout=self.timeout_per_module
                    )
                else:
                    print("[skip: no method]")
                    self.results.module_results[name] = {"status": "skipped", "reason": "no run method"}
                    return

            # Store results in chain data
            if result:
                self.results.modules_successful += 1
                if hasattr(result, '__dict__'):
                    self.chain_data[name] = result.__dict__
                print("[done]")
            else:
                print("[no results]")

            self.results.module_results[name] = {"status": "success"}

        except asyncio.TimeoutError:
            print("[timeout]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "timeout"}
        except Exception as e:
            print(f"[error: {str(e)[:30]}]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "error", "error": str(e)}

    async def _run_v1_module(self, module_tuple: tuple):
        """Execute a V1 attack module."""
        # Unpack tuple (name, class, category, description, needs_param)
        name = module_tuple[0]
        module_class = module_tuple[1]
        category = module_tuple[2]
        description = module_tuple[3]
        needs_param = module_tuple[4] if len(module_tuple) > 4 else False

        self.results.modules_executed += 1
        print(f"  [{name}] {description}...", end=" ", flush=True)

        try:
            # Check if class is abstract
            import inspect
            if inspect.isabstract(module_class):
                print("[skip: abstract]")
                self.results.module_results[name] = {"status": "skipped", "reason": "abstract class"}
                return

            # Try different constructor signatures
            try:
                module = module_class(http_client=self.http_client)
            except TypeError:
                try:
                    module = module_class()
                except TypeError as e:
                    print(f"[skip: constructor]")
                    self.results.module_results[name] = {"status": "skipped", "reason": str(e)[:50]}
                    return

            findings_count = 0

            if needs_param:
                # Parameter-based attacks - test discovered endpoints/params
                if self.discovered_endpoints:
                    # Test endpoints with their discovered parameters
                    for endpoint in self.discovered_endpoints[:10]:  # Limit to 10
                        url = endpoint["url"]
                        method = endpoint.get("method", "GET")
                        for param in endpoint.get("parameters", [])[:5]:  # Limit params
                            result = await self._run_v1_attack(
                                module, url, param, method, name, category, description
                            )
                            if result and result.success:
                                findings_count += 1
                elif self.discovered_params:
                    # Test target URL with discovered param names
                    for param in self.discovered_params[:10]:
                        result = await self._run_v1_attack(
                            module, self.target, param, "GET", name, category, description
                        )
                        if result and result.success:
                            findings_count += 1
                else:
                    # No discovered params - try common ones
                    common_params = ["id", "q", "search", "query", "name", "page", "user", "file", "path"]
                    for param in common_params[:5]:
                        result = await self._run_v1_attack(
                            module, self.target, param, "GET", name, category, description
                        )
                        if result and result.success:
                            findings_count += 1
                            break  # Found something, move on
            else:
                # URL-based attacks - just pass target
                result = await self._run_v1_attack(
                    module, self.target, None, "GET", name, category, description
                )
                if result and result.success:
                    findings_count += 1

            if findings_count > 0:
                self.results.modules_successful += 1
                print(f"[FOUND {findings_count} issues]")
            else:
                print("[clean]")

            self.results.module_results[name] = {
                "status": "success",
                "findings_count": findings_count,
            }

        except asyncio.TimeoutError:
            print("[timeout]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "timeout"}
        except Exception as e:
            print(f"[error: {str(e)[:30]}]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "error", "error": str(e)}

    async def _run_v1_attack(
        self,
        module,
        url: str,
        parameter: Optional[str],
        method: str,
        name: str,
        category: str,
        description: str
    ) -> Optional[AttackResult]:
        """Run a single V1 attack and process results."""
        try:
            # V1 modules expect run(url, parameter, method)
            result = await asyncio.wait_for(
                module.run(url, parameter, method),
                timeout=60  # 60s per individual attack
            )

            # Process AttackResult
            if result and result.success:
                # Create finding from result
                severity = getattr(module, 'severity', Severity.MEDIUM)
                finding = self._create_finding(
                    title=result.details or f"{description} Vulnerability",
                    severity=severity,
                    category=category,
                    description=f"Payload: {result.payload}" if result.payload else result.details,
                    evidence=[Evidence(
                        type=EvidenceType.REQUEST_RESPONSE,
                        description=f"{name} attack successful",
                        content={
                            "url": url,
                            "parameter": parameter,
                            "payload": result.payload,
                            "response_sample": result.data_sample[:500] if result.data_sample else None,
                        },
                        severity=severity,
                        proves=f"{description} vulnerability confirmed",
                    )] if result.payload else [],
                    affected_component=url,
                    attack_module=name,
                )

                # Enrich with recommendation
                vuln_type_map = {
                    "sqli": "sql_injection",
                    "nosql": "nosql_injection",
                    "cmdi": "command_injection",
                    "ssti": "ssti",
                    "xxe": "xxe",
                    "xss": "xss",
                    "ssrf": "ssrf",
                    "idor": "idor",
                }
                vuln_type = vuln_type_map.get(name, name)
                finding.enrich_with_recommendation(vuln_type)

                self._add_finding(finding)

                # Update chain data from result context
                if hasattr(result, 'context') and result.context:
                    self.chain_data.update(result.context)

                # Track access level
                if result.access_gained:
                    if result.access_gained.value > self.results.max_access_level.value:
                        self.results.max_access_level = result.access_gained
                    self.results.access_chain.append(f"{name}: {result.access_gained.value}")

                return result

        except asyncio.TimeoutError:
            pass  # Individual attack timeout, continue
        except Exception:
            pass  # Individual attack error, continue

        return None

    async def _run_v2_module(self, module_class: type):
        """Execute a V2 killchain module."""
        name = module_class.info.name
        self.results.modules_executed += 1
        print(f"  [{name}] {module_class.info.description}...", end=" ", flush=True)

        try:
            # Create config
            config = ModuleConfig(
                target=self.target,
                timeout_seconds=self.timeout_per_module,
                aggressive=self.aggressive,
                chain_data=self.chain_data,
            )

            # Instantiate and run module
            module = module_class(http_client=self.http_client)

            # Check if module can run
            if not await module.check(config):
                print("[skipped - prerequisites not met]")
                self.results.module_results[name] = {"status": "skipped"}
                return

            # Run with timeout
            result = await asyncio.wait_for(
                module.run(config),
                timeout=self.timeout_per_module
            )

            # Process results
            if result and result.success:
                self.results.modules_successful += 1
                evidence_count = len(result.evidence) if result.evidence else 0
                print(f"[SUCCESS - {evidence_count} evidence]")

                # Add evidence to results
                if result.evidence:
                    self.results.all_evidence.extend(result.evidence)

                # Create findings from evidence
                for evidence in (result.evidence or []):
                    finding = self._create_finding(
                        title=evidence.description,
                        severity=evidence.severity,
                        category=module_class.info.phase.value,
                        description=evidence.proves,
                        evidence=[evidence],
                        affected_component=self.target,
                        attack_module=name,
                    )
                    self._add_finding(finding)

                # Update chain data
                if result.data_extracted:
                    self.chain_data.update(result.data_extracted)

                # Track access level
                if result.access_gained:
                    if result.access_gained.value > self.results.max_access_level.value:
                        self.results.max_access_level = result.access_gained
                    self.results.access_chain.append(f"{name}: {result.access_gained.value}")
            else:
                print("[no findings]")

            self.results.module_results[name] = {
                "status": "success" if result and result.success else "no_findings",
                "evidence_count": len(result.evidence) if result and result.evidence else 0,
            }

        except asyncio.TimeoutError:
            print("[timeout]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "timeout"}
        except Exception as e:
            print(f"[error: {str(e)[:30]}]")
            self.results.modules_failed += 1
            self.results.module_results[name] = {"status": "error", "error": str(e)}

    def _create_finding(self, **kwargs) -> Finding:
        """Create a finding with auto-generated ID."""
        self._finding_counter += 1
        return Finding(
            id=f"BREACH-{self._finding_counter:04d}",
            **kwargs
        )

    def _add_finding(self, finding: Finding):
        """Add finding to appropriate severity list."""
        if finding.severity == Severity.CRITICAL:
            self.results.critical_findings.append(finding)
        elif finding.severity == Severity.HIGH:
            self.results.high_findings.append(finding)
        elif finding.severity == Severity.MEDIUM:
            self.results.medium_findings.append(finding)
        elif finding.severity == Severity.LOW:
            self.results.low_findings.append(finding)
        else:
            self.results.info_findings.append(finding)

    def _map_severity(self, severity_str: str) -> Severity:
        """Map string severity to Severity enum."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)

    def _calculate_risk_score(self):
        """Calculate overall risk score (0-100)."""
        score = 0

        # Critical findings: 25 points each (max 50)
        score += min(len(self.results.critical_findings) * 25, 50)

        # High findings: 10 points each (max 30)
        score += min(len(self.results.high_findings) * 10, 30)

        # Medium findings: 3 points each (max 15)
        score += min(len(self.results.medium_findings) * 3, 15)

        # Low findings: 1 point each (max 5)
        score += min(len(self.results.low_findings) * 1, 5)

        self.results.risk_score = min(score, 100)

    def _calculate_business_impact(self):
        """Calculate estimated breach cost."""
        cost = 0

        # Critical: $500,000 each
        cost += len(self.results.critical_findings) * 500000

        # High: $100,000 each
        cost += len(self.results.high_findings) * 100000

        # Medium: $25,000 each
        cost += len(self.results.medium_findings) * 25000

        # Low: $5,000 each
        cost += len(self.results.low_findings) * 5000

        # Access level multiplier
        access_multipliers = {
            AccessLevel.NONE: 1.0,
            AccessLevel.USER: 1.5,
            AccessLevel.ADMIN: 2.0,
            AccessLevel.ROOT: 3.0,
            AccessLevel.DATABASE: 2.5,
            AccessLevel.CLOUD_USER: 2.0,
            AccessLevel.CLOUD_ADMIN: 3.0,
        }
        multiplier = access_multipliers.get(self.results.max_access_level, 1.0)

        self.results.estimated_breach_cost = int(cost * multiplier)

    def _print_summary(self):
        """Print assessment summary."""
        print(f"\n{'='*60}")
        print("BRUTAL ASSESSMENT COMPLETE")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Duration: {self.results.duration_seconds} seconds")
        print(f"\nModules Executed: {self.results.modules_executed}")
        print(f"  - Successful: {self.results.modules_successful}")
        print(f"  - Failed: {self.results.modules_failed}")
        print(f"\nFindings ({self.results.total_findings} total):")
        print(f"  - CRITICAL: {len(self.results.critical_findings)}")
        print(f"  - HIGH: {len(self.results.high_findings)}")
        print(f"  - MEDIUM: {len(self.results.medium_findings)}")
        print(f"  - LOW: {len(self.results.low_findings)}")
        print(f"  - INFO: {len(self.results.info_findings)}")
        print(f"\nRisk Score: {self.results.risk_score}/100")
        print(f"Max Access Level: {self.results.max_access_level.value}")
        print(f"Estimated Breach Cost: ${self.results.estimated_breach_cost:,}")
        print(f"{'='*60}\n")

    def export_json(self, filepath: str):
        """Export results to JSON file."""
        with open(filepath, "w") as f:
            json.dump(self.results.to_dict(), f, indent=2)
        print(f"Results exported to: {filepath}")

    def export_executive_summary(self) -> str:
        """Generate executive summary text."""
        return f"""
BREACH.AI SECURITY ASSESSMENT
=============================
Target: {self.target}
Date: {self.results.completed_at.strftime("%Y-%m-%d %H:%M UTC") if self.results.completed_at else "N/A"}

EXECUTIVE SUMMARY
-----------------
Risk Score: {self.results.risk_score}/100 {"(CRITICAL)" if self.results.risk_score >= 75 else "(HIGH)" if self.results.risk_score >= 50 else "(MEDIUM)" if self.results.risk_score >= 25 else "(LOW)"}
Estimated Breach Cost: ${self.results.estimated_breach_cost:,}
Maximum Access Achieved: {self.results.max_access_level.value}

FINDINGS SUMMARY
----------------
Critical Vulnerabilities: {len(self.results.critical_findings)}
High Vulnerabilities: {len(self.results.high_findings)}
Medium Vulnerabilities: {len(self.results.medium_findings)}
Low Vulnerabilities: {len(self.results.low_findings)}
Informational: {len(self.results.info_findings)}

TOP CRITICAL FINDINGS
---------------------
{chr(10).join([f"- {f.title}" for f in self.results.critical_findings[:5]]) or "None"}

IMMEDIATE ACTIONS REQUIRED
--------------------------
1. Address all CRITICAL findings immediately
2. Schedule remediation for HIGH findings within 7 days
3. Plan fixes for MEDIUM findings within 30 days
4. Review LOW findings during regular maintenance

Assessment conducted by BREACH.AI Autonomous Security Engine
"""


# Convenience function for CLI usage
async def run_brutal_assessment(
    target: str,
    output_dir: str = "./breach_output",
    **kwargs
) -> AssessmentResults:
    """
    Run a brutal assessment and export results.

    Args:
        target: Target URL to assess
        output_dir: Directory for output files
        **kwargs: Additional options for BrutalAssessment

    Returns:
        AssessmentResults with all findings
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    assessment = BrutalAssessment(target=target, **kwargs)
    results = await assessment.run()

    # Export results
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    assessment.export_json(f"{output_dir}/assessment_{timestamp}.json")

    # Export executive summary
    summary = assessment.export_executive_summary()
    with open(f"{output_dir}/executive_summary_{timestamp}.txt", "w") as f:
        f.write(summary)

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python brutal_assessment.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(run_brutal_assessment(target))
