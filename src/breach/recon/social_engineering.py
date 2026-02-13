"""
BREACH.AI - Social Engineering & OSINT Module

Human intelligence gathering and attack surface mapping:
- Employee enumeration
- Email pattern detection
- Org chart reconstruction
- Credential leak association
- Phishing susceptibility analysis
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from breach.utils.logger import logger


class OSINTType(Enum):
    """Types of OSINT."""
    EMPLOYEE = "employee"
    EMAIL = "email"
    SOCIAL = "social"
    CREDENTIAL = "credential"
    ORG_CHART = "org_chart"


@dataclass
class Employee:
    """An employee profile."""
    name: str
    title: Optional[str] = None
    department: Optional[str] = None
    email: Optional[str] = None
    linkedin: Optional[str] = None
    github: Optional[str] = None
    twitter: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None
    tenure: Optional[str] = None

    # Risk indicators
    has_leaked_credentials: bool = False
    leaked_passwords: list[str] = field(default_factory=list)
    social_media_exposure: str = "unknown"
    phishing_susceptibility: str = "unknown"


@dataclass
class EmailPattern:
    """Email pattern for an organization."""
    pattern: str
    confidence: float = 0.0
    examples: list[str] = field(default_factory=list)


@dataclass
class SocialEngineeringResult:
    """Result of social engineering reconnaissance."""
    target: str
    employees: list[Employee] = field(default_factory=list)
    email_patterns: list[EmailPattern] = field(default_factory=list)
    org_structure: dict = field(default_factory=dict)
    high_value_targets: list[Employee] = field(default_factory=list)
    leaked_credentials_count: int = 0
    phishing_vectors: list[str] = field(default_factory=list)


class SocialEngineering:
    """
    Social engineering and OSINT reconnaissance.

    Gathers intelligence about:
    - Employees and their roles
    - Email address patterns
    - Organizational structure
    - Potential phishing vectors
    """

    def __init__(self, http_client=None):
        self.http = http_client

    async def full_osint(
        self,
        target: str,
        company_name: Optional[str] = None
    ) -> SocialEngineeringResult:
        """Run complete social engineering reconnaissance."""
        logger.info(f"Starting social engineering recon for {target}")

        if not company_name:
            company_name = self._extract_company_name(target)

        result = SocialEngineeringResult(target=target)

        # Detect email patterns
        result.email_patterns = await self._detect_email_patterns(target)

        # Identify high-value role patterns
        result.high_value_targets = self._identify_high_value_roles()

        # Identify phishing vectors
        result.phishing_vectors = self._identify_phishing_vectors(company_name)

        logger.info(f"OSINT complete for {target}")
        return result

    def _extract_company_name(self, target: str) -> str:
        """Extract company name from domain."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = domain.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return domain

    # =========================================================================
    # EMAIL PATTERN DETECTION
    # =========================================================================

    async def _detect_email_patterns(self, domain: str) -> list[EmailPattern]:
        """
        Detect email patterns:
        - first.last@domain.com
        - flast@domain.com
        - firstl@domain.com
        - first@domain.com
        """
        logger.debug(f"Detecting email patterns for {domain}")

        patterns = [
            EmailPattern(
                pattern="{first}.{last}@{domain}",
                confidence=0.0,
                examples=["john.smith@company.com"],
            ),
            EmailPattern(
                pattern="{f}{last}@{domain}",
                confidence=0.0,
                examples=["jsmith@company.com"],
            ),
            EmailPattern(
                pattern="{first}{l}@{domain}",
                confidence=0.0,
                examples=["johns@company.com"],
            ),
            EmailPattern(
                pattern="{first}@{domain}",
                confidence=0.0,
                examples=["john@company.com"],
            ),
            EmailPattern(
                pattern="{first}_{last}@{domain}",
                confidence=0.0,
                examples=["john_smith@company.com"],
            ),
            EmailPattern(
                pattern="{first}-{last}@{domain}",
                confidence=0.0,
                examples=["john-smith@company.com"],
            ),
            EmailPattern(
                pattern="{last}.{first}@{domain}",
                confidence=0.0,
                examples=["smith.john@company.com"],
            ),
            EmailPattern(
                pattern="{last}{f}@{domain}",
                confidence=0.0,
                examples=["smithj@company.com"],
            ),
        ]

        return patterns

    def generate_email(
        self,
        first_name: str,
        last_name: str,
        domain: str,
        pattern: EmailPattern
    ) -> str:
        """Generate email address from name and pattern."""
        email = pattern.pattern
        email = email.replace("{first}", first_name.lower())
        email = email.replace("{last}", last_name.lower())
        email = email.replace("{f}", first_name[0].lower())
        email = email.replace("{l}", last_name[0].lower())
        email = email.replace("{domain}", domain)
        return email

    # =========================================================================
    # HIGH-VALUE TARGET IDENTIFICATION
    # =========================================================================

    def _identify_high_value_roles(self) -> list[Employee]:
        """
        Identify high-value target roles.

        Returns template employees representing high-value roles.
        """
        high_value_roles = [
            Employee(
                name="[C-Suite Executive]",
                title="CEO/CTO/CFO/CISO",
                department="Executive",
                phishing_susceptibility="high",
            ),
            Employee(
                name="[IT Administrator]",
                title="IT Administrator / Sysadmin",
                department="IT",
                phishing_susceptibility="medium",
            ),
            Employee(
                name="[Security Personnel]",
                title="Security Engineer / Analyst",
                department="Security",
                phishing_susceptibility="low",
            ),
            Employee(
                name="[Finance/Accounting]",
                title="Controller / Accountant",
                department="Finance",
                phishing_susceptibility="high",
            ),
            Employee(
                name="[HR Personnel]",
                title="HR Manager / Recruiter",
                department="HR",
                phishing_susceptibility="medium",
            ),
            Employee(
                name="[Executive Assistant]",
                title="Executive Assistant",
                department="Executive",
                phishing_susceptibility="high",
            ),
            Employee(
                name="[New Employee]",
                title="Recently Hired",
                department="Various",
                phishing_susceptibility="high",
            ),
        ]

        return high_value_roles

    # =========================================================================
    # PHISHING VECTOR IDENTIFICATION
    # =========================================================================

    def _identify_phishing_vectors(self, company_name: str) -> list[str]:
        """
        Identify potential phishing vectors.
        """
        vectors = []

        # Impersonation scenarios
        impersonation = [
            "IT Support - password reset required",
            "HR - benefits enrollment deadline",
            "Finance - expense reimbursement pending",
            "CEO - urgent wire transfer (BEC)",
            "Vendor - invoice payment required",
            "Legal - contract review needed",
            "Security - account verification required",
        ]

        # Technical pretexts
        technical_pretexts = [
            "Microsoft 365 password expiration",
            "Zoom meeting invitation",
            "DocuSign document to sign",
            "Shared Google Drive document",
            "Dropbox shared file",
            "LinkedIn connection request",
            "GitHub repository access",
            "Slack workspace invitation",
            "VPN configuration update",
            "Two-factor authentication setup",
        ]

        # Timing-based pretexts
        timing_pretexts = [
            "End of quarter - financial reports due",
            "Open enrollment - benefits deadline",
            "Tax season - W2 forms available",
            "Performance review - HR forms",
            "New year - mandatory password reset",
            "Before holiday - urgent request",
        ]

        # Domain typosquatting possibilities
        typosquats = self._generate_typosquats(company_name)

        vectors.extend([f"Impersonation: {i}" for i in impersonation])
        vectors.extend([f"Technical Pretext: {t}" for t in technical_pretexts])
        vectors.extend([f"Timing-based: {t}" for t in timing_pretexts])
        vectors.extend([f"Typosquat Domain: {t}" for t in typosquats[:10]])

        return vectors

    def _generate_typosquats(self, domain: str) -> list[str]:
        """Generate typosquat domain variations for awareness."""
        typosquats = []

        # Character omission
        for i in range(len(domain)):
            typosquats.append(domain[:i] + domain[i+1:])

        # Character duplication
        for i in range(len(domain)):
            typosquats.append(domain[:i] + domain[i] + domain[i:])

        # Adjacent character swap
        for i in range(len(domain) - 1):
            typosquats.append(domain[:i] + domain[i+1] + domain[i] + domain[i+2:])

        # Common replacements
        replacements = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', 'l'],
            'o': ['0'],
            's': ['5', '$'],
            'g': ['9', 'q'],
            't': ['7'],
            'l': ['1', 'i'],
            'b': ['d'],
            'n': ['m'],
            'm': ['n', 'rn'],
        }

        for i, char in enumerate(domain.lower()):
            if char in replacements:
                for replacement in replacements[char]:
                    typosquats.append(domain[:i] + replacement + domain[i+1:])

        # Add common TLD variations
        tld_variations = [
            f"{domain}.co",
            f"{domain}.net",
            f"{domain}.org",
            f"{domain}.io",
            f"{domain}.app",
            f"{domain}-login.com",
            f"{domain}-secure.com",
            f"login-{domain}.com",
            f"secure-{domain}.com",
        ]
        typosquats.extend(tld_variations)

        return list(set(typosquats))

    def generate_phishing_simulation_report(
        self,
        result: SocialEngineeringResult
    ) -> dict:
        """
        Generate a phishing simulation planning report.

        This is for authorized security awareness testing only.
        """
        report = {
            "target": result.target,
            "executive_summary": (
                f"Identified {len(result.email_patterns)} email patterns and "
                f"{len(result.phishing_vectors)} potential phishing vectors."
            ),
            "email_patterns": [
                {
                    "pattern": p.pattern,
                    "confidence": p.confidence,
                    "example": p.examples[0] if p.examples else None,
                }
                for p in result.email_patterns
            ],
            "high_value_roles": [
                {
                    "role": e.title,
                    "department": e.department,
                    "susceptibility": e.phishing_susceptibility,
                }
                for e in result.high_value_targets
            ],
            "recommended_pretexts": result.phishing_vectors[:10],
            "typosquat_domains": [
                v.replace("Typosquat Domain: ", "")
                for v in result.phishing_vectors
                if v.startswith("Typosquat Domain:")
            ][:10],
            "recommendations": [
                "Conduct security awareness training",
                "Implement email authentication (SPF, DKIM, DMARC)",
                "Deploy email security gateway with impersonation detection",
                "Monitor for typosquat domain registrations",
                "Establish clear procedures for sensitive requests",
                "Implement multi-factor authentication",
            ],
        }

        return report


# Convenience function
async def social_engineering_recon(
    target: str,
    company_name: Optional[str] = None,
    http_client=None
) -> SocialEngineeringResult:
    """Run social engineering reconnaissance."""
    se = SocialEngineering(http_client=http_client)
    return await se.full_osint(target, company_name)
