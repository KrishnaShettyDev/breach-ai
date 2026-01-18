"""
BREACH.AI - Centralized Configuration

Type-safe configuration with validation using Pydantic Settings.
Fails fast on missing required secrets.
"""

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Find project root .env file
def _find_env_file() -> str:
    """Find .env file, checking project root first."""
    # Check relative to this file (backend/config.py -> project root)
    project_root = Path(__file__).parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        return str(env_path)
    # Fall back to current directory
    if Path(".env").exists():
        return ".env"
    # Return project root path even if doesn't exist (pydantic handles gracefully)
    return str(env_path)


class Settings(BaseSettings):
    """Application settings with validation."""

    model_config = SettingsConfigDict(
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ===========================================
    # Server
    # ===========================================
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    debug: bool = Field(default=False, description="Enable debug mode")
    environment: str = Field(default="development", description="Environment name")

    # ===========================================
    # Database
    # ===========================================
    database_url: str = Field(
        ...,  # Required
        description="PostgreSQL connection URL",
        examples=["postgresql+asyncpg://user:pass@localhost/breach"],
    )

    # ===========================================
    # Redis
    # ===========================================
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL for rate limiting and job queue",
    )

    # ===========================================
    # Authentication (Clerk)
    # ===========================================
    clerk_secret_key: str = Field(
        ...,  # Required
        min_length=10,
        description="Clerk secret key for JWT verification",
    )
    clerk_publishable_key: str = Field(
        default="",
        description="Clerk publishable key (optional for backend)",
    )

    # ===========================================
    # Billing (Stripe) - Optional, add later
    # ===========================================
    stripe_secret_key: Optional[str] = Field(
        default=None,
        description="Stripe secret key (optional - billing disabled if not set)",
    )
    stripe_webhook_secret: str = Field(
        default="",
        description="Stripe webhook signing secret",
    )
    stripe_starter_price_id: str = Field(
        default="",
        description="Stripe price ID for Starter plan",
    )
    stripe_business_price_id: str = Field(
        default="",
        description="Stripe price ID for Business plan",
    )
    stripe_enterprise_price_id: str = Field(
        default="",
        description="Stripe price ID for Enterprise plan",
    )

    # ===========================================
    # CORS
    # ===========================================
    cors_origins_str: str = Field(
        default="http://localhost:3000",
        alias="cors_origins",
        description="Comma-separated list of allowed CORS origins",
    )

    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS origins from comma-separated string."""
        if not self.cors_origins_str:
            return ["http://localhost:3000"]

        origins = [o.strip() for o in self.cors_origins_str.split(",") if o.strip()]

        # Reject wildcard
        if "*" in origins:
            raise ValueError(
                "Wildcard '*' CORS origin is not allowed. "
                "Specify explicit origins for security."
            )

        # Validate each origin
        for origin in origins:
            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid CORS origin URL: {origin}")

        return origins

    # ===========================================
    # Security
    # ===========================================
    api_key_prefix: str = Field(
        default="breach_",
        description="Prefix for generated API keys",
    )

    # ===========================================
    # Scanning
    # ===========================================
    scan_timeout_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Maximum scan duration in seconds (default 1 hour)",
    )
    max_concurrent_scans: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum concurrent scans per worker",
    )

    # ===========================================
    # Rate Limiting
    # ===========================================
    rate_limit_global: str = Field(
        default="100/minute",
        description="Global rate limit per IP",
    )
    rate_limit_scans: str = Field(
        default="10/minute",
        description="Rate limit for scan creation",
    )
    rate_limit_auth: str = Field(
        default="5/minute",
        description="Rate limit for auth endpoints",
    )

    # ===========================================
    # Stripe Price IDs (for subscription tiers)
    # ===========================================
    stripe_pro_price_id: str = Field(
        default="",
        description="Stripe price ID for Pro plan ($45/mo)",
    )

    # ===========================================
    # AI / LLM Keys (for ChainBreaker mode)
    # ===========================================
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key for Claude (ChainBreaker mode)",
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key (optional, for GPT-based features)",
    )

    # ===========================================
    # Vector DB (Qdrant)
    # ===========================================
    qdrant_url: str = Field(
        default="http://localhost:6333",
        description="Qdrant vector database URL",
    )
    qdrant_api_key: Optional[str] = Field(
        default=None,
        description="Qdrant API key (for cloud deployments)",
    )

    # ===========================================
    # Cloudflare R2 Storage
    # ===========================================
    r2_endpoint_url: Optional[str] = Field(
        default=None,
        description="Cloudflare R2 endpoint URL (e.g., https://<account_id>.r2.cloudflarestorage.com)",
    )
    r2_access_key_id: Optional[str] = Field(
        default=None,
        description="Cloudflare R2 access key ID",
    )
    r2_secret_access_key: Optional[str] = Field(
        default=None,
        description="Cloudflare R2 secret access key",
    )
    r2_bucket_name: str = Field(
        default="breach-ai",
        description="Cloudflare R2 bucket name",
    )
    r2_public_url: Optional[str] = Field(
        default=None,
        description="Public URL for R2 bucket (for public access)",
    )

    # ===========================================
    # Observability (Optional)
    # ===========================================
    sentry_dsn: Optional[str] = Field(
        default=None,
        description="Sentry DSN for error tracking (optional)",
    )
    sentry_traces_sample_rate: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Sentry traces sample rate",
    )
    alert_webhook_url: Optional[str] = Field(
        default=None,
        description="Webhook URL for scan failure alerts (optional)",
    )

    # ===========================================
    # Email Notifications
    # ===========================================
    sendgrid_api_key: Optional[str] = Field(
        default=None,
        description="SendGrid API key for email notifications",
    )
    resend_api_key: Optional[str] = Field(
        default=None,
        description="Resend API key for email notifications",
    )
    email_from: str = Field(
        default="noreply@breach.ai",
        description="Default from email address",
    )
    email_from_name: str = Field(
        default="BREACH.AI",
        description="Default from email name",
    )

    # ===========================================
    # Frontend / URLs
    # ===========================================
    frontend_url: str = Field(
        default="http://localhost:3000",
        description="Frontend application URL (for email links)",
    )

    # ===========================================
    # SSRF Protection
    # ===========================================
    blocked_hosts: set[str] = Field(
        default={
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
        },
        description="Hosts blocked from scanning (SSRF protection)",
    )

    # ===========================================
    # Dangerous Domain Blocking (Abuse Prevention)
    # ===========================================
    blocked_domain_patterns: list[str] = Field(
        default=[
            # Government domains
            "*.gov",
            "*.gov.*",
            "*.mil",
            "*.military.*",
            # Education (without explicit permission)
            "*.edu",
            "*.ac.uk",
            "*.edu.*",
            # Critical infrastructure
            "*.bank",
            "*.healthcare",
            "*.hospital",
            # Reserved/internal
            "*.local",
            "*.internal",
            "*.corp",
            "*.lan",
            # Specific high-risk targets
            "*.google.com",
            "*.facebook.com",
            "*.microsoft.com",
            "*.apple.com",
            "*.amazon.com",
            "*.cloudflare.com",
        ],
        description="Domain patterns blocked from scanning (abuse prevention)",
    )

    # Domains that require enterprise tier to scan
    restricted_domain_patterns: list[str] = Field(
        default=[
            "*.io",
            "*.dev",
            "*.app",
        ],
        description="Domain patterns requiring enterprise subscription",
    )

    @field_validator("blocked_hosts", mode="before")
    @classmethod
    def parse_blocked_hosts(cls, v):
        """Parse blocked hosts from comma-separated string or set."""
        if isinstance(v, str):
            return {h.strip() for h in v.split(",") if h.strip()}
        return v

    # ===========================================
    # Validation
    # ===========================================
    @model_validator(mode="after")
    def validate_settings(self):
        """Validate settings after all fields are set."""
        # Ensure database URL uses async driver
        if self.database_url and "asyncpg" not in self.database_url:
            if "postgresql://" in self.database_url:
                # Auto-fix common mistake
                self.database_url = self.database_url.replace(
                    "postgresql://", "postgresql+asyncpg://"
                )
        return self


# Private IP ranges for SSRF protection
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _matches_pattern(domain: str, pattern: str) -> bool:
    """Check if a domain matches a wildcard pattern."""
    import fnmatch
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()

    # Direct match
    if domain == pattern:
        return True

    # Wildcard match (*.gov matches example.gov)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .gov
        if domain.endswith(suffix) or domain == pattern[2:]:
            return True

    # Use fnmatch for more complex patterns
    return fnmatch.fnmatch(domain, pattern)


def is_blocked_domain(domain: str) -> tuple[bool, str]:
    """
    Check if a domain is blocked from scanning.

    Returns:
        Tuple[bool, str]: (is_blocked, reason)
    """
    domain = domain.lower().strip()

    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # Check against blocked hosts (SSRF protection)
    settings_instance = get_settings()
    if domain in settings_instance.blocked_hosts:
        return True, f"Domain '{domain}' is blocked (internal/metadata host)"

    # Check against blocked domain patterns
    for pattern in settings_instance.blocked_domain_patterns:
        if _matches_pattern(domain, pattern):
            return True, f"Domain '{domain}' matches blocked pattern '{pattern}'. Scanning government, military, educational, and major tech company domains is not permitted without explicit authorization."

    return False, ""


def is_restricted_domain(domain: str) -> tuple[bool, str]:
    """
    Check if a domain requires enterprise tier.

    Returns:
        Tuple[bool, str]: (is_restricted, reason)
    """
    domain = domain.lower().strip()

    if ":" in domain:
        domain = domain.split(":")[0]

    settings_instance = get_settings()
    for pattern in settings_instance.restricted_domain_patterns:
        if _matches_pattern(domain, pattern):
            return True, f"Domain '{domain}' requires Enterprise subscription to scan"

    return False, ""


def validate_scan_target(domain: str, subscription_tier: str = "free") -> tuple[bool, str]:
    """
    Validate if a target domain can be scanned.

    Args:
        domain: The domain to validate
        subscription_tier: User's subscription tier

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Check if blocked
    is_blocked, reason = is_blocked_domain(domain)
    if is_blocked:
        return False, reason

    # Check if restricted (requires enterprise)
    is_restricted, reason = is_restricted_domain(domain)
    if is_restricted and subscription_tier.lower() != "enterprise":
        return False, reason

    # Check for private IPs
    try:
        import socket
        ip = socket.gethostbyname(domain)
        if is_private_ip(ip):
            return False, f"Domain '{domain}' resolves to private IP {ip}"
    except socket.gaierror:
        # Domain doesn't resolve - might be valid for some tests
        pass

    return True, ""


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    This will fail fast if required environment variables are missing,
    preventing the application from starting in an invalid state.
    """
    return Settings()


# Convenience alias
settings = get_settings()


# ===========================================
# Subscription Tier Limits
# ===========================================
# These define the limits for each subscription tier
# Format: {scans_per_month, targets, concurrent_scans, team_members}
# -1 means unlimited

TIER_LIMITS = {
    "free": {
        "scans_per_month": 1,
        "targets": 1,
        "concurrent_scans": 1,
        "team_members": 1,
        "price_monthly": 0,
    },
    "starter": {
        "scans_per_month": 50,
        "targets": 10,
        "concurrent_scans": 2,
        "team_members": 3,
        "price_monthly": 25,
    },
    "pro": {
        "scans_per_month": 200,
        "targets": 50,
        "concurrent_scans": 5,
        "team_members": 10,
        "price_monthly": 45,
    },
    "enterprise": {
        "scans_per_month": -1,  # Unlimited
        "targets": -1,
        "concurrent_scans": -1,
        "team_members": -1,
        "price_monthly": -1,  # Custom pricing
    },
}


def get_tier_limits(tier: str) -> dict:
    """Get limits for a subscription tier."""
    return TIER_LIMITS.get(tier.lower(), TIER_LIMITS["free"])
