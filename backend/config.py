"""
BREACH.AI - Centralized Configuration

Type-safe configuration with validation using Pydantic Settings.
Fails fast on missing required secrets.
"""

import ipaddress
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
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
    # Billing (Stripe)
    # ===========================================
    stripe_secret_key: str = Field(
        ...,  # Required
        min_length=10,
        description="Stripe secret key",
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
