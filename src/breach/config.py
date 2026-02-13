"""
BREACH - CLI Configuration

Simple configuration for the CLI scanner.
All settings are optional with sensible defaults.
"""

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_env_file() -> str:
    """Find .env file."""
    # Check relative to this file
    project_root = Path(__file__).parent.parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        return str(env_path)
    if Path(".env").exists():
        return ".env"
    return str(env_path)


class Settings(BaseSettings):
    """CLI scanner settings - all optional with defaults."""

    model_config = SettingsConfigDict(
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ===========================================
    # AI (Optional)
    # ===========================================
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key for AI-powered scanning",
    )

    # ===========================================
    # Scanning Settings
    # ===========================================
    breach_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Request timeout in seconds",
    )
    breach_rate_limit: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Max requests per minute",
    )
    breach_output_dir: str = Field(
        default="./reports",
        description="Output directory for reports",
    )
    breach_max_connections: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum concurrent connections",
    )
    breach_user_agent: str = Field(
        default="Mozilla/5.0 (compatible; BREACH/2.0; +https://github.com/breach-ai)",
        description="User agent string",
    )
    breach_proxy: Optional[str] = Field(
        default=None,
        description="Proxy server URL",
    )

    # ===========================================
    # Debug
    # ===========================================
    debug: bool = Field(default=False, description="Enable debug mode")

    # ===========================================
    # SSRF Protection
    # ===========================================
    blocked_hosts: set[str] = Field(
        default={
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",
            "metadata.google.internal",
        },
        description="Hosts blocked from scanning",
    )

    blocked_domain_patterns: list[str] = Field(
        default=[
            "*.gov", "*.gov.*", "*.mil",
            "*.edu", "*.ac.uk",
            "*.local", "*.internal", "*.corp", "*.lan",
        ],
        description="Domain patterns blocked from scanning",
    )


# Private IP ranges for SSRF protection
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
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

    if domain == pattern:
        return True

    if pattern.startswith("*."):
        suffix = pattern[1:]
        if domain.endswith(suffix) or domain == pattern[2:]:
            return True

    return fnmatch.fnmatch(domain, pattern)


def is_blocked_domain(domain: str) -> tuple[bool, str]:
    """Check if a domain is blocked from scanning."""
    domain = domain.lower().strip()

    if ":" in domain:
        domain = domain.split(":")[0]

    settings_instance = get_settings()
    if domain in settings_instance.blocked_hosts:
        return True, f"Domain '{domain}' is blocked (internal/metadata host)"

    for pattern in settings_instance.blocked_domain_patterns:
        if _matches_pattern(domain, pattern):
            return True, f"Domain '{domain}' matches blocked pattern '{pattern}'"

    return False, ""


def validate_scan_target(domain: str) -> tuple[bool, str]:
    """Validate if a target domain can be scanned."""
    is_blocked, reason = is_blocked_domain(domain)
    if is_blocked:
        return False, reason

    try:
        import socket
        ip = socket.gethostbyname(domain)
        if is_private_ip(ip):
            return False, f"Domain '{domain}' resolves to private IP {ip}"
    except socket.gaierror:
        pass

    return True, ""


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience alias
settings = get_settings()
