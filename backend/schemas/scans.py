"""
BREACH.AI - Scan Schemas
========================
Pydantic models for scans and findings with SSRF protection.
"""

import ipaddress
import socket
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, HttpUrl, field_validator
from uuid import UUID
from enum import Enum


# ===========================================
# SSRF Protection
# ===========================================

# Blocked hosts for SSRF protection
BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
    "metadata.google",
    "100.100.100.200",  # Alibaba metadata
}

# Private IP ranges
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


def validate_target_url(url: str) -> str:
    """
    Validate target URL for SSRF protection.

    Raises ValueError if URL points to internal/private resources.
    """
    parsed = urlparse(url)

    # Must have scheme and host
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format")

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS protocols are allowed")

    # Extract hostname (without port)
    hostname = parsed.hostname or ""

    # Check against blocked hosts
    if hostname.lower() in BLOCKED_HOSTS:
        raise ValueError(f"Scanning internal hosts is not allowed: {hostname}")

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_private_ip(hostname):
            raise ValueError(f"Scanning private IP addresses is not allowed: {hostname}")
    except ValueError:
        # Not an IP, it's a hostname - resolve and check
        try:
            # Resolve hostname to check for private IPs
            resolved_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in resolved_ips:
                if is_private_ip(ip):
                    raise ValueError(
                        f"Target hostname resolves to private IP: {hostname} -> {ip}"
                    )
        except socket.gaierror:
            # Can't resolve - let the scan handle connection errors
            pass

    return url


class ScanMode(str, Enum):
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"
    CHAINBREAKER = "chainbreaker"
    PROVEN = "proven"  # Proof-by-exploitation mode - only reports exploited vulnerabilities


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============== SCAN SCHEMAS ==============

class ScanCreate(BaseModel):
    """Create a new scan with SSRF-protected URL validation."""
    target_url: HttpUrl = Field(..., description="URL to scan")
    target_id: Optional[UUID] = Field(None, description="Pre-verified target ID")
    mode: ScanMode = ScanMode.NORMAL
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Scan configuration")

    @field_validator("target_url", mode="after")
    @classmethod
    def validate_ssrf(cls, v):
        """Validate URL is not targeting internal resources."""
        return validate_target_url(str(v))


class ScanConfig(BaseModel):
    """Scan configuration options."""
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[str] = None
    excluded_paths: Optional[List[str]] = None
    rate_limit: Optional[int] = Field(None, ge=1, le=100, description="Requests per second")
    timeout: Optional[int] = Field(None, ge=30, le=3600, description="Timeout in seconds")


class ScanResponse(BaseModel):
    """Scan response."""
    id: UUID
    organization_id: UUID
    target_url: str
    mode: ScanMode
    status: ScanStatus

    # Progress
    progress: int
    current_phase: Optional[str]

    # Results
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_business_impact: float

    # Timing
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]

    # Error
    error_message: Optional[str]

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated scan list."""
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ScanDetailResponse(ScanResponse):
    """Scan with findings."""
    findings: List["FindingResponse"] = []
    config: Dict[str, Any] = {}


# ============== FINDING SCHEMAS ==============

class FindingResponse(BaseModel):
    """Finding response."""
    id: UUID
    scan_id: UUID

    # Details
    title: str
    severity: Severity
    category: str
    endpoint: str
    method: str
    parameter: Optional[str]
    description: str

    # Impact
    business_impact: float
    impact_explanation: Optional[str]
    records_exposed: int
    pii_fields: List[str]

    # Remediation
    fix_suggestion: Optional[str]
    references: List[str]
    curl_command: Optional[str]

    # Proven Mode: Exploitation Proof
    is_exploited: bool = False
    exploitation_proof: Dict[str, Any] = {}
    exploitation_proof_type: Optional[str] = None
    exploitation_confidence: float = 0.0
    screenshot_path: Optional[str] = None
    reproduction_steps: List[str] = []
    poc_script: Optional[str] = None

    # Source Analysis (Proven white-box)
    data_flow_source: Optional[str] = None
    data_flow_sink: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None

    # Status
    is_false_positive: bool
    is_resolved: bool
    resolved_at: Optional[datetime]

    discovered_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Update finding status."""
    is_false_positive: Optional[bool] = None
    is_resolved: Optional[bool] = None


class FindingEvidence(BaseModel):
    """Finding evidence details."""
    request: Optional[str]
    response: Optional[str]
    payload: Optional[str]
    screenshot: Optional[str]  # Base64 or URL


# ============== TARGET SCHEMAS ==============

class TargetCreate(BaseModel):
    """Create a target with SSRF-protected URL validation."""
    url: HttpUrl = Field(..., description="Target URL")
    name: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None

    @field_validator("url", mode="after")
    @classmethod
    def validate_ssrf(cls, v):
        """Validate URL is not targeting internal resources."""
        return validate_target_url(str(v))


class TargetResponse(BaseModel):
    """Target response."""
    id: UUID
    organization_id: UUID
    url: str
    name: str
    description: Optional[str]
    is_verified: bool
    verification_method: Optional[str]
    verification_token: Optional[str]
    verified_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class TargetVerification(BaseModel):
    """Target verification info."""
    target_id: UUID
    verification_methods: List[Dict[str, str]]  # [{method: "dns", instructions: "..."}, ...]


# ============== STATS SCHEMAS ==============

class ScanStats(BaseModel):
    """Scan statistics for dashboard."""
    total_scans: int
    scans_this_month: int
    running_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_business_impact: float
    avg_scan_duration: Optional[float]


class SeverityBreakdown(BaseModel):
    """Severity breakdown for charts."""
    critical: int
    high: int
    medium: int
    low: int
    info: int


class CategoryBreakdown(BaseModel):
    """Category breakdown for charts."""
    category: str
    count: int
    percentage: float


# ===========================================
# Query Parameters
# ===========================================

class PaginationParams(BaseModel):
    """Pagination query parameters with limits."""
    page: int = Field(default=1, ge=1, le=1000, description="Page number")
    per_page: int = Field(default=20, ge=1, le=100, description="Items per page")


class ScanFilterParams(BaseModel):
    """Scan list filter parameters."""
    status: Optional[ScanStatus] = Field(None, description="Filter by status")
    mode: Optional[ScanMode] = Field(None, description="Filter by scan mode")
    severity: Optional[Severity] = Field(None, description="Filter by minimum severity")
    target_url: Optional[str] = Field(None, max_length=2048, description="Filter by target URL")


class FindingFilterParams(BaseModel):
    """Finding list filter parameters."""
    severity: Optional[Severity] = Field(None, description="Filter by severity")
    category: Optional[str] = Field(None, max_length=100, description="Filter by category")
    is_false_positive: Optional[bool] = Field(None, description="Filter by false positive status")
    is_resolved: Optional[bool] = Field(None, description="Filter by resolved status")
