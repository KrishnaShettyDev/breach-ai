"""
BREACH.AI - Database Models
============================
SQLAlchemy models for the enterprise security scanner.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer,
    String, Text, JSON, Float, BigInteger, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column

from backend.db.database import Base


# ============== ENUMS ==============

class UserRole(str, PyEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class SubscriptionTier(str, PyEnum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, PyEnum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIALING = "trialing"


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class ScanMode(str, PyEnum):
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"
    CHAINBREAKER = "chainbreaker"
    PROVEN = "proven"  # Proof-by-exploitation mode (only reports exploited vulns)


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============== MODELS ==============

class Organization(Base):
    """
    Organization/Company - top level entity.
    Each organization has its own billing, teams, and scans.
    """
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    # Billing
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    subscription_tier: Mapped[SubscriptionTier] = mapped_column(
        Enum(SubscriptionTier, values_callable=lambda x: [e.value for e in x]),
        default=SubscriptionTier.FREE
    )
    subscription_status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(SubscriptionStatus, values_callable=lambda x: [e.value for e in x]),
        default=SubscriptionStatus.TRIALING
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Limits - Unlimited for all users
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=999999)
    max_targets: Mapped[int] = mapped_column(Integer, default=999999)
    max_team_members: Mapped[int] = mapped_column(Integer, default=999999)
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, default=10)
    scans_this_month: Mapped[int] = mapped_column(Integer, default=0)

    # Settings
    settings: Mapped[dict] = mapped_column(JSON, default=dict)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    """
    User account - can belong to multiple organizations.
    Uses Clerk for authentication.
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Clerk ID (primary auth)
    clerk_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)

    # Profile
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")
    scans_created = relationship("Scan", back_populates="created_by_user")


class OrganizationMember(Base):
    """
    Many-to-many relationship between users and organizations with role.
    """
    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, values_callable=lambda x: [e.value for e in x]), default=UserRole.MEMBER)

    # Timestamps
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (
        Index("ix_org_member_unique", "organization_id", "user_id", unique=True),
    )


class Target(Base):
    """
    Authorized scan targets for an organization.
    Targets must be verified before scanning.
    """
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Target info
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Verification (prove ownership)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_method: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # dns, file, meta
    verification_token: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Settings
    settings: Mapped[dict] = mapped_column(JSON, default=dict)  # excluded paths, rate limits, etc.

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="targets")
    scans = relationship("Scan", back_populates="target")


class Scan(Base):
    """
    Security scan - the core entity.
    """
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Scan info
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode, values_callable=lambda x: [e.value for e in x]), default=ScanMode.NORMAL)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, values_callable=lambda x: [e.value for e in x]), default=ScanStatus.PENDING)

    # Progress
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Results summary
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Business impact
    total_business_impact: Mapped[float] = mapped_column(Float, default=0.0)

    # Configuration
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # headers, cookies, excluded paths

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Error info
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    created_by_user = relationship("User", back_populates="scans_created")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_org_status", "organization_id", "status"),
        Index("ix_scan_created_at", "created_at"),
    )


class Finding(Base):
    """
    Individual vulnerability finding from a scan.
    """
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )

    # Finding details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, values_callable=lambda x: [e.value for e in x]), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # sqli, xss, idor, etc.

    # Location
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # request, response, payload

    # Impact
    business_impact: Mapped[float] = mapped_column(Float, default=0.0)
    impact_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    records_exposed: Mapped[int] = mapped_column(Integer, default=0)
    pii_fields: Mapped[list] = mapped_column(JSON, default=list)

    # Remediation
    fix_suggestion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)  # OWASP, CWE links

    # Reproduction
    curl_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Proven Mode: Exploitation Proof
    is_exploited: Mapped[bool] = mapped_column(Boolean, default=False)  # Was this actually exploited?
    exploitation_proof: Mapped[dict] = mapped_column(JSON, default=dict)  # Proof data
    exploitation_proof_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # js_executed, data_extracted, etc.
    exploitation_confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0.0 to 1.0
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # Path to screenshot evidence
    screenshot_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA256 hash for integrity
    reproduction_steps: Mapped[list] = mapped_column(JSON, default=list)  # Step-by-step reproduction
    poc_script: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Auto-generated PoC script

    # Source Analysis (Proven white-box)
    data_flow_source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # User input source
    data_flow_sink: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Dangerous sink
    source_file: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # File where vulnerability found
    source_line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Line number

    # Status
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_finding_scan_severity", "scan_id", "severity"),
    )


class APIKey(Base):
    """
    API keys for programmatic access.
    """
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Key info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(10), nullable=False)  # First 8 chars for display
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)  # Hashed full key

    # Permissions
    scopes: Mapped[list] = mapped_column(JSON, default=list)  # ["scans:read", "scans:write", etc.]

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_key_hash", "key_hash"),
    )


class AuditLog(Base):
    """
    Audit log for compliance and security.
    """
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Action info
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # scan.created, user.invited, etc.
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)  # scan, user, target, etc.
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Details
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    # Request info
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_org_created", "organization_id", "created_at"),
    )


class ScheduledScan(Base):
    """
    Scheduled/recurring scans.
    """
    __tablename__ = "scheduled_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )

    # Schedule
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)  # "0 2 * * *" = daily at 2am
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")

    # Scan config
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode, values_callable=lambda x: [e.value for e in x]), default=ScanMode.NORMAL)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============== BREACH.AI v2 - KILL CHAIN MODELS ==============

class BreachPhase(str, PyEnum):
    """Kill chain phases."""
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    FOOTHOLD = "foothold"
    ESCALATION = "escalation"
    LATERAL = "lateral"
    DATA_ACCESS = "data_access"
    PROOF = "proof"


class AccessLevel(str, PyEnum):
    """Access levels achieved during breach."""
    NONE = "none"
    ANONYMOUS = "anonymous"
    USER = "user"
    PRIVILEGED_USER = "privileged_user"
    ADMIN = "admin"
    DATABASE = "database"
    CLOUD_USER = "cloud_user"
    CLOUD_ADMIN = "cloud_admin"
    SYSTEM = "system"
    ROOT = "root"


class BreachSession(Base):
    """
    BREACH.AI v2 - Breach Session.
    A complete breach assessment that runs through the 7-phase kill chain.
    """
    __tablename__ = "breach_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    started_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Target info
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, paused, completed, failed
    current_phase: Mapped[BreachPhase] = mapped_column(Enum(BreachPhase, values_callable=lambda x: [e.value for e in x]), default=BreachPhase.RECON)

    # Configuration
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # mode, timeout, scope, rules
    timeout_hours: Mapped[int] = mapped_column(Integer, default=24)
    scope: Mapped[list] = mapped_column(JSON, default=list)  # allowed domains/paths
    rules_of_engagement: Mapped[dict] = mapped_column(JSON, default=dict)

    # Results
    breach_achieved: Mapped[bool] = mapped_column(Boolean, default=False)
    highest_access: Mapped[AccessLevel] = mapped_column(Enum(AccessLevel, values_callable=lambda x: [e.value for e in x]), default=AccessLevel.NONE)
    systems_compromised: Mapped[list] = mapped_column(JSON, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)

    # Business impact
    total_business_impact: Mapped[float] = mapped_column(Float, default=0.0)
    records_exposed: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Error info
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    steps = relationship("BreachStep", back_populates="session", cascade="all, delete-orphan")
    evidence = relationship("BreachEvidence", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_breach_session_org_status", "organization_id", "status"),
        Index("ix_breach_session_created", "created_at"),
    )


class BreachStep(Base):
    """
    A single step in the breach chain.
    """
    __tablename__ = "breach_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("breach_sessions.id", ondelete="CASCADE"), nullable=False
    )

    # Step info
    sequence_num: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[BreachPhase] = mapped_column(Enum(BreachPhase, values_callable=lambda x: [e.value for e in x]), nullable=False)

    # What was attempted
    module_name: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)

    # AI reasoning
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_outcome: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Access gained
    access_gained: Mapped[Optional[AccessLevel]] = mapped_column(Enum(AccessLevel, values_callable=lambda x: [e.value for e in x]), nullable=True)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("BreachSession", back_populates="steps")

    __table_args__ = (
        Index("ix_breach_step_session", "session_id"),
        Index("ix_breach_step_phase", "phase"),
    )


class BreachEvidence(Base):
    """
    Evidence collected during breach - proof of compromise.
    """
    __tablename__ = "breach_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("breach_sessions.id", ondelete="CASCADE"), nullable=False
    )
    step_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("breach_steps.id", ondelete="SET NULL"), nullable=True
    )

    # Evidence type
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # screenshot, data_sample, command_output, etc.

    # Content
    description: Mapped[str] = mapped_column(Text, nullable=False)
    proves: Mapped[str] = mapped_column(Text, nullable=False)  # What does this prove?
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    content_type: Mapped[str] = mapped_column(String(100), default="application/json")
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA256

    # Safety
    is_redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    redaction_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Severity
    severity: Mapped[Severity] = mapped_column(Enum(Severity, values_callable=lambda x: [e.value for e in x]), default=Severity.INFO)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("BreachSession", back_populates="evidence")

    __table_args__ = (
        Index("ix_breach_evidence_session", "session_id"),
        Index("ix_breach_evidence_type", "evidence_type"),
    )


class BrainMemory(Base):
    """
    AI Brain memory - learned patterns for targets across sessions.
    Used by the learning engine for cross-session intelligence.
    """
    __tablename__ = "brain_memory"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )

    # Memory type: technology, endpoint, parameter, vulnerability_hotspot, successful_attack, module_effectiveness
    memory_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Content
    key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)  # JSON string

    # Confidence (0.0 to 1.0) - decays over time
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    # Access tracking
    access_count: Mapped[int] = mapped_column(Integer, default=0)
    last_accessed: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_brain_memory_target", "target_id"),
        Index("ix_brain_memory_type", "memory_type"),
        Index("ix_brain_memory_key", "key"),
    )
