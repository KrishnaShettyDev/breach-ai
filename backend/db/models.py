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
    BUSINESS = "business"
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
        Enum(SubscriptionTier), default=SubscriptionTier.FREE
    )
    subscription_status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(SubscriptionStatus), default=SubscriptionStatus.TRIALING
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Limits (based on tier)
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=10)
    max_targets: Mapped[int] = mapped_column(Integer, default=5)
    max_team_members: Mapped[int] = mapped_column(Integer, default=3)
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
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.MEMBER)

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
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), default=ScanMode.NORMAL)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)

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
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
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
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), default=ScanMode.NORMAL)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
