"""
BREACH.AI - Auth Schemas
========================
Pydantic models for authentication.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID


class UserRegister(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=2, max_length=255)
    organization_name: Optional[str] = Field(None, min_length=2, max_length=255)


class UserLogin(BaseModel):
    """User login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    refresh_token: str


class UserResponse(BaseModel):
    """User response."""
    id: UUID
    email: str
    name: str
    avatar_url: Optional[str] = None
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserWithOrgs(UserResponse):
    """User with organizations."""
    organizations: List["OrganizationBrief"] = []


class OrganizationBrief(BaseModel):
    """Brief organization info."""
    id: UUID
    name: str
    slug: str
    role: str

    class Config:
        from_attributes = True


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    token: str
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str = Field(..., min_length=8)


class APIKeyCreate(BaseModel):
    """Create API key request."""
    name: str = Field(..., min_length=2, max_length=255)
    scopes: List[str] = ["scans:read", "scans:write"]
    expires_in_days: Optional[int] = None  # None = never expires


class APIKeyResponse(BaseModel):
    """API key response (only returned once on creation)."""
    id: UUID
    name: str
    key: str  # Full key - only shown once!
    key_prefix: str
    scopes: List[str]
    expires_at: Optional[datetime]
    created_at: datetime


class APIKeyListItem(BaseModel):
    """API key list item (no full key)."""
    id: UUID
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
