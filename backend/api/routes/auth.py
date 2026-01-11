"""
BREACH.AI - Auth Routes (Clerk)
================================
Simplified auth endpoints using Clerk with rate limiting.
Only handles API keys and user info - Clerk handles login/register.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from backend.config import settings
from backend.db.database import get_db
from backend.services.auth import AuthService
from backend.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


# ============== SCHEMAS ==============

class UserResponse(BaseModel):
    """User response."""
    id: UUID
    email: str
    name: str
    avatar_url: str = None

    class Config:
        from_attributes = True


class OrganizationBrief(BaseModel):
    """Brief organization info."""
    id: UUID
    name: str
    slug: str
    role: str


class UserWithOrgs(UserResponse):
    """User with organizations."""
    organizations: List[OrganizationBrief] = []


class APIKeyCreate(BaseModel):
    """Create API key request."""
    name: str
    scopes: List[str] = ["scans:read", "scans:write"]
    expires_in_days: int = None


class APIKeyResponse(BaseModel):
    """API key response (full key only shown once)."""
    id: UUID
    name: str
    key: str
    key_prefix: str
    scopes: List[str]
    expires_at: str = None
    created_at: str


class APIKeyListItem(BaseModel):
    """API key list item."""
    id: UUID
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    last_used_at: str = None
    expires_at: str = None

    class Config:
        from_attributes = True


# ============== ENDPOINTS ==============

@router.get("/me", response_model=UserWithOrgs)
async def get_me(
    request: Request,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user profile and organizations."""
    user, org = current
    auth_service = AuthService(db)

    orgs = await auth_service.get_user_organizations(user.id)

    return UserWithOrgs(
        id=user.id,
        email=user.email,
        name=user.name,
        avatar_url=user.avatar_url,
        organizations=[OrganizationBrief(**o) for o in orgs],
    )


# ============== API KEYS ==============

@router.post("/api-keys", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_auth)
async def create_api_key(
    request: Request,
    data: APIKeyCreate,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. The full key is only shown once!"""
    user, org = current
    auth_service = AuthService(db)

    api_key, raw_key = await auth_service.create_api_key(
        organization_id=org.id,
        user_id=user.id,
        name=data.name,
        scopes=data.scopes,
        expires_in_days=data.expires_in_days,
    )

    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        created_at=api_key.created_at.isoformat(),
    )


@router.get("/api-keys", response_model=List[APIKeyListItem])
async def list_api_keys(
    request: Request,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for the organization."""
    user, org = current
    auth_service = AuthService(db)

    return await auth_service.list_api_keys(org.id)


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    request: Request,
    key_id: UUID,
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key."""
    user, org = current
    auth_service = AuthService(db)

    success = await auth_service.revoke_api_key(key_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
