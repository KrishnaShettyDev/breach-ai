"""
BREACH.AI - API Dependencies (Clerk)
=====================================
FastAPI dependencies for Clerk authentication.
"""

from typing import Optional, Tuple
from uuid import UUID

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.db.models import User, Organization, OrganizationMember
from backend.services.auth import AuthService

# Security
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Tuple[User, Organization]:
    """
    Get current user from Clerk token or API key.
    Returns tuple of (user, organization).
    """

    auth_service = AuthService(db)

    # Try API key first (for programmatic access)
    if x_api_key:
        result = await auth_service.validate_api_key(x_api_key)
        if result:
            api_key, org = result
            user = await auth_service.get_user_by_id(api_key.created_by)
            if user:
                return user, org

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Try Clerk token
    if credentials:
        payload = await auth_service.verify_clerk_token(credentials.credentials)

        if payload:
            clerk_user_id = payload.get("sub")
            email = payload.get("email") or payload.get("primary_email_address", "")
            name = payload.get("name") or payload.get("first_name", "")

            if clerk_user_id:
                user, org = await auth_service.get_or_create_user_from_clerk(
                    clerk_user_id=clerk_user_id,
                    email=email,
                    name=name,
                )
                return user, org

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Optional[Tuple[User, Organization]]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None

    try:
        return await get_current_user(credentials=credentials, x_api_key=None, db=db)
    except HTTPException:
        return None


def require_role(allowed_roles: list):
    """Dependency factory to require specific roles."""

    async def check_role(
        current: Tuple[User, Organization] = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> Tuple[User, Organization]:
        user, org = current

        from sqlalchemy import select
        result = await db.execute(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.organization_id == org.id,
            )
        )
        member = result.scalar_one_or_none()

        if not member or member.role.value not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return user, org

    return check_role


# Convenience dependencies
require_admin = require_role(["owner", "admin"])
require_member = require_role(["owner", "admin", "member"])
