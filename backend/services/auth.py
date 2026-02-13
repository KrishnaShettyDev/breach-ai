"""
BREACH.AI - Auth Service (Clerk)
=================================
Simplified auth using Clerk for authentication.
Backend just verifies Clerk tokens and syncs users.
"""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any
from uuid import UUID

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.models import User, Organization, OrganizationMember, APIKey, UserRole

logger = structlog.get_logger(__name__)

# Cache for JWKS data (keyed by issuer URL)
_jwks_data_cache: Dict[str, Dict[str, Any]] = {}
_jwks_cache_time: Dict[str, float] = {}

# Cache for verified tokens (keyed by token hash, short TTL)
_token_cache: Dict[str, Tuple[dict, float]] = {}
TOKEN_CACHE_TTL = 60  # 60 seconds

# Cache for user+org lookups (keyed by clerk_user_id)
_user_org_cache: Dict[str, Tuple[Any, Any, float]] = {}
USER_CACHE_TTL = 300  # 5 minutes


class AuthService:
    """Clerk-based authentication service."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ============== CLERK VERIFICATION ==============

    async def verify_clerk_token(self, token: str) -> Optional[dict]:
        """
        Verify a Clerk session token using async HTTP.
        Returns the decoded payload with user info.
        Uses aggressive caching to avoid repeated verification.
        """
        import time

        # Quick cache check using token hash (first 32 chars is enough)
        token_key = token[:64] if len(token) > 64 else token
        cached = _token_cache.get(token_key)
        if cached:
            payload, cache_time = cached
            if time.time() - cache_time < TOKEN_CACHE_TTL:
                return payload

        try:
            import jwt
            from jwt import PyJWK

            # Decode without verification to get issuer and key ID
            unverified_header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified.get("iss", "")
            kid = unverified_header.get("kid")

            if not issuer or "clerk" not in issuer:
                return None

            # Get JWKS data (cached for 1 hour)
            jwks_url = f"{issuer}/.well-known/jwks.json"
            cache_age = time.time() - _jwks_cache_time.get(issuer, 0)

            if issuer not in _jwks_data_cache or cache_age > 3600:
                # Fetch JWKS asynchronously
                async with httpx.AsyncClient() as client:
                    response = await client.get(jwks_url, timeout=10)
                    response.raise_for_status()
                    _jwks_data_cache[issuer] = response.json()
                    _jwks_cache_time[issuer] = time.time()

            jwks_data = _jwks_data_cache[issuer]

            # Find the key by kid
            signing_key = None
            for key_data in jwks_data.get("keys", []):
                if key_data.get("kid") == kid:
                    signing_key = PyJWK.from_dict(key_data).key
                    break

            if not signing_key:
                logger.warning("clerk_key_not_found", kid=kid)
                return None

            payload = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=None,
                options={"verify_aud": False}
            )

            # Cache the verified payload
            _token_cache[token_key] = (payload, time.time())

            # Clean old cache entries periodically (keep last 100)
            if len(_token_cache) > 100:
                sorted_keys = sorted(_token_cache.keys(), key=lambda k: _token_cache[k][1])
                for old_key in sorted_keys[:50]:
                    del _token_cache[old_key]

            return payload

        except Exception as e:
            logger.warning("clerk_token_verification_failed", error=str(e))
            return None

    async def get_or_create_user_from_clerk(self, clerk_user_id: str, email: str, name: str) -> Tuple[User, Organization]:
        """
        Get or create a user from Clerk session data.
        Also creates default organization if needed.
        Uses aggressive caching to avoid DB hits on every request.
        """
        import time

        # Check cache first
        cached = _user_org_cache.get(clerk_user_id)
        if cached:
            user, org, cache_time = cached
            if time.time() - cache_time < USER_CACHE_TTL:
                return user, org

        # Check if user exists
        result = await self.db.execute(
            select(User).where(User.clerk_id == clerk_user_id)
        )
        user = result.scalar_one_or_none()

        if user:
            # Get their organization
            member_result = await self.db.execute(
                select(OrganizationMember).where(OrganizationMember.user_id == user.id)
            )
            member = member_result.scalars().first()

            if member:
                org_result = await self.db.execute(
                    select(Organization).where(Organization.id == member.organization_id)
                )
                org = org_result.scalar_one()
                # Cache the result
                _user_org_cache[clerk_user_id] = (user, org, time.time())
                return user, org

        # Create new user
        if not user:
            user = User(
                email=email,
                name=name or email.split("@")[0],
                clerk_id=clerk_user_id,
                is_verified=True,  # Clerk handles verification
            )
            self.db.add(user)
            await self.db.flush()

        # Create organization
        org_name = f"{user.name}'s Organization"
        slug = self._generate_slug(org_name)

        org = Organization(
            name=org_name,
            slug=slug,
            subscription_tier="free",
            trial_ends_at=datetime.utcnow() + timedelta(days=14),
        )
        self.db.add(org)
        await self.db.flush()

        # Add user as owner
        member = OrganizationMember(
            organization_id=org.id,
            user_id=user.id,
            role=UserRole.OWNER,
        )
        self.db.add(member)

        await self.db.commit()
        await self.db.refresh(user)
        await self.db.refresh(org)

        # Cache the result
        _user_org_cache[clerk_user_id] = (user, org, time.time())

        return user, org

    async def get_user_by_clerk_id(self, clerk_id: str) -> Optional[User]:
        """Get user by Clerk ID."""
        result = await self.db.execute(
            select(User).where(User.clerk_id == clerk_id)
        )
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_user_organizations(self, user_id: UUID) -> list:
        """Get all organizations a user belongs to."""
        result = await self.db.execute(
            select(OrganizationMember).where(OrganizationMember.user_id == user_id)
        )
        memberships = result.scalars().all()

        orgs = []
        for m in memberships:
            org_result = await self.db.execute(
                select(Organization).where(Organization.id == m.organization_id)
            )
            org = org_result.scalar_one_or_none()
            if org:
                orgs.append({
                    "id": org.id,
                    "name": org.name,
                    "slug": org.slug,
                    "role": m.role.value,
                })

        return orgs

    # ============== API KEYS ==============

    async def create_api_key(
        self,
        organization_id: UUID,
        user_id: UUID,
        name: str,
        scopes: list = None,
        expires_in_days: Optional[int] = None,
    ) -> Tuple[APIKey, str]:
        """Create a new API key."""
        scopes = scopes or ["scans:read", "scans:write"]

        # Generate key with configured prefix
        raw_key = f"{settings.api_key_prefix}{secrets.token_urlsafe(32)}"
        key_prefix = raw_key[:len(settings.api_key_prefix) + 8]
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        api_key = APIKey(
            organization_id=organization_id,
            created_by=user_id,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
        self.db.add(api_key)
        await self.db.commit()
        await self.db.refresh(api_key)

        return api_key, raw_key

    async def validate_api_key(self, raw_key: str) -> Optional[Tuple[APIKey, Organization]]:
        """Validate an API key."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        result = await self.db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
            )
        )
        api_key = result.scalar_one_or_none()

        if not api_key:
            return None

        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            return None

        api_key.last_used_at = datetime.utcnow()

        org_result = await self.db.execute(
            select(Organization).where(Organization.id == api_key.organization_id)
        )
        org = org_result.scalar_one_or_none()

        await self.db.commit()

        return api_key, org

    async def list_api_keys(self, organization_id: UUID) -> list:
        """List all API keys for an organization."""
        result = await self.db.execute(
            select(APIKey).where(APIKey.organization_id == organization_id)
        )
        return result.scalars().all()

    async def revoke_api_key(self, key_id: UUID, organization_id: UUID) -> bool:
        """Revoke an API key."""
        result = await self.db.execute(
            select(APIKey).where(
                APIKey.id == key_id,
                APIKey.organization_id == organization_id,
            )
        )
        api_key = result.scalar_one_or_none()

        if not api_key:
            return False

        api_key.is_active = False
        await self.db.commit()
        return True

    # ============== HELPERS ==============

    def _generate_slug(self, name: str) -> str:
        """Generate a URL-safe slug."""
        import re
        slug = name.lower()
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        slug = slug.strip('-')
        slug = f"{slug}-{secrets.token_hex(4)}"
        return slug
