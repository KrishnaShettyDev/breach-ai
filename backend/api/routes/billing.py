"""
BREACH.AI - Billing Routes
===========================
Stripe subscription management endpoints with rate limiting.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from backend.config import settings
from backend.db.database import get_db
from backend.db.models import SubscriptionTier
from backend.services.billing import BillingService
from backend.api.deps import get_current_user, require_admin

router = APIRouter(prefix="/billing", tags=["Billing"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


class CheckoutRequest(BaseModel):
    """Checkout session request."""
    tier: str
    success_url: str
    cancel_url: str


class PortalRequest(BaseModel):
    """Portal session request."""
    return_url: str


class PlanInfo(BaseModel):
    """Plan information."""
    tier: str
    name: str
    price: int
    limits: dict


class SubscriptionInfo(BaseModel):
    """Subscription information."""
    tier: str
    name: str
    status: str
    price: int
    limits: dict
    trial_ends_at: str = None


# ============== SUBSCRIPTION ==============

@router.get("/subscription", response_model=SubscriptionInfo)
async def get_subscription(
    current: tuple = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current subscription information."""
    user, org = current
    billing_service = BillingService(db)

    return await billing_service.get_subscription_info(org)


@router.get("/plans", response_model=List[PlanInfo])
async def get_plans(
    db: AsyncSession = Depends(get_db),
):
    """Get available subscription plans."""
    billing_service = BillingService(db)
    return billing_service.get_available_plans()


@router.post("/checkout")
@limiter.limit(settings.rate_limit_auth)
async def create_checkout(
    request: Request,
    data: CheckoutRequest,
    current: tuple = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a Stripe checkout session for upgrading subscription."""
    user, org = current
    billing_service = BillingService(db)

    try:
        tier = SubscriptionTier(data.tier)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid subscription tier",
        )

    try:
        checkout_url = await billing_service.create_checkout_session(
            organization=org,
            tier=tier,
            email=user.email,
            success_url=data.success_url,
            cancel_url=data.cancel_url,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return {"checkout_url": checkout_url}


@router.post("/portal")
@limiter.limit(settings.rate_limit_auth)
async def create_portal(
    request: Request,
    data: PortalRequest,
    current: tuple = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a Stripe billing portal session for managing subscription."""
    user, org = current
    billing_service = BillingService(db)

    try:
        portal_url = await billing_service.create_portal_session(
            organization=org,
            return_url=data.return_url,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return {"portal_url": portal_url}


# ============== WEBHOOK ==============

@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Stripe webhook events."""
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")

    billing_service = BillingService(db)

    try:
        result = await billing_service.handle_webhook(payload, signature)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
