"""
BREACH.AI - Billing Service
============================
Stripe subscription management.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

import stripe
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.models import Organization, SubscriptionTier, SubscriptionStatus

logger = structlog.get_logger(__name__)

# Initialize Stripe with config (if available)
STRIPE_ENABLED = bool(settings.stripe_secret_key)
if STRIPE_ENABLED:
    stripe.api_key = settings.stripe_secret_key
else:
    logger.warning("stripe_not_configured", message="Stripe API key not set, billing features disabled")

# Pricing configuration
PRICING = {
    SubscriptionTier.FREE: {
        "price_id": None,
        "name": "Free",
        "price": 0,
        "max_scans_per_month": 10,
        "max_targets": 3,
        "max_team_members": 2,
    },
    SubscriptionTier.STARTER: {
        "price_id": settings.stripe_starter_price_id or None,
        "name": "Starter",
        "price": 49,
        "max_scans_per_month": 50,
        "max_targets": 10,
        "max_team_members": 5,
    },
    SubscriptionTier.PRO: {
        "price_id": settings.stripe_pro_price_id or None,
        "name": "Pro",
        "price": 199,
        "max_scans_per_month": 200,
        "max_targets": 50,
        "max_team_members": 20,
    },
    SubscriptionTier.ENTERPRISE: {
        "price_id": settings.stripe_enterprise_price_id or None,
        "name": "Enterprise",
        "price": 499,
        "max_scans_per_month": 1000,
        "max_targets": 200,
        "max_team_members": 100,
    },
}


class BillingService:
    """Stripe billing service."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _require_stripe(self):
        """Raise error if Stripe is not configured."""
        if not STRIPE_ENABLED:
            raise ValueError("Billing is not configured. Please add STRIPE_SECRET_KEY to enable payments.")

    async def get_or_create_customer(self, organization: Organization, email: str) -> str:
        """Get or create a Stripe customer for the organization."""
        self._require_stripe()

        if organization.stripe_customer_id:
            return organization.stripe_customer_id

        # Create new customer
        customer = stripe.Customer.create(
            email=email,
            name=organization.name,
            metadata={
                "organization_id": str(organization.id),
                "organization_slug": organization.slug,
            },
        )

        organization.stripe_customer_id = customer.id
        await self.db.commit()

        return customer.id

    async def create_checkout_session(
        self,
        organization: Organization,
        tier: SubscriptionTier,
        email: str,
        success_url: str,
        cancel_url: str,
    ) -> str:
        """Create a Stripe checkout session for subscription."""

        if tier == SubscriptionTier.FREE:
            raise ValueError("Cannot checkout for free tier")

        pricing = PRICING[tier]
        if not pricing["price_id"]:
            raise ValueError(f"Price ID not configured for {tier.value}")

        customer_id = await self.get_or_create_customer(organization, email)

        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price": pricing["price_id"],
                "quantity": 1,
            }],
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "organization_id": str(organization.id),
                "tier": tier.value,
            },
        )

        return session.url

    async def create_portal_session(
        self,
        organization: Organization,
        return_url: str,
    ) -> str:
        """Create a Stripe billing portal session."""
        self._require_stripe()

        if not organization.stripe_customer_id:
            raise ValueError("Organization has no billing account")

        session = stripe.billing_portal.Session.create(
            customer=organization.stripe_customer_id,
            return_url=return_url,
        )

        return session.url

    async def handle_webhook(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """Handle Stripe webhook events."""

        try:
            event = stripe.Webhook.construct_event(
                payload, signature, settings.stripe_webhook_secret
            )
        except stripe.error.SignatureVerificationError:
            logger.warning("stripe_webhook_invalid_signature")
            raise ValueError("Invalid signature")

        # Handle the event
        if event["type"] == "checkout.session.completed":
            await self._handle_checkout_completed(event["data"]["object"])

        elif event["type"] == "customer.subscription.updated":
            await self._handle_subscription_updated(event["data"]["object"])

        elif event["type"] == "customer.subscription.deleted":
            await self._handle_subscription_deleted(event["data"]["object"])

        elif event["type"] == "invoice.payment_failed":
            await self._handle_payment_failed(event["data"]["object"])

        return {"status": "success", "event_type": event["type"]}

    async def _handle_checkout_completed(self, session: dict) -> None:
        """Handle successful checkout."""

        org_id = session["metadata"].get("organization_id")
        tier = session["metadata"].get("tier")

        if not org_id or not tier:
            return

        result = await self.db.execute(
            select(Organization).where(Organization.id == UUID(org_id))
        )
        org = result.scalar_one_or_none()

        if not org:
            return

        # Update subscription
        pricing = PRICING[SubscriptionTier(tier)]
        org.subscription_tier = SubscriptionTier(tier)
        org.subscription_status = SubscriptionStatus.ACTIVE
        org.stripe_subscription_id = session.get("subscription")
        org.max_scans_per_month = pricing["max_scans_per_month"]
        org.max_targets = pricing["max_targets"]
        org.max_team_members = pricing["max_team_members"]
        org.trial_ends_at = None

        await self.db.commit()

    async def _handle_subscription_updated(self, subscription: dict) -> None:
        """Handle subscription updates."""

        customer_id = subscription["customer"]

        result = await self.db.execute(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        )
        org = result.scalar_one_or_none()

        if not org:
            return

        # Update status
        status_map = {
            "active": SubscriptionStatus.ACTIVE,
            "past_due": SubscriptionStatus.PAST_DUE,
            "canceled": SubscriptionStatus.CANCELED,
            "trialing": SubscriptionStatus.TRIALING,
        }

        org.subscription_status = status_map.get(
            subscription["status"],
            SubscriptionStatus.ACTIVE
        )

        await self.db.commit()

    async def _handle_subscription_deleted(self, subscription: dict) -> None:
        """Handle subscription cancellation."""

        customer_id = subscription["customer"]

        result = await self.db.execute(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        )
        org = result.scalar_one_or_none()

        if not org:
            return

        # Downgrade to free
        pricing = PRICING[SubscriptionTier.FREE]
        org.subscription_tier = SubscriptionTier.FREE
        org.subscription_status = SubscriptionStatus.CANCELED
        org.stripe_subscription_id = None
        org.max_scans_per_month = pricing["max_scans_per_month"]
        org.max_targets = pricing["max_targets"]
        org.max_team_members = pricing["max_team_members"]

        await self.db.commit()

    async def _handle_payment_failed(self, invoice: dict) -> None:
        """Handle failed payment."""

        customer_id = invoice["customer"]

        result = await self.db.execute(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        )
        org = result.scalar_one_or_none()

        if not org:
            return

        org.subscription_status = SubscriptionStatus.PAST_DUE
        await self.db.commit()

    async def get_subscription_info(self, organization: Organization) -> Dict[str, Any]:
        """Get subscription information for an organization."""

        pricing = PRICING[organization.subscription_tier]

        return {
            "tier": organization.subscription_tier.value,
            "name": pricing["name"],
            "status": organization.subscription_status.value,
            "price": pricing["price"],
            "limits": {
                "scans_per_month": organization.max_scans_per_month,
                "scans_used": organization.scans_this_month,
                "targets": organization.max_targets,
                "team_members": organization.max_team_members,
            },
            "trial_ends_at": organization.trial_ends_at.isoformat() if organization.trial_ends_at else None,
        }

    def get_available_plans(self) -> list:
        """Get list of available subscription plans."""

        return [
            {
                "tier": tier.value,
                "name": info["name"],
                "price": info["price"],
                "limits": {
                    "scans_per_month": info["max_scans_per_month"],
                    "targets": info["max_targets"],
                    "team_members": info["max_team_members"],
                },
            }
            for tier, info in PRICING.items()
        ]
