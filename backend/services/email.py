"""
BREACH.AI - Email Notification Service
======================================
Send email notifications for scan events via SendGrid or Resend.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List
import structlog
import httpx

logger = structlog.get_logger(__name__)


@dataclass
class EmailMessage:
    """Email message data."""
    to: str
    subject: str
    html: str
    text: Optional[str] = None
    from_email: Optional[str] = None
    from_name: Optional[str] = None


class EmailProvider(ABC):
    """Abstract email provider."""

    @abstractmethod
    async def send(self, message: EmailMessage) -> bool:
        pass


class SendGridProvider(EmailProvider):
    """SendGrid email provider."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.sendgrid.com/v3"

    async def send(self, message: EmailMessage) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/mail/send",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "personalizations": [{"to": [{"email": message.to}]}],
                        "from": {
                            "email": message.from_email or "noreply@breach.ai",
                            "name": message.from_name or "BREACH.AI",
                        },
                        "subject": message.subject,
                        "content": [
                            {"type": "text/html", "value": message.html},
                        ],
                    },
                    timeout=30.0,
                )

                if response.status_code in [200, 201, 202]:
                    logger.info("sendgrid_email_sent", to=message.to, subject=message.subject)
                    return True
                else:
                    logger.error(
                        "sendgrid_email_failed",
                        status_code=response.status_code,
                        response=response.text,
                    )
                    return False

        except Exception as e:
            logger.error("sendgrid_error", error=str(e))
            return False


class ResendProvider(EmailProvider):
    """Resend email provider."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.resend.com"

    async def send(self, message: EmailMessage) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/emails",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": f"{message.from_name or 'BREACH.AI'} <{message.from_email or 'noreply@breach.ai'}>",
                        "to": [message.to],
                        "subject": message.subject,
                        "html": message.html,
                    },
                    timeout=30.0,
                )

                if response.status_code in [200, 201]:
                    logger.info("resend_email_sent", to=message.to, subject=message.subject)
                    return True
                else:
                    logger.error(
                        "resend_email_failed",
                        status_code=response.status_code,
                        response=response.text,
                    )
                    return False

        except Exception as e:
            logger.error("resend_error", error=str(e))
            return False


class ConsoleProvider(EmailProvider):
    """Console email provider for development/testing."""

    async def send(self, message: EmailMessage) -> bool:
        logger.info(
            "email_console",
            to=message.to,
            subject=message.subject,
            html_length=len(message.html),
        )
        print(f"\n{'='*60}")
        print(f"EMAIL TO: {message.to}")
        print(f"SUBJECT: {message.subject}")
        print(f"{'='*60}")
        print(message.html[:500] + "..." if len(message.html) > 500 else message.html)
        print(f"{'='*60}\n")
        return True


class EmailService:
    """Email notification service."""

    def __init__(self):
        from backend.config import get_settings
        settings = get_settings()

        # Determine which provider to use
        if settings.sendgrid_api_key:
            self.provider = SendGridProvider(settings.sendgrid_api_key)
            logger.info("email_provider_initialized", provider="sendgrid")
        elif settings.resend_api_key:
            self.provider = ResendProvider(settings.resend_api_key)
            logger.info("email_provider_initialized", provider="resend")
        else:
            self.provider = ConsoleProvider()
            logger.warning("email_provider_console", message="No email API key set, using console")

        self.from_email = settings.email_from
        self.from_name = settings.email_from_name
        self.frontend_url = settings.frontend_url

    async def send(self, message: EmailMessage) -> bool:
        """Send an email."""
        if not message.from_email:
            message.from_email = self.from_email
        if not message.from_name:
            message.from_name = self.from_name

        return await self.provider.send(message)

    # ============== SCAN NOTIFICATIONS ==============

    async def send_scan_started(
        self,
        to_email: str,
        target_url: str,
        scan_id: str,
        mode: str,
    ) -> bool:
        """Send notification when scan starts."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .status {{ background: #e3f2fd; color: #1565c0; padding: 15px; border-radius: 8px; text-align: center; font-weight: bold; }}
        .details {{ margin: 20px 0; }}
        .details-row {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }}
        .label {{ color: #666; }}
        .value {{ font-weight: 500; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0;">🔒 BREACH.AI</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.8;">Security Assessment Platform</p>
        </div>
        <div class="content">
            <div class="status">🚀 Scan Started</div>
            <div class="details">
                <div class="details-row">
                    <span class="label">Target</span>
                    <span class="value">{target_url}</span>
                </div>
                <div class="details-row">
                    <span class="label">Mode</span>
                    <span class="value">{mode.title()}</span>
                </div>
                <div class="details-row">
                    <span class="label">Scan ID</span>
                    <span class="value">{scan_id[:8]}...</span>
                </div>
            </div>
            <p style="color: #666;">Your security scan is now running. We'll notify you when it's complete.</p>
        </div>
        <div class="footer">
            <p>BREACH.AI - "We hack you before they do."</p>
        </div>
    </div>
</body>
</html>
"""
        return await self.send(EmailMessage(
            to=to_email,
            subject=f"🚀 Scan Started: {target_url}",
            html=html,
        ))

    async def send_scan_completed(
        self,
        to_email: str,
        target_url: str,
        scan_id: str,
        findings_count: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        total_impact: float,
        dashboard_url: Optional[str] = None,
    ) -> bool:
        """Send notification when scan completes."""
        dashboard_url = dashboard_url or self.frontend_url

        # Determine severity level for styling
        if critical_count > 0:
            status_color = "#dc3545"
            status_bg = "#f8d7da"
            status_text = f"⚠️ {critical_count} CRITICAL vulnerabilities found"
        elif high_count > 0:
            status_color = "#fd7e14"
            status_bg = "#fff3cd"
            status_text = f"⚠️ {high_count} HIGH severity issues found"
        elif medium_count > 0:
            status_color = "#ffc107"
            status_bg = "#fff9e6"
            status_text = f"⚡ {medium_count} MEDIUM severity issues found"
        elif findings_count > 0:
            status_color = "#28a745"
            status_bg = "#d4edda"
            status_text = f"✓ {findings_count} low/info findings"
        else:
            status_color = "#28a745"
            status_bg = "#d4edda"
            status_text = "✅ No vulnerabilities found!"

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .status {{ background: {status_bg}; color: {status_color}; padding: 20px; border-radius: 8px; text-align: center; font-weight: bold; font-size: 18px; border-left: 4px solid {status_color}; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 25px 0; }}
        .stat {{ text-align: center; padding: 15px 5px; border-radius: 8px; }}
        .stat.critical {{ background: #f8d7da; }}
        .stat.high {{ background: #fff3cd; }}
        .stat.medium {{ background: #d1ecf1; }}
        .stat.low {{ background: #d4edda; }}
        .stat.info {{ background: #e2e3e5; }}
        .stat-number {{ font-size: 24px; font-weight: bold; }}
        .stat-label {{ font-size: 11px; color: #666; }}
        .impact {{ background: #fff3cd; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; }}
        .btn {{ display: inline-block; background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 500; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0;">🔒 BREACH.AI</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.8;">Security Assessment Complete</p>
        </div>
        <div class="content">
            <p style="color: #666; margin-bottom: 5px;">Target scanned:</p>
            <p style="font-size: 18px; font-weight: 500; margin: 0 0 20px 0;">{target_url}</p>

            <div class="status">{status_text}</div>

            <div class="stats">
                <div class="stat critical">
                    <div class="stat-number">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat high">
                    <div class="stat-number">{high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat medium">
                    <div class="stat-number">{medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat low">
                    <div class="stat-number">{low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat info">
                    <div class="stat-number">{findings_count - critical_count - high_count - medium_count - low_count}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>

            {f'<div class="impact"><strong>💰 Estimated Business Impact: ${total_impact:,.0f}</strong></div>' if total_impact else ''}

            <div style="text-align: center; margin-top: 30px;">
                <a href="{dashboard_url}/dashboard/scans/{scan_id}" class="btn">View Full Report →</a>
            </div>
        </div>
        <div class="footer">
            <p>BREACH.AI - "We hack you before they do."</p>
            <p style="margin-top: 10px;">
                <a href="{dashboard_url}/dashboard/settings" style="color: #666;">Manage notification preferences</a>
            </p>
        </div>
    </div>
</body>
</html>
"""
        subject_prefix = "🚨" if critical_count else "⚠️" if high_count else "✅"
        return await self.send(EmailMessage(
            to=to_email,
            subject=f"{subject_prefix} Scan Complete: {target_url} - {findings_count} findings",
            html=html,
        ))

    async def send_critical_finding(
        self,
        to_email: str,
        target_url: str,
        finding_title: str,
        finding_description: str,
        scan_id: str,
        dashboard_url: Optional[str] = None,
    ) -> bool:
        """Send immediate alert for critical findings."""
        dashboard_url = dashboard_url or self.frontend_url
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; }}
        .header {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .alert {{ background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .finding-title {{ font-size: 20px; font-weight: bold; color: #dc3545; margin: 0 0 10px 0; }}
        .btn {{ display: inline-block; background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 500; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0;">🚨 CRITICAL ALERT</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Immediate attention required</p>
        </div>
        <div class="content">
            <div class="alert">
                <p class="finding-title">⚠️ {finding_title}</p>
                <p style="color: #666; margin: 0;">{finding_description[:300]}{'...' if len(finding_description) > 300 else ''}</p>
            </div>

            <p><strong>Target:</strong> {target_url}</p>

            <p style="color: #666;">A critical security vulnerability has been discovered during your scan. We recommend addressing this immediately.</p>

            <div style="text-align: center; margin-top: 30px;">
                <a href="{dashboard_url}/dashboard/scans/{scan_id}" class="btn">View Details →</a>
            </div>
        </div>
        <div class="footer">
            <p>BREACH.AI - "We hack you before they do."</p>
        </div>
    </div>
</body>
</html>
"""
        return await self.send(EmailMessage(
            to=to_email,
            subject=f"🚨 CRITICAL: {finding_title} - {target_url}",
            html=html,
        ))


# Singleton instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get the email service singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
