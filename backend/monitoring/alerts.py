"""
BREACH.AI - Alerting System
============================
Webhook-based alerting for scan failures and critical events.
"""

from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from backend.config import settings

logger = structlog.get_logger(__name__)


async def send_scan_failure_alert(
    scan_id: str,
    target_url: str,
    error_message: str,
    organization_id: Optional[str] = None,
) -> bool:
    """
    Send an alert when a scan fails.

    Args:
        scan_id: UUID of the failed scan
        target_url: Target URL that was being scanned
        error_message: Error message from the failure
        organization_id: Optional organization ID

    Returns:
        True if alert was sent successfully
    """
    if not settings.alert_webhook_url:
        logger.debug("alert_skipped_no_webhook")
        return False

    payload = {
        "type": "scan_failure",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "target_url": target_url,
        "error_message": error_message,
        "organization_id": organization_id,
        "environment": settings.environment,
        "service": "BREACH.AI",
    }

    # Format for Slack if URL looks like Slack webhook
    if "slack.com" in settings.alert_webhook_url:
        payload = _format_slack_message(scan_id, target_url, error_message)
    # Format for Discord if URL looks like Discord webhook
    elif "discord.com" in settings.alert_webhook_url:
        payload = _format_discord_message(scan_id, target_url, error_message)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                settings.alert_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()

        logger.info(
            "alert_sent",
            scan_id=scan_id,
            webhook_status=response.status_code
        )
        return True

    except httpx.TimeoutException:
        logger.warning("alert_timeout", scan_id=scan_id)
        return False
    except httpx.HTTPStatusError as e:
        logger.error(
            "alert_failed",
            scan_id=scan_id,
            status_code=e.response.status_code,
            error=str(e)
        )
        return False
    except Exception as e:
        logger.error("alert_error", scan_id=scan_id, error=str(e))
        return False


def _format_slack_message(scan_id: str, target_url: str, error_message: str) -> dict:
    """Format alert as Slack message."""
    return {
        "text": f"⚠️ BREACH.AI Scan Failed",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "⚠️ Scan Failed",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Scan ID:*\n`{scan_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n{target_url}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error:*\n```{error_message[:500]}```"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Environment: {settings.environment} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    }
                ]
            }
        ]
    }


def _format_discord_message(scan_id: str, target_url: str, error_message: str) -> dict:
    """Format alert as Discord message."""
    return {
        "embeds": [
            {
                "title": "⚠️ BREACH.AI Scan Failed",
                "color": 15158332,  # Red
                "fields": [
                    {
                        "name": "Scan ID",
                        "value": f"`{scan_id}`",
                        "inline": True
                    },
                    {
                        "name": "Target",
                        "value": target_url,
                        "inline": True
                    },
                    {
                        "name": "Error",
                        "value": f"```{error_message[:500]}```",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"Environment: {settings.environment}"
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }


async def send_critical_finding_alert(
    scan_id: str,
    target_url: str,
    finding_title: str,
    severity: str,
) -> bool:
    """
    Send an alert for critical findings.

    Args:
        scan_id: UUID of the scan
        target_url: Target URL
        finding_title: Title of the finding
        severity: Severity level

    Returns:
        True if alert was sent successfully
    """
    if not settings.alert_webhook_url:
        return False

    if severity.lower() not in ("critical", "high"):
        return False

    payload = {
        "type": "critical_finding",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "target_url": target_url,
        "finding_title": finding_title,
        "severity": severity,
        "environment": settings.environment,
        "service": "BREACH.AI",
    }

    # Format for Slack
    if "slack.com" in settings.alert_webhook_url:
        emoji = "🔴" if severity.lower() == "critical" else "🟠"
        payload = {
            "text": f"{emoji} {severity.upper()}: {finding_title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {severity.upper()} Finding Detected",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{finding_title}*\n\nTarget: {target_url}\nScan ID: `{scan_id}`"
                    }
                }
            ]
        }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                settings.alert_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()

        logger.info(
            "critical_finding_alert_sent",
            scan_id=scan_id,
            severity=severity,
            finding=finding_title
        )
        return True

    except Exception as e:
        logger.error("critical_finding_alert_failed", error=str(e))
        return False
