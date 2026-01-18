"""
BREACH.AI - Integrations API Routes
====================================

API endpoints for managing Slack, Jira, GitHub, and webhook integrations.
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.db.models import Organization
from backend.api.deps import get_current_user, require_admin
from backend.services.integrations import (
    SlackIntegration, JiraIntegration, GitHubIntegration,
    IntegrationType, NotificationEvent
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])


# ============== Request/Response Models ==============

class SlackConfig(BaseModel):
    """Slack integration configuration."""
    enabled: bool = True
    webhook_url: str = Field(..., description="Slack webhook URL")
    channel: Optional[str] = Field(None, description="Override channel (optional)")
    events: List[str] = Field(
        default=["scan_completed", "critical_finding", "breach_achieved"],
        description="Events to notify"
    )


class JiraConfig(BaseModel):
    """Jira integration configuration."""
    enabled: bool = True
    base_url: str = Field(..., description="Jira instance URL (e.g., https://company.atlassian.net)")
    email: str = Field(..., description="Jira user email")
    api_token: str = Field(..., description="Jira API token")
    project_key: str = Field(..., description="Jira project key (e.g., SEC)")
    issue_type: str = Field(default="Bug", description="Issue type for findings")
    auto_create_issues: bool = Field(default=True, description="Auto-create issues for findings")
    min_severity: str = Field(default="high", description="Minimum severity to create issues")


class GitHubConfig(BaseModel):
    """GitHub integration configuration."""
    enabled: bool = True
    token: str = Field(..., description="GitHub personal access token")
    owner: str = Field(..., description="Repository owner")
    repo: str = Field(..., description="Repository name")
    auto_create_issues: bool = Field(default=True)
    create_security_advisories: bool = Field(default=False)


class WebhookConfig(BaseModel):
    """Webhook integration configuration."""
    name: str = Field(..., min_length=1, max_length=100)
    enabled: bool = True
    url: str = Field(..., description="Webhook endpoint URL")
    secret: Optional[str] = Field(None, description="HMAC secret for signing")
    headers: Optional[dict] = Field(default={}, description="Custom headers")
    events: List[str] = Field(
        default=["scan_completed", "critical_finding"],
        description="Events to send"
    )


class IntegrationsResponse(BaseModel):
    """Current integrations status."""
    slack: Optional[dict] = None
    jira: Optional[dict] = None
    github: Optional[dict] = None
    webhooks: List[dict] = []


class TestResult(BaseModel):
    """Integration test result."""
    success: bool
    message: str


# ============== Endpoints ==============

@router.get("", response_model=IntegrationsResponse)
async def get_integrations(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get current integration configurations.

    Sensitive fields (tokens, secrets) are redacted.
    """
    user, org = current

    settings = org.settings or {}
    integrations = settings.get("integrations", {})

    # Redact sensitive fields
    result = IntegrationsResponse()

    if slack := integrations.get("slack"):
        result.slack = {
            "enabled": slack.get("enabled", False),
            "webhook_url": _redact(slack.get("webhook_url", "")),
            "channel": slack.get("channel"),
            "events": slack.get("events", []),
        }

    if jira := integrations.get("jira"):
        result.jira = {
            "enabled": jira.get("enabled", False),
            "base_url": jira.get("base_url"),
            "email": jira.get("email"),
            "api_token": "********" if jira.get("api_token") else None,
            "project_key": jira.get("project_key"),
            "issue_type": jira.get("issue_type"),
            "auto_create_issues": jira.get("auto_create_issues", True),
            "min_severity": jira.get("min_severity", "high"),
        }

    if github := integrations.get("github"):
        result.github = {
            "enabled": github.get("enabled", False),
            "owner": github.get("owner"),
            "repo": github.get("repo"),
            "token": "********" if github.get("token") else None,
            "auto_create_issues": github.get("auto_create_issues", True),
        }

    for webhook in integrations.get("webhooks", []):
        result.webhooks.append({
            "name": webhook.get("name"),
            "enabled": webhook.get("enabled", False),
            "url": _redact(webhook.get("url", "")),
            "events": webhook.get("events", []),
        })

    return result


@router.put("/slack", response_model=dict)
async def configure_slack(
    config: SlackConfig,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Configure Slack integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" not in settings:
        settings["integrations"] = {}

    settings["integrations"]["slack"] = config.model_dump()
    org.settings = settings

    await db.commit()

    return {"message": "Slack integration configured", "enabled": config.enabled}


@router.put("/jira", response_model=dict)
async def configure_jira(
    config: JiraConfig,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Configure Jira integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" not in settings:
        settings["integrations"] = {}

    settings["integrations"]["jira"] = config.model_dump()
    org.settings = settings

    await db.commit()

    return {"message": "Jira integration configured", "enabled": config.enabled}


@router.put("/github", response_model=dict)
async def configure_github(
    config: GitHubConfig,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Configure GitHub integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" not in settings:
        settings["integrations"] = {}

    settings["integrations"]["github"] = config.model_dump()
    org.settings = settings

    await db.commit()

    return {"message": "GitHub integration configured", "enabled": config.enabled}


@router.post("/webhooks", response_model=dict)
async def add_webhook(
    config: WebhookConfig,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Add a webhook integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" not in settings:
        settings["integrations"] = {}
    if "webhooks" not in settings["integrations"]:
        settings["integrations"]["webhooks"] = []

    # Check for duplicate name
    for webhook in settings["integrations"]["webhooks"]:
        if webhook.get("name") == config.name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Webhook '{config.name}' already exists"
            )

    settings["integrations"]["webhooks"].append(config.model_dump())
    org.settings = settings

    await db.commit()

    return {"message": f"Webhook '{config.name}' added", "enabled": config.enabled}


@router.delete("/webhooks/{name}", response_model=dict)
async def remove_webhook(
    name: str,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Remove a webhook integration."""
    user, org = current

    settings = org.settings or {}
    webhooks = settings.get("integrations", {}).get("webhooks", [])

    original_count = len(webhooks)
    webhooks = [w for w in webhooks if w.get("name") != name]

    if len(webhooks) == original_count:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{name}' not found"
        )

    settings["integrations"]["webhooks"] = webhooks
    org.settings = settings

    await db.commit()

    return {"message": f"Webhook '{name}' removed"}


@router.post("/slack/test", response_model=TestResult)
async def test_slack(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Test Slack integration by sending a test message."""
    user, org = current

    config = (org.settings or {}).get("integrations", {}).get("slack")
    if not config or not config.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Slack integration not configured"
        )

    slack = SlackIntegration(
        webhook_url=config["webhook_url"],
        channel=config.get("channel")
    )

    success = await slack._send_message([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "🧪 *BREACH.AI Test Message*\n\nSlack integration is working correctly!"
            }
        }
    ])

    return TestResult(
        success=success,
        message="Test message sent successfully" if success else "Failed to send test message"
    )


@router.post("/jira/test", response_model=TestResult)
async def test_jira(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Test Jira integration by verifying connection."""
    user, org = current

    config = (org.settings or {}).get("integrations", {}).get("jira")
    if not config or not config.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jira integration not configured"
        )

    import httpx

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{config['base_url']}/rest/api/3/myself",
                auth=(config["email"], config["api_token"]),
                timeout=10
            )

            if response.status_code == 200:
                user_data = response.json()
                return TestResult(
                    success=True,
                    message=f"Connected as {user_data.get('displayName', user_data.get('emailAddress'))}"
                )
            else:
                return TestResult(
                    success=False,
                    message=f"Authentication failed: {response.status_code}"
                )

    except Exception as e:
        return TestResult(success=False, message=f"Connection failed: {str(e)}")


@router.post("/github/test", response_model=TestResult)
async def test_github(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Test GitHub integration by verifying access."""
    user, org = current

    config = (org.settings or {}).get("integrations", {}).get("github")
    if not config or not config.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub integration not configured"
        )

    import httpx

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.github.com/repos/{config['owner']}/{config['repo']}",
                headers={
                    "Authorization": f"Bearer {config['token']}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10
            )

            if response.status_code == 200:
                repo_data = response.json()
                return TestResult(
                    success=True,
                    message=f"Connected to {repo_data.get('full_name')}"
                )
            elif response.status_code == 404:
                return TestResult(
                    success=False,
                    message="Repository not found or no access"
                )
            else:
                return TestResult(
                    success=False,
                    message=f"GitHub API error: {response.status_code}"
                )

    except Exception as e:
        return TestResult(success=False, message=f"Connection failed: {str(e)}")


@router.delete("/slack")
async def disable_slack(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Disable Slack integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" in settings and "slack" in settings["integrations"]:
        settings["integrations"]["slack"]["enabled"] = False
        org.settings = settings
        await db.commit()

    return {"message": "Slack integration disabled"}


@router.delete("/jira")
async def disable_jira(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Disable Jira integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" in settings and "jira" in settings["integrations"]:
        settings["integrations"]["jira"]["enabled"] = False
        org.settings = settings
        await db.commit()

    return {"message": "Jira integration disabled"}


@router.delete("/github")
async def disable_github(
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(require_admin),
):
    """Disable GitHub integration."""
    user, org = current

    settings = org.settings or {}
    if "integrations" in settings and "github" in settings["integrations"]:
        settings["integrations"]["github"]["enabled"] = False
        org.settings = settings
        await db.commit()

    return {"message": "GitHub integration disabled"}


# ============== Helpers ==============

def _redact(value: str, visible_chars: int = 8) -> str:
    """Redact sensitive value, showing only first few characters."""
    if not value:
        return ""
    if len(value) <= visible_chars:
        return "********"
    return value[:visible_chars] + "********"
