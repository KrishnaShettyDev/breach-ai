"""
BREACH.AI - Integration Service
================================

Integrations with external tools:
- Slack: Real-time notifications
- Jira: Automatic ticket creation
- GitHub: Issue creation, code scanning hooks

This is what enterprises expect. MindFort has it. Now we do too.

Features:
- Exponential backoff retry logic
- Circuit breaker pattern for failing integrations
- Async/parallel notification sending
- Graceful degradation on integration failures
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, List, Any, Callable
from uuid import UUID
import json
import random

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Organization, Finding, Scan, Target

logger = structlog.get_logger(__name__)


# ============== RETRY AND CIRCUIT BREAKER ==============

@dataclass
class CircuitState:
    """Circuit breaker state tracking."""
    failures: int = 0
    last_failure: Optional[datetime] = None
    state: str = "closed"  # closed, open, half-open
    reset_timeout: int = 60  # seconds


class ResilientHTTPClient:
    """
    HTTP client with retry logic and circuit breaker.

    Features:
    - Exponential backoff with jitter
    - Circuit breaker to prevent hammering failing services
    - Configurable retry counts and timeouts
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        circuit_threshold: int = 5,
        circuit_reset_timeout: int = 60,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.circuit_threshold = circuit_threshold
        self.circuit_reset_timeout = circuit_reset_timeout
        self._circuits: Dict[str, CircuitState] = {}

    def _get_circuit(self, service: str) -> CircuitState:
        """Get or create circuit state for a service."""
        if service not in self._circuits:
            self._circuits[service] = CircuitState()
        return self._circuits[service]

    def _check_circuit(self, service: str) -> bool:
        """Check if circuit allows requests. Returns True if OK to proceed."""
        circuit = self._get_circuit(service)

        if circuit.state == "closed":
            return True

        if circuit.state == "open":
            # Check if we should try half-open
            if circuit.last_failure:
                elapsed = (datetime.utcnow() - circuit.last_failure).seconds
                if elapsed >= circuit.reset_timeout:
                    circuit.state = "half-open"
                    logger.info("circuit_half_open", service=service)
                    return True
            return False

        # half-open - allow one request through
        return True

    def _record_success(self, service: str):
        """Record successful request."""
        circuit = self._get_circuit(service)
        circuit.failures = 0
        circuit.state = "closed"

    def _record_failure(self, service: str):
        """Record failed request."""
        circuit = self._get_circuit(service)
        circuit.failures += 1
        circuit.last_failure = datetime.utcnow()

        if circuit.failures >= self.circuit_threshold:
            circuit.state = "open"
            logger.warning(
                "circuit_opened",
                service=service,
                failures=circuit.failures,
                reset_in=self.circuit_reset_timeout,
            )

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter."""
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        # Add jitter (±25%)
        jitter = delay * 0.25 * (random.random() * 2 - 1)
        return delay + jitter

    async def request(
        self,
        method: str,
        url: str,
        service: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Make HTTP request with retry and circuit breaker.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            service: Service name for circuit breaker
            **kwargs: Additional arguments for httpx

        Returns:
            Response or None if all retries failed
        """
        if not self._check_circuit(service):
            logger.warning("circuit_open_skipping", service=service, url=url)
            return None

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.request(method, url, **kwargs)

                    # Success
                    if response.status_code < 500:
                        self._record_success(service)
                        return response

                    # Server error - retry
                    last_error = f"HTTP {response.status_code}"

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
            except httpx.ConnectError as e:
                last_error = f"Connection error: {e}"
            except Exception as e:
                last_error = f"Error: {e}"

            # Log retry
            if attempt < self.max_retries:
                delay = self._calculate_delay(attempt)
                logger.warning(
                    "request_retry",
                    service=service,
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    delay=delay,
                    error=last_error,
                )
                await asyncio.sleep(delay)

        # All retries exhausted
        self._record_failure(service)
        logger.error(
            "request_failed",
            service=service,
            url=url,
            error=last_error,
        )
        return None

    async def post(self, url: str, service: str, **kwargs) -> Optional[httpx.Response]:
        """POST request with retry."""
        return await self.request("POST", url, service, **kwargs)

    async def get(self, url: str, service: str, **kwargs) -> Optional[httpx.Response]:
        """GET request with retry."""
        return await self.request("GET", url, service, **kwargs)


# Global resilient client
_http_client: Optional[ResilientHTTPClient] = None


def get_http_client() -> ResilientHTTPClient:
    """Get global resilient HTTP client."""
    global _http_client
    if _http_client is None:
        _http_client = ResilientHTTPClient()
    return _http_client


class IntegrationType(str, Enum):
    """Supported integration types."""
    SLACK = "slack"
    JIRA = "jira"
    GITHUB = "github"
    WEBHOOK = "webhook"


class NotificationEvent(str, Enum):
    """Events that trigger notifications."""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    CRITICAL_FINDING = "critical_finding"
    HIGH_FINDING = "high_finding"
    BREACH_ACHIEVED = "breach_achieved"
    SCHEDULE_TRIGGERED = "schedule_triggered"


@dataclass
class IntegrationConfig:
    """Configuration for an integration."""
    type: IntegrationType
    enabled: bool
    config: Dict[str, Any]
    events: List[NotificationEvent]


# ============== SLACK INTEGRATION ==============

class SlackIntegration:
    """
    Slack integration for real-time notifications.

    Sends rich messages with finding details, severity colors,
    and action buttons.
    """

    SEVERITY_COLORS = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",      # Orange
        "medium": "#ca8a04",    # Yellow
        "low": "#16a34a",       # Green
        "info": "#2563eb",      # Blue
    }

    def __init__(self, webhook_url: str, channel: str = None):
        self.webhook_url = webhook_url
        self.channel = channel

    async def send_scan_started(self, scan: Scan, target: Target) -> bool:
        """Notify when a scan starts."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 Security Scan Started",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target.url}"},
                    {"type": "mrkdwn", "text": f"*Mode:*\n{scan.mode.value}"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan.id}`"},
                    {"type": "mrkdwn", "text": f"*Started:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"},
                ]
            },
        ]

        return await self._send_message(blocks)

    async def send_scan_completed(
        self,
        scan: Scan,
        target: Target,
        findings_summary: Dict[str, int],
        dashboard_url: str = None
    ) -> bool:
        """Notify when a scan completes with summary."""
        critical = findings_summary.get("critical", 0)
        high = findings_summary.get("high", 0)
        medium = findings_summary.get("medium", 0)
        low = findings_summary.get("low", 0)
        total = critical + high + medium + low

        # Determine severity color
        if critical > 0:
            color = self.SEVERITY_COLORS["critical"]
            status_emoji = "🔴"
        elif high > 0:
            color = self.SEVERITY_COLORS["high"]
            status_emoji = "🟠"
        elif medium > 0:
            color = self.SEVERITY_COLORS["medium"]
            status_emoji = "🟡"
        else:
            color = self.SEVERITY_COLORS["low"]
            status_emoji = "🟢"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Security Scan Complete",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target.url}"},
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Findings Breakdown:*\n"
                            f"• 🔴 Critical: *{critical}*\n"
                            f"• 🟠 High: *{high}*\n"
                            f"• 🟡 Medium: *{medium}*\n"
                            f"• 🟢 Low: *{low}*"
                }
            },
        ]

        # Add action button if dashboard URL provided
        if dashboard_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Report"},
                        "url": dashboard_url,
                        "style": "primary"
                    }
                ]
            })

        return await self._send_message(blocks, color=color)

    async def send_critical_finding(
        self,
        finding: Finding,
        target: Target,
        dashboard_url: str = None
    ) -> bool:
        """Immediately notify about a critical finding."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 CRITICAL VULNERABILITY FOUND",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target.url}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n🔴 CRITICAL"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Finding:*\n{finding.title}\n\n"
                            f"*Description:*\n{finding.description[:500]}..."
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected:*\n`{finding.affected_endpoint or 'N/A'}`"
                }
            },
        ]

        if dashboard_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "url": dashboard_url,
                        "style": "danger"
                    }
                ]
            })

        return await self._send_message(blocks, color=self.SEVERITY_COLORS["critical"])

    async def send_breach_achieved(
        self,
        target: Target,
        access_level: str,
        systems_compromised: List[str],
        dashboard_url: str = None
    ) -> bool:
        """Notify when breach simulation achieves access."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "⚠️ BREACH SIMULATION - ACCESS ACHIEVED",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target.url}"},
                    {"type": "mrkdwn", "text": f"*Access Level:*\n`{access_level.upper()}`"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Systems Compromised:*\n" +
                            "\n".join([f"• {s}" for s in systems_compromised[:5]])
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "This was a controlled security assessment. Review findings immediately."
                    }
                ]
            }
        ]

        if dashboard_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Breach Report"},
                        "url": dashboard_url,
                        "style": "danger"
                    }
                ]
            })

        return await self._send_message(blocks, color=self.SEVERITY_COLORS["critical"])

    async def _send_message(self, blocks: List[dict], color: str = None) -> bool:
        """Send message to Slack webhook with retry logic."""
        payload = {"blocks": blocks}

        if self.channel:
            payload["channel"] = self.channel

        if color:
            # Wrap in attachment for color bar
            payload = {
                "attachments": [{
                    "color": color,
                    "blocks": blocks
                }]
            }

        client = get_http_client()
        response = await client.post(
            self.webhook_url,
            service="slack",
            json=payload,
            timeout=10,
        )

        if response is None:
            return False

        success = response.status_code == 200
        if not success:
            logger.error(
                "slack_send_failed",
                status=response.status_code,
                response=response.text[:200] if response.text else None,
            )
        return success


# ============== JIRA INTEGRATION ==============

class JiraIntegration:
    """
    Jira integration for automatic ticket creation.

    Creates issues for findings with proper severity mapping,
    labels, and remediation details.
    """

    SEVERITY_PRIORITY = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug"
    ):
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self._auth = (email, api_token)

    async def create_finding_issue(
        self,
        finding: Finding,
        target: Target,
        scan_id: UUID = None,
        additional_labels: List[str] = None
    ) -> Optional[str]:
        """
        Create a Jira issue for a security finding.

        Returns the issue key (e.g., "SEC-123") or None on failure.
        """
        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        priority = self.SEVERITY_PRIORITY.get(severity.lower(), "Medium")

        labels = [
            "security",
            "breach-ai",
            f"severity-{severity.lower()}",
            finding.category or "vulnerability",
        ]
        if additional_labels:
            labels.extend(additional_labels)

        # Build description with ADF (Atlassian Document Format)
        description = self._build_description(finding, target, scan_id)

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{severity.upper()}] {finding.title}",
                "description": description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": priority},
                "labels": labels,
            }
        }

        client = get_http_client()
        response = await client.post(
            f"{self.base_url}/rest/api/3/issue",
            service="jira",
            json=payload,
            auth=self._auth,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if response is None:
            return None

        if response.status_code == 201:
            data = response.json()
            issue_key = data.get("key")
            logger.info(
                "jira_issue_created",
                issue_key=issue_key,
                finding_id=str(finding.id)
            )
            return issue_key
        else:
            logger.error(
                "jira_create_failed",
                status=response.status_code,
                response=response.text[:200] if response.text else None,
            )
            return None

    async def create_scan_summary_issue(
        self,
        scan: Scan,
        target: Target,
        findings_summary: Dict[str, int],
        critical_findings: List[Finding] = None
    ) -> Optional[str]:
        """Create a summary issue for a completed scan."""
        total = sum(findings_summary.values())

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"Security Scan Complete: {target.url} - {total} findings",
                "description": {
                    "version": 1,
                    "type": "doc",
                    "content": [
                        {
                            "type": "heading",
                            "attrs": {"level": 2},
                            "content": [{"type": "text", "text": "Scan Summary"}]
                        },
                        {
                            "type": "table",
                            "attrs": {"layout": "default"},
                            "content": [
                                {
                                    "type": "tableRow",
                                    "content": [
                                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
                                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Count"}]}]},
                                    ]
                                },
                                *[
                                    {
                                        "type": "tableRow",
                                        "content": [
                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": sev.title()}]}]},
                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(count)}]}]},
                                        ]
                                    }
                                    for sev, count in findings_summary.items()
                                ]
                            ]
                        },
                    ]
                },
                "issuetype": {"name": "Task"},
                "labels": ["security", "breach-ai", "scan-summary"],
            }
        }

        client = get_http_client()
        response = await client.post(
            f"{self.base_url}/rest/api/3/issue",
            service="jira",
            json=payload,
            auth=self._auth,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if response is None:
            return None

        if response.status_code == 201:
            return response.json().get("key")
        return None

    def _build_description(
        self,
        finding: Finding,
        target: Target,
        scan_id: UUID = None
    ) -> dict:
        """Build ADF description for Jira."""
        return {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 2},
                    "content": [{"type": "text", "text": "Vulnerability Details"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.description or "No description available."}]
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Affected Component"}]
                },
                {
                    "type": "codeBlock",
                    "attrs": {"language": "text"},
                    "content": [{"type": "text", "text": finding.affected_endpoint or target.url}]
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Remediation"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.recommendation or "See security documentation."}]
                },
                {
                    "type": "panel",
                    "attrs": {"panelType": "info"},
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "Generated by "},
                                {"type": "text", "text": "BREACH.AI", "marks": [{"type": "strong"}]},
                                {"type": "text", "text": f" | Scan ID: {scan_id}" if scan_id else ""},
                            ]
                        }
                    ]
                }
            ]
        }


# ============== GITHUB INTEGRATION ==============

class GitHubIntegration:
    """
    GitHub integration for security issue creation.

    Creates issues in the repository with proper labels
    and security-focused formatting.
    """

    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }

    async def create_finding_issue(
        self,
        finding: Finding,
        target: Target,
        labels: List[str] = None
    ) -> Optional[int]:
        """
        Create a GitHub issue for a security finding.

        Returns the issue number or None on failure.
        """
        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

        issue_labels = [
            "security",
            "breach-ai",
            f"severity:{severity.lower()}",
        ]
        if labels:
            issue_labels.extend(labels)

        body = self._build_issue_body(finding, target)

        payload = {
            "title": f"[{severity.upper()}] {finding.title}",
            "body": body,
            "labels": issue_labels,
        }

        client = get_http_client()
        response = await client.post(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/issues",
            service="github",
            json=payload,
            headers=self._headers,
            timeout=30,
        )

        if response is None:
            return None

        if response.status_code == 201:
            data = response.json()
            issue_number = data.get("number")
            logger.info(
                "github_issue_created",
                issue_number=issue_number,
                finding_id=str(finding.id)
            )
            return issue_number
        else:
            logger.error(
                "github_create_failed",
                status=response.status_code,
                response=response.text[:200] if response.text else None,
            )
            return None

    async def create_security_advisory(
        self,
        finding: Finding,
        target: Target,
        cve_id: str = None
    ) -> Optional[str]:
        """Create a security advisory (for critical findings)."""
        # GitHub Security Advisories API
        # Only available for repositories with GitHub Advanced Security

        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

        payload = {
            "summary": finding.title,
            "description": finding.description,
            "severity": severity.lower(),
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "other", "name": target.url},
                    "vulnerable_version_range": "*",
                    "patched_versions": None,
                }
            ],
        }

        if cve_id:
            payload["cve_id"] = cve_id

        client = get_http_client()
        response = await client.post(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/security-advisories",
            service="github",
            json=payload,
            headers=self._headers,
            timeout=30,
        )

        if response is None:
            return None

        if response.status_code == 201:
            return response.json().get("ghsa_id")
        return None

    def _build_issue_body(self, finding: Finding, target: Target) -> str:
        """Build markdown body for GitHub issue."""
        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

        return f"""## Security Vulnerability Report

**Severity:** {severity.upper()}
**Target:** {target.url}
**Category:** {finding.category or 'N/A'}

### Description

{finding.description or 'No description available.'}

### Affected Component

```
{finding.affected_endpoint or target.url}
```

### Recommendation

{finding.recommendation or 'See security documentation for remediation guidance.'}

### Evidence

{f'```{finding.evidence}```' if finding.evidence else 'See scan report for detailed evidence.'}

---

<sub>Generated by BREACH.AI Security Scanner</sub>
"""


# ============== WEBHOOK INTEGRATION ==============

class WebhookIntegration:
    """
    Generic webhook integration for custom notifications.

    Sends JSON payloads to any HTTP endpoint.
    """

    def __init__(self, url: str, headers: Dict[str, str] = None, secret: str = None):
        self.url = url
        self.headers = headers or {}
        self.secret = secret

    async def send_event(
        self,
        event: NotificationEvent,
        data: Dict[str, Any]
    ) -> bool:
        """Send event to webhook endpoint."""
        payload = {
            "event": event.value,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }

        headers = {**self.headers, "Content-Type": "application/json"}

        # Add HMAC signature if secret configured
        if self.secret:
            import hmac
            import hashlib
            signature = hmac.new(
                self.secret.encode(),
                json.dumps(payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-Breach-Signature"] = f"sha256={signature}"

        client = get_http_client()
        response = await client.post(
            self.url,
            service=f"webhook_{self.url[:50]}",
            json=payload,
            headers=headers,
            timeout=30,
        )

        if response is None:
            return False

        return 200 <= response.status_code < 300


# ============== INTEGRATION MANAGER ==============

class IntegrationManager:
    """
    Manages all integrations for an organization.

    Handles configuration, event routing, and sending notifications.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self._integrations: Dict[str, Any] = {}

    async def load_integrations(self, organization_id: UUID):
        """Load integration configurations from database."""
        result = await self.db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        org = result.scalar_one_or_none()

        if not org or not org.settings:
            return

        integrations = org.settings.get("integrations", {})

        # Initialize Slack
        if slack_config := integrations.get("slack"):
            if slack_config.get("enabled") and slack_config.get("webhook_url"):
                self._integrations["slack"] = SlackIntegration(
                    webhook_url=slack_config["webhook_url"],
                    channel=slack_config.get("channel")
                )

        # Initialize Jira
        if jira_config := integrations.get("jira"):
            if jira_config.get("enabled"):
                self._integrations["jira"] = JiraIntegration(
                    base_url=jira_config["base_url"],
                    email=jira_config["email"],
                    api_token=jira_config["api_token"],
                    project_key=jira_config["project_key"],
                    issue_type=jira_config.get("issue_type", "Bug")
                )

        # Initialize GitHub
        if github_config := integrations.get("github"):
            if github_config.get("enabled"):
                self._integrations["github"] = GitHubIntegration(
                    token=github_config["token"],
                    owner=github_config["owner"],
                    repo=github_config["repo"]
                )

        # Initialize webhooks
        for webhook in integrations.get("webhooks", []):
            if webhook.get("enabled"):
                key = f"webhook_{webhook['name']}"
                self._integrations[key] = WebhookIntegration(
                    url=webhook["url"],
                    headers=webhook.get("headers"),
                    secret=webhook.get("secret")
                )

    async def notify_scan_started(self, scan: Scan, target: Target):
        """Notify all integrations about scan start."""
        if slack := self._integrations.get("slack"):
            await slack.send_scan_started(scan, target)

        # Send to webhooks
        for key, integration in self._integrations.items():
            if key.startswith("webhook_"):
                await integration.send_event(
                    NotificationEvent.SCAN_STARTED,
                    {"scan_id": str(scan.id), "target_url": target.url}
                )

    async def notify_scan_completed(
        self,
        scan: Scan,
        target: Target,
        findings_summary: Dict[str, int],
        dashboard_url: str = None
    ):
        """Notify all integrations about scan completion."""
        if slack := self._integrations.get("slack"):
            await slack.send_scan_completed(scan, target, findings_summary, dashboard_url)

        if jira := self._integrations.get("jira"):
            await jira.create_scan_summary_issue(scan, target, findings_summary)

        # Webhooks
        for key, integration in self._integrations.items():
            if key.startswith("webhook_"):
                await integration.send_event(
                    NotificationEvent.SCAN_COMPLETED,
                    {
                        "scan_id": str(scan.id),
                        "target_url": target.url,
                        "findings": findings_summary
                    }
                )

    async def notify_critical_finding(
        self,
        finding: Finding,
        target: Target,
        scan_id: UUID = None,
        dashboard_url: str = None
    ):
        """Immediately notify about critical findings."""
        tasks = []

        if slack := self._integrations.get("slack"):
            tasks.append(slack.send_critical_finding(finding, target, dashboard_url))

        if jira := self._integrations.get("jira"):
            tasks.append(jira.create_finding_issue(finding, target, scan_id))

        if github := self._integrations.get("github"):
            tasks.append(github.create_finding_issue(finding, target))

        # Webhooks
        for key, integration in self._integrations.items():
            if key.startswith("webhook_"):
                tasks.append(integration.send_event(
                    NotificationEvent.CRITICAL_FINDING,
                    {
                        "finding_id": str(finding.id),
                        "title": finding.title,
                        "severity": "critical",
                        "target_url": target.url
                    }
                ))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def notify_breach_achieved(
        self,
        target: Target,
        access_level: str,
        systems_compromised: List[str],
        dashboard_url: str = None
    ):
        """Notify about successful breach simulation."""
        if slack := self._integrations.get("slack"):
            await slack.send_breach_achieved(
                target, access_level, systems_compromised, dashboard_url
            )

        for key, integration in self._integrations.items():
            if key.startswith("webhook_"):
                await integration.send_event(
                    NotificationEvent.BREACH_ACHIEVED,
                    {
                        "target_url": target.url,
                        "access_level": access_level,
                        "systems_compromised": systems_compromised
                    }
                )
