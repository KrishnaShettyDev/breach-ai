"""
BREACH.AI v2 - Cloud Hopper

Cross-account and cross-project lateral movement in cloud environments.
Exploits trust relationships, shared credentials, and IAM misconfigurations.
"""

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin

from backend.breach.modules.base import (
    LateralModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# AWS cross-account techniques
AWS_LATERAL = {
    "assume_role": {
        "description": "Assume role in another account via trust policy",
        "requires": ["sts:AssumeRole"],
        "severity": "critical",
    },
    "cross_account_s3": {
        "description": "Access S3 buckets in other accounts",
        "requires": ["s3:GetObject"],
        "severity": "high",
    },
    "shared_ami": {
        "description": "Launch EC2 from shared AMI",
        "requires": ["ec2:RunInstances"],
        "severity": "medium",
    },
    "resource_share": {
        "description": "Access via AWS Resource Access Manager",
        "requires": ["ram:GetResourceShares"],
        "severity": "high",
    },
    "organization_trail": {
        "description": "Access organization-wide CloudTrail",
        "requires": ["cloudtrail:LookupEvents"],
        "severity": "medium",
    },
    "shared_vpc": {
        "description": "Access shared VPC resources",
        "requires": ["ec2:DescribeVpcs"],
        "severity": "medium",
    },
}

# Azure cross-tenant techniques
AZURE_LATERAL = {
    "cross_tenant_access": {
        "description": "Access resources in trusted tenant",
        "requires": ["cross_tenant_trust"],
        "severity": "critical",
    },
    "b2b_guest": {
        "description": "B2B guest access to another tenant",
        "requires": ["guest_invitation"],
        "severity": "high",
    },
    "shared_subscription": {
        "description": "Access shared subscription resources",
        "requires": ["subscription_access"],
        "severity": "high",
    },
    "management_group": {
        "description": "Access via management group hierarchy",
        "requires": ["management_group_reader"],
        "severity": "medium",
    },
    "lighthouse": {
        "description": "Azure Lighthouse delegated access",
        "requires": ["lighthouse_assignment"],
        "severity": "high",
    },
}

# GCP cross-project techniques
GCP_LATERAL = {
    "cross_project_iam": {
        "description": "IAM binding to another project",
        "requires": ["cross_project_role"],
        "severity": "critical",
    },
    "shared_vpc": {
        "description": "Access shared VPC host project",
        "requires": ["shared_vpc_access"],
        "severity": "high",
    },
    "organization_iam": {
        "description": "Organization-level IAM access",
        "requires": ["org_role"],
        "severity": "critical",
    },
    "folder_access": {
        "description": "Access via folder hierarchy",
        "requires": ["folder_role"],
        "severity": "high",
    },
    "service_account_cross_project": {
        "description": "Impersonate SA in another project",
        "requires": ["serviceAccountTokenCreator"],
        "severity": "critical",
    },
}

# Trust relationship patterns to look for
TRUST_PATTERNS = {
    "aws": {
        "external_account": r'"Principal":\s*{\s*"AWS":\s*"arn:aws:iam::(\d{12}):',
        "external_role": r'"arn:aws:iam::(\d{12}):role/([^"]+)"',
        "organization": r'"aws:PrincipalOrgID":\s*"(o-[a-z0-9]+)"',
        "federated": r'"Principal":\s*{\s*"Federated":\s*"([^"]+)"',
    },
    "azure": {
        "tenant_trust": r'"allowedTenants":\s*\[([^\]]+)\]',
        "app_registration": r'"appId":\s*"([a-f0-9-]{36})"',
        "service_principal": r'"servicePrincipalId":\s*"([a-f0-9-]{36})"',
    },
    "gcp": {
        "cross_project_sa": r'serviceAccount:([^@]+)@([^.]+)\.iam\.gserviceaccount\.com',
        "domain_wide": r'user:([^@]+)@([^"]+)',
        "group_binding": r'group:([^@]+)@([^"]+)',
    },
}


@register_module
class CloudHopper(LateralModule):
    """
    Cloud Hopper - Cross-account/cross-project lateral movement.

    Techniques:
    - AWS cross-account role assumption
    - Azure cross-tenant access
    - GCP cross-project impersonation
    - Shared resource exploitation
    - Trust relationship abuse
    - Organization hierarchy traversal
    """

    info = ModuleInfo(
        name="cloud_hopper",
        phase=BreachPhase.LATERAL,
        description="Cross-account lateral movement in cloud environments",
        author="BREACH.AI",
        techniques=["T1078.004", "T1098", "T1550.001"],  # Cloud Accounts, Account Manip, Token Abuse
        platforms=["aws", "azure", "gcp", "cloud"],
        requires_access=True,
        required_access_level=AccessLevel.CLOUD_USER,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have cloud credentials for lateral movement."""
        has_aws = bool(config.chain_data.get("aws_credentials"))
        has_azure = bool(config.chain_data.get("azure_credentials"))
        has_gcp = bool(config.chain_data.get("gcp_credentials"))

        return has_aws or has_azure or has_gcp

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute cross-account lateral movement."""
        self._start_execution()

        lateral_paths = []
        accounts_accessed = []

        # Detect cloud provider
        cloud_provider = self._detect_cloud_provider(config)

        # AWS lateral movement
        if cloud_provider == "aws" or config.chain_data.get("aws_credentials"):
            aws_paths = await self._aws_lateral_movement(config)
            lateral_paths.extend(aws_paths)

        # Azure lateral movement
        if cloud_provider == "azure" or config.chain_data.get("azure_credentials"):
            azure_paths = await self._azure_lateral_movement(config)
            lateral_paths.extend(azure_paths)

        # GCP lateral movement
        if cloud_provider == "gcp" or config.chain_data.get("gcp_credentials"):
            gcp_paths = await self._gcp_lateral_movement(config)
            lateral_paths.extend(gcp_paths)

        # Extract accessed accounts from paths
        for path in lateral_paths:
            if path.get("target_account"):
                if path["target_account"] not in accounts_accessed:
                    accounts_accessed.append(path["target_account"])

        # Add evidence
        for path in lateral_paths:
            severity = Severity.CRITICAL if path.get("severity") == "critical" else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Cloud Lateral: {path['type']} to {path.get('target_account', 'unknown')}",
                content={
                    "type": path["type"],
                    "target_account": path.get("target_account"),
                    "method": path.get("method", ""),
                    "access_gained": path.get("access_gained", ""),
                },
                proves=f"Cross-account access via {path['type']}",
                severity=severity,
            )

        if accounts_accessed:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Accessed {len(accounts_accessed)} external accounts",
                content={"accounts": accounts_accessed},
                proves="Multi-account compromise achieved",
                severity=Severity.CRITICAL,
            )

        return self._create_result(
            success=len(lateral_paths) > 0,
            action="cloud_lateral_movement",
            details=f"Found {len(lateral_paths)} lateral paths to {len(accounts_accessed)} accounts",
            data_extracted={
                "lateral_paths": lateral_paths,
                "accounts_accessed": accounts_accessed,
            } if lateral_paths else None,
            enables_modules=["cloud_storage_raider", "secrets_extractor", "aws_escalator", "azure_escalator", "gcp_escalator"],
        )

    def _detect_cloud_provider(self, config: ModuleConfig) -> Optional[str]:
        """Detect primary cloud provider from context."""
        if config.chain_data.get("in_aws") or config.chain_data.get("aws_credentials"):
            return "aws"
        if config.chain_data.get("in_azure") or config.chain_data.get("azure_credentials"):
            return "azure"
        if config.chain_data.get("in_gcp") or config.chain_data.get("gcp_credentials"):
            return "gcp"
        return None

    async def _aws_lateral_movement(self, config: ModuleConfig) -> list:
        """AWS cross-account lateral movement."""
        paths = []

        # Get current account info
        current_account = config.chain_data.get("aws_account_id", "")
        iam_policies = config.chain_data.get("aws_iam_policies", [])
        trust_policies = config.chain_data.get("aws_trust_policies", [])
        roles = config.chain_data.get("aws_roles", [])

        # Check for cross-account role assumption
        for role in roles:
            role_arn = role.get("arn", "")
            trust_policy = role.get("trust_policy", {})

            # Look for external principals
            trust_str = json.dumps(trust_policy)
            external_accounts = re.findall(
                TRUST_PATTERNS["aws"]["external_account"],
                trust_str
            )

            for ext_account in external_accounts:
                if ext_account != current_account:
                    paths.append({
                        "type": "assume_role",
                        "provider": "aws",
                        "method": AWS_LATERAL["assume_role"]["description"],
                        "target_account": ext_account,
                        "target_role": role_arn,
                        "severity": "critical",
                        "access_gained": "role_access",
                    })

        # Check for S3 cross-account access
        s3_buckets = config.chain_data.get("accessible_s3_buckets", [])
        for bucket in s3_buckets:
            bucket_account = bucket.get("owner_account", "")
            if bucket_account and bucket_account != current_account:
                paths.append({
                    "type": "cross_account_s3",
                    "provider": "aws",
                    "method": AWS_LATERAL["cross_account_s3"]["description"],
                    "target_account": bucket_account,
                    "target_resource": bucket.get("name"),
                    "severity": "high",
                    "access_gained": "data_access",
                })

        # Check for organization access
        org_info = config.chain_data.get("aws_organization")
        if org_info:
            member_accounts = org_info.get("member_accounts", [])
            for account in member_accounts:
                if account != current_account:
                    paths.append({
                        "type": "organization_member",
                        "provider": "aws",
                        "method": "AWS Organization member account access",
                        "target_account": account,
                        "severity": "high",
                        "access_gained": "enumeration",
                    })

        return paths

    async def _azure_lateral_movement(self, config: ModuleConfig) -> list:
        """Azure cross-tenant/subscription lateral movement."""
        paths = []

        # Get current tenant info
        current_tenant = config.chain_data.get("azure_tenant_id", "")
        current_sub = config.chain_data.get("azure_subscription_id", "")

        # Check for cross-tenant access
        trusted_tenants = config.chain_data.get("azure_trusted_tenants", [])
        for tenant in trusted_tenants:
            if tenant != current_tenant:
                paths.append({
                    "type": "cross_tenant_access",
                    "provider": "azure",
                    "method": AZURE_LATERAL["cross_tenant_access"]["description"],
                    "target_account": tenant,
                    "severity": "critical",
                    "access_gained": "tenant_access",
                })

        # Check for B2B guest access
        guest_tenants = config.chain_data.get("azure_guest_tenants", [])
        for tenant in guest_tenants:
            paths.append({
                "type": "b2b_guest",
                "provider": "azure",
                "method": AZURE_LATERAL["b2b_guest"]["description"],
                "target_account": tenant,
                "severity": "high",
                "access_gained": "guest_access",
            })

        # Check for Lighthouse access
        lighthouse_assignments = config.chain_data.get("azure_lighthouse", [])
        for assignment in lighthouse_assignments:
            paths.append({
                "type": "lighthouse",
                "provider": "azure",
                "method": AZURE_LATERAL["lighthouse"]["description"],
                "target_account": assignment.get("customer_tenant"),
                "severity": "high",
                "access_gained": "delegated_access",
            })

        # Check for multi-subscription access
        subscriptions = config.chain_data.get("azure_subscriptions", [])
        for sub in subscriptions:
            if sub.get("id") != current_sub:
                paths.append({
                    "type": "shared_subscription",
                    "provider": "azure",
                    "method": AZURE_LATERAL["shared_subscription"]["description"],
                    "target_account": sub.get("id"),
                    "severity": "high",
                    "access_gained": "subscription_access",
                })

        return paths

    async def _gcp_lateral_movement(self, config: ModuleConfig) -> list:
        """GCP cross-project lateral movement."""
        paths = []

        # Get current project info
        current_project = config.chain_data.get("gcp_project_id", "")

        # Check for cross-project IAM bindings
        iam_bindings = config.chain_data.get("gcp_iam_bindings", [])
        for binding in iam_bindings:
            # Look for service accounts from other projects
            members = binding.get("members", [])
            for member in members:
                match = re.match(TRUST_PATTERNS["gcp"]["cross_project_sa"], member)
                if match:
                    sa_project = match.group(2)
                    if sa_project != current_project:
                        paths.append({
                            "type": "cross_project_iam",
                            "provider": "gcp",
                            "method": GCP_LATERAL["cross_project_iam"]["description"],
                            "target_account": sa_project,
                            "severity": "critical",
                            "access_gained": "project_access",
                        })

        # Check for shared VPC
        shared_vpc = config.chain_data.get("gcp_shared_vpc")
        if shared_vpc:
            host_project = shared_vpc.get("host_project")
            if host_project and host_project != current_project:
                paths.append({
                    "type": "shared_vpc",
                    "provider": "gcp",
                    "method": GCP_LATERAL["shared_vpc"]["description"],
                    "target_account": host_project,
                    "severity": "high",
                    "access_gained": "network_access",
                })

        # Check for organization access
        org_info = config.chain_data.get("gcp_organization")
        if org_info:
            projects = org_info.get("projects", [])
            for project in projects:
                if project != current_project:
                    paths.append({
                        "type": "organization_project",
                        "provider": "gcp",
                        "method": GCP_LATERAL["organization_iam"]["description"],
                        "target_account": project,
                        "severity": "high",
                        "access_gained": "enumeration",
                    })

        # Check for service account impersonation across projects
        impersonatable_sas = config.chain_data.get("gcp_impersonatable_service_accounts", [])
        for sa in impersonatable_sas:
            sa_email = sa.get("email", "")
            match = re.search(r'@([^.]+)\.iam\.gserviceaccount\.com', sa_email)
            if match:
                sa_project = match.group(1)
                if sa_project != current_project:
                    paths.append({
                        "type": "service_account_cross_project",
                        "provider": "gcp",
                        "method": GCP_LATERAL["service_account_cross_project"]["description"],
                        "target_account": sa_project,
                        "target_sa": sa_email,
                        "severity": "critical",
                        "access_gained": "impersonation",
                    })

        return paths
