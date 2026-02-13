"""
BREACH.AI v2 - GCP Escalator

GCP privilege escalation module exploiting service account impersonation,
IAM policies, metadata server, and cross-project access.
"""

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin

from breach.modules.base import (
    EscalationModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# GCP Metadata server endpoints
GCP_METADATA = {
    "base": "http://169.254.169.254",
    "base_alt": "http://metadata.google.internal",
    "project_id": "/computeMetadata/v1/project/project-id",
    "project_number": "/computeMetadata/v1/project/numeric-project-id",
    "zone": "/computeMetadata/v1/instance/zone",
    "hostname": "/computeMetadata/v1/instance/hostname",
    "service_accounts": "/computeMetadata/v1/instance/service-accounts/",
    "default_token": "/computeMetadata/v1/instance/service-accounts/default/token",
    "default_email": "/computeMetadata/v1/instance/service-accounts/default/email",
    "default_scopes": "/computeMetadata/v1/instance/service-accounts/default/scopes",
    "instance_attributes": "/computeMetadata/v1/instance/attributes/",
    "project_attributes": "/computeMetadata/v1/project/attributes/",
    "kube_env": "/computeMetadata/v1/instance/attributes/kube-env",
    "ssh_keys": "/computeMetadata/v1/project/attributes/ssh-keys",
}

# GCP privilege escalation paths
GCP_PRIVESC_PATHS = [
    {
        "name": "metadata_token_theft",
        "description": "Service account token from metadata server",
        "requires": ["gce_instance"],
        "provides": "service_account_token",
        "severity": "high",
    },
    {
        "name": "service_account_impersonation",
        "description": "Impersonate another service account",
        "requires": ["iam.serviceAccountTokenCreator"],
        "provides": "elevated_service_account",
        "severity": "critical",
    },
    {
        "name": "project_owner",
        "description": "Project Owner role",
        "requires": ["roles/owner"],
        "provides": "project_admin",
        "severity": "critical",
    },
    {
        "name": "project_editor",
        "description": "Project Editor role",
        "requires": ["roles/editor"],
        "provides": "project_write",
        "severity": "high",
    },
    {
        "name": "compute_admin",
        "description": "Compute Admin - can access VMs",
        "requires": ["compute.admin"],
        "provides": "compute_access",
        "severity": "high",
    },
    {
        "name": "storage_admin",
        "description": "Storage Admin - full bucket access",
        "requires": ["storage.admin"],
        "provides": "storage_full_access",
        "severity": "critical",
    },
    {
        "name": "secrets_manager",
        "description": "Secret Manager access",
        "requires": ["secretmanager.secretAccessor"],
        "provides": "secrets",
        "severity": "critical",
    },
    {
        "name": "cloudfunctions_deploy",
        "description": "Deploy Cloud Functions for RCE",
        "requires": ["cloudfunctions.admin"],
        "provides": "code_execution",
        "severity": "high",
    },
    {
        "name": "cloudrun_deploy",
        "description": "Deploy Cloud Run for RCE",
        "requires": ["run.admin"],
        "provides": "code_execution",
        "severity": "high",
    },
    {
        "name": "gke_admin",
        "description": "GKE cluster admin access",
        "requires": ["container.admin"],
        "provides": "kubernetes_admin",
        "severity": "critical",
    },
    {
        "name": "iam_policy_admin",
        "description": "Modify IAM policies",
        "requires": ["iam.securityAdmin"],
        "provides": "iam_admin",
        "severity": "critical",
    },
    {
        "name": "organization_admin",
        "description": "Organization administrator",
        "requires": ["resourcemanager.organizationAdmin"],
        "provides": "org_admin",
        "severity": "critical",
    },
]

# Dangerous GCP IAM roles
GCP_DANGEROUS_ROLES = {
    "roles/owner": {
        "description": "Full project access including IAM",
        "severity": "critical",
    },
    "roles/editor": {
        "description": "Edit all resources except IAM",
        "severity": "high",
    },
    "roles/iam.securityAdmin": {
        "description": "Manage IAM policies",
        "severity": "critical",
    },
    "roles/iam.serviceAccountAdmin": {
        "description": "Manage service accounts",
        "severity": "critical",
    },
    "roles/iam.serviceAccountTokenCreator": {
        "description": "Create service account tokens",
        "severity": "critical",
    },
    "roles/iam.serviceAccountUser": {
        "description": "Act as service account",
        "severity": "high",
    },
    "roles/compute.admin": {
        "description": "Full compute access",
        "severity": "high",
    },
    "roles/compute.instanceAdmin": {
        "description": "Manage compute instances",
        "severity": "high",
    },
    "roles/storage.admin": {
        "description": "Full storage access",
        "severity": "high",
    },
    "roles/storage.objectAdmin": {
        "description": "Full object access",
        "severity": "high",
    },
    "roles/secretmanager.admin": {
        "description": "Full Secret Manager access",
        "severity": "critical",
    },
    "roles/secretmanager.secretAccessor": {
        "description": "Access secrets",
        "severity": "high",
    },
    "roles/container.admin": {
        "description": "Full GKE access",
        "severity": "critical",
    },
    "roles/cloudfunctions.admin": {
        "description": "Deploy and manage functions",
        "severity": "high",
    },
    "roles/run.admin": {
        "description": "Deploy and manage Cloud Run",
        "severity": "high",
    },
    "roles/cloudsql.admin": {
        "description": "Full Cloud SQL access",
        "severity": "high",
    },
    "roles/bigquery.admin": {
        "description": "Full BigQuery access",
        "severity": "high",
    },
}

# GCP API endpoints
GCP_APIS = {
    "projects": "https://cloudresourcemanager.googleapis.com/v1/projects",
    "iam_policies": "https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy",
    "service_accounts": "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts",
    "storage_buckets": "https://storage.googleapis.com/storage/v1/b?project={project}",
    "compute_instances": "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances",
    "secrets": "https://secretmanager.googleapis.com/v1/projects/{project}/secrets",
    "gke_clusters": "https://container.googleapis.com/v1/projects/{project}/locations/-/clusters",
    "functions": "https://cloudfunctions.googleapis.com/v1/projects/{project}/locations/-/functions",
}


@register_module
class GCPEscalator(EscalationModule):
    """
    GCP Escalator - GCP privilege escalation.

    Techniques:
    - Metadata server token theft
    - Service account impersonation
    - IAM policy enumeration and abuse
    - Secret Manager access
    - Cloud Functions/Run deployment
    - GKE cluster access
    - Cross-project access
    - Organization-level escalation
    """

    info = ModuleInfo(
        name="gcp_escalator",
        phase=BreachPhase.ESCALATION,
        description="GCP privilege escalation via service accounts, IAM, metadata",
        author="BREACH.AI",
        techniques=["T1098", "T1078.004", "T1552.005"],  # Account Manip, Cloud Accounts, Cloud API
        platforms=["gcp", "cloud"],
        requires_access=True,
        required_access_level=AccessLevel.CLOUD_USER,
        provides_access=True,
        max_access_level=AccessLevel.CLOUD_ADMIN,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have GCP access to escalate."""
        has_gcp_creds = bool(
            config.chain_data.get("gcp_token") or
            config.chain_data.get("gcp_credentials") or
            config.chain_data.get("in_gce_instance") or
            config.chain_data.get("gcp_service_account_key")
        )
        return has_gcp_creds

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute GCP privilege escalation."""
        self._start_execution()

        escalation_paths = []
        achieved_admin = False

        # Try metadata server token theft
        metadata_result = await self._exploit_metadata_server(config)
        if metadata_result:
            escalation_paths.append(metadata_result)

        # Enumerate current access
        current_access = await self._enumerate_access(config)

        # Check IAM bindings
        iam_paths = await self._check_iam_bindings(current_access, config)
        escalation_paths.extend(iam_paths)

        # Check for service account impersonation
        impersonation_paths = await self._check_impersonation(current_access, config)
        escalation_paths.extend(impersonation_paths)

        # Try Secret Manager access
        secret_paths = await self._exploit_secrets(current_access, config)
        escalation_paths.extend(secret_paths)

        # Check for compute access
        compute_paths = await self._check_compute_access(current_access, config)
        escalation_paths.extend(compute_paths)

        # Check for GKE access
        gke_paths = await self._check_gke_access(current_access, config)
        escalation_paths.extend(gke_paths)

        # Check for Cloud Functions/Run deployment
        serverless_paths = await self._check_serverless_access(current_access, config)
        escalation_paths.extend(serverless_paths)

        # Check cross-project access
        cross_project_paths = await self._check_cross_project(current_access, config)
        escalation_paths.extend(cross_project_paths)

        # Determine if admin achieved
        for path in escalation_paths:
            if path.get("provides") in ["project_admin", "org_admin", "iam_admin"]:
                achieved_admin = True
                break

        # Determine access level
        access_gained = None
        if achieved_admin:
            access_gained = AccessLevel.CLOUD_ADMIN
        elif any(p.get("provides") in ["secrets", "storage_full_access"] for p in escalation_paths):
            access_gained = AccessLevel.DATABASE
        elif escalation_paths:
            access_gained = AccessLevel.CLOUD_USER

        # Add evidence
        for path in escalation_paths:
            severity = Severity.CRITICAL if path.get("severity") == "critical" else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"GCP Escalation: {path['name']}",
                content={
                    "path": path["name"],
                    "description": path.get("description", ""),
                    "provides": path.get("provides", ""),
                    "data": path.get("data", {}),
                },
                proves=f"GCP privilege escalation via {path['name']}",
                severity=severity,
            )

        return self._create_result(
            success=len(escalation_paths) > 0,
            action="gcp_privilege_escalation",
            details=f"Found {len(escalation_paths)} GCP escalation paths, admin: {achieved_admin}",
            access_gained=access_gained,
            data_extracted={"escalation_paths": escalation_paths} if escalation_paths else None,
            enables_modules=["cloud_storage_raider", "secrets_extractor"] if access_gained else [],
        )

    async def _exploit_metadata_server(self, config: ModuleConfig) -> Optional[dict]:
        """Try to get service account token from metadata server."""
        if not config.chain_data.get("in_gce_instance"):
            return None

        # In real implementation, would make HTTP request to metadata server
        # with header: Metadata-Flavor: Google
        token = config.chain_data.get("gcp_metadata_token")
        service_account = config.chain_data.get("gcp_service_account_email")

        if token:
            return {
                "name": "metadata_token_theft",
                "description": f"Obtained token for: {service_account or 'default'}",
                "provides": "service_account_token",
                "severity": "high",
                "data": {
                    "service_account": service_account,
                    "scopes": config.chain_data.get("gcp_token_scopes", []),
                },
            }

        return None

    async def _enumerate_access(self, config: ModuleConfig) -> dict:
        """Enumerate current GCP access."""
        return {
            "projects": config.chain_data.get("gcp_projects", []),
            "iam_bindings": config.chain_data.get("gcp_iam_bindings", []),
            "service_accounts": config.chain_data.get("gcp_service_accounts", []),
            "buckets": config.chain_data.get("gcp_buckets", []),
            "instances": config.chain_data.get("gcp_instances", []),
            "secrets": config.chain_data.get("gcp_secrets", []),
            "gke_clusters": config.chain_data.get("gcp_gke_clusters", []),
            "functions": config.chain_data.get("gcp_functions", []),
        }

    async def _check_iam_bindings(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for dangerous IAM role bindings."""
        paths = []
        iam_bindings = current_access.get("iam_bindings", [])

        for binding in iam_bindings:
            role = binding.get("role", "")
            if role in GCP_DANGEROUS_ROLES:
                role_info = GCP_DANGEROUS_ROLES[role]
                paths.append({
                    "name": f"iam_{role.split('/')[-1].lower()}",
                    "description": role_info["description"],
                    "provides": self._map_role_to_provides(role),
                    "severity": role_info["severity"],
                    "data": {"role": role, "resource": binding.get("resource", "")},
                })

        return paths

    async def _check_impersonation(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for service account impersonation capability."""
        paths = []
        service_accounts = current_access.get("service_accounts", [])
        iam_bindings = current_access.get("iam_bindings", [])

        # Check if we have token creator role
        has_token_creator = any(
            "serviceAccountTokenCreator" in b.get("role", "")
            for b in iam_bindings
        )

        if has_token_creator and service_accounts:
            for sa in service_accounts:
                paths.append({
                    "name": "service_account_impersonation",
                    "description": f"Can impersonate: {sa.get('email', '')}",
                    "provides": "elevated_service_account",
                    "severity": "critical",
                    "data": {"target_sa": sa.get("email", "")},
                })

        return paths

    async def _exploit_secrets(self, current_access: dict, config: ModuleConfig) -> list:
        """Try to access Secret Manager secrets."""
        paths = []
        secrets = current_access.get("secrets", [])

        if secrets:
            paths.append({
                "name": "secrets_manager",
                "description": f"Access to {len(secrets)} secrets",
                "provides": "secrets",
                "severity": "critical",
                "data": {
                    "secret_count": len(secrets),
                    "secrets": [s.get("name") for s in secrets[:10]],
                },
            })

        return paths

    async def _check_compute_access(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for compute instance access."""
        paths = []
        instances = current_access.get("instances", [])
        iam_bindings = current_access.get("iam_bindings", [])

        has_compute_admin = any(
            "compute.admin" in b.get("role", "") or
            "compute.instanceAdmin" in b.get("role", "")
            for b in iam_bindings
        )

        if has_compute_admin and instances:
            paths.append({
                "name": "compute_admin",
                "description": f"Compute admin access to {len(instances)} instances",
                "provides": "compute_access",
                "severity": "high",
                "data": {"instance_count": len(instances)},
            })

        return paths

    async def _check_gke_access(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for GKE cluster access."""
        paths = []
        clusters = current_access.get("gke_clusters", [])

        for cluster in clusters:
            cluster_name = cluster.get("name", "")
            has_admin = cluster.get("admin_access", False)

            if has_admin:
                paths.append({
                    "name": "gke_admin",
                    "description": f"GKE admin access: {cluster_name}",
                    "provides": "kubernetes_admin",
                    "severity": "critical",
                    "data": {"cluster_name": cluster_name},
                })

        return paths

    async def _check_serverless_access(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for Cloud Functions/Run deployment access."""
        paths = []
        iam_bindings = current_access.get("iam_bindings", [])

        has_functions_admin = any(
            "cloudfunctions.admin" in b.get("role", "")
            for b in iam_bindings
        )

        has_run_admin = any(
            "run.admin" in b.get("role", "")
            for b in iam_bindings
        )

        if has_functions_admin:
            paths.append({
                "name": "cloudfunctions_deploy",
                "description": "Can deploy Cloud Functions for code execution",
                "provides": "code_execution",
                "severity": "high",
                "data": {"service": "cloud_functions"},
            })

        if has_run_admin:
            paths.append({
                "name": "cloudrun_deploy",
                "description": "Can deploy Cloud Run for code execution",
                "provides": "code_execution",
                "severity": "high",
                "data": {"service": "cloud_run"},
            })

        return paths

    async def _check_cross_project(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for cross-project access."""
        paths = []
        projects = current_access.get("projects", [])

        if len(projects) > 1:
            paths.append({
                "name": "cross_project_access",
                "description": f"Access to {len(projects)} projects",
                "provides": "multi_project",
                "severity": "high",
                "data": {
                    "project_count": len(projects),
                    "projects": [p.get("projectId") for p in projects],
                },
            })

        return paths

    def _map_role_to_provides(self, role: str) -> str:
        """Map IAM role to capability."""
        mapping = {
            "roles/owner": "project_admin",
            "roles/editor": "project_write",
            "roles/iam.securityAdmin": "iam_admin",
            "roles/storage.admin": "storage_full_access",
            "roles/secretmanager.admin": "secrets",
            "roles/container.admin": "kubernetes_admin",
        }
        return mapping.get(role, "elevated_access")
