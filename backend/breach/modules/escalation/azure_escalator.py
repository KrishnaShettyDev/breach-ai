"""
BREACH.AI v2 - Azure Escalator

Azure privilege escalation module exploiting Managed Identity, RBAC,
Key Vault, Storage accounts, and subscription access.
"""

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin

from backend.breach.modules.base import (
    EscalationModule,
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


# Azure IMDS (Instance Metadata Service) endpoints
AZURE_IMDS = {
    "base": "http://169.254.169.254",
    "metadata": "/metadata/instance?api-version=2021-02-01",
    "identity_token": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "identity_token_vault": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
    "identity_token_storage": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
    "identity_token_graph": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
}

# Azure privilege escalation paths
AZURE_PRIVESC_PATHS = [
    {
        "name": "managed_identity_arm",
        "description": "Managed Identity with Azure Resource Manager access",
        "requires": ["managed_identity"],
        "provides": "arm_access",
        "severity": "high",
    },
    {
        "name": "key_vault_access",
        "description": "Access to Key Vault secrets via Managed Identity",
        "requires": ["managed_identity", "vault_token"],
        "provides": "secrets",
        "severity": "critical",
    },
    {
        "name": "storage_account_keys",
        "description": "Extract storage account keys via ARM",
        "requires": ["arm_access", "storage_account"],
        "provides": "storage_full_access",
        "severity": "critical",
    },
    {
        "name": "subscription_contributor",
        "description": "Contributor role on subscription",
        "requires": ["arm_access"],
        "provides": "subscription_write",
        "severity": "critical",
    },
    {
        "name": "subscription_owner",
        "description": "Owner role on subscription",
        "requires": ["arm_access"],
        "provides": "subscription_admin",
        "severity": "critical",
    },
    {
        "name": "global_admin",
        "description": "Azure AD Global Administrator",
        "requires": ["graph_access"],
        "provides": "tenant_admin",
        "severity": "critical",
    },
    {
        "name": "automation_runbook",
        "description": "Execute code via Automation Runbook",
        "requires": ["arm_access", "automation_account"],
        "provides": "code_execution",
        "severity": "high",
    },
    {
        "name": "vm_run_command",
        "description": "Execute commands on VMs via Run Command",
        "requires": ["arm_access", "vm_contributor"],
        "provides": "vm_access",
        "severity": "high",
    },
    {
        "name": "function_app_deploy",
        "description": "Deploy code to Function App",
        "requires": ["arm_access", "function_contributor"],
        "provides": "code_execution",
        "severity": "high",
    },
    {
        "name": "aks_admin",
        "description": "AKS cluster admin credentials",
        "requires": ["arm_access", "aks_cluster"],
        "provides": "kubernetes_admin",
        "severity": "critical",
    },
]

# Azure RBAC roles for privilege escalation
AZURE_DANGEROUS_ROLES = {
    "Owner": {
        "scope": "full",
        "description": "Full access including RBAC management",
        "severity": "critical",
    },
    "Contributor": {
        "scope": "write",
        "description": "Create and manage resources, no RBAC",
        "severity": "high",
    },
    "User Access Administrator": {
        "scope": "rbac",
        "description": "Manage RBAC assignments",
        "severity": "critical",
    },
    "Virtual Machine Contributor": {
        "scope": "vm",
        "description": "Manage VMs - potential for Run Command",
        "severity": "high",
    },
    "Key Vault Administrator": {
        "scope": "vault",
        "description": "Full Key Vault access",
        "severity": "critical",
    },
    "Key Vault Secrets Officer": {
        "scope": "vault_secrets",
        "description": "Manage Key Vault secrets",
        "severity": "critical",
    },
    "Storage Account Contributor": {
        "scope": "storage",
        "description": "Manage storage accounts including keys",
        "severity": "high",
    },
    "Storage Blob Data Owner": {
        "scope": "storage_data",
        "description": "Full access to blob data",
        "severity": "high",
    },
    "Automation Contributor": {
        "scope": "automation",
        "description": "Manage automation - potential RCE",
        "severity": "high",
    },
    "Azure Kubernetes Service Cluster Admin Role": {
        "scope": "aks",
        "description": "Full AKS cluster access",
        "severity": "critical",
    },
}

# Azure ARM API endpoints
AZURE_ARM_ENDPOINTS = {
    "subscriptions": "/subscriptions?api-version=2020-01-01",
    "resource_groups": "/subscriptions/{sub}/resourcegroups?api-version=2021-04-01",
    "key_vaults": "/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview",
    "storage_accounts": "/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts?api-version=2021-06-01",
    "vms": "/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines?api-version=2021-07-01",
    "role_assignments": "/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2020-10-01",
    "aks_clusters": "/subscriptions/{sub}/providers/Microsoft.ContainerService/managedClusters?api-version=2021-07-01",
}


@register_module
class AzureEscalator(EscalationModule):
    """
    Azure Escalator - Azure privilege escalation.

    Techniques:
    - Managed Identity token theft from IMDS
    - Key Vault secret extraction
    - Storage account key retrieval
    - RBAC role enumeration and abuse
    - VM Run Command execution
    - Automation Runbook exploitation
    - AKS cluster admin credential theft
    - Cross-subscription access
    """

    info = ModuleInfo(
        name="azure_escalator",
        phase=BreachPhase.ESCALATION,
        description="Azure privilege escalation via Managed Identity, RBAC, Key Vault",
        author="BREACH.AI",
        techniques=["T1098", "T1078.004", "T1552.005"],  # Account Manip, Cloud Accounts, Cloud API
        platforms=["azure", "cloud"],
        requires_access=True,
        required_access_level=AccessLevel.CLOUD_USER,
        provides_access=True,
        max_access_level=AccessLevel.CLOUD_ADMIN,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have Azure access to escalate."""
        has_azure_creds = bool(
            config.chain_data.get("azure_token") or
            config.chain_data.get("azure_credentials") or
            config.chain_data.get("in_azure_vm")
        )
        return has_azure_creds

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute Azure privilege escalation."""
        self._start_execution()

        escalation_paths = []
        achieved_admin = False

        # Try IMDS token theft
        imds_result = await self._exploit_imds(config)
        if imds_result:
            escalation_paths.append(imds_result)

        # Enumerate current access
        current_access = await self._enumerate_access(config)

        # Check RBAC roles
        role_paths = await self._check_dangerous_roles(current_access, config)
        escalation_paths.extend(role_paths)

        # Try Key Vault access
        vault_paths = await self._exploit_key_vault(current_access, config)
        escalation_paths.extend(vault_paths)

        # Try storage account keys
        storage_paths = await self._exploit_storage_accounts(current_access, config)
        escalation_paths.extend(storage_paths)

        # Check for VM Run Command
        vm_paths = await self._check_vm_access(current_access, config)
        escalation_paths.extend(vm_paths)

        # Check for AKS access
        aks_paths = await self._check_aks_access(current_access, config)
        escalation_paths.extend(aks_paths)

        # Check cross-subscription access
        cross_sub_paths = await self._check_cross_subscription(current_access, config)
        escalation_paths.extend(cross_sub_paths)

        # Determine if admin achieved
        for path in escalation_paths:
            if path.get("provides") in ["subscription_admin", "tenant_admin"]:
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
                description=f"Azure Escalation: {path['name']}",
                content={
                    "path": path["name"],
                    "description": path.get("description", ""),
                    "provides": path.get("provides", ""),
                    "data": path.get("data", {}),
                },
                proves=f"Azure privilege escalation via {path['name']}",
                severity=severity,
            )

        return self._create_result(
            success=len(escalation_paths) > 0,
            action="azure_privilege_escalation",
            details=f"Found {len(escalation_paths)} Azure escalation paths, admin: {achieved_admin}",
            access_gained=access_gained,
            data_extracted={"escalation_paths": escalation_paths} if escalation_paths else None,
            enables_modules=["cloud_storage_raider", "secrets_extractor"] if access_gained else [],
        )

    async def _exploit_imds(self, config: ModuleConfig) -> Optional[dict]:
        """Try to get Managed Identity token from IMDS."""
        if not config.chain_data.get("in_azure_vm"):
            return None

        # In real implementation, would make HTTP request to IMDS
        # Here we check chain_data for token
        token = config.chain_data.get("azure_managed_identity_token")

        if token:
            return {
                "name": "managed_identity_arm",
                "description": "Obtained Managed Identity token from IMDS",
                "provides": "arm_access",
                "severity": "high",
                "data": {"token_type": "bearer", "resource": "management.azure.com"},
            }

        return None

    async def _enumerate_access(self, config: ModuleConfig) -> dict:
        """Enumerate current Azure access."""
        return {
            "subscriptions": config.chain_data.get("azure_subscriptions", []),
            "role_assignments": config.chain_data.get("azure_role_assignments", []),
            "key_vaults": config.chain_data.get("azure_key_vaults", []),
            "storage_accounts": config.chain_data.get("azure_storage_accounts", []),
            "vms": config.chain_data.get("azure_vms", []),
            "aks_clusters": config.chain_data.get("azure_aks_clusters", []),
        }

    async def _check_dangerous_roles(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for dangerous RBAC role assignments."""
        paths = []
        role_assignments = current_access.get("role_assignments", [])

        for assignment in role_assignments:
            role_name = assignment.get("role_name", "")
            if role_name in AZURE_DANGEROUS_ROLES:
                role_info = AZURE_DANGEROUS_ROLES[role_name]
                paths.append({
                    "name": f"rbac_{role_name.lower().replace(' ', '_')}",
                    "description": role_info["description"],
                    "provides": role_info["scope"],
                    "severity": role_info["severity"],
                    "data": {"scope": assignment.get("scope", "")},
                })

        return paths

    async def _exploit_key_vault(self, current_access: dict, config: ModuleConfig) -> list:
        """Try to access Key Vault secrets."""
        paths = []
        key_vaults = current_access.get("key_vaults", [])

        for vault in key_vaults:
            vault_name = vault.get("name", "")
            secrets = vault.get("secrets", [])

            if secrets:
                paths.append({
                    "name": "key_vault_access",
                    "description": f"Access to Key Vault: {vault_name}",
                    "provides": "secrets",
                    "severity": "critical",
                    "data": {
                        "vault_name": vault_name,
                        "secret_count": len(secrets),
                        "secrets": [s.get("name") for s in secrets[:10]],
                    },
                })

        return paths

    async def _exploit_storage_accounts(self, current_access: dict, config: ModuleConfig) -> list:
        """Try to get storage account keys."""
        paths = []
        storage_accounts = current_access.get("storage_accounts", [])

        for account in storage_accounts:
            account_name = account.get("name", "")
            has_keys = account.get("keys_accessible", False)

            if has_keys:
                paths.append({
                    "name": "storage_account_keys",
                    "description": f"Storage account keys for: {account_name}",
                    "provides": "storage_full_access",
                    "severity": "critical",
                    "data": {"account_name": account_name},
                })

        return paths

    async def _check_vm_access(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for VM Run Command access."""
        paths = []
        vms = current_access.get("vms", [])

        for vm in vms:
            vm_name = vm.get("name", "")
            can_run_command = vm.get("run_command_access", False)

            if can_run_command:
                paths.append({
                    "name": "vm_run_command",
                    "description": f"Run Command access on VM: {vm_name}",
                    "provides": "vm_access",
                    "severity": "high",
                    "data": {"vm_name": vm_name},
                })

        return paths

    async def _check_aks_access(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for AKS cluster admin access."""
        paths = []
        clusters = current_access.get("aks_clusters", [])

        for cluster in clusters:
            cluster_name = cluster.get("name", "")
            has_admin = cluster.get("admin_access", False)

            if has_admin:
                paths.append({
                    "name": "aks_admin",
                    "description": f"AKS admin access: {cluster_name}",
                    "provides": "kubernetes_admin",
                    "severity": "critical",
                    "data": {"cluster_name": cluster_name},
                })

        return paths

    async def _check_cross_subscription(self, current_access: dict, config: ModuleConfig) -> list:
        """Check for cross-subscription access."""
        paths = []
        subscriptions = current_access.get("subscriptions", [])

        if len(subscriptions) > 1:
            paths.append({
                "name": "cross_subscription_access",
                "description": f"Access to {len(subscriptions)} subscriptions",
                "provides": "multi_subscription",
                "severity": "high",
                "data": {"subscription_count": len(subscriptions)},
            })

        return paths
