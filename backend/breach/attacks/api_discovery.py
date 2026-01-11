"""
BREACH.AI - API Discovery Module

Comprehensive API reconnaissance and discovery.
Find every endpoint, every parameter, every weakness.

Discovery Categories:
1. Endpoint Enumeration - Find all API endpoints
2. Schema Extraction - OpenAPI, GraphQL introspection
3. Version Detection - Find old/deprecated versions
4. Parameter Discovery - Hidden params, debug modes
5. Authentication Mapping - How the API authenticates
6. Rate Limit Probing - Find the limits
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import Severity
from backend.breach.utils.logger import logger


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    path: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    auth_required: bool = False
    rate_limited: bool = False
    content_type: str = "application/json"
    response_schema: Optional[dict] = None


@dataclass
class APISchema:
    """Extracted API schema."""
    type: str  # openapi, graphql, swagger, raml
    version: str = ""
    endpoints: list[APIEndpoint] = field(default_factory=list)
    auth_schemes: list[str] = field(default_factory=list)
    raw_schema: Optional[str] = None


@dataclass
class APIDiscoveryResult:
    """Result of API discovery."""
    base_url: str
    api_type: str  # rest, graphql, soap, grpc
    versions_found: list[str] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    schemas: list[APISchema] = field(default_factory=list)
    auth_methods: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


class APIDiscovery(BaseAttack):
    """
    API DISCOVERY - Comprehensive API reconnaissance.

    Maps the entire API attack surface:
    - Every endpoint
    - Every parameter
    - Every authentication method
    - Every version (including deprecated)
    """

    name = "API Discovery"
    attack_type = "api_discovery"
    description = "Comprehensive API endpoint discovery and mapping"
    severity = Severity.INFO
    owasp_category = "API Security"
    cwe_id = 200

    # Common API paths to probe
    API_PATHS = [
        # Version prefixes
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/v1", "/rest/v2",

        # Common endpoints
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/docs", "/redoc",

        # Health/Status
        "/health", "/healthz", "/ready", "/status",
        "/api/health", "/api/status",

        # Debug/Admin
        "/debug", "/admin", "/internal",
        "/api/debug", "/api/admin",
        "/_debug", "/_admin", "/_internal",

        # Common resources
        "/users", "/api/users",
        "/accounts", "/api/accounts",
        "/auth", "/api/auth",
        "/login", "/api/login",
        "/config", "/api/config",
        "/settings", "/api/settings",
    ]

    # Schema discovery paths
    SCHEMA_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api/swagger.json",
        "/api/openapi.json",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/v3/swagger.json",
        "/docs/swagger.json",
        "/.well-known/openapi.json",
    ]

    # GraphQL paths
    GRAPHQL_PATHS = [
        "/graphql",
        "/graphiql",
        "/playground",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
    ]

    # Version patterns
    VERSION_PATTERNS = [
        r'/v(\d+)/',
        r'/api/v(\d+)/',
        r'/version/(\d+)/',
        r'api-version=(\d+)',
        r'version=(\d+)',
    ]

    # Hidden parameter names to probe
    HIDDEN_PARAMS = [
        "debug", "_debug", "test", "_test",
        "admin", "_admin", "internal", "_internal",
        "verbose", "_verbose", "trace", "_trace",
        "dev", "_dev", "staging", "_staging",
        "callback", "jsonp", "format",
        "fields", "include", "expand", "embed",
        "page", "limit", "offset", "cursor",
        "sort", "order", "filter", "q", "query",
        "token", "key", "api_key", "apikey",
        "id", "user_id", "account_id",
    ]

    def get_payloads(self) -> list[str]:
        return self.API_PATHS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if target has APIs."""
        response = await self.http_client.get(url)

        api_indicators = [
            "api", "json", "graphql", "swagger",
            "rest", "endpoint", "oauth", "bearer",
        ]

        body_lower = response.body.lower()
        content_type = response.headers.get("Content-Type", "").lower()

        return (
            any(ind in body_lower for ind in api_indicators) or
            "application/json" in content_type or
            "graphql" in content_type
        )

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Discover and map the API."""
        result = self._create_result(False, url, parameter)

        discovery = APIDiscoveryResult(base_url=url, api_type="unknown")

        logger.info("[API] Starting comprehensive API discovery...")

        # Phase 1: Probe common paths
        endpoints = await self._probe_endpoints(url)
        discovery.endpoints.extend(endpoints)
        logger.info(f"[API] Found {len(endpoints)} endpoints")

        # Phase 2: Schema discovery
        schemas = await self._discover_schemas(url)
        discovery.schemas.extend(schemas)

        for schema in schemas:
            discovery.endpoints.extend(schema.endpoints)
            discovery.auth_methods.extend(schema.auth_schemes)

        # Phase 3: GraphQL detection
        graphql = await self._detect_graphql(url)
        if graphql:
            discovery.api_type = "graphql"
            discovery.endpoints.extend(graphql.get("endpoints", []))
            if graphql.get("introspection"):
                discovery.vulnerabilities.append("GraphQL introspection enabled")

        # Phase 4: Version enumeration
        versions = await self._enumerate_versions(url)
        discovery.versions_found.extend(versions)
        if len(versions) > 1:
            discovery.vulnerabilities.append(f"Multiple API versions exposed: {versions}")

        # Phase 5: Technology fingerprinting
        techs = await self._fingerprint_technologies(url)
        discovery.technologies.extend(techs)

        # Phase 6: Authentication mapping
        auth = await self._map_authentication(url, discovery.endpoints)
        discovery.auth_methods.extend(auth)

        # Phase 7: Hidden parameter discovery
        hidden = await self._discover_hidden_params(url, discovery.endpoints[:5])
        for endpoint in hidden:
            discovery.endpoints.append(endpoint)

        # Build result
        if discovery.endpoints or discovery.schemas:
            result.success = True
            result.details = (
                f"API mapped: {len(discovery.endpoints)} endpoints, "
                f"{len(discovery.schemas)} schemas, "
                f"{len(discovery.versions_found)} versions"
            )

            if discovery.vulnerabilities:
                result.severity = Severity.MEDIUM
                result.details += f". Vulnerabilities: {discovery.vulnerabilities}"

            result.add_evidence(
                "api_discovery",
                "API structure discovered",
                json.dumps({
                    "endpoints": [e.path for e in discovery.endpoints[:20]],
                    "schemas": [s.type for s in discovery.schemas],
                    "versions": discovery.versions_found,
                    "auth": list(set(discovery.auth_methods)),
                    "vulnerabilities": discovery.vulnerabilities,
                }, indent=2)
            )

            result.data_sample = json.dumps({
                "api_type": discovery.api_type,
                "endpoints": len(discovery.endpoints),
                "versions": discovery.versions_found,
            })

        return result

    async def _probe_endpoints(self, url: str) -> list[APIEndpoint]:
        """Probe common API paths."""
        endpoints = []
        tasks = []

        for path in self.API_PATHS:
            tasks.append(self._probe_single_endpoint(url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, APIEndpoint):
                endpoints.append(result)

        return endpoints

    async def _probe_single_endpoint(self, base_url: str, path: str) -> Optional[APIEndpoint]:
        """Probe a single endpoint."""
        try:
            full_url = urljoin(base_url, path)
            response = await self.http_client.get(full_url)

            if response.status_code in [200, 201, 401, 403]:
                endpoint = APIEndpoint(
                    path=path,
                    method="GET",
                    auth_required=response.status_code in [401, 403],
                    content_type=response.headers.get("Content-Type", ""),
                )

                # Try to detect parameters from response
                if response.status_code == 200:
                    try:
                        data = json.loads(response.body)
                        if isinstance(data, dict):
                            endpoint.response_schema = {"keys": list(data.keys())[:10]}
                    except json.JSONDecodeError:
                        pass

                return endpoint

        except Exception:
            pass

        return None

    async def _discover_schemas(self, url: str) -> list[APISchema]:
        """Discover API schemas (OpenAPI, Swagger, etc.)."""
        schemas = []

        for path in self.SCHEMA_PATHS:
            try:
                full_url = urljoin(url, path)
                response = await self.http_client.get(full_url)

                if response.status_code == 200:
                    schema = self._parse_schema(response.body, path)
                    if schema:
                        schemas.append(schema)
                        logger.info(f"[API] Found schema at {path}")

            except Exception:
                continue

        return schemas

    def _parse_schema(self, content: str, path: str) -> Optional[APISchema]:
        """Parse API schema document."""
        try:
            # Try JSON
            data = json.loads(content)

            # OpenAPI 3.x
            if "openapi" in data:
                schema = APISchema(
                    type="openapi",
                    version=data.get("openapi", ""),
                    raw_schema=content[:5000],
                )

                # Extract endpoints
                for path_str, methods in data.get("paths", {}).items():
                    for method, details in methods.items():
                        if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            params = []
                            for param in details.get("parameters", []):
                                params.append(param.get("name", ""))

                            schema.endpoints.append(APIEndpoint(
                                path=path_str,
                                method=method.upper(),
                                parameters=params,
                            ))

                # Extract auth schemes
                if "securityDefinitions" in data or "components" in data:
                    security = data.get("components", {}).get("securitySchemes", {})
                    security.update(data.get("securityDefinitions", {}))
                    schema.auth_schemes = list(security.keys())

                return schema

            # Swagger 2.x
            if "swagger" in data:
                schema = APISchema(
                    type="swagger",
                    version=data.get("swagger", ""),
                    raw_schema=content[:5000],
                )

                for path_str, methods in data.get("paths", {}).items():
                    for method, details in methods.items():
                        if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            schema.endpoints.append(APIEndpoint(
                                path=path_str,
                                method=method.upper(),
                            ))

                return schema

        except json.JSONDecodeError:
            # Try YAML
            if "openapi:" in content or "swagger:" in content:
                return APISchema(
                    type="openapi" if "openapi:" in content else "swagger",
                    version="",
                    raw_schema=content[:5000],
                )

        return None

    async def _detect_graphql(self, url: str) -> Optional[dict]:
        """Detect GraphQL endpoints."""
        result = {}

        for path in self.GRAPHQL_PATHS:
            try:
                full_url = urljoin(url, path)

                # Test with introspection query
                introspection_query = {
                    "query": "{ __schema { types { name } } }"
                }

                response = await self.http_client.post(
                    full_url,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    try:
                        data = json.loads(response.body)
                        if "data" in data and "__schema" in str(data):
                            result["endpoint"] = path
                            result["introspection"] = True
                            result["endpoints"] = [APIEndpoint(
                                path=path,
                                method="POST",
                                content_type="application/json",
                            )]
                            logger.info(f"[API] GraphQL with introspection at {path}")
                            return result

                    except json.JSONDecodeError:
                        pass

                # Check if it's GraphQL without introspection
                if "graphql" in response.body.lower() or "query" in response.body.lower():
                    result["endpoint"] = path
                    result["introspection"] = False
                    return result

            except Exception:
                continue

        return result if result else None

    async def _enumerate_versions(self, url: str) -> list[str]:
        """Find all API versions."""
        versions = set()

        # Check common version patterns
        version_paths = [
            "/v1", "/v2", "/v3", "/v4", "/v5",
            "/api/v1", "/api/v2", "/api/v3",
        ]

        for path in version_paths:
            try:
                full_url = urljoin(url, path)
                response = await self.http_client.get(full_url)

                if response.status_code in [200, 401, 403]:
                    # Extract version
                    for pattern in self.VERSION_PATTERNS:
                        match = re.search(pattern, path)
                        if match:
                            versions.add(f"v{match.group(1)}")
                            break

            except Exception:
                continue

        # Also check response headers
        response = await self.http_client.get(url)
        version_headers = ["X-API-Version", "API-Version", "X-Version"]
        for header in version_headers:
            if header in response.headers:
                versions.add(response.headers[header])

        return list(versions)

    async def _fingerprint_technologies(self, url: str) -> list[str]:
        """Identify API technologies in use."""
        techs = []

        response = await self.http_client.get(url)
        headers = response.headers

        # Server header
        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")

        # Framework detection
        framework_headers = {
            "X-Powered-By": lambda v: f"Powered by: {v}",
            "X-AspNet-Version": lambda v: f"ASP.NET: {v}",
            "X-Runtime": lambda v: "Ruby on Rails",
            "X-Django-Version": lambda v: f"Django: {v}",
        }

        for header, formatter in framework_headers.items():
            if header in headers:
                techs.append(formatter(headers[header]))

        # Response-based detection
        content_type = headers.get("Content-Type", "")
        if "application/json" in content_type:
            techs.append("JSON API")
        if "application/xml" in content_type:
            techs.append("XML API")
        if "graphql" in content_type.lower():
            techs.append("GraphQL")

        return techs

    async def _map_authentication(self, url: str, endpoints: list[APIEndpoint]) -> list[str]:
        """Map API authentication methods."""
        auth_methods = []

        response = await self.http_client.get(url)

        # Check WWW-Authenticate header
        www_auth = response.headers.get("WWW-Authenticate", "")
        if www_auth:
            auth_methods.append(f"WWW-Authenticate: {www_auth}")

        # Check for common auth patterns in endpoints
        for endpoint in endpoints:
            if endpoint.auth_required:
                # Try to determine auth type
                test_response = await self.http_client.get(
                    urljoin(url, endpoint.path)
                )

                if test_response.status_code == 401:
                    if "bearer" in test_response.body.lower():
                        auth_methods.append("Bearer Token")
                    if "api" in test_response.body.lower() and "key" in test_response.body.lower():
                        auth_methods.append("API Key")
                    if "basic" in test_response.headers.get("WWW-Authenticate", "").lower():
                        auth_methods.append("Basic Auth")

        return list(set(auth_methods))

    async def _discover_hidden_params(
        self,
        url: str,
        endpoints: list[APIEndpoint]
    ) -> list[APIEndpoint]:
        """Discover hidden parameters."""
        discovered = []

        for endpoint in endpoints[:5]:  # Limit to first 5
            for param in self.HIDDEN_PARAMS:
                try:
                    test_url = f"{urljoin(url, endpoint.path)}?{param}=1"
                    response = await self.http_client.get(test_url)

                    # Check if parameter had an effect
                    baseline = await self.http_client.get(urljoin(url, endpoint.path))

                    if (
                        response.status_code != baseline.status_code or
                        len(response.body) != len(baseline.body)
                    ):
                        new_endpoint = APIEndpoint(
                            path=endpoint.path,
                            method="GET",
                            parameters=[param],
                        )
                        discovered.append(new_endpoint)
                        logger.debug(f"[API] Hidden param found: {param} on {endpoint.path}")

                except Exception:
                    continue

        return discovered


async def discover_api(url: str, http_client=None) -> APIDiscoveryResult:
    """
    Convenience function to discover API.

    Usage:
        result = await discover_api("https://api.target.com")
    """
    discovery = APIDiscovery(http_client)
    await discovery.exploit(url)
    return APIDiscoveryResult(base_url=url, api_type="rest")
