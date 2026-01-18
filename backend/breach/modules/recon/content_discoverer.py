"""
BREACH.AI v2 - Content Discoverer Module

Directory and file discovery through brute forcing and crawling.
"""

import asyncio
from urllib.parse import urljoin, urlparse

from backend.breach.modules.base import (
    ReconModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from backend.breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    Severity,
)


# Common directories and files to check
COMMON_PATHS = [
    # Config and sensitive files
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/config.yml", "/config.yaml",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/server.xml",
    "/package.json", "/composer.json", "/Gemfile",
    "/wp-config.php", "/wp-config.php.bak",

    # Backup files
    "/backup.sql", "/database.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/data.sql",

    # API endpoints
    "/api", "/api/v1", "/api/v2",
    "/api/health", "/api/status", "/api/info",
    "/api/users", "/api/admin", "/api/config",
    "/api/docs", "/api/swagger", "/api/openapi.json",
    "/swagger.json", "/openapi.yaml",
    "/graphql", "/graphiql",

    # Admin interfaces
    "/admin", "/administrator", "/admin.php",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/mysql",
    "/adminer.php", "/adminer",
    "/dashboard", "/panel", "/console",
    "/manager", "/management",

    # Debug/Dev
    "/debug", "/test", "/dev",
    "/phpinfo.php", "/info.php",
    "/_profiler", "/_debug",
    "/server-status", "/server-info",
    "/trace.axd", "/elmah.axd",

    # Common CMS paths
    "/sitemap.xml", "/robots.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/security.txt", "/.well-known/security.txt",

    # Cloud/DevOps
    "/.aws/credentials", "/.docker/config.json",
    "/Dockerfile", "/docker-compose.yml",
    "/kubernetes.yml", "/k8s/",
    "/.github/workflows",

    # Logs
    "/logs", "/log", "/error_log",
    "/access.log", "/error.log",
    "/debug.log", "/app.log",
]

# Sensitive file extensions to look for
SENSITIVE_EXTENSIONS = [".bak", ".old", ".backup", ".sql", ".log", ".conf", ".config"]


@register_module
class ContentDiscoverer(ReconModule):
    """
    Content Discoverer - Find hidden files and directories.

    Features:
    - Directory brute forcing
    - Sensitive file detection
    - Backup file hunting
    - API endpoint enumeration
    - Git/SVN exposure detection
    """

    info = ModuleInfo(
        name="content_discoverer",
        phase=BreachPhase.RECON,
        description="Directory and file discovery",
        author="BREACH.AI",
        techniques=["T1083", "T1592.002"],  # File and Directory Discovery
        platforms=["web"],
        requires_access=False,
    )

    async def check(self, config: ModuleConfig) -> bool:
        return bool(config.target)

    async def run(self, config: ModuleConfig) -> ModuleResult:
        self._start_execution()

        found_paths = []
        sensitive_files = []
        api_endpoints = []
        git_exposed = False

        # Check common paths
        semaphore = asyncio.Semaphore(20)

        async def check_path(path: str):
            async with semaphore:
                url = urljoin(config.target, path)
                try:
                    response = await self._safe_request(
                        "GET", url, timeout=10, follow_redirects=False
                    )
                    if response:
                        status = response.get("status_code", 0)
                        if status == 200:
                            content_length = len(response.get("text", ""))
                            return {
                                "path": path,
                                "status": status,
                                "size": content_length,
                                "content_type": response.get("headers", {}).get("content-type", ""),
                            }
                        elif status in [301, 302, 307, 308]:
                            return {
                                "path": path,
                                "status": status,
                                "redirect": response.get("headers", {}).get("location", ""),
                            }
                except Exception:
                    pass
                return None

        tasks = [check_path(path) for path in COMMON_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and isinstance(result, dict):
                path = result["path"]
                found_paths.append(result)

                # Categorize findings
                if path.startswith("/.git"):
                    git_exposed = True
                    sensitive_files.append(path)
                elif any(s in path for s in [".env", "config", "backup", ".sql", "credentials"]):
                    sensitive_files.append(path)
                elif path.startswith("/api"):
                    api_endpoints.append(path)

        # Add evidence
        if found_paths:
            self._add_evidence(
                evidence_type=EvidenceType.API_RESPONSE,
                description=f"Content discovery found {len(found_paths)} paths",
                content={
                    "paths": found_paths[:50],
                    "sensitive_count": len(sensitive_files),
                    "api_endpoints": api_endpoints,
                },
                proves="Hidden content and attack surface exposed",
                severity=Severity.LOW,
            )

        if git_exposed:
            self._add_evidence(
                evidence_type=EvidenceType.FILE_CONTENT,
                description="Git repository exposed",
                content={"path": "/.git/", "risk": "Source code and history leaked"},
                proves="Complete source code potentially accessible",
                severity=Severity.HIGH,
            )

        if sensitive_files:
            self._add_evidence(
                evidence_type=EvidenceType.FILE_CONTENT,
                description="Sensitive files exposed",
                content={"files": sensitive_files},
                proves="Configuration and secrets potentially accessible",
                severity=Severity.MEDIUM,
            )

        return self._create_result(
            success=len(found_paths) > 0,
            action="content_discovery",
            details=f"Found {len(found_paths)} paths ({len(sensitive_files)} sensitive)",
            data_extracted={
                "found_paths": [p["path"] for p in found_paths],
                "sensitive_files": sensitive_files,
                "api_endpoints": api_endpoints,
                "git_exposed": git_exposed,
            },
            new_endpoints=[p["path"] for p in found_paths if p.get("status") == 200],
            enables_modules=["sqli_destroyer", "auth_obliterator"] if api_endpoints else [],
        )
