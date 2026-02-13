"""
BREACH.AI - God Level Web Spider
=================================
Comprehensive website crawler that discovers EVERYTHING.
"""

import asyncio
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import aiohttp

from .payloads import ENDPOINT_WORDLIST, SENSITIVE_FILES


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint with all its details."""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    body_params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    status_code: int = 0
    response_length: int = 0
    requires_auth: bool = False
    is_api: bool = False
    is_form: bool = False
    source: str = ""  # Where we found this endpoint


@dataclass
class SpiderResult:
    """Complete results from spidering."""
    base_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    extracted_ids: Set[str] = field(default_factory=set)
    extracted_emails: Set[str] = field(default_factory=set)
    extracted_urls: Set[str] = field(default_factory=set)
    technology: Dict[str, str] = field(default_factory=dict)
    pages_crawled: int = 0
    total_requests: int = 0


class DeepSpider:
    """
    God-level web spider that discovers everything.

    Features:
    - Recursive crawling with configurable depth
    - JavaScript analysis for hidden API endpoints
    - Form extraction with all parameters
    - Sensitive file discovery
    - ID/UUID extraction for IDOR testing
    - Technology fingerprinting
    - Endpoint fuzzing with wordlist
    """

    # Patterns to extract from JavaScript
    JS_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v[0-9]/[^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'endpoint\s*:\s*["\']([^"\']+)["\']',
        r'baseURL\s*:\s*["\']([^"\']+)["\']',
        r'apiUrl\s*:\s*["\']([^"\']+)["\']',
        r'href\s*=\s*["\']([^"\']+)["\']',
        r'action\s*=\s*["\']([^"\']+)["\']',
    ]

    # UUID pattern
    UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

    # Numeric ID pattern
    NUMERIC_ID_PATTERN = re.compile(r'(?:id|Id|ID)["\s:=]+["\']?(\d+)["\']?')

    # Email pattern
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    # Technology signatures
    TECH_SIGNATURES = {
        'next.js': [r'_next/static', r'__NEXT_DATA__', r'next-auth'],
        'react': [r'react', r'reactDOM', r'_reactRoot'],
        'vue': [r'vue', r'__vue__', r'v-model'],
        'angular': [r'ng-app', r'angular', r'ng-controller'],
        'express': [r'express', r'X-Powered-By: Express'],
        'django': [r'csrfmiddlewaretoken', r'django', r'__admin__'],
        'rails': [r'rails', r'csrf-token', r'authenticity_token'],
        'laravel': [r'laravel', r'XSRF-TOKEN', r'laravel_session'],
        'spring': [r'spring', r'JSESSIONID', r'_csrf'],
        'asp.net': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'aspnet'],
        'wordpress': [r'wp-content', r'wp-includes', r'wp-json'],
        'supabase': [r'supabase\.co', r'\.supabase\.'],
        'firebase': [r'firebase', r'firebaseio\.com'],
        'auth0': [r'auth0', r'\.auth0\.com'],
        'clerk': [r'clerk', r'\.clerk\.'],
        'stripe': [r'stripe', r'pk_live_', r'pk_test_'],
        'graphql': [r'graphql', r'__schema', r'__typename'],
    }

    # Skip these file extensions
    SKIP_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
        '.exe', '.dll', '.so', '.dmg',
    }

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        max_depth: int = 5,
        max_pages: int = 500,
        timeout: int = 10,
        concurrent_requests: int = 20,
    ):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.concurrent_requests = concurrent_requests

        self._visited: Set[str] = set()
        self._to_visit: List[tuple] = []  # (url, depth)
        self._semaphore = asyncio.Semaphore(concurrent_requests)

    async def crawl(self, cookies: Dict = None, progress_callback=None) -> SpiderResult:
        """
        Crawl the entire website and discover everything.
        """
        result = SpiderResult(base_url=self.base_url)

        print(f"\n[SPIDER] Starting comprehensive crawl of {self.base_url}")
        print(f"[SPIDER] Max depth: {self.max_depth}, Max pages: {self.max_pages}")

        # Phase 1: Crawl the main site (0-8%)
        print(f"\n[SPIDER] Phase 1: Recursive crawling...")
        if progress_callback:
            progress_callback(2, "Crawling pages...")
        self._to_visit.append((self.base_url, 0))

        while self._to_visit and result.pages_crawled < self.max_pages:
            # Process batch of URLs concurrently
            batch = []
            while self._to_visit and len(batch) < self.concurrent_requests:
                url, depth = self._to_visit.pop(0)
                if url not in self._visited and depth <= self.max_depth:
                    batch.append((url, depth))
                    self._visited.add(url)

            if batch:
                tasks = [self._crawl_page(url, depth, result, cookies) for url, depth in batch]
                await asyncio.gather(*tasks, return_exceptions=True)

                # Update progress during crawling
                if progress_callback:
                    progress_pct = min(8, 2 + int(result.pages_crawled / max(self.max_pages, 1) * 6))
                    progress_callback(progress_pct, f"Crawled {result.pages_crawled} pages...")

        print(f"[SPIDER] Crawled {result.pages_crawled} pages")

        # Phase 2: Fuzz for hidden endpoints (8-12%)
        print(f"\n[SPIDER] Phase 2: Fuzzing for hidden endpoints...")
        if progress_callback:
            progress_callback(9, "Fuzzing hidden endpoints...")
        await self._fuzz_endpoints(result, cookies)
        if progress_callback:
            progress_callback(12, f"Found {len(result.endpoints)} endpoints")

        # Phase 3: Check for sensitive files (12-15%)
        print(f"\n[SPIDER] Phase 3: Checking sensitive files...")
        if progress_callback:
            progress_callback(13, "Checking sensitive files...")
        await self._check_sensitive_files(result, cookies)
        if progress_callback:
            progress_callback(15, f"Found {len(result.sensitive_files)} sensitive files")

        # Phase 4: Analyze JavaScript files (15-18%)
        print(f"\n[SPIDER] Phase 4: Analyzing JavaScript files...")
        if progress_callback:
            progress_callback(16, "Analyzing JavaScript...")
        await self._analyze_js_files(result, cookies)
        if progress_callback:
            progress_callback(18, f"Analyzed JS, found {len(result.api_endpoints)} APIs")

        # Phase 5: Try to find API documentation (18-20%)
        print(f"\n[SPIDER] Phase 5: Looking for API documentation...")
        if progress_callback:
            progress_callback(19, "Looking for API docs...")
        await self._find_api_docs(result, cookies)

        # Deduplicate endpoints
        seen = set()
        unique_endpoints = []
        for ep in result.endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        result.endpoints = unique_endpoints

        print(f"\n[SPIDER] Complete! Found:")
        print(f"  - {len(result.endpoints)} endpoints")
        print(f"  - {len(result.forms)} forms")
        print(f"  - {len(result.api_endpoints)} API endpoints")
        print(f"  - {len(result.sensitive_files)} sensitive files")
        print(f"  - {len(result.extracted_ids)} IDs for IDOR testing")
        print(f"  - Technologies: {', '.join(result.technology.keys()) or 'Unknown'}")

        return result

    async def _crawl_page(
        self,
        url: str,
        depth: int,
        result: SpiderResult,
        cookies: Dict = None
    ):
        """Crawl a single page and extract everything."""
        async with self._semaphore:
            try:
                # Skip non-same-origin
                if not self._is_same_origin(url):
                    return

                # Skip certain extensions
                if self._should_skip(url):
                    return

                async with self.session.get(
                    url,
                    cookies=cookies,
                    ssl=False,
                    timeout=self.timeout,
                    allow_redirects=True
                ) as response:
                    result.pages_crawled += 1
                    result.total_requests += 1

                    body = await response.text()
                    content_type = response.headers.get('Content-Type', '')

                    # Add as endpoint
                    endpoint = DiscoveredEndpoint(
                        url=url.split('?')[0],
                        method="GET",
                        params=list(parse_qs(urlparse(url).query).keys()),
                        status_code=response.status,
                        response_length=len(body),
                        content_type=content_type,
                        requires_auth=response.status in [401, 403],
                        source="crawl"
                    )
                    result.endpoints.append(endpoint)

                    # Detect technology
                    self._detect_technology(body, str(response.headers), result)

                    # Extract data
                    self._extract_ids(body, result)
                    self._extract_emails(body, result)

                    # Parse HTML
                    if 'html' in content_type.lower():
                        soup = BeautifulSoup(body, 'html.parser')

                        # Extract links
                        links = self._extract_links(soup, url)
                        for link in links:
                            if link not in self._visited:
                                self._to_visit.append((link, depth + 1))

                        # Extract forms
                        forms = self._extract_forms(soup, url)
                        for form in forms:
                            result.forms.append(form)
                            # Add form action as endpoint
                            if form.get('action'):
                                ep = DiscoveredEndpoint(
                                    url=form['action'],
                                    method=form.get('method', 'POST').upper(),
                                    body_params=[inp['name'] for inp in form.get('inputs', []) if inp.get('name')],
                                    is_form=True,
                                    source="form"
                                )
                                result.endpoints.append(ep)

                        # Extract script URLs
                        scripts = self._extract_scripts(soup, url)
                        for script in scripts:
                            if script not in result.js_files:
                                result.js_files.append(script)

                    # Extract API endpoints from content
                    api_endpoints = self._extract_api_endpoints(body)
                    for api_url in api_endpoints:
                        full_url = urljoin(self.base_url, api_url)
                        if full_url not in result.api_endpoints and self._is_same_origin(full_url):
                            result.api_endpoints.append(full_url)
                            result.endpoints.append(DiscoveredEndpoint(
                                url=full_url,
                                method="GET",
                                is_api=True,
                                source="js_extraction"
                            ))

            except Exception as e:
                pass  # Continue on errors

    def _is_same_origin(self, url: str) -> bool:
        """Check if URL is same origin."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or not parsed.netloc
        except:
            return False

    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped."""
        try:
            path = urlparse(url).path.lower()
            return any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)
        except:
            return False

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        links = []

        for tag in soup.find_all(['a', 'area', 'link']):
            href = tag.get('href')
            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                full_url = urljoin(base_url, href).split('#')[0]
                if self._is_same_origin(full_url):
                    links.append(full_url)

        return list(set(links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract all forms with their fields."""
        forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            action_url = urljoin(base_url, action) if action else base_url

            form_data = {
                'action': action_url,
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': [],
            }

            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    form_data['inputs'].append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                        'required': inp.has_attr('required'),
                    })

            forms.append(form_data)

        return forms

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract external JavaScript URLs."""
        scripts = []

        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if self._is_same_origin(full_url):
                    scripts.append(full_url)

        return scripts

    def _extract_api_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from content."""
        endpoints = []

        for pattern in self.JS_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/') and '//' not in match[:3]:
                    endpoints.append(match)

        return list(set(endpoints))

    def _extract_ids(self, content: str, result: SpiderResult):
        """Extract UUIDs and numeric IDs."""
        # UUIDs
        uuids = self.UUID_PATTERN.findall(content)
        result.extracted_ids.update(uuids[:100])  # Limit

        # Numeric IDs
        numeric_ids = self.NUMERIC_ID_PATTERN.findall(content)
        result.extracted_ids.update(numeric_ids[:50])

    def _extract_emails(self, content: str, result: SpiderResult):
        """Extract email addresses."""
        emails = self.EMAIL_PATTERN.findall(content)
        result.extracted_emails.update(emails[:50])

    def _detect_technology(self, body: str, headers: str, result: SpiderResult):
        """Detect technology stack."""
        combined = body.lower() + headers.lower()

        for tech, patterns in self.TECH_SIGNATURES.items():
            if tech not in result.technology:
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        result.technology[tech] = "detected"
                        break

    async def _fuzz_endpoints(self, result: SpiderResult, cookies: Dict = None):
        """Fuzz for hidden endpoints using wordlist."""
        found = 0

        # Test common paths
        tasks = []
        for word in ENDPOINT_WORDLIST:
            for prefix in ['/', '/api/', '/api/v1/', '/api/v2/']:
                url = f"{self.base_url}{prefix}{word}"
                if url not in self._visited:
                    tasks.append(self._probe_endpoint(url, result, cookies))

        # Process in batches
        for i in range(0, len(tasks), self.concurrent_requests):
            batch = tasks[i:i + self.concurrent_requests]
            results = await asyncio.gather(*batch, return_exceptions=True)
            found += sum(1 for r in results if r is True)

        print(f"[SPIDER] Fuzzing found {found} additional endpoints")

    async def _probe_endpoint(
        self,
        url: str,
        result: SpiderResult,
        cookies: Dict = None
    ) -> bool:
        """Probe a single endpoint."""
        async with self._semaphore:
            try:
                self._visited.add(url)
                result.total_requests += 1

                async with self.session.get(
                    url,
                    cookies=cookies,
                    ssl=False,
                    timeout=self.timeout
                ) as response:
                    if response.status in [200, 201, 301, 302, 401, 403, 405]:
                        body = await response.text()

                        # Skip if it's a generic error page
                        if response.status == 200 and len(body) > 50:
                            if not any(x in body.lower() for x in ['not found', '404', 'page not found']):
                                endpoint = DiscoveredEndpoint(
                                    url=url,
                                    method="GET",
                                    status_code=response.status,
                                    response_length=len(body),
                                    requires_auth=response.status in [401, 403],
                                    is_api='/api/' in url,
                                    source="fuzz"
                                )
                                result.endpoints.append(endpoint)

                                # Extract IDs from response
                                self._extract_ids(body, result)

                                return True

                        # Still add auth-required endpoints
                        elif response.status in [401, 403]:
                            endpoint = DiscoveredEndpoint(
                                url=url,
                                method="GET",
                                status_code=response.status,
                                requires_auth=True,
                                is_api='/api/' in url,
                                source="fuzz"
                            )
                            result.endpoints.append(endpoint)
                            return True

            except:
                pass

            return False

    async def _check_sensitive_files(self, result: SpiderResult, cookies: Dict = None):
        """Check for sensitive files."""
        found = 0

        tasks = []
        for filename in SENSITIVE_FILES:
            url = f"{self.base_url}/{filename.lstrip('/')}"
            tasks.append(self._check_sensitive_file(url, filename, result, cookies))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = sum(1 for r in results if r is True)

        print(f"[SPIDER] Found {found} sensitive files")

    async def _check_sensitive_file(
        self,
        url: str,
        filename: str,
        result: SpiderResult,
        cookies: Dict = None
    ) -> bool:
        """Check a single sensitive file."""
        async with self._semaphore:
            try:
                result.total_requests += 1

                async with self.session.get(
                    url,
                    cookies=cookies,
                    ssl=False,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        body = await response.text()

                        # Verify it's actual content, not error page
                        if len(body) > 10:
                            if not any(x in body.lower() for x in ['<!doctype', '<html', 'not found', '404']):
                                result.sensitive_files.append({
                                    'url': url,
                                    'filename': filename,
                                    'size': len(body),
                                    'sample': body[:500],
                                })
                                return True

                            # Check for .env files specifically
                            if '.env' in filename and '=' in body:
                                result.sensitive_files.append({
                                    'url': url,
                                    'filename': filename,
                                    'size': len(body),
                                    'sample': body[:500],
                                })
                                return True

            except:
                pass

            return False

    async def _analyze_js_files(self, result: SpiderResult, cookies: Dict = None):
        """Analyze JavaScript files for endpoints."""
        found = 0

        for js_url in result.js_files[:100]:  # Limit to 100 JS files
            try:
                async with self._semaphore:
                    result.total_requests += 1

                    async with self.session.get(
                        js_url,
                        cookies=cookies,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()

                            # Extract API endpoints
                            api_endpoints = self._extract_api_endpoints(body)
                            for api_url in api_endpoints:
                                full_url = urljoin(self.base_url, api_url)
                                if full_url not in result.api_endpoints and self._is_same_origin(full_url):
                                    result.api_endpoints.append(full_url)
                                    result.endpoints.append(DiscoveredEndpoint(
                                        url=full_url,
                                        method="GET",
                                        is_api=True,
                                        source="js_analysis"
                                    ))
                                    found += 1

                            # Extract IDs
                            self._extract_ids(body, result)

            except:
                pass

        print(f"[SPIDER] JS analysis found {found} additional API endpoints")

    async def _find_api_docs(self, result: SpiderResult, cookies: Dict = None):
        """Try to find API documentation."""
        doc_paths = [
            '/swagger.json', '/openapi.json', '/api-docs',
            '/swagger/v1/swagger.json', '/v1/swagger.json',
            '/api/swagger.json', '/api/openapi.json',
            '/docs', '/redoc', '/graphql', '/graphiql',
            '/.well-known/openapi.json',
        ]

        for path in doc_paths:
            url = f"{self.base_url}{path}"
            try:
                async with self._semaphore:
                    result.total_requests += 1

                    async with self.session.get(
                        url,
                        cookies=cookies,
                        ssl=False,
                        timeout=self.timeout
                    ) as response:
                        if response.status == 200:
                            body = await response.text()

                            # Check if it's OpenAPI/Swagger
                            if 'swagger' in body.lower() or 'openapi' in body.lower():
                                print(f"[SPIDER] Found API docs at {url}")

                                # Parse and extract endpoints
                                try:
                                    spec = json.loads(body)
                                    paths = spec.get('paths', {})

                                    for path, methods in paths.items():
                                        full_url = urljoin(self.base_url, path)

                                        for method, details in methods.items():
                                            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                                                # Extract parameters
                                                params = []
                                                for param in details.get('parameters', []):
                                                    if param.get('name'):
                                                        params.append(param['name'])

                                                result.endpoints.append(DiscoveredEndpoint(
                                                    url=full_url,
                                                    method=method.upper(),
                                                    params=params if method.upper() == 'GET' else [],
                                                    body_params=params if method.upper() != 'GET' else [],
                                                    is_api=True,
                                                    source="openapi"
                                                ))
                                except:
                                    pass
            except:
                pass
