"""
BREACH.AI - Web Crawler

Web crawling for endpoint and parameter discovery.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from backend.breach.core.memory import Endpoint
from backend.breach.utils.helpers import (
    normalize_url, is_same_origin, extract_links, extract_forms, extract_scripts
)
from backend.breach.utils.http import HTTPClient, HTTPResponse
from backend.breach.utils.logger import logger


@dataclass
class CrawlResult:
    """Result of web crawling."""
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    parameters: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)

    # Stats
    pages_crawled: int = 0
    errors: int = 0


class WebCrawler:
    """
    Web crawler for endpoint and parameter discovery.

    Features:
    - Recursive crawling with depth control
    - JavaScript parsing for API endpoints
    - Form extraction
    - Parameter discovery
    - Same-origin policy enforcement
    """

    # Patterns that indicate API endpoints in JavaScript
    API_PATTERNS = [
        r'["\']/(api|v[0-9]+)/[^"\']+["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    # File extensions to skip
    SKIP_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.css', '.woff', '.woff2', '.ttf', '.eot',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar',
        '.mp3', '.mp4', '.avi', '.mov',
    }

    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        max_depth: int = 3,
        max_pages: int = 500,
        respect_robots: bool = True,
    ):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots

        self._visited: Set[str] = set()
        self._to_visit: list[tuple[str, int]] = []  # (url, depth)
        self._robots_disallowed: Set[str] = set()

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl a website starting from the given URL.

        Args:
            start_url: Starting URL for crawling

        Returns:
            CrawlResult with discovered endpoints
        """
        start_url = normalize_url(start_url)
        base_url = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"

        result = CrawlResult(base_url=base_url)

        # Create HTTP client if not provided
        own_client = False
        if not self.http_client:
            self.http_client = HTTPClient(base_url=base_url)
            own_client = True

        try:
            # Parse robots.txt
            if self.respect_robots:
                await self._parse_robots(base_url)

            # Start crawling
            self._to_visit.append((start_url, 0))

            while self._to_visit and result.pages_crawled < self.max_pages:
                url, depth = self._to_visit.pop(0)

                if url in self._visited:
                    continue

                if depth > self.max_depth:
                    continue

                # Skip disallowed by robots.txt
                if self._is_disallowed(url):
                    continue

                # Skip non-same-origin
                if not is_same_origin(url, base_url):
                    continue

                # Skip certain file extensions
                if self._should_skip(url):
                    continue

                self._visited.add(url)

                # Fetch page
                try:
                    response = await self.http_client.get(url)
                    result.pages_crawled += 1

                    if response.is_success:
                        # Process the page
                        await self._process_page(url, response, depth, result, base_url)

                except Exception as e:
                    logger.debug(f"Crawl error for {url}: {e}")
                    result.errors += 1

            # Fetch and analyze JavaScript files
            await self._analyze_scripts(result)

        finally:
            if own_client:
                await self.http_client.close()

        return result

    async def _parse_robots(self, base_url: str):
        """Parse robots.txt for disallowed paths."""
        try:
            response = await self.http_client.get(f"{base_url}/robots.txt")
            if response.is_success:
                for line in response.body.split('\n'):
                    line = line.strip().lower()
                    if line.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self._robots_disallowed.add(path)
        except Exception:
            pass

    def _is_disallowed(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt."""
        path = urlparse(url).path
        for disallowed in self._robots_disallowed:
            if path.startswith(disallowed):
                return True
        return False

    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped based on extension."""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    async def _process_page(
        self,
        url: str,
        response: HTTPResponse,
        depth: int,
        result: CrawlResult,
        base_url: str
    ):
        """Process a crawled page."""
        content_type = response.content_type or ""

        # Skip non-HTML
        if "html" not in content_type.lower() and "text" not in content_type.lower():
            return

        # Parse HTML
        soup = BeautifulSoup(response.body, 'lxml')

        # Extract endpoint info
        endpoint = Endpoint(
            url=url,
            method="GET",
            content_type=content_type,
            status_code=response.status_code,
            parameters=list(parse_qs(urlparse(url).query).keys()),
        )
        result.endpoints.append(endpoint)

        # Extract links and add to crawl queue
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
                form_endpoint = Endpoint(
                    url=form['action'],
                    method=form.get('method', 'GET').upper(),
                    parameters=[inp.get('name', '') for inp in form.get('inputs', []) if inp.get('name')],
                )
                result.endpoints.append(form_endpoint)

        # Extract script URLs
        scripts = self._extract_script_urls(soup, url)
        for script in scripts:
            if script not in result.scripts:
                result.scripts.append(script)

        # Extract inline API endpoints from scripts
        api_endpoints = self._extract_api_endpoints(response.body)
        for api_url in api_endpoints:
            full_url = urljoin(url, api_url)
            if full_url not in result.api_endpoints:
                result.api_endpoints.append(full_url)

                # Add as endpoint
                result.endpoints.append(Endpoint(
                    url=full_url,
                    method="GET",  # Unknown, could be any
                ))

        # Extract parameters from URL patterns in content
        self._extract_parameters(response.body, url, result)

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        """Extract links from HTML."""
        links = []

        for tag in soup.find_all(['a', 'area']):
            href = tag.get('href')
            if href:
                full_url = urljoin(base_url, href)
                # Remove fragments
                full_url = full_url.split('#')[0]
                if full_url and is_same_origin(full_url, base_url):
                    links.append(full_url)

        return list(set(links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[dict]:
        """Extract forms from HTML."""
        forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url

            form_data = {
                'action': action,
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': [],
            }

            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    form_data['inputs'].append({
                        'name': name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required'),
                    })

            forms.append(form_data)

        return forms

    def _extract_script_urls(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        """Extract external script URLs."""
        scripts = []

        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if is_same_origin(full_url, base_url):
                    scripts.append(full_url)

        return scripts

    def _extract_api_endpoints(self, content: str) -> list[str]:
        """Extract API endpoints from content using regex patterns."""
        endpoints = []

        for pattern in self.API_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and match.startswith('/'):
                    endpoints.append(match)

        return list(set(endpoints))

    def _extract_parameters(self, content: str, url: str, result: CrawlResult):
        """Extract potential parameter names from content."""
        # Look for common parameter patterns
        param_patterns = [
            r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
            r'id=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
            r'\?([a-zA-Z_][a-zA-Z0-9_]*)=',
            r'&([a-zA-Z_][a-zA-Z0-9_]*)=',
            r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
        ]

        params = set()
        for pattern in param_patterns:
            matches = re.findall(pattern, content)
            params.update(matches)

        for param in params:
            if len(param) > 1 and not param.startswith('_'):
                result.parameters.append({
                    'name': param,
                    'source': url,
                })

    async def _analyze_scripts(self, result: CrawlResult):
        """Fetch and analyze JavaScript files for endpoints."""
        for script_url in result.scripts[:50]:  # Limit to 50 scripts
            try:
                response = await self.http_client.get(script_url)
                if response.is_success:
                    # Extract API endpoints from JS
                    api_endpoints = self._extract_api_endpoints(response.body)
                    for api_url in api_endpoints:
                        full_url = urljoin(result.base_url, api_url)
                        if full_url not in result.api_endpoints:
                            result.api_endpoints.append(full_url)
                            result.endpoints.append(Endpoint(url=full_url))

                    # Look for hardcoded secrets (informational)
                    self._check_for_secrets(response.body, script_url, result)

            except Exception as e:
                logger.debug(f"Script analysis error for {script_url}: {e}")

    def _check_for_secrets(self, content: str, source: str, result: CrawlResult):
        """Check for hardcoded secrets in JavaScript (informational)."""
        secret_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
            (r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Secret'),
            (r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password'),
            (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Key'),
        ]

        for pattern, secret_type in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.debug(f"Potential {secret_type} found in {source}")
