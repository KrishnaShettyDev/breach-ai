"""
BREACH.AI - HTTP Client

Async HTTP client with rate limiting, retry logic, and security testing features.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from breach.utils.logger import logger


@dataclass
class HTTPResponse:
    """Wrapper for HTTP responses with security-relevant metadata."""
    url: str
    status_code: int
    headers: dict
    body: str
    elapsed_ms: float

    # Security-relevant fields
    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: int = 0
    cookies: dict = field(default_factory=dict)

    # Redirect info
    redirect_url: Optional[str] = None
    redirect_count: int = 0

    # Error info
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    def contains(self, text: str, case_sensitive: bool = False) -> bool:
        """Check if response body contains text."""
        if case_sensitive:
            return text in self.body
        return text.lower() in self.body.lower()

    def header(self, name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        return self.headers.get(name.lower())


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_second: int = 50):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class HTTPClient:
    """
    Async HTTP client optimized for security testing.

    Features:
    - Rate limiting to avoid overwhelming targets
    - Automatic retries with exponential backoff
    - Cookie and session management
    - Proxy support
    - Custom User-Agent rotation
    - Response caching (optional)
    """

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    ]

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        rate_limit: int = 50,
        max_retries: int = 3,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects

        self.rate_limiter = RateLimiter(rate_limit)
        self.request_count = 0
        self._ua_index = 0

        # Create client
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            verify=verify_ssl,
            proxy=proxy,
            headers=self.DEFAULT_HEADERS.copy(),
        )

        # Cookie jar for session management
        self.cookies: dict[str, str] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    def _get_url(self, path: str) -> str:
        """Resolve URL against base URL if set."""
        if self.base_url and not path.startswith(('http://', 'https://')):
            return urljoin(self.base_url, path)
        return path

    def _rotate_user_agent(self) -> str:
        """Get the next User-Agent in rotation."""
        ua = self.USER_AGENTS[self._ua_index % len(self.USER_AGENTS)]
        self._ua_index += 1
        return ua

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        timeout: Optional[float] = None,
        allow_redirects: Optional[bool] = None,
        rotate_ua: bool = False,
    ) -> HTTPResponse:
        """
        Make an HTTP request with rate limiting and retries.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: URL or path (resolved against base_url if set)
            params: Query parameters
            data: Form data
            json: JSON body
            headers: Additional headers
            cookies: Additional cookies
            timeout: Request timeout override
            allow_redirects: Override follow_redirects setting
            rotate_ua: Rotate User-Agent header

        Returns:
            HTTPResponse object
        """
        await self.rate_limiter.acquire()

        full_url = self._get_url(url)

        # Prepare headers
        req_headers = self.DEFAULT_HEADERS.copy()
        if rotate_ua:
            req_headers["User-Agent"] = self._rotate_user_agent()
        if headers:
            req_headers.update(headers)

        # Merge cookies
        req_cookies = {**self.cookies}
        if cookies:
            req_cookies.update(cookies)

        # Retry loop
        last_error = None
        for attempt in range(self.max_retries):
            try:
                start_time = time.monotonic()

                response = await self._client.request(
                    method=method.upper(),
                    url=full_url,
                    params=params,
                    data=data,
                    json=json,
                    headers=req_headers,
                    cookies=req_cookies,
                    timeout=timeout or self.timeout,
                    follow_redirects=allow_redirects if allow_redirects is not None else self.follow_redirects,
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000
                self.request_count += 1

                # Update cookies from response
                for cookie in response.cookies.jar:
                    self.cookies[cookie.name] = cookie.value

                # Build response object
                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=response.text,
                    elapsed_ms=elapsed_ms,
                    server=response.headers.get("server"),
                    content_type=response.headers.get("content-type"),
                    content_length=len(response.content),
                    cookies=dict(response.cookies),
                    redirect_url=str(response.url) if response.url != full_url else None,
                    redirect_count=len(response.history),
                )

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

            except httpx.RequestError as e:
                last_error = f"Request error: {e}"
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        # All retries failed
        return HTTPResponse(
            url=full_url,
            status_code=0,
            headers={},
            body="",
            elapsed_ms=0,
            error=last_error,
        )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse:
        """OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    # Security testing helpers

    async def test_method(self, url: str, method: str) -> bool:
        """Test if an HTTP method is allowed."""
        response = await self.request(method, url)
        return response.status_code != 405

    async def get_allowed_methods(self, url: str) -> list[str]:
        """Get allowed HTTP methods for a URL."""
        response = await self.options(url)
        allow_header = response.header("allow")
        if allow_header:
            return [m.strip().upper() for m in allow_header.split(",")]

        # Fallback: test common methods
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        allowed = []
        for method in methods:
            if await self.test_method(url, method):
                allowed.append(method)
        return allowed

    async def check_cors(self, url: str, origin: str = "https://evil.com") -> dict:
        """Check CORS configuration."""
        response = await self.options(url, headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        })

        return {
            "allows_origin": response.header("access-control-allow-origin"),
            "allows_credentials": response.header("access-control-allow-credentials"),
            "allows_methods": response.header("access-control-allow-methods"),
            "allows_headers": response.header("access-control-allow-headers"),
            "vulnerable": response.header("access-control-allow-origin") == "*" or
                         response.header("access-control-allow-origin") == origin,
        }

    def set_auth(self, username: str, password: str):
        """Set basic authentication."""
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._client.headers["Authorization"] = f"Basic {credentials}"

    def set_bearer_token(self, token: str):
        """Set bearer token authentication."""
        self._client.headers["Authorization"] = f"Bearer {token}"

    def set_cookie(self, name: str, value: str):
        """Set a cookie."""
        self.cookies[name] = value

    def clear_cookies(self):
        """Clear all cookies."""
        self.cookies.clear()
