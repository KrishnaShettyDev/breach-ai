"""
BREACH.AI HTTP Client

A robust async HTTP client for security testing.
Features:
- Connection pooling
- Rate limiting
- Error handling
- Response parsing
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, List
from urllib.parse import urljoin

import aiohttp


@dataclass
class HTTPResponse:
    """Wrapper for HTTP responses."""
    status_code: int
    headers: Dict[str, str]
    body: str
    url: str
    error: Optional[str] = None

    def json(self) -> Any:
        """Parse body as JSON."""
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            return None

    def header(self, name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return None


class HTTPClient:
    """
    Async HTTP client for security testing.

    Features:
    - Automatic session management
    - Rate limiting
    - Error handling
    - Cookie management
    """

    def __init__(
        self,
        timeout: float = 30.0,
        rate_limit: float = 10.0,
        user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def _ensure_session(self):
        """Ensure we have an active session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ssl=False  # Allow self-signed certs
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent}
            )

    async def _rate_limit(self):
        """Apply rate limiting."""
        async with self._lock:
            import time
            now = time.time()
            elapsed = now - self._last_request
            min_interval = 1.0 / self.rate_limit

            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)

            self._last_request = time.time()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None,
        follow_redirects: bool = True
    ) -> HTTPResponse:
        """Make an HTTP request."""
        await self._ensure_session()
        await self._rate_limit()

        try:
            kwargs = {
                "method": method,
                "url": url,
                "headers": headers or {},
                "allow_redirects": follow_redirects
            }

            if json_data is not None:
                kwargs["json"] = json_data
            elif data is not None:
                kwargs["data"] = data

            async with self._session.request(**kwargs) as resp:
                body = await resp.text()
                return HTTPResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    url=str(resp.url)
                )

        except aiohttp.ClientError as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                url=url,
                error=str(e)
            )
        except asyncio.TimeoutError:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                url=url,
                error="Request timeout"
            )
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                url=url,
                error=f"Unknown error: {e}"
            )

    async def get(self, url: str, headers: Optional[Dict] = None) -> HTTPResponse:
        """HTTP GET request."""
        return await self.request("GET", url, headers=headers)

    async def post(
        self,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None
    ) -> HTTPResponse:
        """HTTP POST request."""
        return await self.request("POST", url, headers=headers, data=data, json_data=json_data)

    async def put(
        self,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None
    ) -> HTTPResponse:
        """HTTP PUT request."""
        return await self.request("PUT", url, headers=headers, data=data, json_data=json_data)

    async def delete(self, url: str, headers: Optional[Dict] = None) -> HTTPResponse:
        """HTTP DELETE request."""
        return await self.request("DELETE", url, headers=headers)

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
