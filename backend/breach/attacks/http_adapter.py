"""
BREACH.AI - HTTP Client Adapter

Adapts aiohttp sessions to work with the attack module interface.
This bridges the main engine (aiohttp) with the attack modules (HTTPClient interface).
"""

import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlencode

import aiohttp


@dataclass
class HTTPResponse:
    """Response wrapper matching the attack module interface."""
    url: str
    status_code: int
    headers: dict
    body: str
    elapsed_ms: float

    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: int = 0
    cookies: dict = field(default_factory=dict)
    redirect_url: Optional[str] = None
    redirect_count: int = 0
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
        if case_sensitive:
            return text in self.body
        return text.lower() in self.body.lower()

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class AiohttpAdapter:
    """
    Adapts an aiohttp.ClientSession to the HTTPClient interface
    expected by the attack modules.
    """

    def __init__(self, session: aiohttp.ClientSession, base_url: str = ""):
        self.session = session
        self.base_url = base_url
        self.cookies: dict = {}
        self.request_count = 0

    def _get_url(self, path: str) -> str:
        if self.base_url and not path.startswith(('http://', 'https://')):
            return urljoin(self.base_url, path)
        return path

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
        **kwargs
    ) -> HTTPResponse:
        """Make an HTTP request matching the attack module interface."""
        full_url = self._get_url(url)

        # Merge cookies
        req_cookies = {**self.cookies}
        if cookies:
            req_cookies.update(cookies)

        try:
            start_time = time.monotonic()

            async with self.session.request(
                method=method.upper(),
                url=full_url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                cookies=req_cookies if req_cookies else None,
                ssl=False,
                timeout=timeout or 15,
            ) as response:
                body = await response.text()
                elapsed_ms = (time.monotonic() - start_time) * 1000
                self.request_count += 1

                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=body,
                    elapsed_ms=elapsed_ms,
                    server=response.headers.get("Server"),
                    content_type=response.headers.get("Content-Type"),
                    content_length=len(body),
                    cookies=dict(response.cookies),
                )

        except Exception as e:
            return HTTPResponse(
                url=full_url,
                status_code=0,
                headers={},
                body="",
                elapsed_ms=0,
                error=str(e),
            )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("OPTIONS", url, **kwargs)

    def set_cookie(self, name: str, value: str):
        self.cookies[name] = value

    def clear_cookies(self):
        self.cookies.clear()
