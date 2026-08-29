import asyncio
import random
from typing import Dict, Any, Optional, Tuple
import aiohttp

class AsyncHttpClient:
    """
    Client HTTP Asynchronous terpusat dengan dukungan:
    - User-Agent Rotation otomatis
    - Concurrency Semaphore (Rate Limiter)
    - Proxy HTTP/SOCKS
    - Connection Pooling
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36"
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout_sec = self.config.get("app.timeout", 10)
        self.max_concurrency = self.config.get("app.max_concurrency", 25)
        self.rotate_ua = self.config.get("app.rotate_user_agent", True)
        self.semaphore = asyncio.Semaphore(self.max_concurrency)
        self._session: Optional[aiohttp.ClientSession] = None
        
    def _get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        custom_ua = self.config.get("http.user_agent")
        if custom_ua:
            ua = custom_ua
        else:
            ua = random.choice(self.USER_AGENTS) if self.rotate_ua else self.USER_AGENTS[0]
            
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "keep-alive"
        }
        
        custom_cookie = self.config.get("http.cookie")
        if custom_cookie:
            headers["Cookie"] = custom_cookie
            
        cfg_headers = self.config.get("http.headers", {})
        if isinstance(cfg_headers, dict):
            headers.update(cfg_headers)
            
        if custom_headers:
            headers.update(custom_headers)
        return headers
        
    def _get_proxy(self) -> Optional[str]:
        cli_proxy = self.config.get("http.proxy")
        if cli_proxy:
            return cli_proxy
        if self.config.get("proxy.enabled", False):
            http_proxy = self.config.get("proxy.http_proxy", "")
            socks_proxy = self.config.get("proxy.socks5_proxy", "")
            return socks_proxy or http_proxy or None
        return None
        
    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
            connector = aiohttp.TCPConnector(limit=100, ssl=False)
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session
        
    def _prepare_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        kw = dict(kwargs)
        if "timeout" in kw and isinstance(kw["timeout"], (int, float)):
            kw["timeout"] = aiohttp.ClientTimeout(total=float(kw["timeout"]))
        return kw

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Tuple[int, str, Dict[str, str]]:
        """
        Melakukan HTTP GET asynchronous dengan semaphore rate limiting.
        Return: (status_code, response_text, response_headers)
        """
        async with self.semaphore:
            session = await self.get_session()
            req_headers = self._get_headers(headers)
            proxy = self._get_proxy()
            call_kwargs = self._prepare_kwargs(kwargs)
            
            try:
                async with session.get(url, headers=req_headers, proxy=proxy, allow_redirects=True, **call_kwargs) as resp:
                    text = await resp.text(errors="ignore")
                    return resp.status, text, dict(resp.headers)
            except Exception as e:
                return 0, str(e), {}
                
    async def head(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Tuple[int, Dict[str, str]]:
        async with self.semaphore:
            session = await self.get_session()
            req_headers = self._get_headers(headers)
            proxy = self._get_proxy()
            call_kwargs = self._prepare_kwargs(kwargs)
            
            try:
                async with session.head(url, headers=req_headers, proxy=proxy, allow_redirects=True, **call_kwargs) as resp:
                    return resp.status, dict(resp.headers)
            except Exception:
                return 0, {}
                
    async def options(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Tuple[int, str, Dict[str, str]]:
        async with self.semaphore:
            session = await self.get_session()
            req_headers = self._get_headers(headers)
            proxy = self._get_proxy()
            call_kwargs = self._prepare_kwargs(kwargs)
            
            try:
                async with session.options(url, headers=req_headers, proxy=proxy, allow_redirects=True, **call_kwargs) as resp:
                    text = await resp.text(errors="ignore")
                    return resp.status, text, dict(resp.headers)
            except Exception as e:
                return 0, str(e), {}
                
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
