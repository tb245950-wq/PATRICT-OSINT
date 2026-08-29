import re
import ssl
import json
import uuid
import socket
import base64
import hashlib
import asyncio
import aiohttp
import ipaddress
import http.client
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.base_module import BaseOSINTModule

# Subnet IP Resmi Cloudflare (IPv4)
CLOUDFLARE_IPV4_RANGES = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22")
]

class WebOSINT(BaseOSINTModule):
    name: str = "Web & Infrastructure Intelligence"
    module_id: str = "web_osint"
    description: str = "Enterprise Web Recon Engine: Dual-Scope Domain Identity, Passive Multi-Source Subdomain Enumeration, Sanctum/JWT Auth Fingerprinting, Soft-404 Calibrated Content Discovery, WAF & Cloudflare Origin Bypass."
    version: str = "3.0.0"
    priority: int = 1
    target_type: str = "web"

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
        return target

    def _parse_domain_identity(self, target: str) -> Dict[str, Any]:
        """
        Pemetaan Identitas Domain & Dual-Scope Parsing (Zero-dependency):
        Memisahkan Target FQDN, Apex / Root Domain, dan Subdomain Prefix
        dengan dukungan multi-part ccTLD (misal: .ac.id, .co.id, .co.uk, .com.au, dll.).
        """
        url = self._normalize_url(target)
        parsed = urllib.parse.urlparse(url)
        fqdn = parsed.netloc or parsed.path
        if ":" in fqdn:
            fqdn = fqdn.split(":")[0]
        fqdn = fqdn.strip().lower()

        # Deteksi jika target adalah alamat IP mentah
        try:
            ipaddress.ip_address(fqdn)
            return {
                "target_fqdn": fqdn,
                "root_domain": fqdn,
                "subdomain_prefix": "",
                "is_subdomain": False,
                "is_ip": True
            }
        except ValueError:
            pass

        two_part_suffixes = {
            "ac.id", "co.id", "go.id", "sch.id", "or.id", "net.id", "web.id", "my.id", "biz.id", "mil.id",
            "co.uk", "gov.uk", "org.uk", "ac.uk", "ltd.uk", "me.uk", "net.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au",
            "com.sg", "edu.sg", "gov.sg", "org.sg", "per.sg", "net.sg",
            "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp",
            "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
            "com.br", "net.br", "org.br", "gov.br", "edu.br",
            "com.mx", "gob.mx", "edu.mx", "org.mx",
            "co.za", "gov.za", "org.za", "ac.za",
            "com.cn", "gov.cn", "org.cn", "edu.cn",
            "co.in", "gov.in", "org.in", "ac.in", "edu.in"
        }

        parts = fqdn.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_suffixes:
            root_domain = ".".join(parts[-3:])
            subdomain_parts = parts[:-3]
        elif len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            subdomain_parts = parts[:-2]
        else:
            root_domain = fqdn
            subdomain_parts = []

        subdomain_prefix = ".".join(subdomain_parts)
        is_subdomain = bool(subdomain_prefix)

        return {
            "target_fqdn": fqdn,
            "root_domain": root_domain,
            "subdomain_prefix": subdomain_prefix,
            "is_subdomain": is_subdomain,
            "is_ip": False
        }

    def _is_cloudflare_ip(self, ip_str: str) -> bool:
        """Memeriksa apakah IP berada dalam subnet resmi Cloudflare"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cidr in CLOUDFLARE_IPV4_RANGES:
                if ip_obj in cidr:
                    return True
        except Exception:
            pass
        return False

    def _identify_cdn_provider(self, ip_str: str, isp_str: str = "", headers: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Identifikasi penyedia CDN / WAF berbasis IP subnet, ISP GeoIP, dan HTTP response headers."""
        if self._is_cloudflare_ip(ip_str):
            return True, "Cloudflare CDN / WAF"

        isp_lower = (isp_str or "").lower()
        if "cloudflare" in isp_lower:
            return True, "Cloudflare CDN / WAF"
        if "akamai" in isp_lower:
            return True, "Akamai Edge CDN"
        if "fastly" in isp_lower:
            return True, "Fastly CDN"
        if "amazon" in isp_lower or "cloudfront" in isp_lower:
            return True, "AWS CloudFront"
        if "imperva" in isp_lower or "incapsula" in isp_lower:
            return True, "Imperva Incapsula"
        if "sucuri" in isp_lower:
            return True, "Sucuri CloudProxy"
        if "alibaba" in isp_lower:
            return True, "Alibaba Cloud CDN"
        if "google" in isp_lower and ("google cloud" in isp_lower or "google llc" in isp_lower):
            return True, "Google Cloud Platform / CDN"

        if headers:
            h_str = str(headers).lower()
            if "cf-ray" in h_str or "server: cloudflare" in h_str:
                return True, "Cloudflare CDN / WAF"
            if "x-amz-cf-id" in h_str:
                return True, "AWS CloudFront"
            if "x-akamai-transformed" in h_str:
                return True, "Akamai Edge CDN"
            if "x-fastly-request-id" in h_str:
                return True, "Fastly CDN"

        return False, "Direct Origin IP"

    def _decode_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Mendekode header dan payload JWT (Base64 URL decode) tanpa perlu verifikasi secret signature."""
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                def b64_decode(s: str) -> Dict[str, Any]:
                    rem = len(s) % 4
                    if rem > 0:
                        s += "=" * (4 - rem)
                    decoded = base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
                    return json.loads(decoded)

                header = b64_decode(parts[0])
                payload = b64_decode(parts[1])

                exp_val = payload.get("exp")
                exp_formatted = "N/A"
                is_expired = None
                if isinstance(exp_val, (int, float)):
                    try:
                        exp_dt = datetime.fromtimestamp(exp_val, timezone.utc)
                        exp_formatted = exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        is_expired = datetime.now(timezone.utc) > exp_dt
                    except Exception:
                        pass

                return {
                    "is_jwt": True,
                    "algorithm": header.get("alg", "Unknown"),
                    "token_type": header.get("typ", "JWT"),
                    "issuer": payload.get("iss", "N/A"),
                    "subject": payload.get("sub", "N/A"),
                    "audience": payload.get("aud", "N/A"),
                    "roles": payload.get("roles") or payload.get("role") or payload.get("scope") or "N/A",
                    "issued_at": payload.get("iat", "N/A"),
                    "expiration": exp_formatted,
                    "is_expired": is_expired,
                    "raw_payload_preview": payload
                }
            except Exception:
                pass
        return None

    def _extract_page_metadata(self, html_content: str) -> Dict[str, Any]:
        """Ekstraksi Title, Meta Description, Keywords, Generator, OpenGraph, dan Email Scraping"""
        meta = {
            "title": "",
            "description": "",
            "keywords": "",
            "generator": "",
            "og_title": "",
            "og_description": "",
            "emails_found": []
        }
        if not html_content:
            return meta

        title_match = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            meta["title"] = " ".join(title_match.group(1).split())

        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', html_content, re.IGNORECASE)
        if desc_match:
            meta["description"] = desc_match.group(1).strip()

        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']', html_content, re.IGNORECASE)
        if gen_match:
            meta["generator"] = gen_match.group(1).strip()

        og_title_match = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\'](.*?)["\']', html_content, re.IGNORECASE)
        if og_title_match:
            meta["og_title"] = og_title_match.group(1).strip()

        raw_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content)
        valid_emails = set()
        for em in raw_emails:
            clean_em = em.strip(".,;:\"'()[]{}").lower()
            if len(clean_em) < 60 and not clean_em.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".js", ".css")):
                valid_emails.add(clean_em)
        meta["emails_found"] = sorted(list(valid_emails))[:15]
        return meta

    def _grade_security_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Menilai dan memberikan grade (A+ s/d F) kepatuhan HTTP Security Headers OWASP"""
        score = 0
        total_max = 100
        analysis = {}

        h_map = {k.lower(): v for k, v in headers.items()}

        # 1. HSTS (25 Poin)
        hsts = h_map.get("strict-transport-security")
        if hsts:
            if "max-age=" in hsts:
                score += 25
                analysis["Strict-Transport-Security"] = {"status": "PASS", "score": 25, "value": hsts}
            else:
                score += 10
                analysis["Strict-Transport-Security"] = {"status": "WARN", "score": 10, "value": hsts, "reason": "max-age tidak dikonfigurasi"}
        else:
            analysis["Strict-Transport-Security"] = {"status": "FAIL", "score": 0, "reason": "HSTS header tidak ditemukan"}

        # 2. CSP (25 Poin)
        csp = h_map.get("content-security-policy")
        if csp:
            score += 25
            analysis["Content-Security-Policy"] = {"status": "PASS", "score": 25, "value": csp[:60] + "..." if len(csp) > 60 else csp}
        else:
            analysis["Content-Security-Policy"] = {"status": "FAIL", "score": 0, "reason": "CSP header tidak ditemukan"}

        # 3. X-Frame-Options (15 Poin)
        xfo = h_map.get("x-frame-options")
        if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
            score += 15
            analysis["X-Frame-Options"] = {"status": "PASS", "score": 15, "value": xfo}
        else:
            analysis["X-Frame-Options"] = {"status": "FAIL", "score": 0, "reason": "Clickjacking protection tidak aktif"}

        # 4. X-Content-Type-Options (15 Poin)
        xcto = h_map.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            score += 15
            analysis["X-Content-Type-Options"] = {"status": "PASS", "score": 15, "value": xcto}
        else:
            analysis["X-Content-Type-Options"] = {"status": "FAIL", "score": 0, "reason": "MIME-sniffing protection tidak aktif"}

        # 5. Referrer-Policy (10 Poin)
        rp = h_map.get("referrer-policy")
        if rp:
            score += 10
            analysis["Referrer-Policy"] = {"status": "PASS", "score": 10, "value": rp}
        else:
            analysis["Referrer-Policy"] = {"status": "FAIL", "score": 0, "reason": "Referrer-Policy tidak disetel"}

        # 6. Permissions-Policy (10 Poin)
        pp = h_map.get("permissions-policy") or h_map.get("feature-policy")
        if pp:
            score += 10
            analysis["Permissions-Policy"] = {"status": "PASS", "score": 10, "value": pp[:50] + "..." if len(pp) > 50 else pp}
        else:
            analysis["Permissions-Policy"] = {"status": "FAIL", "score": 0, "reason": "Permissions-Policy tidak disetel"}

        if score >= 90:
            grade = "A+" if score == 100 else "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 25:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "max_score": total_max,
            "grade": grade,
            "details": analysis
        }

    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass
        return None

    def _extract_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Ekstraksi metadata sertifikat SSL/TLS, validasi masa aktif, Subject Alternative Names (SANs) & Wildcard."""
        cert_info = {
            "has_ssl": False,
            "tls_version": None,
            "cipher": None,
            "issuer": {},
            "subject": {},
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "is_expired": False,
            "serial_number": None,
            "san_list": [],
            "wildcard_domains": [],
            "multi_host_domains": [],
            "has_wildcard": False
        }

        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False

        sni_hostname = None if is_ip else domain

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()

                    cert_info["has_ssl"] = True
                    cert_info["tls_version"] = tls_ver or "TLS"
                    cert_info["cipher"] = f"{cipher[0]} ({cipher[1]})" if cipher else "Unknown"

                    if cert:
                        for item in cert.get("issuer", ()):
                            for k, v in item:
                                cert_info["issuer"][k] = v
                        for item in cert.get("subject", ()):
                            for k, v in item:
                                cert_info["subject"][k] = v

                        not_before = cert.get("notBefore", "")
                        not_after = cert.get("notAfter", "")
                        cert_info["valid_from"] = not_before
                        cert_info["valid_until"] = not_after
                        cert_info["serial_number"] = cert.get("serialNumber", "")

                        exp_dt = self._parse_cert_date(not_after)
                        if exp_dt:
                            now = datetime.now(timezone.utc)
                            diff = (exp_dt - now).days
                            cert_info["days_remaining"] = diff
                            cert_info["is_expired"] = diff < 0

                        sans = []
                        wildcards = []
                        for san_type, san_val in cert.get("subjectAltName", ()):
                            if san_type.lower() == "dns":
                                clean_val = san_val.lower().strip()
                                sans.append(clean_val)
                                if clean_val.startswith("*."):
                                    wildcards.append(clean_val)

                        unique_sans = sorted(list(set(sans)))
                        cert_info["san_list"] = unique_sans
                        cert_info["wildcard_domains"] = wildcards
                        cert_info["has_wildcard"] = len(wildcards) > 0
                        cert_info["multi_host_domains"] = [s for s in unique_sans if not s.startswith("*.")][:25]
        except (ssl.SSLError, socket.error, socket.timeout, OSError) as e:
            self.logger.debug(f"SSL connect failed on {domain}: {e}")
            try:
                ctx_fallback = ssl._create_unverified_context()
                with socket.create_connection((domain, 443), timeout=4.0) as sock:
                    with ctx_fallback.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                        cert_info["has_ssl"] = True
                        cert_info["tls_version"] = ssock.version() or "TLS (Unverified/Self-Signed)"
                        c = ssock.cipher()
                        cert_info["cipher"] = f"{c[0]} ({c[1]})" if c else "Unknown"
            except Exception:
                pass

        return cert_info

    async def _query_crtsh_subdomains(self, domain: str) -> Set[str]:
        """Query Certificate Transparency Logs via crt.sh API"""
        subdomains = set()
        if not self.async_client or not domain or domain == "N/A":
            return subdomains

        custom_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*"
        }

        queries = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q={domain}&output=json"
        ]

        for url in queries:
            try:
                status, text, _ = await self.async_client.get(url, headers=custom_headers, timeout=6)
                if status == 200 and text.strip().startswith("["):
                    entries = json.loads(text)
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            clean_sub = sub.strip().lower()
                            if clean_sub.startswith("*."):
                                clean_sub = clean_sub[2:]
                            if (clean_sub.endswith("." + domain) or clean_sub == domain) and re.match(r"^[a-z0-9.-]+$", clean_sub):
                                subdomains.add(clean_sub)
                    if subdomains:
                        break
            except Exception as e:
                self.logger.debug(f"crt.sh query error for {url}: {e}")
        return subdomains

    async def _query_hackertarget_subdomains(self, domain: str) -> Set[str]:
        """Query HackerTarget Passive DNS Hostsearch API"""
        subdomains = set()
        if not self.async_client or not domain:
            return subdomains
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            status, text, _ = await self.async_client.get(url, timeout=5)
            if status == 200 and text and "error" not in text.lower():
                for line in text.strip().split("\n"):
                    if "," in line:
                        host = line.split(",")[0].strip().lower()
                        if host.endswith("." + domain) or host == domain:
                            subdomains.add(host)
        except Exception:
            pass
        return subdomains

    async def _query_alienvault_subdomains(self, domain: str) -> Set[str]:
        """Query AlienVault OTX Passive DNS API"""
        subdomains = set()
        if not self.async_client or not domain:
            return subdomains
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            status, text, _ = await self.async_client.get(url, timeout=5)
            if status == 200 and text.strip().startswith("{"):
                data = json.loads(text)
                for entry in data.get("passive_dns", []):
                    h = entry.get("hostname", "").strip().lower()
                    if h and (h.endswith("." + domain) or h == domain):
                        subdomains.add(h)
        except Exception:
            pass
        return subdomains

    async def _resolve_single_subdomain(self, sub: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """Resolusi cepat non-blocking alamat IP dan status CDN/WAF untuk satu subdomain."""
        async with semaphore:
            loop = asyncio.get_running_loop()
            ip_val = None
            try:
                addr_info = await loop.getaddrinfo(sub, 80)
                if addr_info:
                    ip_val = addr_info[0][4][0]
            except Exception:
                pass

            is_cdn = False
            cdn_name = "Direct Origin IP"
            if ip_val:
                is_cdn, cdn_name = self._identify_cdn_provider(ip_val)

            return {
                "subdomain": sub,
                "ip": ip_val or "Unresolved / Inactive",
                "is_active": bool(ip_val),
                "is_cdn": is_cdn,
                "cdn_provider": cdn_name
            }

    async def _discover_subdomains_passive(self, root_domain: str, target_fqdn: str) -> Dict[str, Any]:
        """
        Mesin Enumerasi Subdomain Pasif Multi-Source:
        Menggabungkan crt.sh CT Logs, HackerTarget Passive DNS, dan AlienVault OTX,
        dilengkapi deduplikasi dan resolusi IP paralel cepat.
        """
        subdomain_report = {
            "root_domain": root_domain,
            "target_fqdn": target_fqdn,
            "total_found": 0,
            "active_count": 0,
            "sources_queried": ["crt.sh CT Logs", "HackerTarget Passive DNS", "AlienVault OTX"],
            "subdomains": []
        }

        if not root_domain or root_domain == "N/A":
            return subdomain_report

        tasks = [
            self._query_crtsh_subdomains(root_domain),
            self._query_hackertarget_subdomains(root_domain),
            self._query_alienvault_subdomains(root_domain)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged_subs: Set[str] = set()
        for res in results:
            if isinstance(res, set):
                merged_subs.update(res)

        # Selalu sertakan target FQDN dan root domain
        if target_fqdn and (target_fqdn.endswith("." + root_domain) or target_fqdn == root_domain):
            merged_subs.add(target_fqdn)
        merged_subs.add(root_domain)

        sorted_subs = sorted(list(merged_subs))
        subdomain_report["total_found"] = len(sorted_subs)

        # Resolusi paralel dengan semaphore 25 workers (dibatasi 40 subdomain teratas untuk efisiensi)
        sub_sample = sorted_subs[:40]
        sem = asyncio.Semaphore(25)
        res_tasks = [self._resolve_single_subdomain(sub, sem) for sub in sub_sample]
        resolved_results = await asyncio.gather(*res_tasks, return_exceptions=True)

        final_sub_list = []
        active_cnt = 0
        for item in resolved_results:
            if isinstance(item, dict):
                item["is_target_fqdn"] = (item["subdomain"] == target_fqdn)
                if item["is_active"]:
                    active_cnt += 1
                final_sub_list.append(item)

        subdomain_report["active_count"] = active_cnt
        subdomain_report["subdomains"] = final_sub_list
        return subdomain_report

    async def _probe_auth_and_tokens(
        self,
        base_url: str,
        cookies_captured: Dict[str, Any],
        headers: Dict[str, Any],
        html_content: str
    ) -> Dict[str, Any]:
        """
        Granular Authentication & Token Fingerprinting:
        - Deteksi Laravel Sanctum (Stateful SPA) vs Laravel Session Tradisional via probe /sanctum/csrf-cookie.
        - Deteksi Stateless Token & Regex Scan JWT di headers, cookies, dan HTML body dengan payload claim decoding.
        - Comprehensive Cookie Flag Auditing (HttpOnly, Secure, SameSite).
        """
        auth_intel = {
            "auth_architecture": "Standard / Stateless (No Auth Cookie)",
            "auth_types_detected": [],
            "laravel_sanctum": {
                "is_sanctum_active": False,
                "sanctum_endpoint": None,
                "mode": "Not Detected"
            },
            "jwt_tokens": [],
            "session_cookies": [],
            "cookie_audit": {
                "total_cookies": len(cookies_captured),
                "httponly_all": True,
                "secure_all": True,
                "samesite": "Not Configured",
                "cookie_details": []
            }
        }

        # 1. Probing Pasif Laravel Sanctum CSRF Endpoint
        if self.async_client:
            sanctum_endpoints = ["/sanctum/csrf-cookie", "/api/sanctum/csrf-cookie"]
            for ep in sanctum_endpoints:
                try:
                    probe_url = urllib.parse.urljoin(base_url, ep)
                    st, _, resp_headers = await self.async_client.get(probe_url, timeout=4)
                    cookie_hdrs = str(resp_headers.get("set-cookie", "")).lower()
                    if st in (200, 204) and ("xsrf-token" in cookie_hdrs or "laravel" in cookie_hdrs or st == 204):
                        auth_intel["laravel_sanctum"]["is_sanctum_active"] = True
                        auth_intel["laravel_sanctum"]["sanctum_endpoint"] = ep
                        auth_intel["laravel_sanctum"]["mode"] = "Laravel Sanctum (Stateful SPA Mode)"
                        auth_intel["auth_types_detected"].append("Laravel Sanctum (Stateful SPA)")
                        break
                except Exception:
                    pass

        # 2. Periksa Cookies untuk Kerangka Kerja & Sesi
        framework_cookie_map = {
            "laravel_session": "Laravel Session (Cookie-based Traditional)",
            "xsrf-token": "Laravel / SPA CSRF Token",
            "sessionid": "Django Session",
            "csrftoken": "Django CSRF",
            "phpsessid": "PHP Native Session",
            "asp.net_sessionid": "ASP.NET Session",
            ".aspnetcore.cookies": "ASP.NET Core Identity Session",
            ".aspnetcore.antiforgery": "ASP.NET Core Antiforgery",
            "connect.sid": "Express / Node.js Session",
            "jsessionid": "Java / Spring Boot Session",
            "session": "Flask / Python Session",
            "_session_id": "Ruby on Rails Session"
        }

        for c_name, c_val in cookies_captured.items():
            c_name_lower = c_name.lower()
            val_str = str(c_val)

            matched_framework = None
            for key_pattern, fw_name in framework_cookie_map.items():
                if key_pattern in c_name_lower:
                    matched_framework = fw_name
                    auth_intel["auth_types_detected"].append(fw_name)
                    auth_intel["session_cookies"].append({"name": c_name, "framework": fw_name})
                    break

        # 3. Regex Scanner untuk JSON Web Token (JWT) di Headers, Cookies, dan HTML Body
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        scanned_jwt_tokens = set()

        # Scan di Cookies
        for c_name, c_val in cookies_captured.items():
            for m in jwt_pattern.findall(str(c_val)):
                if m not in scanned_jwt_tokens:
                    scanned_jwt_tokens.add(m)
                    decoded = self._decode_jwt_token(m)
                    if decoded:
                        decoded["found_in"] = f"Cookie '{c_name}'"
                        auth_intel["jwt_tokens"].append(decoded)
                        auth_intel["auth_types_detected"].append("JSON Web Token (JWT)")

        # Scan di Headers
        for h_k, h_v in headers.items():
            for m in jwt_pattern.findall(str(h_v)):
                if m not in scanned_jwt_tokens:
                    scanned_jwt_tokens.add(m)
                    decoded = self._decode_jwt_token(m)
                    if decoded:
                        decoded["found_in"] = f"HTTP Header '{h_k}'"
                        auth_intel["jwt_tokens"].append(decoded)
                        auth_intel["auth_types_detected"].append("JSON Web Token (JWT)")

        # Scan di HTML / JavaScript Body
        if html_content:
            for m in jwt_pattern.findall(html_content):
                if m not in scanned_jwt_tokens:
                    scanned_jwt_tokens.add(m)
                    decoded = self._decode_jwt_token(m)
                    if decoded:
                        decoded["found_in"] = "HTML Page Body / Embedded Script"
                        auth_intel["jwt_tokens"].append(decoded)
                        auth_intel["auth_types_detected"].append("JSON Web Token (JWT)")

        # 4. Comprehensive Cookie Flag Auditing
        set_cookie_raw = []
        for h_k, h_v in headers.items():
            if h_k.lower() == "set-cookie":
                set_cookie_raw.append(h_v)

        all_set_cookies = " ".join(set_cookie_raw).lower()
        if set_cookie_raw:
            auth_intel["cookie_audit"]["httponly_all"] = "httponly" in all_set_cookies
            auth_intel["cookie_audit"]["secure_all"] = "secure" in all_set_cookies
            if "samesite=strict" in all_set_cookies:
                auth_intel["cookie_audit"]["samesite"] = "Strict"
            elif "samesite=lax" in all_set_cookies:
                auth_intel["cookie_audit"]["samesite"] = "Lax"
            elif "samesite=none" in all_set_cookies:
                auth_intel["cookie_audit"]["samesite"] = "None"

        # Tentukan ringkasan arsitektur autentikasi
        if auth_intel["laravel_sanctum"]["is_sanctum_active"]:
            auth_intel["auth_architecture"] = "Laravel Sanctum (Stateful SPA Mode)"
        elif auth_intel["jwt_tokens"]:
            auth_intel["auth_architecture"] = "Stateless JWT Authentication"
        elif auth_intel["session_cookies"]:
            auth_intel["auth_architecture"] = f"Stateful Session ({auth_intel['session_cookies'][0]['framework']})"
        else:
            auth_intel["auth_architecture"] = "Standard / Stateless (Public Access)"

        auth_intel["auth_types_detected"] = sorted(list(set(auth_intel["auth_types_detected"])))
        return auth_intel

    def _detect_waf(self, headers: Dict[str, Any], html_content: str) -> List[str]:
        """Mendeteksi Firewall Aplikasi Web (WAF) & Cloud Security Gateway"""
        wafs = []
        headers_str = str(headers).lower()
        html_lower = html_content.lower()

        if "cf-ray" in headers_str or "cloudflare" in headers_str or "attention required! | cloudflare" in html_lower:
            wafs.append("Cloudflare WAF")
        if "x-amzn-requestid" in headers_str or "awselb" in headers_str or "aws-waf" in headers_str:
            wafs.append("AWS WAF / Shield")
        if "akamai" in headers_str or "x-akamai-transformed" in headers_str:
            wafs.append("Akamai Kona WAF")
        if "x-sucuri-id" in headers_str or "sucuri" in headers_str:
            wafs.append("Sucuri CloudProxy")
        if "x-iinfo" in headers_str or "incap_ses" in headers_str or "visid_incap" in headers_str:
            wafs.append("Imperva Incapsula")
        if "mod_security" in headers_str or "modsecurity" in headers_str or "owasp_crs" in html_lower:
            wafs.append("ModSecurity (OWASP CRS)")
        if "generated by wordfence" in html_lower or "wordfence" in headers_str:
            wafs.append("Wordfence Security WAF")
        if "bigip" in headers_str or ("ts" in headers_str and "f5" in headers_str):
            wafs.append("F5 BIG-IP ASM")

        return list(set(wafs))

    def _detect_tech_stack(self, headers: Dict[str, Any], html_content: str) -> Dict[str, List[str]]:
        """Mendeteksi Web Server, Bahasa Pemrograman, Framework, dan CMS (WhatWeb Engine)"""
        stack = {
            "web_servers": [],
            "programming_languages": [],
            "backend_frameworks": [],
            "frontend_libraries": [],
            "cms_and_platforms": [],
            "waf_and_security": [],
            "analytics_and_cdn": []
        }

        headers_str = str(headers).lower()
        html_lower = html_content.lower()

        # 1. Web Servers
        server_hdr = str(headers.get("server", "")).lower()
        if "nginx" in server_hdr or "nginx" in headers_str:
            stack["web_servers"].append("Nginx")
        if "apache" in server_hdr or "apache" in headers_str:
            stack["web_servers"].append("Apache HTTP Server")
        if "litespeed" in server_hdr:
            stack["web_servers"].append("LiteSpeed Web Server")
        if "caddy" in server_hdr:
            stack["web_servers"].append("Caddy")
        if "microsoft-iis" in server_hdr or "iis" in server_hdr:
            stack["web_servers"].append("Microsoft IIS")
        if "openresty" in server_hdr:
            stack["web_servers"].append("OpenResty")

        # 2. Programming Languages / Runtimes
        x_powered = str(headers.get("x-powered-by", "")).lower()
        if "php" in x_powered or "php" in headers_str or ".php" in html_lower:
            php_ver = re.search(r'php/([0-9.]+)', x_powered or headers_str)
            stack["programming_languages"].append(f"PHP {php_ver.group(1)}" if php_ver else "PHP")
        if "python" in x_powered or "gunicorn" in server_hdr or "uvicorn" in server_hdr:
            stack["programming_languages"].append("Python")
        if "express" in x_powered or "node" in x_powered or "next.js" in x_powered:
            stack["programming_languages"].append("Node.js / JavaScript")
        if "asp.net" in x_powered or "aspnet" in headers_str:
            stack["programming_languages"].append("C# / ASP.NET")
        if "ruby" in x_powered or "phusion passenger" in server_hdr:
            stack["programming_languages"].append("Ruby")
        if "servlet" in headers_str or "tomcat" in server_hdr or "jetty" in server_hdr:
            stack["programming_languages"].append("Java / JVM")

        # 3. Backend Frameworks
        if "laravel" in headers_str or "laravel_session" in headers_str or "xsrf-token" in headers_str:
            stack["backend_frameworks"].append("Laravel Framework")
        if "django" in headers_str or "csrftoken" in headers_str:
            stack["backend_frameworks"].append("Django")
        if "spring" in headers_str or "jsessionid" in headers_str:
            stack["backend_frameworks"].append("Spring Boot")
        if "rails" in headers_str or "_session_id" in headers_str:
            stack["backend_frameworks"].append("Ruby on Rails")
        if "next" in headers_str or "__next" in html_lower:
            stack["backend_frameworks"].append("Next.js")
        if "nuxt" in headers_str or "__nuxt" in html_lower:
            stack["backend_frameworks"].append("Nuxt.js")

        # 4. Frontend Libraries
        if "react" in html_lower or "_reactroot" in html_lower or "react-dom" in html_lower:
            stack["frontend_libraries"].append("React")
        if "vue" in html_lower or "v-data" in html_lower or "vuejs" in html_lower:
            stack["frontend_libraries"].append("Vue.js")
        if "alpine" in html_lower or "x-data" in html_lower:
            stack["frontend_libraries"].append("Alpine.js")
        if "tailwind" in html_lower:
            stack["frontend_libraries"].append("Tailwind CSS")
        if "bootstrap" in html_lower:
            stack["frontend_libraries"].append("Bootstrap")
        if "jquery" in html_lower or "jquery" in headers_str:
            stack["frontend_libraries"].append("jQuery")

        # 5. CMS & Platforms
        if "wp-content" in html_lower or "wp-includes" in html_lower or "wordpress" in headers_str:
            stack["cms_and_platforms"].append("WordPress")
        if "drupal" in html_lower or "drupal" in headers_str:
            stack["cms_and_platforms"].append("Drupal")
        if "joomla" in html_lower or "joomla" in headers_str:
            stack["cms_and_platforms"].append("Joomla")
        if "moodle" in html_lower:
            stack["cms_and_platforms"].append("Moodle LMS")

        # 6. WAF & Security
        stack["waf_and_security"] = self._detect_waf(headers, html_content)

        for k in stack:
            stack[k] = sorted(list(set(stack[k])))
        return stack

    def _detect_origin_ip_leak(self, domain: str, dns_records: Dict[str, Any], server_geoip: Dict[str, Any]) -> Dict[str, Any]:
        """
        Otomasi Deteksi Kebocoran Origin IP (Cloudflare / CDN Bypass Heuristic):
        Mencocokkan IP di MX, SPF, TXT, dan direct origin subdomains dengan IP Cloudflare.
        """
        leak_report = {
            "is_behind_cdn": False,
            "cdn_provider": None,
            "leak_detected": False,
            "leaked_ips": [],
            "summary": "No CDN leak detected."
        }

        current_ip = server_geoip.get("ip") or (dns_records.get("A", [])[0] if dns_records.get("A") else "")
        isp = server_geoip.get("isp", "")
        asn = server_geoip.get("asn", "")

        is_cf = self._is_cloudflare_ip(current_ip) or "cloudflare" in isp.lower() or "as13335" in str(asn).lower()
        if is_cf:
            leak_report["is_behind_cdn"] = True
            leak_report["cdn_provider"] = "Cloudflare CDN / WAF"
        elif any(cdn in isp.lower() for cdn in ["akamai", "fastly", "incapsula", "imperva"]):
            leak_report["is_behind_cdn"] = True
            leak_report["cdn_provider"] = isp

        if not leak_report["is_behind_cdn"]:
            leak_report["summary"] = "Server langsung terhubung ke IP publik (Tidak menggunakan CDN/Cloudflare)."
            return leak_report

        candidate_ips = []

        # 1. Cek Resolusi MX Record
        for mx in dns_records.get("MX", []):
            parts = mx.split()
            mx_host = parts[-1].rstrip(".") if parts else mx.rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                if mx_ip and not self._is_cloudflare_ip(mx_ip) and mx_ip != "0.0.0.0":
                    candidate_ips.append({
                        "ip": mx_ip,
                        "source": f"MX Record ({mx_host})",
                        "confidence": "HIGH",
                        "risk": "Bypasses Cloudflare DDoS & WAF protections via Mail Server Origin."
                    })
            except (socket.gaierror, socket.timeout, OSError):
                pass

        # 2. Cek SPF Record dalam TXT
        for txt in dns_records.get("TXT", []):
            if "v=spf1" in txt.lower():
                ip4_matches = re.findall(r'ip4:([0-9.]+)', txt)
                for ip4 in ip4_matches:
                    if not self._is_cloudflare_ip(ip4) and ip4 != "0.0.0.0":
                        candidate_ips.append({
                            "ip": ip4,
                            "source": "TXT SPF Record (v=spf1 ip4:)",
                            "confidence": "HIGH",
                            "risk": "Origin IP tercantum secara publik di SPF Record DNS."
                        })

        # 3. Cek Subdomain Origin yang Sering Tidak di-Proxy
        common_direct_subs = ["mail", "direct", "origin", "ftp", "cpanel", "direct-connect", "admin", "dev", "staging"]
        for sub in common_direct_subs:
            test_host = f"{sub}.{domain}"
            try:
                sub_ip = socket.gethostbyname(test_host)
                if sub_ip and not self._is_cloudflare_ip(sub_ip) and sub_ip != "0.0.0.0":
                    candidate_ips.append({
                        "ip": sub_ip,
                        "source": f"Direct Subdomain ({test_host})",
                        "confidence": "CRITICAL",
                        "risk": "Subdomain internal menunjuk langsung ke backend server tanpa proteksi Cloudflare."
                    })
            except (socket.gaierror, socket.timeout, OSError):
                pass

        seen_ips = set()
        unique_leaks = []
        for cand in candidate_ips:
            if cand["ip"] not in seen_ips and cand["ip"] != current_ip:
                seen_ips.add(cand["ip"])
                unique_leaks.append(cand)

        if unique_leaks:
            leak_report["leak_detected"] = True
            leak_report["leaked_ips"] = unique_leaks
            leak_report["summary"] = f"Terdeteksi {len(unique_leaks)} potensi kebocoran Origin IP di balik CDN Cloudflare!"
        else:
            leak_report["summary"] = "Proteksi CDN Cloudflare aktif rapat. Tidak ditemukan kebocoran origin IP di MX/SPF/Subdomain."

        return leak_report

    async def _query_wayback_endpoints(self, target_fqdn: str) -> List[str]:
        """Query Wayback Machine CDX API untuk menemukan endpoint tersembunyi yang pernah terindeks."""
        paths = []
        if not self.async_client or not target_fqdn:
            return paths
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={target_fqdn}/*&output=json&fl=original&collapse=urlkey&limit=30"
            status, text, _ = await self.async_client.get(url, timeout=5)
            if status == 200 and text.strip().startswith("["):
                rows = json.loads(text)
                if len(rows) > 1:
                    for r in rows[1:]:
                        if r and isinstance(r[0], str):
                            orig_url = r[0]
                            parsed = urllib.parse.urlparse(orig_url)
                            p = parsed.path
                            if p and p != "/" and not p.endswith((".jpg", ".png", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".woff2")):
                                paths.append(p)
        except Exception:
            pass
        return sorted(list(set(paths)))[:15]

    async def _probe_single_path(
        self,
        base_url: str,
        path: str,
        desc: str,
        default_sev: str,
        file_type: str,
        baseline_info: Dict[str, Any],
        semaphore: asyncio.Semaphore
    ) -> Optional[Dict[str, Any]]:
        """Probing satu endpoint dengan kalibrasi Soft-404 baseline & content-type verification."""
        async with semaphore:
            probe_url = urllib.parse.urljoin(base_url, path)
            try:
                status, body, headers = await self.async_client.get(probe_url, timeout=6)
                if status in (200, 301, 302, 401, 403):
                    is_real = True
                    content_len = len(body)
                    assigned_sev = default_sev
                    body_lower = body.lower()
                    content_type = str(headers.get("content-type", "")).lower()

                    if status in (401, 403):
                        assigned_sev = "BLOCKED"
                        status_phrase = http.client.responses.get(status, "Forbidden")
                        desc = f"{desc} (Akses Diblokir [{status_phrase}])"

                    elif status == 200:
                        is_html = "<!doctype html" in body_lower or "<html" in body_lower or "<head" in body_lower or "<body" in body_lower

                        # A. Soft 404 Check: Bandingkan dengan Baseline Acak
                        if baseline_info.get("status") == 200:
                            current_hash = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
                            if current_hash == baseline_info.get("hash"):
                                is_real = False
                            elif abs(content_len - baseline_info.get("length", 0)) <= 20:
                                is_real = False
                            elif baseline_info.get("title"):
                                p_title_m = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
                                if p_title_m and p_title_m.group(1).strip().lower() == baseline_info.get("title"):
                                    is_real = False

                        # B. Format & Content-Type Validation
                        if is_real:
                            if file_type in ("config", "log", "sql"):
                                if is_html or "text/html" in content_type:
                                    is_real = False
                            elif file_type == "git":
                                if not ("ref: refs/" in body or len(body.strip()) == 40 or "ref:" in body_lower):
                                    is_real = False
                            elif file_type == "phpinfo":
                                if "php version" not in body_lower and "zend engine" not in body_lower:
                                    is_real = False
                            elif file_type == "server-status":
                                if "apache server status" not in body_lower and "server uptime" not in body_lower:
                                    is_real = False
                            elif file_type == "robots":
                                if not any(k in body_lower for k in ["user-agent", "disallow", "allow", "sitemap"]):
                                    is_real = False
                            elif file_type == "sitemap":
                                if not any(k in body_lower for k in ["<urlset", "<sitemapindex", "<url>"]):
                                    is_real = False
                            elif file_type == "security-txt":
                                if not any(k in body_lower for k in ["contact:", "expires:", "encryption:"]):
                                    is_real = False

                    if is_real:
                        return {
                            "path": path,
                            "url": probe_url,
                            "status": status,
                            "status_badge": f"[{status} {http.client.responses.get(status, '')}]".strip(),
                            "description": desc,
                            "severity": assigned_sev,
                            "size_bytes": content_len,
                            "content_type": headers.get("content-type", "Unknown")
                        }
            except Exception:
                pass
            return None

    async def _discover_endpoints_and_paths(self, base_url: str, target_fqdn: str) -> Dict[str, Any]:
        """
        High-Performance Content Discovery & Path Fuzzing Engine:
        - Baseline Soft-404 Calibration
        - Core Tiered Wordlist (~60 critical paths)
        - Wayback Machine CDX Historical Path Mining
        - Concurrency rate limiter (asyncio.Semaphore 25 workers)
        """
        discovery_result = {
            "baseline_calibrated": False,
            "baseline_status": 404,
            "baseline_length": 0,
            "total_probed": 0,
            "total_discovered": 0,
            "cdx_historical_paths_found": [],
            "endpoints": []
        }

        if not self.async_client:
            return discovery_result

        # 1. Soft 404 Baseline Calibration
        random_token = f"patrict-chk-{uuid.uuid4().hex[:12]}.html"
        baseline_url = urllib.parse.urljoin(base_url, f"/{random_token}")
        baseline_info = {
            "status": 404,
            "length": 0,
            "hash": "",
            "title": ""
        }

        try:
            b_status, b_body, _ = await self.async_client.get(baseline_url, timeout=5)
            baseline_info["status"] = b_status
            baseline_info["length"] = len(b_body)
            baseline_info["hash"] = hashlib.md5(b_body.encode("utf-8", errors="ignore")).hexdigest()
            t_m = re.search(r"<title>(.*?)</title>", b_body, re.IGNORECASE)
            if t_m:
                baseline_info["title"] = t_m.group(1).strip().lower()
            discovery_result["baseline_calibrated"] = True
            discovery_result["baseline_status"] = b_status
            discovery_result["baseline_length"] = len(b_body)
        except Exception:
            pass

        # 2. Built-in Core Tiered Wordlist (~60 critical paths)
        core_wordlist = [
            # Config & Secrets
            ("/.env", "Environment Secrets / API Keys", "CRITICAL", "config"),
            ("/.env.local", "Local Environment Configuration", "CRITICAL", "config"),
            ("/.env.production", "Production Environment Configuration", "CRITICAL", "config"),
            ("/.env.backup", "Environment Secrets Backup", "CRITICAL", "config"),
            ("/.env.example", "Sample Environment Template", "LOW", "config"),
            ("/.git/HEAD", "Git Repository Metadata Exposure", "CRITICAL", "git"),
            ("/.git/config", "Git Repository Configuration", "CRITICAL", "git"),
            ("/.svn/entries", "SVN Repository Metadata Exposure", "HIGH", "config"),
            ("/web.config", "IIS Web Configuration File", "HIGH", "config"),
            ("/.htaccess", "Apache Server Configuration", "MEDIUM", "config"),
            ("/config.json", "Application Configuration File", "HIGH", "config"),
            ("/configuration.php.bak", "Joomla Configuration Backup", "CRITICAL", "config"),
            ("/wp-config.php.bak", "WordPress Configuration Backup", "CRITICAL", "config"),
            ("/wp-config.old", "WordPress Config Old Backup", "CRITICAL", "config"),

            # Backups & Database Dumps
            ("/backup.sql", "Database Backup Dump", "CRITICAL", "sql"),
            ("/db.sql", "SQL Database Dump", "CRITICAL", "sql"),
            ("/dump.sql", "Database Dump File", "CRITICAL", "sql"),
            ("/database.sqlite", "SQLite Database File", "CRITICAL", "sql"),
            ("/db_backup.sql", "Database SQL Backup", "CRITICAL", "sql"),
            ("/backup.zip", "Full Website Backup Archive", "CRITICAL", "config"),
            ("/site.tar.gz", "Site Compressed Backup Archive", "CRITICAL", "config"),
            ("/www.zip", "Web Root Zip Archive", "CRITICAL", "config"),

            # Framework & Logs
            ("/storage/logs/laravel.log", "Laravel Application Error Log", "HIGH", "log"),
            ("/telescope", "Laravel Telescope Debug Dashboard", "HIGH", "admin"),
            ("/horizon", "Laravel Horizon Queue Dashboard", "HIGH", "admin"),
            ("/_ignition/health-check", "Laravel Ignition Error Page", "CRITICAL", "admin"),
            ("/phpinfo.php", "PHP Information & Environment Leak", "HIGH", "phpinfo"),
            ("/info.php", "PHP Info Test Page", "HIGH", "phpinfo"),
            ("/server-status", "Apache Server Status Page", "MEDIUM", "server-status"),
            ("/actuator/health", "Spring Boot Actuator Health", "MEDIUM", "actuator"),
            ("/actuator/env", "Spring Boot Actuator Environment Secrets", "CRITICAL", "actuator"),
            ("/docker-compose.yml", "Docker Compose Infrastructure Setup", "HIGH", "config"),
            ("/Dockerfile", "Docker Container Build File", "HIGH", "config"),

            # Admin & Portals
            ("/admin", "Administrative Portal", "INFO", "admin"),
            ("/administrator", "Administrator Login", "INFO", "admin"),
            ("/login", "User Login Endpoint", "INFO", "admin"),
            ("/dashboard", "Application Dashboard", "INFO", "admin"),
            ("/cpanel", "cPanel Web Hosting Portal", "INFO", "admin"),
            ("/portal", "Web Portal Endpoint", "INFO", "admin"),
            ("/auth/login", "Authentication Login Gateway", "INFO", "admin"),
            ("/backend", "Backend Administration Interface", "INFO", "admin"),

            # API & Documentation
            ("/api/v1", "REST API v1 Root Endpoint", "LOW", "api"),
            ("/api/v2", "REST API v2 Root Endpoint", "LOW", "api"),
            ("/api/documentation", "API Documentation Interface", "LOW", "html-docs"),
            ("/swagger-ui.html", "Swagger API Documentation UI", "LOW", "html-docs"),
            ("/swagger/index.html", "Swagger OpenAPI Index", "LOW", "html-docs"),
            ("/openapi.json", "OpenAPI JSON Specification", "LOW", "json-docs"),
            ("/api-docs", "API Documentation Endpoint", "LOW", "json-docs"),
            ("/graphql", "GraphQL API Endpoint", "INFO", "graphql"),
            ("/graphiql", "GraphiQL Interactive IDE", "MEDIUM", "graphql"),

            # Public Directives & Standard Files
            ("/robots.txt", "Robots Crawler Directives", "INFO", "robots"),
            ("/sitemap.xml", "XML Sitemap", "INFO", "sitemap"),
            ("/.well-known/security.txt", "Security Policy Contact", "INFO", "security-txt"),
            ("/.well-known/apple-app-site-association", "Apple App Site Association", "INFO", "json-docs"),
            ("/.well-known/assetlinks.json", "Android Digital Asset Links", "INFO", "json-docs")
        ]

        # 3. Query Wayback Machine CDX API untuk menemukan endpoint historis tambahan
        cdx_paths = await self._query_wayback_endpoints(target_fqdn)
        discovery_result["cdx_historical_paths_found"] = cdx_paths
        existing_paths = {item[0] for item in core_wordlist}

        for cp in cdx_paths:
            if cp not in existing_paths and len(cp) <= 80:
                core_wordlist.append((cp, "Wayback Machine Historical Indexed Endpoint", "INFO", "cdx-path"))

        discovery_result["total_probed"] = len(core_wordlist)

        # 4. Eksekusi Fuzzing Asynchronous dengan Semaphore 25 workers
        sem = asyncio.Semaphore(25)
        fuzz_tasks = [
            self._probe_single_path(base_url, p, desc, sev, ftype, baseline_info, sem)
            for p, desc, sev, ftype in core_wordlist
        ]
        results = await asyncio.gather(*fuzz_tasks, return_exceptions=True)

        valid_endpoints = []
        for r in results:
            if isinstance(r, dict) and r is not None:
                valid_endpoints.append(r)

        discovery_result["total_discovered"] = len(valid_endpoints)
        discovery_result["endpoints"] = valid_endpoints
        return discovery_result

    def _generate_threat_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Menghasilkan rangkuman ancaman keamanan, tingkat risiko keseluruhan (Threat Score),
        dan rekomendasi mitigasi konkret untuk target web.
        """
        threats = []
        risk_score = 0

        # 1. Security Headers
        sec_grade = results.get("security_headers_grade", {})
        grade = sec_grade.get("grade", "N/A")
        if grade in ("D", "F"):
            risk_score += 25
            threats.append({
                "category": "HTTP Security Headers",
                "severity": "HIGH",
                "title": f"Security Headers Lemah (Grade {grade})",
                "impact": "Web rentan terhadap serangan XSS, Clickjacking, dan MIME-sniffing.",
                "mitigation": "Konfigurasikan CSP, HSTS, X-Frame-Options, dan X-Content-Type-Options."
            })
        elif grade in ("C", "B"):
            risk_score += 10
            threats.append({
                "category": "HTTP Security Headers",
                "severity": "MEDIUM",
                "title": f"Security Headers Belum Lengkap (Grade {grade})",
                "impact": "Beberapa header perlindungan penting belum diaktifkan.",
                "mitigation": "Terapkan rekomendasi header yang hilang."
            })

        # 2. Origin IP Leak
        origin_leak = results.get("origin_ip_leak", {})
        if origin_leak.get("leak_detected"):
            risk_score += 35
            leaks = origin_leak.get("leaked_ips", [])
            threats.append({
                "category": "CDN / Infrastructure Bypass",
                "severity": "CRITICAL",
                "title": f"Kebocoran Origin Server IP ({len(leaks)} IP Terdeteksi)",
                "impact": "Penyerang dapat membypass proteksi WAF & DDoS Cloudflare dengan menyerang IP origin langsung.",
                "mitigation": "Gunakan firewall pada server origin agar hanya menerima traffic dari IP subnet resmi Cloudflare."
            })

        # 3. Sensitive Endpoints Discovered
        endpoints = results.get("content_discovery", {}).get("endpoints", [])
        critical_files = [f for f in endpoints if f.get("severity") == "CRITICAL" and f.get("status") == 200]
        high_files = [f for f in endpoints if f.get("severity") == "HIGH" and f.get("status") == 200]

        if critical_files:
            risk_score += 40
            names = ", ".join([f["path"] for f in critical_files[:3]])
            threats.append({
                "category": "Data Exposure / Secrets Leak",
                "severity": "CRITICAL",
                "title": f"File Konfigurasi / Secret Kritis Terekspos ({names})",
                "impact": "Kunci API, database credentials, atau source code dapat diunduh oleh publik.",
                "mitigation": "Blokir akses publik ke file titik (.) dan file backup pada konfigurasi web server (Nginx/Apache)."
            })
        elif high_files:
            risk_score += 20
            names = ", ".join([f["path"] for f in high_files[:3]])
            threats.append({
                "category": "Information Disclosure",
                "severity": "HIGH",
                "title": f"File Log / Debug Terekspos ({names})",
                "impact": "Informasi stack trace dan environment internal dapat dipelajari penyerang.",
                "mitigation": "Pindahkan folder log ke luar direktori public web root."
            })

        # 4. SSL Expiry
        ssl_data = results.get("ssl_certificate", {})
        days_left = ssl_data.get("days_remaining")
        if ssl_data.get("is_expired"):
            risk_score += 30
            threats.append({
                "category": "SSL/TLS Security",
                "severity": "HIGH",
                "title": "Sertifikat SSL/TLS Telah Kedaluwarsa",
                "impact": "Pengguna akan menerima peringatan keamanan di browser, koneksi berisiko MITM.",
                "mitigation": "Perbarui sertifikat SSL/TLS segera."
            })
        elif days_left is not None and 0 <= days_left < 14:
            risk_score += 10
            threats.append({
                "category": "SSL/TLS Security",
                "severity": "MEDIUM",
                "title": f"Sertifikat SSL/TLS Akan Kedaluwarsa dalam {days_left} hari",
                "impact": "Layanan web berisiko terganggu jika sertifikat tidak diperbarui tepat waktu.",
                "mitigation": "Aktifkan auto-renewal certbot / ACME client."
            })

        # 5. Cookie Security Audit
        auth_data = results.get("auth_intelligence", {})
        cookie_audit = auth_data.get("cookie_audit", {})
        if cookie_audit.get("total_cookies", 0) > 0:
            if not cookie_audit.get("httponly_all") or not cookie_audit.get("secure_all"):
                risk_score += 10
                threats.append({
                    "category": "Session & Cookie Security",
                    "severity": "MEDIUM",
                    "title": "Flag Keamanan Cookie Belum Lengkap (HttpOnly / Secure)",
                    "impact": "Session token dapat dicuri via XSS jika HttpOnly tidak aktif.",
                    "mitigation": "Set flag 'HttpOnly; Secure; SameSite=Lax' pada semua Set-Cookie session."
                })

        if risk_score >= 65:
            overall_risk = "CRITICAL"
        elif risk_score >= 40:
            overall_risk = "HIGH"
        elif risk_score >= 20:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "risk_score": min(100, risk_score),
            "overall_threat_level": overall_risk,
            "total_threats_identified": len(threats),
            "threats": threats
        }

    def _resolve_dns(self, domain: str) -> Dict[str, Any]:
        """Melakukan resolusi DNS record A, AAAA, MX, NS, TXT, CNAME"""
        records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        if not DNS_AVAILABLE:
            try:
                ip = socket.gethostbyname(domain)
                records["A"].append(ip)
            except Exception:
                pass
            return records

        for r_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, r_type, lifetime=4.0)
                for rdata in answers:
                    records[r_type].append(str(rdata))
            except Exception:
                pass

        return records

    async def _get_server_geoip(self, ip: str) -> Dict[str, Any]:
        """Mengambil data GeoIP & Koordinat Server"""
        if not ip or not self.async_client or ip in ("127.0.0.1", "localhost", "0.0.0.0"):
            return {
                "ip": ip or "N/A",
                "country": "Unknown Location / Protected IP",
                "city": "",
                "isp": "Unknown ISP",
                "latitude": "-",
                "longitude": "-",
                "maps_url": ""
            }
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query"
            status, text, _ = await self.async_client.get(url, timeout=5)
            if status == 200:
                data = json.loads(text)
                if data.get("status") == "success":
                    lat, lon = data.get("lat"), data.get("lon")
                    return {
                        "ip": ip,
                        "country": data.get("country") or "Unknown Country",
                        "region": data.get("regionName") or "",
                        "city": data.get("city") or "",
                        "latitude": lat if lat is not None else "-",
                        "longitude": lon if lon is not None else "-",
                        "isp": data.get("isp") or data.get("org") or "Unknown ISP",
                        "organization": data.get("org") or "",
                        "asn": data.get("as") or "",
                        "maps_url": f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else ""
                    }
        except Exception:
            pass

        return {
            "ip": ip,
            "country": "Unknown Location / Protected IP",
            "city": "",
            "isp": "Unknown ISP",
            "latitude": "-",
            "longitude": "-",
            "maps_url": ""
        }

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self._normalize_url(target)
        identity = self._parse_domain_identity(target)
        target_fqdn = identity["target_fqdn"]
        root_domain = identity["root_domain"]

        results = {
            "target_url": url,
            "domain_identity": identity,
            "domain": target_fqdn,
            "root_domain": root_domain,
            "page_metadata": {},
            "http_methods_allowed": [],
            "redirect_chain": [],
            "final_url": url,
            "final_status": 200,
            "security_headers": {},
            "security_headers_grade": {},
            "ssl_certificate": {},
            "passive_subdomains": {},
            "origin_ip_leak": {},
            "auth_intelligence": {},
            "tech_stack": {},
            "content_discovery": {},
            "dns_records": {},
            "server_geoip": {},
            "threat_vulnerability_summary": {},
            "whatweb_summary": ""
        }

        # 1. Resolusi DNS Target FQDN
        dns_data = self._resolve_dns(target_fqdn)
        results["dns_records"] = dns_data

        a_records = dns_data.get("A", [])
        server_ip = a_records[0] if a_records else ""
        if not server_ip and target_fqdn and target_fqdn != "N/A":
            try:
                server_ip = socket.gethostbyname(target_fqdn)
            except Exception:
                server_ip = ""

        # 2. Resolusi GeoIP & Koordinat Server
        if server_ip:
            results["server_geoip"] = await self._get_server_geoip(server_ip)

        # 3. Ekstraksi Metadata Sertifikat SSL/TLS & SANs
        results["ssl_certificate"] = self._extract_ssl_certificate(target_fqdn)

        # 4. Mesin Enumerasi Subdomain Pasif Multi-Source (crt.sh, HackerTarget, AlienVault)
        if not identity.get("is_ip"):
            results["passive_subdomains"] = await self._discover_subdomains_passive(root_domain, target_fqdn)

        # 5. Otomasi Deteksi Kebocoran Origin IP (Cloudflare / CDN Bypass)
        results["origin_ip_leak"] = self._detect_origin_ip_leak(target_fqdn, dns_data, results["server_geoip"])

        if not self.async_client:
            return self.success_response(results, "Analisis DNS & SSL Selesai.")

        # 6. Analisis HTTP Methods (OPTIONS & HEAD)
        try:
            status, _, headers = await self.async_client.options(url, timeout=5)
            allow_header = headers.get("allow", "") or headers.get("Allow", "")
            if allow_header:
                results["http_methods_allowed"] = [m.strip() for m in allow_header.split(",")]
        except Exception:
            pass

        # 7. Lacak Jalur Redirect (Redirect Chains) & Ambil Response Body
        redirect_chain = []
        html_content = ""
        final_headers = {}
        cookies_captured = {}

        try:
            session = await self.async_client.get_session()
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as response:
                for resp in response.history:
                    redirect_chain.append({
                        "status_code": resp.status,
                        "url": str(resp.url),
                        "reason": getattr(resp, "reason", "")
                    })

                results["final_url"] = str(response.url)
                results["final_status"] = response.status
                final_headers = dict(response.headers)

                for k, v in response.cookies.items():
                    cookies_captured[k] = v.value

                html_content = await response.text(errors="ignore")
        except Exception as e:
            self.logger.warning(f"Error requesting target URL: {e}")
            redirect_chain.append({"status_code": 0, "url": url, "error": str(e)})

        results["redirect_chain"] = redirect_chain

        # 8. Ekstraksi Metadata Halaman & Scraping Email
        results["page_metadata"] = self._extract_page_metadata(html_content)

        # 9. Security Headers Analysis & Grader (A+ sampai F)
        sec_header_keys = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Access-Control-Allow-Origin"
        ]
        sec_headers = {}
        for h_key in sec_header_keys:
            val = final_headers.get(h_key) or final_headers.get(h_key.lower())
            sec_headers[h_key] = val if val else "Missing (Not Implemented)"
        results["security_headers"] = sec_headers
        results["security_headers_grade"] = self._grade_security_headers(final_headers)

        # 10. Granular Authentication & Token Fingerprinting (Sanctum, JWT, Cookies)
        results["auth_intelligence"] = await self._probe_auth_and_tokens(results["final_url"], cookies_captured, final_headers, html_content)

        # 11. Tech Stack Fingerprinting (WhatWeb Style)
        results["tech_stack"] = self._detect_tech_stack(final_headers, html_content)

        # 12. High-Performance Content Discovery & Path Fuzzing (Soft-404 Calibrated + CDX)
        results["content_discovery"] = await self._discover_endpoints_and_paths(results["final_url"], target_fqdn)

        # Compat alias untuk reporting lama
        results["sensitive_files_found"] = results["content_discovery"].get("endpoints", [])
        results["crtsh_subdomains"] = {
            "total_found": results.get("passive_subdomains", {}).get("total_found", 0),
            "unique_subdomains": [s["subdomain"] for s in results.get("passive_subdomains", {}).get("subdomains", [])]
        }

        # 13. Vulnerability & Threat Intelligence Summary Matrix
        results["threat_vulnerability_summary"] = self._generate_threat_summary(results)

        # 14. Bangun WhatWeb Brief Line Summary
        status_phrase = http.client.responses.get(results['final_status'], "OK" if results['final_status'] == 200 else "")
        brief_parts = [f"{results['final_url']} [{results['final_status']} {status_phrase}]".strip()]
        geo = results.get("server_geoip", {})
        if geo.get("country") and geo.get("country") != "Unknown Location / Protected IP":
            brief_parts.append(f"Country[{geo.get('country').upper()}][{geo.get('country')[:2].upper()}]")
        if server_ip:
            brief_parts.append(f"IP[{server_ip}]")
        if results["page_metadata"].get("title"):
            brief_parts.append(f"Title[{results['page_metadata'].get('title')}]")
        if results["security_headers_grade"].get("grade"):
            brief_parts.append(f"Grade[{results['security_headers_grade'].get('grade')}]")
        if results["auth_intelligence"].get("auth_architecture"):
            brief_parts.append(f"Auth[{results['auth_intelligence'].get('auth_architecture')}]")
        if results["origin_ip_leak"].get("leak_detected"):
            brief_parts.append("OriginLeak[DETECTED]")
        if results["tech_stack"].get("web_servers"):
            brief_parts.append(f"HTTPServer[{', '.join(results['tech_stack'].get('web_servers'))}]")
        if results["tech_stack"].get("waf_and_security"):
            brief_parts.append(f"WAF[{', '.join(results['tech_stack'].get('waf_and_security'))}]")
        if results["tech_stack"].get("programming_languages"):
            brief_parts.append(f"Language[{', '.join(results['tech_stack'].get('programming_languages'))}]")
        if results["tech_stack"].get("backend_frameworks"):
            brief_parts.append(f"Framework[{', '.join(results['tech_stack'].get('backend_frameworks'))}]")

        results["whatweb_summary"] = ", ".join(brief_parts)
        return self.success_response(results, f"Enterprise Reconnaissance Web & Infrastruktur {target_fqdn} Selesai.")
