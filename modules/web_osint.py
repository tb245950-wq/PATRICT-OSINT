import re
import json
import socket
import base64
import hashlib
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.base_module import BaseOSINTModule

class WebOSINT(BaseOSINTModule):
    name: str = "Web & Infrastructure Intelligence"
    module_id: str = "web_osint"
    description: str = "Analisis mendalam web ala WhatWeb: HTTP headers, security headers, WAF, redirect chain, auth/JWT/Sanctum, tech stack, DNS, endpoints & GeoIP."
    version: str = "2.2.0"
    priority: int = 1
    target_type: str = "web"

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
        return target

    def _extract_domain(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc or parsed.path
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return netloc

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Mendekode payload JWT tanpa perlu verifikasi secret key"""
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                def b64_decode(s):
                    rem = len(s) % 4
                    if rem > 0:
                        s += "=" * (4 - rem)
                    return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore"))

                header = b64_decode(parts[0])
                payload = b64_decode(parts[1])
                return {
                    "header": header,
                    "payload": payload,
                    "is_jwt": True
                }
            except Exception:
                pass
        return None

    def _analyze_cookies_and_auth(self, cookies: Dict[str, Any], headers: Dict[str, Any]) -> Dict[str, Any]:
        """Mendeteksi tipe session, cookies login, JWT, Sanctum, Django, ASP.NET, dll."""
        auth_findings = {
            "auth_type_detected": [],
            "jwt_tokens": [],
            "session_cookies": [],
            "security_flags": {
                "httponly": False,
                "secure": False,
                "samesite": None
            }
        }

        for c_name, c_val in cookies.items():
            c_name_lower = c_name.lower()
            val_str = str(c_val)

            # Deteksi JWT dalam Cookie
            if val_str.startswith("eyJ") and "." in val_str:
                jwt_data = self._decode_jwt(val_str)
                if jwt_data:
                    auth_findings["auth_type_detected"].append(f"JWT (in '{c_name}')")
                    auth_findings["jwt_tokens"].append({
                        "cookie_name": c_name,
                        "header": jwt_data["header"],
                        "payload": jwt_data["payload"]
                    })

            # Deteksi Laravel Sanctum / Laravel Session
            if "laravel_session" in c_name_lower or "xsrf-token" in c_name_lower:
                auth_findings["auth_type_detected"].append("Laravel (Session/Sanctum)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Laravel"})

            # Deteksi Django
            elif "sessionid" in c_name_lower or "csrftoken" in c_name_lower:
                auth_findings["auth_type_detected"].append("Django (Session/CSRF)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Django"})

            # Deteksi PHP Native
            elif "phpsessid" in c_name_lower:
                auth_findings["auth_type_detected"].append("PHP Native (PHPSESSID)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "PHP Native"})

            # Deteksi ASP.NET
            elif "asp.net" in c_name_lower or ".aspnetcore" in c_name_lower:
                auth_findings["auth_type_detected"].append("ASP.NET / .NET Core")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "ASP.NET"})

            # Deteksi Express.js / Node
            elif "connect.sid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Express.js (Node.js)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Express.js"})

            # Deteksi Java Spring
            elif "jsessionid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Java Spring / Tomcat")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Java Spring"})

            # Deteksi Cloudflare
            elif "__cf" in c_name_lower or "cf_clearance" in c_name_lower:
                auth_findings["auth_type_detected"].append("Cloudflare Clearance")

        # Periksa Header Set-Cookie Flags
        set_cookie_raw = str(headers.get("set-cookie", "") or headers.get("Set-Cookie", ""))
        if "httponly" in set_cookie_raw.lower():
            auth_findings["security_flags"]["httponly"] = True
        if "secure" in set_cookie_raw.lower():
            auth_findings["security_flags"]["secure"] = True
        if "samesite=strict" in set_cookie_raw.lower():
            auth_findings["security_flags"]["samesite"] = "Strict"
        elif "samesite=lax" in set_cookie_raw.lower():
            auth_findings["security_flags"]["samesite"] = "Lax"
        elif "samesite=none" in set_cookie_raw.lower():
            auth_findings["security_flags"]["samesite"] = "None"

        auth_findings["auth_type_detected"] = list(set(auth_findings["auth_type_detected"]))
        if not auth_findings["auth_type_detected"]:
            auth_findings["auth_type_detected"].append("Standard / Stateless / None")

        return auth_findings

    def _detect_waf(self, headers: Dict[str, Any], html_content: str) -> List[str]:
        """Mendeteksi Web Application Firewall (WAF) & Protection Layer"""
        waf_detected = []
        headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
        html_lower = html_content.lower()

        if "cf-ray" in headers_str or "__cfduid" in headers_str or "cloudflare" in headers_str:
            waf_detected.append("Cloudflare WAF / CDN")
        if "x-amz-cf-id" in headers_str or "awselb" in headers_str or "aws-waf" in headers_str:
            waf_detected.append("AWS CloudFront / AWS WAF")
        if "x-akamai" in headers_str or "akamai" in headers_str:
            waf_detected.append("Akamai Edge / Kona WAF")
        if "x-sucuri" in headers_str or "sucuri" in headers_str:
            waf_detected.append("Sucuri CloudProxy WAF")
        if "x-iinfo" in headers_str or "incap_ses" in headers_str or "visid_incap" in headers_str:
            waf_detected.append("Imperva Incapsula WAF")
        if "wordfence" in html_lower or "wordfence" in headers_str:
            waf_detected.append("Wordfence Security (WordPress)")
        if "mod_security" in headers_str or "modsecurity" in headers_str:
            waf_detected.append("ModSecurity OWASP WAF")
        if "f5_cspm" in headers_str or "bigip" in headers_str or "f5" in headers_str:
            waf_detected.append("F5 BIG-IP ASM")

        return list(set(waf_detected))

    def _detect_tech_stack(self, headers: Dict[str, Any], html_content: str) -> Dict[str, List[str]]:
        """Mendeteksi stack teknologi lengkap ala WhatWeb (Web Server, Framework, CMS, Frontend, CDN, Language)"""
        stack = {
            "web_servers": [],
            "programming_languages": [],
            "backend_frameworks": [],
            "frontend_libraries": [],
            "cms_and_platforms": [],
            "waf_and_security": [],
            "analytics_and_cdn": []
        }

        headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
        html_lower = html_content.lower()

        # 1. Web Servers & Proxies
        server_header = str(headers.get("server", "") or headers.get("Server", ""))
        if server_header:
            stack["web_servers"].append(server_header)
        if "cloudflare" in headers_str:
            stack["web_servers"].append("Cloudflare Edge Server")
        if "nginx" in html_lower or "nginx" in headers_str:
            stack["web_servers"].append("Nginx")
        if "apache" in html_lower or "apache" in headers_str:
            stack["web_servers"].append("Apache HTTP Server")
        if "litespeed" in headers_str or "litespeed" in html_lower:
            stack["web_servers"].append("LiteSpeed Web Server")
        if "caddy" in headers_str:
            stack["web_servers"].append("Caddy Web Server")
        if "microsoft-iis" in headers_str or "iis" in headers_str:
            stack["web_servers"].append("Microsoft IIS")
        if "openresty" in headers_str:
            stack["web_servers"].append("OpenResty (Nginx+Lua)")

        # 2. Languages & Runtimes
        powered_by = str(headers.get("x-powered-by", "") or headers.get("X-Powered-By", ""))
        if powered_by:
            stack["programming_languages"].append(f"X-Powered-By: {powered_by}")

        if "php" in headers_str or "phpsessid" in headers_str or ".php" in html_lower:
            stack["programming_languages"].append("PHP")
        if "python" in powered_by.lower() or "django" in html_lower or "flask" in html_lower or "fastapi" in html_lower:
            stack["programming_languages"].append("Python")
        if "node" in powered_by.lower() or "express" in powered_by.lower() or "__next" in html_lower or "__nuxt" in html_lower:
            stack["programming_languages"].append("Node.js / JavaScript")
        if "ruby" in headers_str or "phusion" in headers_str or "passenger" in headers_str:
            stack["programming_languages"].append("Ruby")
        if "asp.net" in headers_str or ".aspnetcore" in headers_str:
            stack["programming_languages"].append("C# / .NET Core / ASP.NET")
        if "java" in headers_str or "jsessionid" in headers_str or "servlet" in headers_str:
            stack["programming_languages"].append("Java / JVM")

        # 3. Backend & Fullstack Frameworks
        if "laravel" in html_lower or "laravel" in headers_str or "xsrf-token" in headers_str:
            stack["backend_frameworks"].append("Laravel (PHP)")
        if "symfony" in html_lower or "symfony" in headers_str:
            stack["backend_frameworks"].append("Symfony (PHP)")
        if "codeigniter" in html_lower or "ci_session" in headers_str:
            stack["backend_frameworks"].append("CodeIgniter (PHP)")
        if "django" in html_lower or "csrftoken" in headers_str:
            stack["backend_frameworks"].append("Django (Python)")
        if "fastapi" in html_lower or "fastapi" in headers_str:
            stack["backend_frameworks"].append("FastAPI (Python)")
        if "flask" in html_lower:
            stack["backend_frameworks"].append("Flask (Python)")
        if "spring" in html_lower or "jsessionid" in headers_str:
            stack["backend_frameworks"].append("Spring Boot (Java)")
        if "rails" in html_lower or "actionpack" in headers_str:
            stack["backend_frameworks"].append("Ruby on Rails")
        if "__next" in html_lower or "next.js" in html_lower:
            stack["backend_frameworks"].append("Next.js (React Framework)")
        if "__nuxt" in html_lower or "nuxt.js" in html_lower:
            stack["backend_frameworks"].append("Nuxt.js (Vue Framework)")
        if "remix" in html_lower:
            stack["backend_frameworks"].append("Remix (Fullstack React)")
        if "sveltekit" in html_lower:
            stack["backend_frameworks"].append("SvelteKit")
        if "astro" in html_lower or "astro-island" in html_lower:
            stack["backend_frameworks"].append("Astro")

        # 4. CMS & Platforms
        if "wp-content" in html_lower or "wp-includes" in html_lower or "wp-json" in html_lower:
            # Cari versi WordPress jika ada
            wp_version = ""
            m_gen = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)["\']', html_content, re.I)
            if m_gen and m_gen.group(1):
                wp_version = f" (v{m_gen.group(1)})"
            stack["cms_and_platforms"].append(f"WordPress{wp_version}")
        if "drupal" in html_lower or "drupal.js" in html_lower:
            stack["cms_and_platforms"].append("Drupal CMS")
        if "joomla" in html_lower:
            stack["cms_and_platforms"].append("Joomla CMS")
        if "shopify" in html_lower or "myshopify.com" in html_lower or "cdn.shopify.com" in html_lower:
            stack["cms_and_platforms"].append("Shopify E-Commerce")
        if "woocommerce" in html_lower or "wc-ajax" in html_lower:
            stack["cms_and_platforms"].append("WooCommerce")
        if "magento" in html_lower or "mage/cookies" in html_lower:
            stack["cms_and_platforms"].append("Magento")
        if "ghost" in html_lower or "ghost-root" in html_lower:
            stack["cms_and_platforms"].append("Ghost CMS")
        if "wix.com" in html_lower:
            stack["cms_and_platforms"].append("Wix Website Builder")
        if "squarespace" in html_lower:
            stack["cms_and_platforms"].append("Squarespace")
        if "webflow" in html_lower:
            stack["cms_and_platforms"].append("Webflow")
        if "strapi" in html_lower:
            stack["cms_and_platforms"].append("Strapi Headless CMS")

        # 5. Frontend UI & JavaScript Libraries
        if "react" in html_lower or "react-dom" in html_lower or "__react" in html_lower:
            stack["frontend_libraries"].append("React")
        if "vue" in html_lower or "vuejs" in html_lower or "v-" in html_lower:
            stack["frontend_libraries"].append("Vue.js")
        if "angular" in html_lower or "ng-" in html_lower or "ng-version" in html_lower:
            stack["frontend_libraries"].append("Angular")
        if "svelte" in html_lower:
            stack["frontend_libraries"].append("Svelte")
        if "bootstrap" in html_lower or "bootstrap.min.css" in html_lower:
            stack["frontend_libraries"].append("Bootstrap CSS")
        if "tailwind" in html_lower or "tailwindcss" in html_lower:
            stack["frontend_libraries"].append("Tailwind CSS")
        if "jquery" in html_lower or "jquery.min.js" in html_lower:
            stack["frontend_libraries"].append("jQuery")
        if "alpine" in html_lower or "x-data" in html_lower:
            stack["frontend_libraries"].append("Alpine.js")
        if "htmx" in html_lower or "hx-get" in html_lower or "hx-post" in html_lower:
            stack["frontend_libraries"].append("HTMX")
        if "fontawesome" in html_lower or "fa-" in html_lower:
            stack["frontend_libraries"].append("FontAwesome Icons")

        # 6. WAF & Security Layer
        stack["waf_and_security"] = self._detect_waf(headers, html_content)

        # 7. CDN & Analytics
        if "cloudflare" in headers_str or "cf-ray" in headers_str:
            stack["analytics_and_cdn"].append("Cloudflare CDN")
        if "cloudfront" in headers_str or "x-amz-cf-id" in headers_str:
            stack["analytics_and_cdn"].append("AWS CloudFront")
        if "fastly" in headers_str:
            stack["analytics_and_cdn"].append("Fastly CDN")
        if "googletagmanager.com" in html_lower or "google-analytics.com" in html_lower or "gtag(" in html_lower:
            stack["analytics_and_cdn"].append("Google Analytics / GTM")
        if "hotjar" in html_lower:
            stack["analytics_and_cdn"].append("Hotjar Analytics")

        for key in stack:
            stack[key] = list(set(stack[key]))

        return stack

    def _extract_page_metadata(self, html_content: str) -> Dict[str, str]:
        """Mengekstrak judul halaman, meta description, generator, dan meta tag"""
        meta_info = {
            "title": "",
            "description": "",
            "generator": "",
            "emails_found": []
        }

        # Title
        t_match = re.search(r"<title>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        if t_match:
            meta_info["title"] = t_match.group(1).strip()

        # Meta Description
        d_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html_content, re.IGNORECASE)
        if d_match:
            meta_info["description"] = d_match.group(1).strip()

        # Meta Generator
        g_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', html_content, re.IGNORECASE)
        if g_match:
            meta_info["generator"] = g_match.group(1).strip()

        # Email Scraping dari HTML
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content)
        filtered_emails = [e for e in set(emails) if not e.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')) and len(e) < 50]
        meta_info["emails_found"] = filtered_emails[:10]

        return meta_info

    async def _probe_interesting_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Memeriksa keberadaan endpoint menarik (robots.txt, sitemap.xml, graphql, security.txt, swagger)"""
        endpoints_to_check = [
            ("robots.txt", "/robots.txt"),
            ("Sitemap XML", "/sitemap.xml"),
            ("Security TXT", "/.well-known/security.txt"),
            ("GraphQL API", "/graphql"),
            ("Swagger / OpenAPI", "/swagger-ui.html"),
            ("API Docs", "/api-docs")
        ]

        detected = []
        if not self.async_client:
            return detected

        for label, path in endpoints_to_check:
            probe_url = urllib.parse.urljoin(base_url, path)
            try:
                status, _, _ = await self.async_client.get(probe_url)
                if status in (200, 301, 302, 401, 403):
                    detected.append({
                        "name": label,
                        "url": probe_url,
                        "status": status
                    })
            except Exception:
                pass

        return detected

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
        """Mengambil data koordinat & GeoIP dari server IP publik"""
        if not ip or not self.async_client:
            return {}

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query"
            status, text, _ = await self.async_client.get(url)
            if status == 200:
                data = json.loads(text)
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "asn": data.get("as"),
                        "maps_url": f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}"
                    }
        except Exception as e:
            self.logger.warning(f"Gagal mengambil GeoIP server ({ip}): {e}")

        return {"ip": ip}

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self._normalize_url(target)
        domain = self._extract_domain(url)

        results = {
            "target_url": url,
            "domain": domain,
            "page_metadata": {},
            "http_methods_allowed": [],
            "redirect_chain": [],
            "final_url": url,
            "final_status": 200,
            "security_headers": {},
            "auth_intelligence": {},
            "tech_stack": {},
            "interesting_endpoints": [],
            "dns_records": {},
            "server_geoip": {}
        }

        # 1. Resolusi DNS Domain
        dns_data = self._resolve_dns(domain)
        results["dns_records"] = dns_data

        server_ip = dns_data.get("A", [None])[0]
        if not server_ip:
            try:
                server_ip = socket.gethostbyname(domain)
            except Exception:
                server_ip = ""

        # 2. Resolusi GeoIP & Koordinat Server
        if server_ip:
            results["server_geoip"] = await self._get_server_geoip(server_ip)

        if not self.async_client:
            return self.success_response(results, "Analisis DNS & GeoIP Selesai.")

        # 3. Analisis HTTP Methods (OPTIONS & HEAD)
        try:
            status, _, headers = await self.async_client.options(url)
            allow_header = headers.get("allow", "") or headers.get("Allow", "")
            if allow_header:
                results["http_methods_allowed"] = [m.strip() for m in allow_header.split(",")]
        except Exception:
            pass

        # 4. Lacak Jalur Redirect (Redirect Chains) & Ambil Response Body
        redirect_chain = []
        html_content = ""
        final_headers = {}
        cookies_captured = {}

        try:
            session = await self.async_client.get_session()
            async with session.get(url, allow_redirects=True, timeout=12) as response:
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

                html_content = await response.text()
        except Exception as e:
            self.logger.warning(f"Error requesting target URL: {e}")
            redirect_chain.append({"status_code": 0, "url": url, "error": str(e)})

        results["redirect_chain"] = redirect_chain

        # 5. Ekstraksi Metadata Halaman & Scraping Email
        results["page_metadata"] = self._extract_page_metadata(html_content)

        # 6. Security Headers Analysis
        sec_header_keys = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Access-Control-Allow-Origin"
        ]
        sec_headers = {}
        for h_key in sec_header_keys:
            val = final_headers.get(h_key) or final_headers.get(h_key.lower())
            sec_headers[h_key] = val if val else "Missing (Not Implemented)"
        results["security_headers"] = sec_headers

        # 7. Auth & Cookies Intelligence
        results["auth_intelligence"] = self._analyze_cookies_and_auth(cookies_captured, final_headers)

        # 8. Tech Stack Fingerprinting (WhatWeb Style)
        results["tech_stack"] = self._detect_tech_stack(final_headers, html_content)

        # 9. Probe Endpoint Menarik (robots.txt, sitemap.xml, GraphQL, dll)
        results["interesting_endpoints"] = await self._probe_interesting_endpoints(results["final_url"])

        return self.success_response(results, f"Pemindaian Web & Infrastruktur {domain} Berhasil.")
