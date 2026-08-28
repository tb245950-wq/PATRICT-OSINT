import re
import json
import socket
import base64
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
    description: str = "Analisis mendalam web: HTTP methods, redirect chains, auth/JWT/Sanctum tokens, tech stack, DNS, & server GeoIP."
    version: str = "2.0.0"
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

        # Periksa semua cookie names & values
        for c_name, c_val in cookies.items():
            c_name_lower = c_name.lower()
            val_str = str(c_val)

            # Deteksi JWT dalam Cookie
            if val_str.startswith("eyJ") and "." in val_str:
                jwt_data = self._decode_jwt(val_str)
                if jwt_data:
                    auth_findings["auth_type_detected"].append(f"JWT (JSON Web Token in '{c_name}')")
                    auth_findings["jwt_tokens"].append({
                        "cookie_name": c_name,
                        "header": jwt_data["header"],
                        "payload": jwt_data["payload"]
                    })

            # Deteksi Laravel Sanctum / Laravel Session
            if "laravel_session" in c_name_lower or "xsrf-token" in c_name_lower:
                auth_findings["auth_type_detected"].append("Laravel (Session / CSRF / Sanctum)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Laravel"})

            # Deteksi Django
            elif "sessionid" in c_name_lower or "csrftoken" in c_name_lower:
                auth_findings["auth_type_detected"].append("Django (Session / CSRF)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Django"})

            # Deteksi PHP Standard
            elif "phpsessid" in c_name_lower:
                auth_findings["auth_type_detected"].append("PHP Native Session")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "PHP Native"})

            # Deteksi ASP.NET
            elif "asp.net" in c_name_lower or ".aspnetcore" in c_name_lower:
                auth_findings["auth_type_detected"].append("ASP.NET / .NET Core Session")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "ASP.NET"})

            # Deteksi Express.js / Node
            elif "connect.sid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Express.js (Node.js session)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Express.js"})

            # Deteksi Java Spring
            elif "jsessionid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Java Spring / Tomcat Session")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Java / Spring"})

            # Deteksi Cloudflare
            elif "__cf" in c_name_lower or "cf_clearance" in c_name_lower:
                auth_findings["auth_type_detected"].append("Cloudflare Protection / Bot Management")

        # Periksa Header Set-Cookie
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

        # Unique auth types
        auth_findings["auth_type_detected"] = list(set(auth_findings["auth_type_detected"]))
        if not auth_findings["auth_type_detected"]:
            auth_findings["auth_type_detected"].append("Standard / Stateless / None")

        return auth_findings

    def _detect_tech_stack(self, headers: Dict[str, Any], html_content: str) -> Dict[str, List[str]]:
        """Mendeteksi stack teknologi (Web Server, Framework, CMS, Frontend, CDN)"""
        stack = {
            "web_servers": [],
            "backend_frameworks": [],
            "frontend_libraries": [],
            "cms_and_platforms": [],
            "analytics_and_cdn": []
        }

        headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
        html_lower = html_content.lower()

        # 1. Web Servers
        server_header = str(headers.get("server", "") or headers.get("Server", ""))
        if server_header:
            stack["web_servers"].append(server_header)
        elif "cloudflare" in headers_str:
            stack["web_servers"].append("Cloudflare Edge Server")
        elif "nginx" in html_lower or "nginx" in headers_str:
            stack["web_servers"].append("Nginx")
        elif "apache" in html_lower or "apache" in headers_str:
            stack["web_servers"].append("Apache HTTP Server")

        # 2. Backend & Frameworks
        powered_by = str(headers.get("x-powered-by", "") or headers.get("X-Powered-By", ""))
        if powered_by:
            stack["backend_frameworks"].append(f"X-Powered-By: {powered_by}")

        if "laravel" in html_lower or "laravel" in headers_str or "xsrf-token" in headers_str:
            stack["backend_frameworks"].append("Laravel (PHP)")
        if "django" in html_lower or "csrftoken" in headers_str:
            stack["backend_frameworks"].append("Django (Python)")
        if "express" in powered_by.lower() or "next.js" in html_lower or "__next" in html_lower:
            if "__next" in html_lower:
                stack["backend_frameworks"].append("Next.js (React/Node)")
            else:
                stack["backend_frameworks"].append("Node.js / Express")
        if "nuxt" in html_lower or "__nuxt" in html_lower:
            stack["backend_frameworks"].append("Nuxt.js (Vue/Node)")
        if "rails" in html_lower or "phusion" in headers_str:
            stack["backend_frameworks"].append("Ruby on Rails")

        # 3. CMS & Platforms
        if "wp-content" in html_lower or "wp-includes" in html_lower:
            stack["cms_and_platforms"].append("WordPress")
        if "drupal" in html_lower or "drupal.js" in html_lower:
            stack["cms_and_platforms"].append("Drupal")
        if "joomla" in html_lower:
            stack["cms_and_platforms"].append("Joomla")
        if "shopify" in html_lower or "myshopify.com" in html_lower:
            stack["cms_and_platforms"].append("Shopify")
        if "ghost" in html_lower:
            stack["cms_and_platforms"].append("Ghost CMS")

        # 4. Frontend Libraries
        if "react" in html_lower or "react-dom" in html_lower or "__react" in html_lower:
            stack["frontend_libraries"].append("React")
        if "vue" in html_lower or "vuejs" in html_lower or "v-" in html_lower:
            stack["frontend_libraries"].append("Vue.js")
        if "bootstrap" in html_lower:
            stack["frontend_libraries"].append("Bootstrap CSS")
        if "tailwind" in html_lower:
            stack["frontend_libraries"].append("Tailwind CSS")
        if "jquery" in html_lower or "jquery.min.js" in html_lower:
            stack["frontend_libraries"].append("jQuery")
        if "alpine" in html_lower or "x-data" in html_lower:
            stack["frontend_libraries"].append("Alpine.js")

        # 5. CDN & Analytics
        if "cloudflare" in headers_str or "cf-ray" in headers_str:
            stack["analytics_and_cdn"].append("Cloudflare CDN")
        if "cloudfront" in headers_str or "x-amz-cf-id" in headers_str:
            stack["analytics_and_cdn"].append("AWS CloudFront")
        if "googletagmanager.com" in html_lower or "google-analytics.com" in html_lower:
            stack["analytics_and_cdn"].append("Google Analytics / Tag Manager")

        for key in stack:
            stack[key] = list(set(stack[key]))

        return stack

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
            # Gunakan IP API gratis untuk resolusi GeoIP server
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
            "http_methods_allowed": [],
            "redirect_chain": [],
            "final_url": url,
            "security_headers": {},
            "auth_intelligence": {},
            "tech_stack": {},
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
            # Gunakan session aiohttp untuk menelusuri redirect
            session = await self.async_client.get_session()
            async with session.get(url, allow_redirects=True, timeout=12) as response:
                # Catat history redirect
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

        # 5. Security Headers Analysis
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

        # 6. Auth & Cookies Intelligence
        results["auth_intelligence"] = self._analyze_cookies_and_auth(cookies_captured, final_headers)

        # 7. Tech Stack Fingerprinting
        results["tech_stack"] = self._detect_tech_stack(final_headers, html_content)

        return self.success_response(results, f"Pemindaian Web & Infrastruktur {domain} Berhasil.")
