import re
import ssl
import json
import uuid
import socket
import base64
import hashlib
import asyncio
import ipaddress
import http.client
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.base_module import BaseOSINTModule

# Cloudflare IP Ranges (IPv4)
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
    description: str = "Analisis mendalam web ala WhatWeb: SSL/TLS, crt.sh CT logs, Security Headers Grader, Cloudflare Origin Leak, Sensitive Files (Soft 404 filtered), WAF, JWT, tech stack & Threat Summary."
    version: str = "2.3.1"
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
                auth_findings["auth_type_detected"].append("PHP Native Session")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "PHP"})

            # Deteksi ASP.NET
            elif "asp.net_sessionid" in c_name_lower or ".aspxauth" in c_name_lower:
                auth_findings["auth_type_detected"].append("ASP.NET Session")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "ASP.NET"})

            # Deteksi Express.js / Node.js
            elif "connect.sid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Express/Node.js (connect.sid)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Express.js"})

            # Deteksi Spring Boot
            elif "jsessionid" in c_name_lower:
                auth_findings["auth_type_detected"].append("Java / Spring Boot (JSESSIONID)")
                auth_findings["session_cookies"].append({"name": c_name, "framework": "Java/Spring"})

        # Periksa Cookie Security Flags dari Set-Cookie header
        set_cookie_headers = []
        for h_key, h_val in headers.items():
            if h_key.lower() == "set-cookie":
                set_cookie_headers.append(h_val)

        if set_cookie_headers:
            all_set_cookies = " ".join(set_cookie_headers).lower()
            auth_findings["security_flags"]["httponly"] = "httponly" in all_set_cookies
            auth_findings["security_flags"]["secure"] = "secure" in all_set_cookies
            if "samesite=strict" in all_set_cookies:
                auth_findings["security_flags"]["samesite"] = "Strict"
            elif "samesite=lax" in all_set_cookies:
                auth_findings["security_flags"]["samesite"] = "Lax"
            elif "samesite=none" in all_set_cookies:
                auth_findings["security_flags"]["samesite"] = "None"

        if not auth_findings["auth_type_detected"]:
            auth_findings["auth_type_detected"].append("Standard / Stateless (No Auth Cookie)")

        auth_findings["auth_type_detected"] = list(set(auth_findings["auth_type_detected"]))
        return auth_findings

    def _detect_waf(self, headers: Dict[str, Any], html_content: str) -> List[str]:
        """Mendeteksi Firewall Aplikasi Web (WAF)"""
        wafs = []
        headers_str = str(headers).lower()
        html_lower = html_content.lower()

        # Cloudflare WAF
        if "cf-ray" in headers_str or "cloudflare" in headers_str or "attention required! | cloudflare" in html_lower:
            wafs.append("Cloudflare WAF")
        # AWS WAF
        if "x-amzn-requestid" in headers_str or "awselb" in headers_str or "aws-waf" in headers_str:
            wafs.append("AWS WAF / Shield")
        # Akamai
        if "akamai" in headers_str or "x-akamai-transformed" in headers_str:
            wafs.append("Akamai Kona WAF")
        # Sucuri
        if "x-sucuri-id" in headers_str or "sucuri" in headers_str:
            wafs.append("Sucuri CloudProxy")
        # Imperva Incapsula
        if "x-iinfo" in headers_str or "incap_ses" in headers_str or "visid_incap" in headers_str:
            wafs.append("Imperva Incapsula")
        # ModSecurity
        if "mod_security" in headers_str or "modsecurity" in headers_str or "owasp_crs" in html_lower:
            wafs.append("ModSecurity (OWASP CRS)")
        # Wordfence (WordPress)
        if "generated by wordfence" in html_lower or "wordfence" in headers_str:
            wafs.append("Wordfence Security WAF")
        # F5 BIG-IP ASM
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
        if "laravel" in headers_str or "laravel_session" in headers_str:
            stack["backend_frameworks"].append("Laravel Framework")
        if "django" in headers_str or "csrftoken" in headers_str:
            stack["backend_frameworks"].append("Django")
        if "fastapi" in headers_str or "starlette" in headers_str:
            stack["backend_frameworks"].append("FastAPI")
        if "flask" in headers_str or "werkzeug" in server_hdr:
            stack["backend_frameworks"].append("Flask")
        if "spring" in headers_str or "spring-boot" in headers_str:
            stack["backend_frameworks"].append("Spring Boot")
        if "express" in x_powered:
            stack["backend_frameworks"].append("Express.js")
        if "next.js" in x_powered or "__next" in html_lower or "/_next/" in html_lower:
            stack["backend_frameworks"].append("Next.js (React Framework)")
        if "nuxt" in html_lower or "/_nuxt/" in html_lower:
            stack["backend_frameworks"].append("Nuxt.js (Vue Framework)")

        # 4. CMS & Platforms
        if "wp-content" in html_lower or "wp-includes" in html_lower or "wordpress" in headers_str:
            wp_ver = re.search(r'content="wordpress ([0-9.]+)"', html_lower)
            stack["cms_and_platforms"].append(f"WordPress {wp_ver.group(1)}" if wp_ver else "WordPress")
        if "drupal" in headers_str or "drupal.js" in html_lower or "drupal.settings" in html_lower:
            stack["cms_and_platforms"].append("Drupal")
        if "joomla" in html_lower or "joomla" in headers_str:
            stack["cms_and_platforms"].append("Joomla")
        if "shopify" in html_lower or "cdn.shopify.com" in html_lower:
            stack["cms_and_platforms"].append("Shopify E-Commerce")
        if "woocommerce" in html_lower:
            stack["cms_and_platforms"].append("WooCommerce")
        if "magento" in html_lower:
            stack["cms_and_platforms"].append("Magento")
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

    def _extract_page_metadata(self, html_content: str) -> Dict[str, Any]:
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

    def _grade_security_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Security Headers Grader: Menganalisis kelengkapan header keamanan modern
        dan memberikan skor (A+ sampai F) beserta rekomendasi perbaikan.
        """
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        score = 0
        max_score = 100
        header_evaluations = {}
        recommendations = []

        # 1. HSTS (Strict-Transport-Security) - Bobot 25 poin
        hsts = headers_lower.get("strict-transport-security")
        if hsts:
            hsts_score = 15
            details = []
            if "max-age" in hsts:
                try:
                    age_match = re.search(r'max-age=(\d+)', hsts)
                    if age_match and int(age_match.group(1)) >= 10886400:
                        hsts_score += 5
                        details.append("Long max-age (>= 18 weeks)")
                    else:
                        details.append("Short max-age (< 18 weeks)")
                        recommendations.append("Tingkatkan max-age HSTS ke minimal 31536000 detik (1 tahun).")
                except (ValueError, TypeError):
                    pass
            if "includesubdomains" in hsts.lower():
                hsts_score += 3
                details.append("includeSubDomains")
            else:
                recommendations.append("Tambahkan 'includeSubDomains' pada header HSTS.")
            if "preload" in hsts.lower():
                hsts_score += 2
                details.append("preload")
            score += hsts_score
            header_evaluations["Strict-Transport-Security"] = {
                "status": "PASS",
                "value": hsts,
                "score": f"{hsts_score}/25",
                "details": ", ".join(details)
            }
        else:
            header_evaluations["Strict-Transport-Security"] = {
                "status": "FAIL",
                "value": "Missing",
                "score": "0/25",
                "details": "Tidak ada proteksi HSTS (Rentan MITM & SSL Stripping)"
            }
            recommendations.append("Implementasikan Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")

        # 2. CSP (Content-Security-Policy) - Bobot 25 poin
        csp = headers_lower.get("content-security-policy")
        if csp:
            csp_score = 20
            details = []
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                csp_score -= 5
                details.append("Contains 'unsafe-inline' or 'unsafe-eval' (Reduced protection)")
                recommendations.append("Hindari penggunaan 'unsafe-inline' dan 'unsafe-eval' pada CSP.")
            else:
                details.append("Strict policy without unsafe directives")
            if "default-src" in csp or "script-src" in csp:
                csp_score += 5
                details.append("Has default-src/script-src")
            score += max(0, csp_score)
            header_evaluations["Content-Security-Policy"] = {
                "status": "PASS",
                "value": csp[:60] + "..." if len(csp) > 60 else csp,
                "score": f"{csp_score}/25",
                "details": ", ".join(details)
            }
        else:
            header_evaluations["Content-Security-Policy"] = {
                "status": "FAIL",
                "value": "Missing",
                "score": "0/25",
                "details": "Tidak ada proteksi CSP (Rentan XSS & Data Injection)"
            }
            recommendations.append("Terapkan Content-Security-Policy untuk membatasi sumber script & asset.")

        # 3. X-Frame-Options - Bobot 15 poin
        xfo = headers_lower.get("x-frame-options")
        if xfo:
            xfo_val = xfo.strip().upper()
            if xfo_val in ("DENY", "SAMEORIGIN"):
                score += 15
                header_evaluations["X-Frame-Options"] = {
                    "status": "PASS",
                    "value": xfo,
                    "score": "15/15",
                    "details": f"Proteksi Clickjacking Aktif ({xfo_val})"
                }
            else:
                score += 5
                header_evaluations["X-Frame-Options"] = {
                    "status": "WARN",
                    "value": xfo,
                    "score": "5/15",
                    "details": "Konfigurasi X-Frame-Options tidak standar"
                }
        else:
            header_evaluations["X-Frame-Options"] = {
                "status": "FAIL",
                "value": "Missing",
                "score": "0/15",
                "details": "Tidak ada proteksi Clickjacking (Dapat di-iframe)"
            }
            recommendations.append("Tambahkan X-Frame-Options: SAMEORIGIN atau DENY untuk mencegah Clickjacking.")

        # 4. X-Content-Type-Options - Bobot 15 poin
        xcto = headers_lower.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            score += 15
            header_evaluations["X-Content-Type-Options"] = {
                "status": "PASS",
                "value": xcto,
                "score": "15/15",
                "details": "MIME-sniffing dimatikan (nosniff)"
            }
        else:
            header_evaluations["X-Content-Type-Options"] = {
                "status": "FAIL",
                "value": xcto or "Missing",
                "score": "0/15",
                "details": "Rentan MIME-sniffing vulnerability"
            }
            recommendations.append("Tambahkan X-Content-Type-Options: nosniff.")

        # 5. Referrer-Policy - Bobot 10 poin
        ref_pol = headers_lower.get("referrer-policy")
        if ref_pol:
            score += 10
            header_evaluations["Referrer-Policy"] = {
                "status": "PASS",
                "value": ref_pol,
                "score": "10/10",
                "details": f"Policy: {ref_pol}"
            }
        else:
            header_evaluations["Referrer-Policy"] = {
                "status": "FAIL",
                "value": "Missing",
                "score": "0/10",
                "details": "Referrer data dapat bocor ke domain pihak ketiga"
            }
            recommendations.append("Tambahkan Referrer-Policy: strict-origin-when-cross-origin.")

        # 6. Permissions-Policy - Bobot 10 poin
        perm_pol = headers_lower.get("permissions-policy")
        if perm_pol:
            score += 10
            header_evaluations["Permissions-Policy"] = {
                "status": "PASS",
                "value": perm_pol[:50] + "..." if len(perm_pol) > 50 else perm_pol,
                "score": "10/10",
                "details": "Fitur browser & hardware dibatasi secara eksplisit"
            }
        else:
            header_evaluations["Permissions-Policy"] = {
                "status": "FAIL",
                "value": "Missing",
                "score": "0/10",
                "details": "Permissions-Policy belum dikonfigurasi"
            }
            recommendations.append("Tambahkan Permissions-Policy (misal: camera=(), microphone=(), geolocation=()).")

        # Pengurangan poin untuk Server Version & Tech Exposure (Informational Leakage)
        if "server" in headers_lower and any(c.isdigit() for c in headers_lower["server"]):
            score = max(0, score - 5)
            recommendations.append(f"Sembunyikan versi server dari header Server: '{headers_lower['server']}'.")
        if "x-powered-by" in headers_lower:
            score = max(0, score - 5)
            recommendations.append(f"Hapus header X-Powered-By: '{headers_lower['x-powered-by']}' untuk mencegah banner grabbing.")

        # Menghitung Grade
        score = max(0, min(100, score))
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B+"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "max_score": max_score,
            "grade": grade,
            "evaluations": header_evaluations,
            "recommendations": recommendations
        }

    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """Parser tangguh untuk berbagai format tanggal ASN.1 / X.509 certificate"""
        if not date_str:
            return None
        clean_str = " ".join(date_str.strip().split())
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b %d %H:%M:%S %Y",
            "%Y%m%d%H%M%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S %Z",
            "%d %b %Y %H:%M:%S %Z"
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(clean_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    def _extract_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Mengambil dan membedah metadata sertifikat SSL/TLS langsung dari koneksi port 443"""
        cert_info = {
            "has_ssl": False,
            "issuer": {},
            "subject": {},
            "valid_from": "",
            "valid_until": "",
            "days_remaining": None,
            "is_expired": False,
            "tls_version": "",
            "cipher": "",
            "san_list": [],
            "serial_number": ""
        }

        if not domain or domain == "N/A":
            return cert_info

        # Penanganan SNI: hanya set server_hostname jika bukan raw IP
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False

        sni_hostname = None if is_ip else domain

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=6.0) as sock:
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
                        for san_type, san_val in cert.get("subjectAltName", ()):
                            if san_type.lower() == "dns":
                                sans.append(san_val)
                        cert_info["san_list"] = list(set(sans))
        except (ssl.SSLError, socket.error, socket.timeout, OSError) as e:
            self.logger.debug(f"Verified SSL connection failed on {domain}: {e}. Trying unverified fallback...")
            try:
                ctx_fallback = ssl._create_unverified_context()
                with socket.create_connection((domain, 443), timeout=5.0) as sock:
                    with ctx_fallback.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                        cert_info["has_ssl"] = True
                        cert_info["tls_version"] = ssock.version() or "TLS (Unverified/Self-Signed)"
                        c = ssock.cipher()
                        cert_info["cipher"] = f"{c[0]} ({c[1]})" if c else "Unknown"
            except Exception:
                pass

        return cert_info

    async def _fetch_crtsh_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Passive Subdomain Discovery via Certificate Transparency (CT Logs via crt.sh API).
        Dilengkapi retry mechanism, rate limit handling, dan pembersihan wildcard/newline.
        """
        ct_data = {
            "total_found": 0,
            "unique_subdomains": [],
            "issuers_seen": [],
            "source": "crt.sh (Certificate Transparency Logs)"
        }

        if not self.async_client or not domain or domain == "N/A":
            return ct_data

        custom_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*"
        }

        queries = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q={domain}&output=json"
        ]
        
        subdomains = set()
        issuers = set()

        for url in queries:
            for attempt in range(2):
                try:
                    status, text, _ = await self.async_client.get(url, headers=custom_headers, timeout=8)
                    if status == 200 and text.strip().startswith("["):
                        entries = json.loads(text)
                        for entry in entries:
                            name_val = entry.get("name_value", "")
                            for sub in name_val.split("\n"):
                                clean_sub = sub.strip().lower()
                                if clean_sub.startswith("*."):
                                    clean_sub = clean_sub[2:]
                                if clean_sub.endswith(domain) and clean_sub != domain and re.match(r"^[a-z0-9.-]+$", clean_sub):
                                    subdomains.add(clean_sub)
                            
                            issuer = entry.get("issuer_name", "")
                            if "O=" in issuer:
                                match = re.search(r'O=([^,]+)', issuer)
                                if match:
                                    issuers.add(match.group(1).strip(' "'))
                        if subdomains:
                            break
                except Exception as e:
                    self.logger.debug(f"crt.sh attempt {attempt+1} failed for {url}: {e}")
                    await asyncio.sleep(0.5)
            if subdomains:
                break

        ct_data["unique_subdomains"] = sorted(list(subdomains))[:60]
        ct_data["total_found"] = len(subdomains)
        ct_data["issuers_seen"] = list(issuers)[:5]
        return ct_data

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

    def _detect_origin_ip_leak(self, domain: str, dns_records: Dict[str, Any], server_geoip: Dict[str, Any]) -> Dict[str, Any]:
        """
        Otomasi Deteksi Kebocoran Origin IP (Cloudflare / CDN Bypass Heuristic):
        Mencocokkan IP di MX, SPF, TXT, dan direct subdomain dengan IP Cloudflare.
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

        # 2. Cek Resolusi MX Record
        for mx in dns_records.get("MX", []):
            parts = mx.split()
            mx_host = parts[-1].rstrip(".") if parts else mx.rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                if mx_ip and not self._is_cloudflare_ip(mx_ip):
                    candidate_ips.append({
                        "ip": mx_ip,
                        "source": f"MX Record ({mx_host})",
                        "confidence": "HIGH",
                        "risk": "Bypasses Cloudflare DDoS & WAF protections via Mail Server Origin."
                    })
            except (socket.gaierror, socket.timeout, OSError):
                pass

        # 3. Cek SPF Record dalam TXT
        for txt in dns_records.get("TXT", []):
            if "v=spf1" in txt.lower():
                ip4_matches = re.findall(r'ip4:([0-9.]+)', txt)
                for ip4 in ip4_matches:
                    if not self._is_cloudflare_ip(ip4):
                        candidate_ips.append({
                            "ip": ip4,
                            "source": "TXT SPF Record (v=spf1 ip4:)",
                            "confidence": "HIGH",
                            "risk": "Origin IP tercantum secara publik di SPF Record DNS."
                        })

        # 4. Cek Subdomain Origin yang Sering Tidak di-Proxy
        common_direct_subs = ["mail", "direct", "origin", "ftp", "cpanel", "direct-connect", "admin", "dev", "staging"]
        for sub in common_direct_subs:
            test_host = f"{sub}.{domain}"
            try:
                sub_ip = socket.gethostbyname(test_host)
                if sub_ip and not self._is_cloudflare_ip(sub_ip):
                    candidate_ips.append({
                        "ip": sub_ip,
                        "source": f"Direct Subdomain ({test_host})",
                        "confidence": "CRITICAL",
                        "risk": "Subdomain internal menunjuk langsung ke backend server tanpa proteksi Cloudflare."
                    })
            except (socket.gaierror, socket.timeout, OSError):
                pass

        # Hapus duplikat IP
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

    async def _probe_sensitive_files(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Sensitive File & Directory Discovery (Passive Probing):
        Dilengkapi Soft 404 Baseline Detection & WAF Catch-All Filtering.
        - Status 401/403 diberi status [BLOCKED] / [INFO].
        - Status 200 diverifikasi terhadap baseline 404 acak & Content-Type.
        """
        candidates = [
            # High / Critical Exposure Files
            ("/.env", "Environment Secrets / API Keys", "CRITICAL", "config"),
            ("/.env.local", "Local Environment Configuration", "CRITICAL", "config"),
            ("/.env.production", "Production Environment Configuration", "CRITICAL", "config"),
            ("/.git/HEAD", "Git Repository Metadata Exposure", "CRITICAL", "git"),
            ("/.git/config", "Git Repository Configuration", "CRITICAL", "git"),
            ("/config.json", "Application Configuration File", "HIGH", "config"),
            ("/web.config", "IIS Web Configuration File", "HIGH", "config"),
            ("/storage/logs/laravel.log", "Laravel Application Error Log", "HIGH", "log"),
            ("/phpinfo.php", "PHP Information & Environment Leak", "HIGH", "phpinfo"),
            ("/info.php", "PHP Info Test Page", "HIGH", "phpinfo"),
            ("/server-status", "Apache Server Status Page", "MEDIUM", "server-status"),
            ("/wp-config.php.bak", "WordPress Configuration Backup", "CRITICAL", "config"),
            ("/wp-config.old", "WordPress Config Old Backup", "CRITICAL", "config"),
            ("/backup.sql", "Database Backup Dump", "CRITICAL", "sql"),
            ("/db.sql", "SQL Database Dump", "CRITICAL", "sql"),
            ("/docker-compose.yml", "Docker Compose Infrastructure Setup", "HIGH", "config"),
            ("/Dockerfile", "Docker Container Build File", "HIGH", "config"),
            ("/actuator/health", "Spring Boot Actuator Health", "MEDIUM", "actuator"),
            ("/actuator/env", "Spring Boot Actuator Environment Secrets", "CRITICAL", "actuator"),
            ("/swagger-ui.html", "Swagger / OpenAPI Documentation", "LOW", "html-docs"),
            ("/api-docs", "API Documentation Endpoint", "LOW", "json-docs"),
            ("/graphql", "GraphQL API Endpoint", "INFO", "graphql"),
            ("/robots.txt", "Robots Crawler Directives", "INFO", "robots"),
            ("/sitemap.xml", "XML Sitemap", "INFO", "sitemap"),
            ("/.well-known/security.txt", "Security Policy Contact", "INFO", "security-txt")
        ]

        findings = []
        if not self.async_client:
            return findings

        # 1. Soft 404 & WAF Catch-All Baseline Request
        random_token = f"patrict-chk-{uuid.uuid4().hex[:12]}.html"
        baseline_url = urllib.parse.urljoin(base_url, f"/{random_token}")
        
        baseline_status = 404
        baseline_len = 0
        baseline_hash = ""
        baseline_title = ""

        try:
            b_status, b_body, b_headers = await self.async_client.get(baseline_url, timeout=6)
            baseline_status = b_status
            baseline_len = len(b_body)
            baseline_hash = hashlib.md5(b_body.encode("utf-8", errors="ignore")).hexdigest()
            t_match = re.search(r"<title>(.*?)</title>", b_body, re.IGNORECASE)
            if t_match:
                baseline_title = t_match.group(1).strip().lower()
        except Exception:
            pass

        # 2. Eksekusi Probe Setiap Endpoint
        for path, desc, default_sev, file_type in candidates:
            probe_url = urllib.parse.urljoin(base_url, path)
            try:
                status, body, headers = await self.async_client.get(probe_url, timeout=6)
                if status in (200, 301, 302, 401, 403):
                    is_real = True
                    content_len = len(body)
                    assigned_sev = default_sev
                    body_lower = body.lower()
                    content_type = str(headers.get("content-type", "")).lower()

                    # Status 401 & 403: Terproteksi / Diblokir oleh Server
                    if status in (401, 403):
                        assigned_sev = "BLOCKED"
                        status_phrase = http.client.responses.get(status, "Forbidden")
                        desc = f"{desc} (Akses Diblokir oleh Server [{status_phrase}])"

                    # Status 200: Validasi Ketat Terhadap Soft 404 / Catch-all & Content-Type
                    elif status == 200:
                        is_html = "<!doctype html" in body_lower or "<html" in body_lower or "<head" in body_lower or "<body" in body_lower

                        # A. Soft 404 Check: Bandingkan dengan Baseline Acak
                        if baseline_status == 200:
                            current_hash = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
                            # Hash identik dengan 404 acak
                            if current_hash == baseline_hash:
                                is_real = False
                            # Ukuran identik (toleransi ±15 bytes)
                            elif abs(content_len - baseline_len) <= 15:
                                is_real = False
                            # Judul halaman sama persis dengan baseline 404
                            elif baseline_title:
                                p_title_m = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
                                if p_title_m and p_title_m.group(1).strip().lower() == baseline_title:
                                    is_real = False

                        # B. Format & Content-Type Validation per Tipe File
                        if is_real:
                            if file_type in ("config", "log", "sql"):
                                # File config/sql/log tidak boleh berupa halaman HTML
                                if is_html or "text/html" in content_type:
                                    is_real = False

                            elif file_type == "git":
                                # .git/HEAD harus memuat ref atau hash 40 karakter
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
                        findings.append({
                            "path": path,
                            "url": probe_url,
                            "status": status,
                            "description": desc,
                            "severity": assigned_sev,
                            "size_bytes": content_len,
                            "content_type": headers.get("content-type", "Unknown")
                        })
            except (socket.timeout, asyncio.TimeoutError, ConnectionError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"Error probing {probe_url}: {e}")

        return findings

    def _generate_threat_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Menghasilkan rangkuman ancaman keamanan, tingkat risiko keseluruhan (Threat Score),
        dan rekomendasi mitigasi konkret untuk target web.
        Hanya memasukkan file yang benar-benar berstatus 200 OK yang terverifikasi.
        """
        threats = []
        risk_score = 0  # 0 to 100

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

        # Origin IP Leak
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

        # Sensitive Files Exposed (Hanya hitung yang berstatus 200 OK dengan konten terverifikasi)
        files = results.get("sensitive_files_found", [])
        critical_files = [f for f in files if f.get("severity") == "CRITICAL" and f.get("status") == 200]
        high_files = [f for f in files if f.get("severity") == "HIGH" and f.get("status") == 200]

        if critical_files:
            risk_score += 40
            names = ", ".join([f["path"] for f in critical_files])
            threats.append({
                "category": "Data Exposure / Credentials Leak",
                "severity": "CRITICAL",
                "title": f"File Konfigurasi / Secret Kritis Terekspos ({names})",
                "impact": "Kunci API, database credentials, atau source code dapat diunduh oleh publik.",
                "mitigation": "Blokir akses publik ke file titik (.) dan file backup pada konfigurasi web server (Nginx/Apache)."
            })
        elif high_files:
            risk_score += 20
            names = ", ".join([f["path"] for f in high_files])
            threats.append({
                "category": "Information Disclosure",
                "severity": "HIGH",
                "title": f"File Log / Debug Terekspos ({names})",
                "impact": "Informasi stack trace dan environment internal dapat dipelajari penyerang.",
                "mitigation": "Pindahkan folder log ke luar direktori public web root."
            })

        # SSL Expiry
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

        # Cookie Security Flags (Hanya dievaluasi jika ada session cookie aktif)
        auth_data = results.get("auth_intelligence", {})
        session_cookies = auth_data.get("session_cookies", [])
        jwt_tokens = auth_data.get("jwt_tokens", [])
        flags = auth_data.get("security_flags", {})

        if (session_cookies or jwt_tokens) and (not flags.get("httponly") or not flags.get("secure")):
            risk_score += 10
            threats.append({
                "category": "Session & Cookie Security",
                "severity": "MEDIUM",
                "title": "Flag Keamanan Cookie Belum Lengkap (HttpOnly / Secure)",
                "impact": "Session token dapat dicuri via XSS jika HttpOnly tidak aktif.",
                "mitigation": "Set flag 'HttpOnly; Secure; SameSite=Lax' pada semua Set-Cookie session."
            })

        # Overall Risk Level Mapping
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
            except (socket.gaierror, socket.timeout, OSError):
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
        """Mengambil data koordinat & GeoIP dari server IP publik dengan fallback rapi"""
        if not ip or not self.async_client:
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
            status, text, _ = await self.async_client.get(url, timeout=6)
            if status == 200:
                data = json.loads(text)
                if data.get("status") == "success":
                    lat = data.get("lat")
                    lon = data.get("lon")
                    maps_url = f"https://www.google.com/maps?q={lat},{lon}" if lat is not None and lon is not None else ""
                    return {
                        "ip": ip,
                        "country": data.get("country") or "Unknown Country",
                        "region": data.get("regionName") or "",
                        "city": data.get("city") or "",
                        "latitude": lat if lat is not None else "-",
                        "longitude": lon if lon is not None else "-",
                        "isp": data.get("isp") or data.get("org") or "Unknown ISP / Organization",
                        "organization": data.get("org") or "",
                        "asn": data.get("as") or "",
                        "maps_url": maps_url
                    }
        except Exception as e:
            self.logger.warning(f"Gagal mengambil GeoIP server ({ip}): {e}")

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
            "security_headers_grade": {},
            "ssl_certificate": {},
            "crtsh_subdomains": {},
            "origin_ip_leak": {},
            "auth_intelligence": {},
            "tech_stack": {},
            "sensitive_files_found": [],
            "dns_records": {},
            "server_geoip": {},
            "threat_vulnerability_summary": {},
            "whatweb_summary": ""
        }

        # 1. Resolusi DNS Domain
        dns_data = self._resolve_dns(domain)
        results["dns_records"] = dns_data

        a_records = dns_data.get("A", [])
        server_ip = a_records[0] if a_records else ""
        if not server_ip and domain and domain != "N/A":
            try:
                server_ip = socket.gethostbyname(domain)
            except (socket.gaierror, socket.timeout, OSError):
                server_ip = ""

        # 2. Resolusi GeoIP & Koordinat Server
        if server_ip:
            results["server_geoip"] = await self._get_server_geoip(server_ip)

        # 3. Ekstraksi Metadata Sertifikat SSL/TLS
        results["ssl_certificate"] = self._extract_ssl_certificate(domain)

        # 4. Passive Subdomain Discovery via CT Logs (crt.sh)
        results["crtsh_subdomains"] = await self._fetch_crtsh_subdomains(domain)

        # 5. Otomasi Deteksi Kebocoran Origin IP (Cloudflare / CDN Bypass)
        results["origin_ip_leak"] = self._detect_origin_ip_leak(domain, dns_data, results["server_geoip"])

        if not self.async_client:
            return self.success_response(results, "Analisis DNS & SSL Selesai.")

        # 6. Analisis HTTP Methods (OPTIONS & HEAD)
        try:
            status, _, headers = await self.async_client.options(url, timeout=6)
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

        # 8. Ekstraksi Metadata Halaman & Scraping Email
        results["page_metadata"] = self._extract_page_metadata(html_content)

        # 9. Security Headers Analysis & Grader (A+ sampai F)
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
        results["security_headers_grade"] = self._grade_security_headers(final_headers)

        # 10. Auth & Cookies Intelligence
        results["auth_intelligence"] = self._analyze_cookies_and_auth(cookies_captured, final_headers)

        # 11. Tech Stack Fingerprinting (WhatWeb Style)
        results["tech_stack"] = self._detect_tech_stack(final_headers, html_content)

        # 12. Sensitive File & Directory Discovery (Passive Probing with Soft 404 Filtering)
        results["sensitive_files_found"] = await self._probe_sensitive_files(results["final_url"])

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
        if results["tech_stack"].get("cms_and_platforms"):
            brief_parts.append(f"CMS[{', '.join(results['tech_stack'].get('cms_and_platforms'))}]")
        if results["tech_stack"].get("frontend_libraries"):
            brief_parts.append(f"JScript[{', '.join(results['tech_stack'].get('frontend_libraries'))}]")
        results["whatweb_summary"] = ", ".join(brief_parts)

        return self.success_response(results, f"Pemindaian Web & Infrastruktur {domain} Berhasil.")
