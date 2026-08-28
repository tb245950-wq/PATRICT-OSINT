#!/usr/bin/env python3
# ============================================================
# PATRICT-OSINT FRAMEWORK - MONOREPO ORCHESTRATOR
# VERSION: 2.5.0
# ============================================================

import os
import sys
import re
import json
import asyncio
import argparse
import http.client
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from core.config_manager import ConfigManager
from core.async_client import AsyncHttpClient
from core.plugin_loader import PluginLoader
from visualizers.graph_engine import GraphEngine
from reports.report_generator import ReportGenerator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "2.5.0"

# ANSI Terminal Colors
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BOLD = "\033[1m"
RESET = "\033[0m"

class PATRICTOrchestrator:
    """
    Main Orchestrator for PATRICT-OSINT Framework.
    Mengatur konfigurasi, dynamic plugin loader, eksekusi async,
    pencetakan hasil kaya langsung di terminal, dan ekspor JSON.
    """
    
    def __init__(
        self,
        config_path: str = None,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
        headers: Optional[List[str]] = None,
        cookie: Optional[str] = None,
        proxy: Optional[str] = None,
        aggression: int = 1,
        max_threads: Optional[int] = None,
        verbose: bool = False,
        quiet: bool = False,
        no_errors: bool = False
    ):
        if config_path is None:
            default_cfg = os.path.join(BASE_DIR, "config", "config.yaml")
            if not os.path.exists(default_cfg):
                default_cfg = os.path.join(BASE_DIR, "config", "config.example.yaml")
            config_path = default_cfg
        elif not os.path.isabs(config_path) and not os.path.exists(config_path):
            candidate = os.path.join(BASE_DIR, config_path)
            if os.path.exists(candidate):
                config_path = candidate

        self.config_manager = ConfigManager(config_path)
        
        # Override HTTP & runtime options dari CLI flags
        if timeout:
            self.config_manager.set("app.timeout", timeout)
        if max_threads:
            self.config_manager.set("app.max_concurrency", max_threads)
        if user_agent:
            self.config_manager.set("http.user_agent", user_agent)
        if cookie:
            self.config_manager.set("http.cookie", cookie)
        if proxy:
            self.config_manager.set("http.proxy", proxy)
        if headers:
            h_dict = {}
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    h_dict[k.strip()] = v.strip()
            self.config_manager.set("http.headers", h_dict)
            
        self.aggression = aggression
        self.config_manager.set("web.aggression", aggression)
        self.verbose = verbose
        self.quiet = quiet
        self.no_errors = no_errors
            
        self.output_dir = self.config_manager.get("app.output_dir", "./output")
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.async_client = AsyncHttpClient(self.config_manager)
        
        modules_dir = os.path.join(BASE_DIR, "modules")
        if not os.path.exists(modules_dir):
            modules_dir = "modules"
            
        self.plugin_loader = PluginLoader(
            modules_dir=modules_dir,
            config=self.config_manager,
            async_client=self.async_client
        )
        self.graph_engine = GraphEngine(self.output_dir)
        self.report_generator = ReportGenerator(
            output_dir=self.output_dir,
            template_dir=os.path.join(BASE_DIR, "reports", "templates")
        )

    def print_banner(self):
        banner = rf"""
{BLUE}==================================================================={RESET}
{BLUE}  ____       _  _____ ____  ___ ____ _____ {RESET}       {WHITE} ___  ____ ___ _   _ _____ {RESET}
{BLUE} |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|{RESET}      {WHITE}/ _ \/ ___|_ _| \ | |_   _|{RESET}
{BLUE} | |_) |   / _ \ | | | |_) || | |     | |  {CYAN}____ {WHITE}| | | \___ \| ||  \| | | |  {RESET}
{BLUE} |  __/   / ___ \| | |  _ < | | |___  | | {CYAN}|____|{WHITE}| |_| |___) | || |\  | | |  {RESET}
{BLUE} |_|     /_/   \_\_| |_| \_\___\____| |_|  {RESET}      {WHITE}\___/|____/___|_| \_| |_|  {RESET}
{BLUE}==================================================================={RESET}
                        {BLUE}PATRICT{WHITE}-{CYAN}OSINT {WHITE}v{VERSION}{RESET}
{BLUE}==================================================================={RESET}
"""
        print(banner)

    def list_plugins(self):
        """Menampilkan daftar seluruh plugin/modul yang tersedia."""
        modules = self.plugin_loader.discover_and_load(target_type="all", verbose=False)
        print("\nAvailable Modules / Plugins in PATRICT-OSINT:\n")
        print(f"  {'MODULE ID':<22} {'DOMAIN':<8} {'VERSION':<8} {'DESCRIPTION'}")
        print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*45}")
        for m in modules:
            print(f"  {m.module_id:<22} {m.target_type:<8} {m.version:<8} {m.name}")
        print(f"\nTotal: {len(modules)} plugins loaded.\n")

    def _print_phone_terminal(self, target: str, results: Dict[str, Any]):
        p_data = results.get("phone_osint", {}).get("data", {})
        c_data = results.get("caller_id_osint", {}).get("data", {})
        l_data = results.get("location_osint", {}).get("data", {})
        s_data = results.get("social_osint", {}).get("data", {})
        e_data = results.get("email_osint", {}).get("data", {})
        w_data = results.get("whatsapp_osint", {}).get("data", {})
        d_data = results.get("dorking_osint", {}).get("data", {})

        formatting = p_data.get("formatting", {})
        telecom_meta = p_data.get("telecom_meta", {})
        hlr_info = p_data.get("hlr_carrier_intelligence", {})
        endpoints = p_data.get("endpoint_links", {})
        threat_links = p_data.get("threat_intel_links", [])
        dorks = p_data.get("osint_dorks", [])
        wa_intel = p_data.get("whatsapp_intelligence", {})

        e164_str = formatting.get("e164") or p_data.get("e164", target)
        nat_str = formatting.get("national") or p_data.get("national", "N/A")
        rfc3966_str = formatting.get("rfc3966", f"tel:{e164_str}")
        line_type = telecom_meta.get("line_type") or p_data.get("type", "Mobile / Seluler")
        is_valid = p_data.get("validation", {}).get("is_valid_e164", p_data.get("valid", True))
        timezones = telecom_meta.get("timezones", [])
        tz_display = ", ".join(timezones) if timezones else "Asia/Jakarta (WIB - UTC+7)"

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL RECONNAISSANCE TELEKOMUNIKASI (PHONE){RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target Input{RESET}        : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Format E.164 (ITU-T){RESET}: {GREEN}{BOLD}{e164_str}{RESET}")
        print(f"  {CYAN}Format Nasional{RESET}     : {WHITE}{nat_str}{RESET}")
        print(f"  {CYAN}Format RFC3966{RESET}      : {WHITE}{rfc3966_str}{RESET}")
        print(f"  {CYAN}Tipe Saluran (Line){RESET} : {WHITE}{line_type}{RESET}")
        print(f"  {CYAN}Zona Waktu (TZ){RESET}     : {WHITE}{tz_display}{RESET}")
        print(f"  {CYAN}Status Validitas{RESET}    : {GREEN}ITU-T E.164 VALID [OK]{RESET}" if is_valid else f"  {CYAN}Status Validitas{RESET}    : {YELLOW}POSSIBLE / UNCONFIRMED{RESET}")

        # 1. Database HLR & Operator Intelligence Granular
        print(f"\n{YELLOW}[+] DATABASE OFFLINE HLR & OPERATOR TELEKOMUNIKASI:{RESET}")
        print(f"  * Operator / Provider : {GREEN}{BOLD}{hlr_info.get('carrier_name') or p_data.get('carrier', 'N/A')}{RESET}")
        print(f"  * Brand / Produk Kartu: {WHITE}{hlr_info.get('card_brand', 'Prepaid/Postpaid')}{RESET}")
        print(f"  * Granularitas Prefix : {WHITE}{hlr_info.get('match_level', 'Regional')} (Prefix: {hlr_info.get('prefix', '')}){RESET}")
        mcc_mnc_str = f"MCC: {hlr_info.get('mcc', '510')} | MNC: {hlr_info.get('mnc', 'N/A')}"
        print(f"  * Kode Jaringan Telco : {WHITE}{mcc_mnc_str}{RESET}")
        print(f"  * Wilayah Alokasi HLR : {WHITE}{hlr_info.get('hlr_region') or telecom_meta.get('location_description', 'Indonesia')}{RESET}")
        print(f"  * Teknologi Jaringan  : {WHITE}{hlr_info.get('network_technology', 'GSM / 4G / 5G')}{RESET}")

        # 2. Identitas & Caller Directory
        print(f"\n{YELLOW}[+] IDENTITAS & CALLER DIRECTORY REGISTRY:{RESET}")
        owner_name = c_data.get("owner_name") or c_data.get("name") or c_data.get("caller_name") or "Tidak ditemukan di direktori publik (Private)"
        spam_score = c_data.get("spam_score", 0)
        spam_display = f"{GREEN}Clean (0% Spam Score) [OK]{RESET}" if (spam_score == 0 or spam_score == "0%") else f"{RED}{spam_score}% Spam Score [WARN]{RESET}"
        print(f"  * Nama Teridentifikasi: {WHITE}{owner_name}{RESET}")
        print(f"  * Skor Reputasi/Spam  : {spam_display}")

        # 3. Direct Messaging & Passive WhatsApp Verification
        print(f"\n{YELLOW}[+] DIRECT MESSAGING & VERIFIKASI ENDPOINT:{RESET}")
        wa_link = endpoints.get("whatsapp_direct", f"https://wa.me/{re.sub(r'[^0-9]', '', e164_str)}")
        tg_link = endpoints.get("telegram_direct", f"https://t.me/+{re.sub(r'[^0-9]', '', e164_str)}")
        tc_link = endpoints.get("truecaller_search", f"https://www.truecaller.com/search/id/{re.sub(r'[^0-9]', '', nat_str)}")
        sync_link = endpoints.get("syncme_search", f"https://sync.me/search/?number={urllib.parse.quote_plus(e164_str)}")

        wa_badge = wa_intel.get("status_badge", "Direct Link Available")
        print(f"  * Status WhatsApp     : {GREEN if 'Active' in wa_intel.get('status', '') or wa_intel.get('is_business') else WHITE}{wa_badge}{RESET}")
        print(f"  * WhatsApp Direct API : {CYAN}{wa_link}{RESET}")
        print(f"  * Telegram Profile    : {CYAN}{tg_link}{RESET}")
        print(f"  * Truecaller Lookup   : {CYAN}{tc_link}{RESET}")
        print(f"  * Sync.ME Lookup Web  : {CYAN}{sync_link}{RESET}")

        # 4. Kebocoran Data (Data Breach Intelligence)
        breach_status = e_data.get("breach_status", "Clean / Not Found in Public Dumps")
        breaches = e_data.get("breaches", [])
        print(f"\n{YELLOW}[+] STATUS KEBOCORAN DATA (DATA BREACH INTELLIGENCE):{RESET}")
        if breaches:
            print(f"  * Status Kebocoran    : {RED}{BOLD}DITEMUKAN DI {len(breaches)} DATABASE LEAK!{RESET}")
            for b in breaches[:3]:
                print(f"    - [{b.get('breach_date', 'N/A')}] {WHITE}{b.get('title')}{RESET} ({', '.join(b.get('data_classes', [])[:3])})")
        else:
            print(f"  * Status Kebocoran    : {GREEN}{breach_status} [AMAN]{RESET}")

        # 5. Threat Intel & Deep Breach Search Links
        if threat_links:
            print(f"\n{YELLOW}[+] THREAT INTEL & DEEP BREACH SEARCH SHORTCUTS:{RESET}")
            for tl in threat_links[:4]:
                print(f"  * {WHITE}{BOLD}{tl.get('platform')}{RESET} ({tl.get('category')}):")
                print(f"    {CYAN}{tl.get('url')}{RESET}")

        # 6. Media Sosial Terverifikasi
        accounts = s_data.get("accounts", []) if isinstance(s_data, dict) else []
        print(f"\n{YELLOW}[+] AKUN MEDIA SOSIAL TERHUBUNG ({len(accounts)} Ditemukan):{RESET}")
        if accounts:
            for acc in accounts:
                print(f"  * {acc.get('platform', 'Platform') : <20} : {GREEN}Terdeteksi{RESET} ({acc.get('url', '')})")
        else:
            print(f"  * {WHITE}Tidak ditemukan akun media sosial publik dengan signature nomor ini.{RESET}")

        # 7. Automated OSINT Google Dorking Generator (Clickable Links)
        print(f"\n{YELLOW}[+] GOOGLE & DUCKDUCKGO OSINT DORKING LINKS:{RESET}")
        if dorks:
            for d in dorks:
                print(f"  * {WHITE}{BOLD}{d.get('category')}{RESET}:")
                print(f"    {CYAN}{d.get('google_search_url')}{RESET}")
        else:
            encoded_q = urllib.parse.quote(f'"{e164_str}" OR "{nat_str}"')
            print(f"  * Dokumen Publik (.PDF/.XLSX): {CYAN}https://www.google.com/search?q={encoded_q}+filetype:pdf{RESET}")
            print(f"  * Marketplace & Forum        : {CYAN}https://www.google.com/search?q={encoded_q}+site:tokopedia.com+OR+site:shopee.co.id{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_web_terminal(self, target: str, results: Dict[str, Any], brief: bool = False):
        w_data = results.get("web_osint", {}).get("data", {})
        
        # Mode Brief satu baris ala WhatWeb
        if brief:
            summary = w_data.get("whatweb_summary")
            if summary:
                print(f"{summary}")
            else:
                print(f"{target} [{w_data.get('final_status', 200)} OK]")
            return

        meta = w_data.get("page_metadata", {})
        geo = w_data.get("server_geoip", {})
        stack = w_data.get("tech_stack", {})
        auth = w_data.get("auth_intelligence", {})
        dns_rec = w_data.get("dns_records", {})
        sec_grade = w_data.get("security_headers_grade", {})
        ssl_info = w_data.get("ssl_certificate", {})
        crt_data = w_data.get("crtsh_subdomains", {})
        origin_leak = w_data.get("origin_ip_leak", {})
        sensitive_files = w_data.get("sensitive_files_found", [])
        threat_data = w_data.get("threat_vulnerability_summary", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL RECONNAISSANCE WEB & WHATWEB FINGERPRINT{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target URL{RESET}          : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Domain Asli{RESET}         : {WHITE}{w_data.get('domain', 'N/A')}{RESET}")
        
        status_code = w_data.get('final_status', 200)
        status_phrase = http.client.responses.get(status_code, "OK" if status_code == 200 else "")
        status_color = GREEN if status_code == 200 else (YELLOW if status_code in (301, 302) else RED)
        print(f"  {CYAN}Status HTTP{RESET}         : {status_color}{status_code} {status_phrase}{RESET}")
        print(f"  {CYAN}Final Destination{RESET}   : {WHITE}{w_data.get('final_url', target)}{RESET}")
        
        if meta.get("title"):
            print(f"  {CYAN}Page Title{RESET}        : {WHITE}{meta.get('title')}{RESET}")
            
        methods = w_data.get("http_methods_allowed", [])
        print(f"  {CYAN}Allowed Methods{RESET}     : {GREEN}{', '.join(methods) if methods else 'GET, HEAD'}{RESET}")

        # Server GeoIP
        print(f"\n{YELLOW}[+] SERVER & NETWORK GEOIP:{RESET}")
        print(f"  * IP Publik Server  : {WHITE}{geo.get('ip', 'N/A')}{RESET}")
        
        city = str(geo.get("city", "")).strip()
        country = str(geo.get("country", "")).strip()
        if city and country and city != "Unknown City" and country != "Unknown Country":
            loc_str = f"{city}, {country}"
        elif country and country != "Unknown Country" and country != "Unknown Location / Protected IP":
            loc_str = country
        elif city and city != "Unknown City":
            loc_str = city
        else:
            loc_str = "Unknown Location / Protected IP"

        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if lat is not None and lon is not None and str(lat) != "-" and str(lon) != "-":
            coord_str = f"(Lat: {lat}, Lon: {lon})"
        else:
            coord_str = ""

        loc_line = f"{loc_str} {coord_str}".strip()
        print(f"  * Lokasi Server     : {WHITE}{loc_line}{RESET}")
        print(f"  * ISP / Organisasi  : {WHITE}{geo.get('isp') or geo.get('organization') or 'Unknown ISP / Protected IP'}{RESET}")
        if geo.get("asn"):
            print(f"  * ASN Jaringan      : {WHITE}{geo.get('asn')}{RESET}")
        if geo.get("maps_url"):
            print(f"  * Lokasi Google Maps: {CYAN}{geo.get('maps_url')}{RESET}")

        # 1. SSL/TLS Certificate Intelligence
        print(f"\n{YELLOW}[+] SERTIFIKAT SSL/TLS & ENKRIPSI:{RESET}")
        if ssl_info.get("has_ssl"):
            issuer_org = ssl_info.get("issuer", {}).get("organizationName") or ssl_info.get("issuer", {}).get("commonName") or "N/A"
            days = ssl_info.get("days_remaining")
            if days is not None:
                exp_badge = f"{GREEN}{days} hari tersisa [VALID]{RESET}" if days > 14 else f"{RED}{days} hari tersisa [EXPIRING SOON]{RESET}"
            else:
                exp_badge = f"{GREEN}Sertifikat Valid (Masa berlaku aktif){RESET}"
            print(f"  * Issuer Authority  : {WHITE}{issuer_org}{RESET}")
            print(f"  * Masa Berlaku      : {WHITE}{ssl_info.get('valid_from', '-')} s/d {ssl_info.get('valid_until', '-')}{RESET}")
            print(f"  * Status Kedaluwarsa: {exp_badge}")
            print(f"  * Protokol & Cipher : {WHITE}{ssl_info.get('tls_version', 'TLS')} - {ssl_info.get('cipher', 'N/A')}{RESET}")
            print(f"  * SANs Terdaftar    : {WHITE}{len(ssl_info.get('san_list', []))} domain{RESET}")
        else:
            print(f"  * {RED}Tidak ada sertifikat SSL/TLS aktif (Port 443 tidak merespon/Plain HTTP).{RESET}")

        # 2. Passive Subdomain Discovery via CT Logs (crt.sh)
        sub_count = crt_data.get("total_found", 0)
        print(f"\n{YELLOW}[+] SUBDOMAIN PASIF DARI CERTIFICATE TRANSPARENCY ({sub_count} Ditemukan):{RESET}")
        if crt_data.get("unique_subdomains"):
            sample_subs = crt_data.get("unique_subdomains", [])[:8]
            for sub in sample_subs:
                print(f"  * {CYAN}{sub}{RESET}")
            if sub_count > 8:
                print(f"  * {WHITE}... dan {sub_count - 8} subdomain lainnya (lihat file laporan JSON/MD).{RESET}")
        else:
            print(f"  * {WHITE}Tidak ditemukan subdomain pasif di CT logs.{RESET}")

        # 3. Cloudflare / CDN Origin IP Leak Alert
        if origin_leak.get("leak_detected"):
            print(f"\n{RED}{BOLD}[!] PERINGATAN: POTENSI KEBOCORAN ORIGIN IP SERVER TERDETEKSI!{RESET}")
            print(f"  * Target di balik   : {YELLOW}{origin_leak.get('cdn_provider')}{RESET}")
            for leak in origin_leak.get("leaked_ips", []):
                print(f"  {RED}[!] POTENTIAL ORIGIN IP LEAK: {WHITE}{BOLD}{leak.get('ip')}{RESET} {YELLOW}(Sumber: {leak.get('source')}){RESET}")
                print(f"      Risiko          : {WHITE}{leak.get('risk')}{RESET}")
        elif origin_leak.get("is_behind_cdn"):
            print(f"\n{YELLOW}[+] DETEKSI CDN & CLOUDFLARE:{RESET}")
            print(f"  * Status CDN        : {GREEN}Aktif ({origin_leak.get('cdn_provider')}){RESET}")
            print(f"  * Kebocoran Origin  : {GREEN}Tidak ditemukan (Rapat) [OK]{RESET}")

        # 4. Security Headers Grader
        grade = sec_grade.get("grade", "N/A")
        score = sec_grade.get("score", 0)
        grade_color = GREEN if grade in ("A+", "A") else (CYAN if grade in ("B+", "B") else (YELLOW if grade == "C" else RED))
        
        print(f"\n{YELLOW}[+] SECURITY HEADERS GRADER:{RESET}")
        print(f"  * Skor & Grade      : {grade_color}{BOLD}[ GRADE: {grade} ]{RESET} {WHITE}(Skor Keamanan: {score}/100){RESET}")
        evals = sec_grade.get("evaluations", {})
        for h_name, h_val in evals.items():
            st = h_val.get("status")
            st_badge = f"{GREEN}[PASS]{RESET}" if st == "PASS" else (f"{YELLOW}[WARN]{RESET}" if st == "WARN" else f"{RED}[FAIL]{RESET}")
            print(f"  * {h_name : <28}: {st_badge} {WHITE}{h_val.get('score')}{RESET} - {h_val.get('details')}")

        if sec_grade.get("recommendations"):
            print(f"  {YELLOW}Rekomendasi Hardening:{RESET}")
            for rec in sec_grade.get("recommendations")[:3]:
                print(f"    - {WHITE}{rec}{RESET}")

        # 5. Sensitive File & Directory Discovery
        if sensitive_files:
            print(f"\n{YELLOW}[+] DISCOVERY FILE & DIREKTORI SENSITIF ({len(sensitive_files)} Terdeteksi):{RESET}")
            for sf in sensitive_files:
                sev = sf.get("severity", "INFO")
                if sev in ("CRITICAL", "HIGH"):
                    sev_color = RED
                elif sev == "BLOCKED":
                    sev_color = GREEN
                elif sev == "MEDIUM":
                    sev_color = YELLOW
                else:
                    sev_color = CYAN
                status_color = GREEN if sf.get("status") == 200 else (YELLOW if sf.get("status") in (401, 403) else WHITE)
                print(f"  * {sev_color}[{sev : <8}]{RESET} {WHITE}{sf.get('path') : <28}{RESET} : {status_color}[{sf.get('status')}]{RESET} ({sf.get('description')}, {sf.get('size_bytes')} B)")

        # 6. Tech Stack ala WhatWeb
        print(f"\n{YELLOW}[+] STACK TEKNOLOGI & FINGERPRINTING:{RESET}")
        servers = stack.get("web_servers", [])
        langs = stack.get("programming_languages", [])
        backends = stack.get("backend_frameworks", [])
        frontends = stack.get("frontend_libraries", [])
        cms_list = stack.get("cms_and_platforms", [])
        wafs = stack.get("waf_and_security", [])
        cdns = stack.get("analytics_and_cdn", [])

        print(f"  * Web Servers       : {WHITE}{', '.join(servers) if servers else 'Hidden / Generic'}{RESET}")
        if langs:
            print(f"  * Language/Runtime  : {WHITE}{', '.join(langs)}{RESET}")
        if backends:
            print(f"  * Backend Framework : {WHITE}{', '.join(backends)}{RESET}")
        if frontends:
            print(f"  * Frontend Tech     : {WHITE}{', '.join(frontends)}{RESET}")
        if cms_list:
            print(f"  * CMS / Platform    : {WHITE}{', '.join(cms_list)}{RESET}")
        if wafs:
            print(f"  * WAF / Firewall    : {YELLOW}{', '.join(wafs)}{RESET}")
        if cdns:
            print(f"  * CDN / Analytics   : {WHITE}{', '.join(cdns)}{RESET}")

        # 7. Auth & Security
        print(f"\n{YELLOW}[+] AUTHENTICATION & COOKIE SECURITY:{RESET}")
        auth_types = auth.get("auth_type_detected", ["Standard / Stateless"])
        print(f"  * Tipe Auth/Session : {WHITE}{', '.join(auth_types)}{RESET}")
        
        flags = auth.get("security_flags", {})
        httponly = f"{GREEN}Aktif [OK]{RESET}" if flags.get("httponly") else f"{RED}Tidak Aktif [FAIL]{RESET}"
        secure = f"{GREEN}Aktif [OK]{RESET}" if flags.get("secure") else f"{RED}Tidak Aktif [FAIL]{RESET}"
        samesite = flags.get("samesite") or "Default"
        print(f"  * Cookie Flags      : HttpOnly: {httponly} | Secure: {secure} | SameSite: {WHITE}{samesite}{RESET}")

        # 8. DNS Records
        if any(dns_rec.values()):
            print(f"\n{YELLOW}[+] DNS RECORDS MATRIX:{RESET}")
            for r_type in ["A", "MX", "NS", "TXT"]:
                r_val = dns_rec.get(r_type, [])
                if r_val:
                    print(f"  * {r_type : <18}: {WHITE}{', '.join(r_val[:3])}{RESET}")

        # 9. Executive Vulnerability & Threat Assessment Summary Matrix
        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"         {WHITE}{BOLD}RANGKUMAN ANCAMAN & VULNERABILITY ASSESSMENT{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        threat_level = threat_data.get("overall_threat_level", "LOW")
        tl_color = RED if threat_level in ("CRITICAL", "HIGH") else (YELLOW if threat_level == "MEDIUM" else GREEN)
        
        print(f"  * Tingkat Ancaman   : {tl_color}{BOLD}[ {threat_level} ]{RESET} (Risk Score: {threat_data.get('risk_score', 0)}/100)")
        print(f"  * Total Temuan      : {WHITE}{threat_data.get('total_threats_identified', 0)} poin ancaman teridentifikasi{RESET}")
        
        threat_items = threat_data.get("threats", [])
        if threat_items:
            print(f"\n  {YELLOW}Rincian Ancaman & Mitigasi:{RESET}")
            for idx, th in enumerate(threat_items, 1):
                th_color = RED if th.get("severity") in ("CRITICAL", "HIGH") else (YELLOW if th.get("severity") == "MEDIUM" else CYAN)
                print(f"  [{idx}] {th_color}[{th.get('severity')}]{RESET} {WHITE}{BOLD}{th.get('title')}{RESET} ({th.get('category')})")
                print(f"      Dampak          : {WHITE}{th.get('impact')}{RESET}")
                print(f"      Mitigasi        : {GREEN}{th.get('mitigation')}{RESET}")
        else:
            print(f"  {GREEN}[+] Konfigurasi aman, tidak ditemukan celah ancaman kritis pada scope ini.{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_file_terminal(self, target: str, results: Dict[str, Any]):
        f_data = results.get("file_forensics", {}).get("data", {})
        f_info = f_data.get("file_info", {})
        hashes = f_data.get("cryptographic_hashes", {})
        entropy = f_data.get("shannon_entropy", {})
        magic = f_data.get("magic_bytes_inspection", {})
        exif = f_data.get("exif_metadata", {})
        pdf = f_data.get("pdf_forensics", {})
        office = f_data.get("office_forensics", {})
        lsb = f_data.get("lsb_steganography", {})
        carving = f_data.get("binary_carving_and_payload", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL FORENSIK MEDIA, DOKUMEN & BERKAS{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Nama Berkas{RESET}         : {WHITE}{f_info.get('file_name', os.path.basename(target))}{RESET}")
        print(f"  {CYAN}Lokasi Path{RESET}         : {WHITE}{f_info.get('file_path', target)}{RESET}")
        print(f"  {CYAN}Ukuran Berkas{RESET}       : {WHITE}{f_info.get('file_size_formatted', 'N/A')} ({f_info.get('file_size_bytes', 0)} bytes){RESET}")
        print(f"  {CYAN}Ekstensi Berkas{RESET}     : {WHITE}{f_info.get('file_extension', 'N/A')}{RESET}")

        # 1. Kriptografi & Shannon Entropy
        print(f"\n{YELLOW}[+] KRIPTOGRAFI & SHANNON ENTROPY INTEGRITAS:{RESET}")
        print(f"  * MD5               : {WHITE}{hashes.get('md5', 'N/A')}{RESET}")
        print(f"  * SHA-1             : {WHITE}{hashes.get('sha1', 'N/A')}{RESET}")
        print(f"  * SHA-256           : {WHITE}{hashes.get('sha256', 'N/A')}{RESET}")
        
        ent_val = entropy.get("entropy", 0.0)
        ent_rating = entropy.get("rating", "UNKNOWN")
        ent_color = RED if ent_rating == "VERY HIGH" else (YELLOW if ent_rating == "HIGH" else GREEN)
        print(f"  * Shannon Entropy   : {ent_color}{ent_val} bits/byte [{ent_rating}]{RESET}")
        print(f"  * Analisis Entropy  : {WHITE}{entropy.get('description', 'N/A')}{RESET}")

        # 2. Verifikasi Magic Bytes & Anti-Spoofing
        print(f"\n{YELLOW}[+] VERIFIKASI MAGIC BYTES & ANTI-SPOOFING:{RESET}")
        is_spoofed = magic.get("is_extension_spoofed", False)
        spoof_badge = f"{RED}[PERINGATAN] Ekstensi dipalsukan / Spoofed!{RESET}" if is_spoofed else f"{GREEN}Valid (Sesuai signature) [OK]{RESET}"
        print(f"  * Tipe Berkas Asli  : {WHITE}{magic.get('detected_file_type', 'Unknown')}{RESET}")
        print(f"  * Status Ekstensi   : {spoof_badge}")

        # 3. EXIF Kamera, Optik, & GPS Presisi
        if exif.get("has_exif"):
            print(f"\n{YELLOW}[+] METADATA KAMERA, OPTIK & PENGAMBILAN GAMBAR:{RESET}")
            camera = f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
            print(f"  * Perangkat/Kamera  : {WHITE}{camera or 'N/A'}{RESET}")
            if exif.get("lens_model"):
                print(f"  * Model Lensa       : {WHITE}{exif.get('lens_model')}{RESET}")
            if exif.get("software"):
                print(f"  * Software Editor   : {WHITE}{exif.get('software')}{RESET}")
            if exif.get("artist") or exif.get("copyright"):
                print(f"  * Author / Hak Cipta: {WHITE}{exif.get('artist') or 'N/A'} (© {exif.get('copyright') or 'N/A'}){RESET}")
            if exif.get("user_comment"):
                print(f"  * User Comment      : {CYAN}{exif.get('user_comment')}{RESET}")
            if exif.get("datetime_original"):
                print(f"  * Waktu Pemotretan  : {WHITE}{exif.get('datetime_original')}{RESET}")
            
            # Exposure parameters
            exp_parts = []
            if exif.get("exposure_time"):
                exp_parts.append(f"Exp: {exif.get('exposure_time')}")
            if exif.get("f_number"):
                exp_parts.append(f"Aperture: {exif.get('f_number')}")
            if exif.get("iso_speed"):
                exp_parts.append(f"ISO: {exif.get('iso_speed')}")
            if exif.get("focal_length"):
                exp_parts.append(f"Focal: {exif.get('focal_length')}")
            if exp_parts:
                print(f"  * Parameter Optik   : {WHITE}{' | '.join(exp_parts)}{RESET}")
            if exif.get("flash"):
                print(f"  * Status Flash      : {WHITE}{exif.get('flash')}{RESET}")

            # GPS Coordinates
            gps = exif.get("gps_coordinates")
            if gps:
                print(f"\n  {GREEN}[!] DATA GEOLOKASI GPS TERDETEKSI:{RESET}")
                print(f"  * Desimal Koordinat : {GREEN}Lat: {gps.get('latitude')}, Lon: {gps.get('longitude')}{RESET}")
                if gps.get("dms_formatted"):
                    print(f"  * Format DMS        : {WHITE}{gps.get('dms_formatted')}{RESET}")
                if gps.get("altitude"):
                    print(f"  * Ketinggian/Alt    : {WHITE}{gps.get('altitude')}{RESET}")
                print(f"  * Google Maps URL   : {CYAN}{gps.get('google_maps_url')}{RESET}")
                print(f"  * OpenStreetMap URL : {CYAN}{gps.get('openstreetmap_url')}{RESET}")

        # 4. Dokumen PDF Forensics (jika target PDF)
        if pdf.get("is_pdf"):
            print(f"\n{YELLOW}[+] METADATA DOKUMEN PDF & AUDIT KEAMANAN:{RESET}")
            print(f"  * Format / Versi    : {WHITE}{pdf.get('pdf_version', 'PDF')}{RESET}")
            print(f"  * Judul Dokumen     : {WHITE}{pdf.get('title') or 'N/A'}{RESET}")
            print(f"  * Penulis / Author  : {WHITE}{pdf.get('author') or 'N/A'}{RESET}")
            print(f"  * Pembuat / Creator : {WHITE}{pdf.get('creator') or 'N/A'} (Producer: {pdf.get('producer') or 'N/A'}){RESET}")
            print(f"  * Waktu Dibuat      : {WHITE}{pdf.get('creation_date') or 'N/A'}{RESET}")
            print(f"  * Total Halaman     : {WHITE}{pdf.get('page_count', 0)} Halaman{RESET}")
            enc_status = f"{RED}Terenkripsi (Password Protected){RESET}" if pdf.get("is_encrypted") else f"{GREEN}Tidak Terenkripsi [OK]{RESET}"
            print(f"  * Status Enkripsi   : {enc_status}")
            if pdf.get("suspicious_actions"):
                print(f"  * Temuan Keamanan   : {RED}{BOLD}{' | '.join(pdf.get('suspicious_actions'))}{RESET}")

        # 5. Dokumen Office Forensics (.docx, .xlsx, .pptx)
        if office.get("is_office_doc"):
            print(f"\n{YELLOW}[+] METADATA DOKUMEN MICROSOFT OFFICE & AUDIT MACRO:{RESET}")
            print(f"  * Tipe Dokumen      : {WHITE}{office.get('doc_type')}{RESET}")
            print(f"  * Author / Creator  : {WHITE}{office.get('creator') or 'N/A'}{RESET}")
            print(f"  * Terakhir Diubah   : {WHITE}{office.get('last_modified_by') or 'N/A'}{RESET}")
            print(f"  * Revisi Ke         : {WHITE}{office.get('revision') or '1'}{RESET}")
            print(f"  * Aplikasi Pembuat  : {WHITE}{office.get('application') or 'Office'} (v{office.get('app_version') or 'N/A'}){RESET}")
            if office.get("total_editing_time_minutes"):
                print(f"  * Total Waktu Edit  : {WHITE}{office.get('total_editing_time_minutes')}{RESET}")
            macro_status = f"{RED}{BOLD}[PERINGATAN] Terdeteksi VBA Macros (Potensi Payload Malware!){RESET}" if office.get("has_vba_macros") else f"{GREEN}Bersih (Tidak ada VBA Macros) [OK]{RESET}"
            print(f"  * Status VBA Macros : {macro_status}")

        # 6. LSB Steganography Probing
        if lsb.get("lsb_probed"):
            print(f"\n{YELLOW}[+] LEAST SIGNIFICANT BIT (LSB) STEGANOGRAPHY PROBING:{RESET}")
            if lsb.get("suspicious_stego_detected"):
                print(f"  * Status LSB        : {RED}{BOLD}[PERINGATAN] Terdeteksi Anomali / Signature Tersembunyi pada LSB!{RESET}")
                if lsb.get("detected_signatures"):
                    print(f"  * Signature LSB     : {YELLOW}{', '.join(lsb.get('detected_signatures'))}{RESET}")
                if lsb.get("recovered_preview"):
                    print(f"  * Preview LSB Data  : {CYAN}{lsb.get('recovered_preview')}{RESET}")
            else:
                print(f"  * Status LSB        : {GREEN}Bersih (Tidak terdeteksi anomali teks/signature pada LSB) [OK]{RESET}")
            print(f"  * Rasio Karakter    : {WHITE}{lsb.get('printable_ascii_ratio', 0.0) * 100:.1f}% Printable ASCII Characters{RESET}")

        # 7. Deep Binary Carving & Trailing Payload
        print(f"\n{YELLOW}[+] DEEP BINARY CARVING & TRAILING PAYLOAD EXTRACTION:{RESET}")
        if carving.get("has_trailing_payload"):
            print(f"  * Status Trailing   : {RED}{BOLD}[ALERT] DITEMUKAN {carving.get('trailing_size_formatted')} TRAILING DATA SETELAH EOF!{RESET}")
            print(f"  * Tipe Payload      : {YELLOW}{carving.get('detected_payload_type')}{RESET}")
            print(f"  * Entropy Payload   : {WHITE}{carving.get('trailing_entropy')} bits/byte ({carving.get('trailing_entropy_rating')}){RESET}")
            if carving.get("carved_file_path"):
                print(f"  * Hasil Carve File  : {GREEN}{BOLD}{carving.get('carved_file_path')}{RESET}")
                print(f"  * Hash MD5 Carved   : {WHITE}{carving.get('carved_file_md5')}{RESET}")
            if carving.get("interesting_strings"):
                print(f"  * String Payload    : {CYAN}{', '.join(carving.get('interesting_strings')[:4])}{RESET}")
        else:
            print(f"  * Status Trailing   : {GREEN}Bersih (Marker EOF valid, tidak ada appended data) [OK]{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    async def run(
        self,
        target: str,
        target_type: str = "phone",
        module_filter: Optional[List[str]] = None,
        scope: str = "default",
        show_banner: bool = True,
        save_json: bool = True,
        output_file: Optional[str] = None,
        save_html: bool = False,
        brief: bool = False
    ) -> Dict[str, Any]:
        if show_banner and not brief and not self.quiet:
            self.print_banner()

        type_labels = {
            "phone": "Phone Intelligence",
            "web": "Web & Tech Recon",
            "file": "Media & File Forensics",
            "all": "All Domains"
        }
        
        if not brief and not self.quiet:
            print(f"[*] Target Reconnaissance : {WHITE}{target}{RESET}")
            print(f"[*] Tipe Domain          : {CYAN}{type_labels.get(target_type, target_type.upper())}{RESET}")
            print(f"[*] Scope Penyelidikan   : {GREEN}{scope.upper()}{RESET}")
            print(f"[*] Waktu Mulai          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"[*] Memuat Modul Dinamis...")
        
        # 1. Dynamic Discovery & Loading Modul
        modules = self.plugin_loader.discover_and_load(target_type=target_type, module_filter=module_filter, verbose=not (brief or self.quiet))
        if not brief and not self.quiet:
            print(f"[*] Total {len(modules)} Modul Siap Dijalankan.\n")
        
        results: Dict[str, Any] = {
            "meta": {
                "target": target,
                "target_type": target_type,
                "scope": scope,
                "aggression": self.aggression,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "total_modules": len(modules)
            }
        }
        
        context: Dict[str, Any] = {"aggression": self.aggression, "scope": scope}
        
        # 2. Eksekusi Modul Secara Terstruktur
        for module in modules:
            if not brief and not self.quiet:
                print(f"  [>] Menjalankan: {module.name}...")
            try:
                mod_result = await module.run(target, context=context)
                results[module.module_id] = mod_result
                context[module.module_id] = mod_result
            except Exception as e:
                if not brief and not self.quiet and not self.no_errors:
                    print(f"  [!] Error pada modul {module.name}: {e}")
                results[module.module_id] = module.error_response(str(e))
                
        # Tutup async session setelah scanning selesai
        await self.async_client.close()
        
        if not brief and not self.quiet:
            print(f"\n{GREEN}[+] Pemindaian Selesai.{RESET}")
        
        # 3. Cetak Hasil Lengkap Langsung di Layar Terminal
        if target_type == "phone":
            self._print_phone_terminal(target, results)
        elif target_type == "web":
            self._print_web_terminal(target, results, brief=brief)
        elif target_type == "file":
            self._print_file_terminal(target, results)
        else:
            if "phone_osint" in results or "caller_id_osint" in results:
                self._print_phone_terminal(target, results)
            if "web_osint" in results:
                self._print_web_terminal(target, results, brief=brief)
            if "file_forensics" in results:
                self._print_file_terminal(target, results)

        # 4. Simpan File JSON & Markdown Audit di Direktori Kerja
        if save_json and not brief:
            if output_file:
                cwd_json_path = os.path.abspath(output_file)
            else:
                safe_name = target.replace("+", "").replace("://", "_").replace("/", "_").replace(":", "_").replace(" ", "_")
                cwd_json_path = os.path.join(os.getcwd(), f"report_{target_type}_{safe_name}.json")
                
            try:
                with open(cwd_json_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                if not self.quiet:
                    print(f"  {GREEN}[+] File JSON tersimpan di     : {WHITE}{cwd_json_path}{RESET}")
            except Exception as e:
                if not self.no_errors:
                    print(f"  [!] Gagal menyimpan file JSON di {cwd_json_path}: {e}")

            # Buat file Markdown (.md) dan HTML
            reports = self.report_generator.generate_all_reports(
                target=target,
                full_data=results,
                target_type=target_type
            )
            md_file = reports.get("markdown")
            if md_file and not self.quiet:
                print(f"  {GREEN}[+] Laporan Markdown Audit     : {WHITE}{md_file}{RESET}")

            if save_html:
                html_file = reports.get("html")
                if html_file and not self.quiet:
                    print(f"  {GREEN}[+] Dashboard HTML Interaktif  : {WHITE}{html_file}{RESET}")

        return results

def detect_target_type(target: str) -> str:
    target_clean = target.strip()
    if target_clean.startswith("http://") or target_clean.startswith("https://") or (re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", target_clean) and not target_clean.startswith("+")):
        return "web"
    if os.path.exists(target_clean) or any(target_clean.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".pdf", ".tiff"]):
        return "file"
    return "phone"

def select_menu_interactive(options: List[str]) -> int:
    """
    Selektor menu interaktif berbasis keyboard (Up/Down Arrow, Page Up, Page Down, Enter)
    """
    try:
        import tty
        import termios
        TERMIOS_AVAILABLE = True
    except ImportError:
        TERMIOS_AVAILABLE = False

    if not TERMIOS_AVAILABLE or not sys.stdin.isatty():
        print(f"{YELLOW}[+] PILIH DOMAIN PENYELIDIKAN:{RESET}")
        for i, opt in enumerate(options):
            print(f"  [{i+1}] {opt}")
        try:
            val = input().strip()
            return int(val) - 1
        except Exception:
            return 0

    selected_idx = 0
    num_options = len(options)

    # Sembunyikan kursor saat navigasi
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    def draw(first: bool = False):
        if not first:
            sys.stdout.write(f"\033[{num_options + 2}A\r")
        sys.stdout.write(f"\r\033[K{YELLOW}[+] PILIH DOMAIN PENYELIDIKAN:{RESET}\r\n\r\n")
        for idx, opt in enumerate(options):
            if idx == selected_idx:
                sys.stdout.write(f"\r\033[K  {CYAN}>  {WHITE}{opt}{RESET}\r\n")
            else:
                sys.stdout.write(f"\r\033[K     {WHITE}{opt}{RESET}\r\n")
        sys.stdout.flush()

    draw(first=True)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 in ("[", "O"):
                    ch3 = sys.stdin.read(1)
                    if ch3 == "A":  # Up Arrow
                        selected_idx = (selected_idx - 1) % num_options
                        draw()
                    elif ch3 == "B":  # Down Arrow
                        selected_idx = (selected_idx + 1) % num_options
                        draw()
                    elif ch3 == "5":  # Page Up
                        sys.stdin.read(1)  # consume ~
                        selected_idx = (selected_idx - 1) % num_options
                        draw()
                    elif ch3 == "6":  # Page Down
                        sys.stdin.read(1)  # consume ~
                        selected_idx = (selected_idx + 1) % num_options
                        draw()
                    elif ch3 in ("H", "1"):  # Home
                        selected_idx = 0
                        draw()
                    elif ch3 in ("F", "4"):  # End
                        selected_idx = num_options - 1
                        draw()
            elif ch in ("\r", "\n"):
                break
            elif ch in ("k", "w", "K", "W"):
                selected_idx = (selected_idx - 1) % num_options
                draw()
            elif ch in ("j", "s", "J", "S"):
                selected_idx = (selected_idx + 1) % num_options
                draw()
            elif ch in ("q", "Q", "\x03", "\x04"):
                selected_idx = num_options - 1
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.stdout.write("\033[?25h\r")
        sys.stdout.flush()

    return selected_idx

def print_help_menu():
    help_text = """
Usage: osint [options] <target>

TARGET SELECTION:
  <TARGETs>                     Enter Phone (+62xxx), URL (https://xxx), Domain,
                                IP address, or Image/File (/path/to/img.jpg).
  --input-file=FILE, -i         Read targets from a file.

TARGET MODIFICATION:
  --url-prefix=PREFIX           Add a prefix to target URLs (e.g. https://).
  --url-suffix=SUFFIX           Add a suffix to target URLs (e.g. /robots.txt).
  --mode, -m=MODE               Force domain mode: phone, web, file, all.

AGGRESSION:
The aggression level controls the trade-off between speed/stealth and reliability.
  --aggression, -a=LEVEL        Set the aggression level (1, 3, 4). Default: 1.
  1. Stealthy                   Makes minimal HTTP requests and follows redirects.
  3. Aggressive                 Probes common endpoints (robots, sitemap, .git, .env, graphql, wp).
  4. Heavy                      Deep probing with all sensitive security paths and CMS signatures.

HTTP OPTIONS:
  --user-agent, -U=AGENT        Identify as AGENT instead of default randomized browser UA.
  --header, -H=HEADER           Add an HTTP header. eg "Authorization: Bearer token".
  --cookie, -c=COOKIES          Use custom cookies, e.g. 'name=value; session=xyz'.
  --timeout, -T=SECONDS         Connection timeout in seconds. Default: 10.

PROXY:
  --proxy=URL                   Set proxy (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050).

PLUGINS & MODULES:
  --list-plugins, -l            List all available OSINT and WhatWeb plugins.
  --modules, -M=LIST            Select modules/plugins. LIST is a comma-delimited set
                                (e.g. -M web_osint or -M phone_osint,whatsapp_osint).
  --scope, -S=LEVEL             Set scan scope: quick, default, deep, full. Default: default.

OUTPUT:
  --verbose, -v                 Verbose output with detailed breakdown of all plugins and signatures.
  --brief, -b                   Display brief WhatWeb one-line summary output.
  --quiet, -q                   Do not display module loading progress to STDOUT.
  --no-errors                   Suppress error messages.

LOGGING:
  --output, -o=FILE             Save output to specified JSON file.
  --html                        Generate interactive HTML dashboard in output/ directory.
  --no-json                     Do not save JSON report to disk.

PERFORMANCE & STABILITY:
  --max-threads=NUM             Number of simultaneous async workers. Default: 25.

HELP & MISCELLANEOUS:
  --help, -h                    Complete usage help (this help screen).
  --version, -V                 Display framework version information.

EXAMPLE USAGE:
* Standard phone reconnaissance:
  osint +6281234567890

* WhatWeb-style web reconnaissance:
  osint https://example.com

* Aggressive web scan with custom User-Agent and headers:
  osint -t https://example.com -m web -a 3 -U "CustomScanner/1.0" -H "X-Forwarded-For: 127.0.0.1"

* Brief one-line scan for multiple domains:
  osint https://target1.com --brief

* Forensic analysis of an image:
  osint /path/to/evidence.jpg -m file

* Phone reconnaissance running only WhatsApp and Social modules:
  osint -t +6281234567890 -M phone_osint,whatsapp_osint -o report.json
"""
    print(help_text)

async def main_async():
    # Periksa -h atau --help atau -help
    if any(arg in sys.argv for arg in ["-h", "--help", "-help", "help", "--short-help"]):
        print_help_menu()
        sys.exit(0)

    if any(arg in sys.argv for arg in ["-v", "--version", "-version", "version", "-V"]):
        print(f"PATRICT-OSINT Framework v{VERSION}")
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="PATRICT-OSINT Framework v2.2.0 - Automated Multi-Domain Intelligence & Forensics",
        usage="osint [target] [options]",
        add_help=False
    )
    parser.add_argument("target_pos", nargs="?", help="Target penyelidikan", default=None)
    parser.add_argument("-t", "--target", help="Target penyelidikan", default=None)
    parser.add_argument("-i", "--input-file", help="Baca daftar target dari file", default=None)
    parser.add_argument("-m", "--mode", choices=["phone", "web", "file", "all"], help="Mode penyelidikan", default=None)
    parser.add_argument("-M", "--modules", help="Daftar modul spesifik", default=None)
    parser.add_argument("-S", "--scope", choices=["quick", "default", "deep", "full"], help="Cakupan penyelidikan", default="default")
    parser.add_argument("-a", "--aggression", type=int, choices=[1, 3, 4], help="Level agresi WhatWeb (1, 3, 4)", default=1)
    parser.add_argument("-U", "--user-agent", help="Custom User-Agent string", default=None)
    parser.add_argument("-H", "--header", action="append", help="Custom HTTP Header (bisa multiple)", default=[])
    parser.add_argument("-c", "--cookie", help="Custom cookie string", default=None)
    parser.add_argument("--proxy", help="Proxy URL", default=None)
    parser.add_argument("--url-prefix", help="Prefix ditambahkan ke URL target", default="")
    parser.add_argument("--url-suffix", help="Suffix ditambahkan ke URL target", default="")
    parser.add_argument("-b", "--brief", action="store_true", help="Output ringkas satu baris WhatWeb", default=False)
    parser.add_argument("-l", "--list-plugins", action="store_true", help="Tampilkan daftar plugin", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Tampilkan detail verbose", default=False)
    parser.add_argument("-q", "--quiet", action="store_true", help="Sembunyikan log progress", default=False)
    parser.add_argument("--no-errors", action="store_true", help="Sembunyikan pesan error", default=False)
    parser.add_argument("--max-threads", type=int, help="Jumlah thread / konkurensi", default=None)
    parser.add_argument("-T", "--timeout", type=int, help="Timeout koneksi HTTP dalam detik", default=None)
    parser.add_argument("--config", help="Path ke file konfigurasi YAML", default="config/config.yaml")
    parser.add_argument("-o", "--output", help="Path / nama file output JSON kustom", default=None)
    parser.add_argument("--html", action="store_true", help="Ekspor laporan HTML ke folder output/", default=False)
    parser.add_argument("--no-json", action="store_true", help="Jangan simpan file JSON di direktori aktif", default=False)
    args = parser.parse_args()
    
    orchestrator = PATRICTOrchestrator(
        config_path=args.config,
        timeout=args.timeout,
        user_agent=args.user_agent,
        headers=args.header,
        cookie=args.cookie,
        proxy=args.proxy,
        aggression=args.aggression,
        max_threads=args.max_threads,
        verbose=args.verbose,
        quiet=args.quiet,
        no_errors=args.no_errors
    )

    if args.list_plugins:
        orchestrator.list_plugins()
        sys.exit(0)
    
    # Kumpulkan target
    targets_to_scan = []
    if args.input_file:
        if os.path.exists(args.input_file):
            with open(args.input_file, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith("#"):
                        targets_to_scan.append(clean_line)
        else:
            print(f"[!] Error: File '{args.input_file}' tidak ditemukan.")
            sys.exit(1)
    else:
        raw_target = args.target_pos or args.target
        if raw_target:
            targets_to_scan.append(raw_target)

    mode = args.mode
    is_interactive = len(targets_to_scan) == 0
    
    # Parse module filter jika ada
    module_filter = None
    if args.modules:
        module_filter = [m.strip() for m in args.modules.split(",") if m.strip()]
    
    EXIT_KEYWORDS = {"exit", "quit", "q", ":q", "keluar", "stop", "bye", "cancel", "0"}
    HELP_KEYWORDS = {"-help", "--help", "-h", "help", "?", "menu", "--h"}
    BACK_KEYWORDS = {"back", "kembali", "b"}

    if is_interactive:
        target = None
        while True:
            if not target:
                orchestrator.print_banner()
                
                MENU_OPTIONS = [
                    "Phone Intelligence",
                    "Web & Tech Recon",
                    "Media & File Forensics",
                    "Keluar"
                ]
                
                selected_idx = select_menu_interactive(MENU_OPTIONS)
                
                if selected_idx == 3 or selected_idx < 0:
                    print("\n[*] Keluar dari PATRICT-OSINT.")
                    sys.exit(0)
                    
                mode_map = {0: "phone", 1: "web", 2: "file"}
                mode = mode_map.get(selected_idx, "phone")

            while True:
                if not target:
                    try:
                        target = input(f"\n{YELLOW}[?]{RESET} Masukkan Target: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print("\n[*] Keluar dari PATRICT-OSINT.")
                        sys.exit(0)
                        
                if not target:
                    print("\n[!] Error: Target tidak boleh kosong.")
                    continue

                # Periksa keyword bantuan
                if target.lower() in HELP_KEYWORDS:
                    print_help_menu()
                    target = None
                    continue

                # Periksa keyword kembali ke menu domain
                if target.lower() in BACK_KEYWORDS:
                    target = None
                    break

                # Periksa keyword keluar
                if target.lower() in EXIT_KEYWORDS:
                    print("\n[*] Keluar dari PATRICT-OSINT.")
                    sys.exit(0)

                # Deteksi mode otomatis jika belum ditentukan
                if not mode:
                    mode = detect_target_type(target)

                # Validasi dan normalisasi per mode
                if mode == "phone":
                    digits = re.sub(r"\D", "", target)
                    if not digits or len(digits) < 5:
                        print(f"\n[!] Error: Input '{target}' bukan format nomor telepon yang valid.")
                        target = None
                        continue

                    if target.startswith("08"):
                        target = "+62" + target[1:]
                    elif target.startswith("62") and not target.startswith("+"):
                        target = "+" + target
                    elif not target.startswith("+") and digits:
                        target = "+" + digits
                        
                elif mode == "web":
                    if args.url_prefix and not target.startswith(args.url_prefix):
                        target = args.url_prefix + target
                    if args.url_suffix and not target.endswith(args.url_suffix):
                        target = target + args.url_suffix

                    clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                    if clean_host.startswith("-") or ("." not in clean_host and clean_host not in ("localhost", "127.0.0.1")):
                        print(f"\n[!] Error: Input '{target}' bukan format URL atau domain web yang valid.")
                        target = None
                        continue

                    if not target.startswith("http://") and not target.startswith("https://"):
                        target = "https://" + target
                        
                elif mode == "file":
                    if not os.path.exists(target):
                        print(f"\n[!] Error: File '{target}' tidak ditemukan di sistem.")
                        target = None
                        continue

                # Input valid, keluar dari loop input
                break

            if target:
                targets_to_scan.append(target)
                break

    # Eksekusi scan untuk setiap target
    for target in targets_to_scan:
        current_mode = mode or detect_target_type(target)
        
        # Validasi per mode
        if current_mode == "phone":
            digits = re.sub(r"\D", "", target)
            if target.startswith("08"):
                target = "+62" + target[1:]
            elif target.startswith("62") and not target.startswith("+"):
                target = "+" + target
            elif not target.startswith("+") and digits:
                target = "+" + digits
        elif current_mode == "web":
            if args.url_prefix and not target.startswith(args.url_prefix):
                target = args.url_prefix + target
            if args.url_suffix and not target.endswith(args.url_suffix):
                target = target + args.url_suffix
            if not target.startswith("http://") and not target.startswith("https://"):
                target = "https://" + target

        if not args.brief and not args.quiet:
            print("")
            
        await orchestrator.run(
            target,
            target_type=current_mode,
            module_filter=module_filter,
            scope=args.scope,
            show_banner=False,
            save_json=not args.no_json,
            output_file=args.output,
            save_html=args.html,
            brief=args.brief
        )

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan oleh pengguna.")
        sys.exit(0)

if __name__ == "__main__":
    main()
