#!/usr/bin/env python3
# ============================================================
# PATRICT-OSINT FRAMEWORK - MONOREPO ORCHESTRATOR
# VERSION: 2.6.0
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
VERSION = "2.6.0"

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
        identity = w_data.get("domain_identity", {})
        subdomains_info = w_data.get("passive_subdomains", {})
        discovery = w_data.get("content_discovery", {})
        origin_leak = w_data.get("origin_ip_leak", {})
        threat_data = w_data.get("threat_vulnerability_summary", {})

        target_fqdn = identity.get("target_fqdn") or w_data.get("domain", target)
        root_domain = identity.get("root_domain") or target_fqdn

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"       {WHITE}{BOLD}ENTERPRISE WEB & INFRASTRUCTURE INTELLIGENCE{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target URL{RESET}          : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Target FQDN{RESET}         : {WHITE}{target_fqdn}{RESET}")
        print(f"  {CYAN}Apex / Root Domain{RESET}  : {WHITE}{root_domain}{RESET}")
        if identity.get("is_subdomain"):
            print(f"  {CYAN}Subdomain Prefix{RESET}   : {YELLOW}{identity.get('subdomain_prefix')}{RESET} (Subdomain Scope)")
        else:
            print(f"  {CYAN}Domain Scope{RESET}       : {GREEN}Apex / Root Domain (Full Infrastructure Scope){RESET}")
        
        status_code = w_data.get('final_status', 200)
        status_phrase = http.client.responses.get(status_code, "OK" if status_code == 200 else "")
        status_color = GREEN if status_code == 200 else (YELLOW if status_code in (301, 302) else RED)
        print(f"  {CYAN}Status HTTP{RESET}         : {status_color}{status_code} {status_phrase}{RESET}")
        print(f"  {CYAN}Final Destination{RESET}   : {WHITE}{w_data.get('final_url', target)}{RESET}")
        
        if meta.get("title"):
            print(f"  {CYAN}Page Title{RESET}        : {WHITE}{meta.get('title')}{RESET}")
            
        methods = w_data.get("http_methods_allowed", [])
        print(f"  {CYAN}Allowed Methods{RESET}     : {GREEN}{', '.join(methods) if methods else 'GET, HEAD'}{RESET}")

        # 1. Server GeoIP & Network
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
        loc_display = f"{loc_str} {coord_str}".strip()
        print(f"  * Lokasi Server     : {WHITE}{loc_display}{RESET}")
        print(f"  * ISP / Organisasi  : {WHITE}{geo.get('isp') or geo.get('organization') or 'Unknown ISP / Protected IP'}{RESET}")
        if geo.get("asn"):
            print(f"  * ASN Jaringan      : {WHITE}{geo.get('asn')}{RESET}")
        if geo.get("maps_url"):
            print(f"  * Lokasi Google Maps: {CYAN}{geo.get('maps_url')}{RESET}")

        # 2. SSL/TLS Certificate Intelligence & SANs
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
            wild_status = f"{YELLOW}Ada Wildcard (*.) [OK]{RESET}" if ssl_info.get("has_wildcard") else f"{WHITE}Single/Multi-Host{RESET}"
            print(f"  * Tipe Sertifikat   : {wild_status}")
            print(f"  * SANs Terdaftar    : {WHITE}{len(ssl_info.get('san_list', []))} domain{RESET}")
        else:
            print(f"  * {RED}Tidak ada sertifikat SSL/TLS aktif (Port 443 tidak merespon/Plain HTTP).{RESET}")

        # 3. Mesin Enumerasi Subdomain Pasif Multi-Source
        sub_list = subdomains_info.get("subdomains", [])
        total_sub_found = subdomains_info.get("total_found", 0)
        active_sub_cnt = subdomains_info.get("active_count", 0)
        print(f"\n{YELLOW}[+] ENUMERASI SUBDOMAIN PASIF ({total_sub_found} Ditemukan | {active_sub_cnt} Aktif):{RESET}")
        print(f"  * Sumber Analisis   : {WHITE}{', '.join(subdomains_info.get('sources_queried', ['crt.sh', 'HackerTarget']))}{RESET}")
        if sub_list:
            for s_entry in sub_list[:12]:
                s_name = s_entry.get("subdomain", "")
                s_ip = s_entry.get("ip", "N/A")
                s_prov = s_entry.get("cdn_provider", "Direct Origin IP")
                is_target = s_entry.get("is_target_fqdn", False)
                
                target_tag = f"{YELLOW}[TARGET FQDN]{RESET} " if is_target else "  * "
                prov_color = CYAN if s_entry.get("is_cdn") else GREEN
                print(f"  {target_tag}{WHITE}{s_name : <32}{RESET} -> {WHITE}{s_ip : <16}{RESET} [{prov_color}{s_prov}{RESET}]")
            if len(sub_list) > 12:
                print(f"  * {WHITE}... dan {total_sub_found - 12} subdomain lainnya (tersimpan di laporan JSON/MD).{RESET}")
        else:
            print(f"  * {WHITE}Tidak ditemukan subdomain pasif tambahan.{RESET}")

        # 4. Cloudflare / CDN Origin IP Leak Alert
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

        # 5. Arsitektur Autentikasi, Sesi, & Token Fingerprinting
        print(f"\n{YELLOW}[+] ARSITEKTUR AUTENTIKASI & TOKEN SECURITY:{RESET}")
        auth_arch = auth.get("auth_architecture", "Standard / Stateless")
        print(f"  * Mode Autentikasi  : {CYAN}{BOLD}{auth_arch}{RESET}")
        
        sanctum = auth.get("laravel_sanctum", {})
        if sanctum.get("is_sanctum_active"):
            print(f"  * Laravel Sanctum   : {GREEN}[ACTIVE]{RESET} {WHITE}Endpoint {sanctum.get('sanctum_endpoint')} aktif (Stateful SPA CSRF){RESET}")
        
        jwt_list = auth.get("jwt_tokens", [])
        if jwt_list:
            print(f"  * JWT Tokens        : {YELLOW}{len(jwt_list)} token terdeteksi & didekode{RESET}")
            for j in jwt_list[:2]:
                exp_status = f"{RED}[EXPIRED]{RESET}" if j.get("is_expired") else f"{GREEN}[VALID]{RESET}"
                print(f"    - [{CYAN}{j.get('found_in')}{RESET}] Alg: {WHITE}{j.get('algorithm')}{RESET} | Iss: {WHITE}{j.get('issuer')}{RESET} | Sub: {WHITE}{j.get('subject')}{RESET} | Exp: {WHITE}{j.get('expiration')} {exp_status}")

        cookie_audit = auth.get("cookie_audit", {})
        httponly = f"{GREEN}PASS [OK]{RESET}" if cookie_audit.get("httponly_all") else f"{RED}FAIL (Rentan XSS / No HttpOnly){RESET}"
        secure = f"{GREEN}PASS [OK]{RESET}" if cookie_audit.get("secure_all") else f"{RED}FAIL (No Secure Flag){RESET}"
        samesite = cookie_audit.get("samesite") or "Not Configured"
        print(f"  * Cookie Audit      : HttpOnly: {httponly} | Secure: {secure} | SameSite: {WHITE}{samesite}{RESET}")

        # 6. High-Performance Content Discovery & Endpoint Fuzzing
        endpoints = discovery.get("endpoints", [])
        cdx_paths = discovery.get("cdx_historical_paths_found", [])
        b_status = discovery.get("baseline_status", 404)
        b_len = discovery.get("baseline_length", 0)

        print(f"\n{YELLOW}[+] CONTENT DISCOVERY & ENDPOINT FUZZING ({len(endpoints)} Ditemukan):{RESET}")
        print(f"  * Kalibrasi Soft-404: {WHITE}Baseline HTTP {b_status} ({b_len} bytes) - Catch-All Filtered [OK]{RESET}")
        if endpoints:
            for ep in endpoints:
                sev = ep.get("severity", "INFO")
                if sev in ("CRITICAL", "HIGH"):
                    sev_color = RED
                elif sev == "BLOCKED":
                    sev_color = GREEN
                elif sev == "MEDIUM":
                    sev_color = YELLOW
                else:
                    sev_color = CYAN
                
                st_code = ep.get("status", 200)
                st_color = GREEN if st_code == 200 else (YELLOW if st_code in (401, 403) else CYAN)
                print(f"  * {sev_color}[{sev : <8}]{RESET} {WHITE}{ep.get('path') : <28}{RESET} : {st_color}{ep.get('status_badge', f'[{st_code}]')}{RESET} ({ep.get('description')}, {ep.get('size_bytes')} B)")

        if cdx_paths:
            print(f"  * {CYAN}Wayback Machine Historical Paths:{RESET} {WHITE}{', '.join(cdx_paths[:4])}{RESET}")

        # 7. Security Headers Grader
        grade = sec_grade.get("grade", "N/A")
        score = sec_grade.get("score", 0)
        grade_color = GREEN if grade in ("A+", "A") else (CYAN if grade in ("B+", "B") else (YELLOW if grade == "C" else RED))
        
        print(f"\n{YELLOW}[+] SECURITY HEADERS GRADER:{RESET}")
        print(f"  * Skor & Grade      : {grade_color}{BOLD}[ GRADE: {grade} ]{RESET} {WHITE}(Skor Keamanan: {score}/100){RESET}")
        details = sec_grade.get("details", {})
        for h_name, h_val in details.items():
            st = h_val.get("status")
            st_badge = f"{GREEN}[PASS]{RESET}" if st == "PASS" else (f"{YELLOW}[WARN]{RESET}" if st == "WARN" else f"{RED}[FAIL]{RESET}")
            val_txt = h_val.get('value') or h_val.get('reason') or ''
            print(f"  * {h_name : <28}: {st_badge} {WHITE}{h_val.get('score')} pts{RESET} - {val_txt}")

        # 8. Tech Stack ala WhatWeb
        print(f"\n{YELLOW}[+] STACK TEKNOLOGI & FINGERPRINTING:{RESET}")
        servers = stack.get("web_servers", [])
        langs = stack.get("programming_languages", [])
        backends = stack.get("backend_frameworks", [])
        frontends = stack.get("frontend_libraries", [])
        cms_list = stack.get("cms_and_platforms", [])
        wafs = stack.get("waf_and_security", [])

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

        # 9. DNS Records Matrix
        if any(dns_rec.values()):
            print(f"\n{YELLOW}[+] DNS RECORDS MATRIX:{RESET}")
            for r_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                r_val = dns_rec.get(r_type, [])
                if r_val:
                    print(f"  * {r_type : <18}: {WHITE}{', '.join(r_val[:3])}{RESET}")

        # 10. Infrastruktur Jaringan & Reverse DNS (if available)
        net_data = results.get("network_osint", {}).get("data", {})
        if net_data:
            print(f"\n{YELLOW}[+] INFRASTRUKTUR JARINGAN & REVERSE DNS:{RESET}")
            print(f"  * Target Host       : {WHITE}{net_data.get('target_host')}{RESET}")
            if net_data.get("resolved_ipv4"):
                print(f"  * Alamat IPv4       : {WHITE}{', '.join(net_data.get('resolved_ipv4'))}{RESET}")
            print(f"  * Reverse DNS (PTR) : {CYAN}{net_data.get('reverse_dns_ptr')}{RESET}")
            asn_info = net_data.get("asn_and_isp", {})
            if asn_info.get("isp") and asn_info.get("isp") != "N/A":
                print(f"  * ISP / Organisasi  : {WHITE}{asn_info.get('isp')} ({asn_info.get('org', 'N/A')}) - ASN: {asn_info.get('as_number', 'N/A')}{RESET}")
            open_ports = net_data.get("open_ports_summary", [])
            if open_ports:
                ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in open_ports])
                print(f"  * Port Terbuka      : {GREEN}{ports_str}{RESET}")

        # 11. Riwayat Arsip Web Wayback Machine (if available)
        hist_data = results.get("web_history", {}).get("data", {})
        if hist_data and hist_data.get("has_history"):
            print(f"\n{YELLOW}[+] RIWAYAT ARSIP WEB (WAYBACK MACHINE CDX):{RESET}")
            print(f"  * Status Arsip      : {GREEN}{hist_data.get('status')}{RESET}")
            print(f"  * Snapshot Pertama  : {WHITE}{hist_data.get('first_snapshot') or 'N/A'}{RESET}")
            print(f"  * Snapshot Terakhir : {WHITE}{hist_data.get('last_snapshot') or 'N/A'}{RESET}")

        # 12. Executive Vulnerability & Threat Assessment Summary Matrix
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
        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_file_terminal(self, target: str, results: Dict[str, Any]):
        f_data = results.get("file_forensics", {}).get("data", {})
        f_info = f_data.get("file_info", {})
        hashes = f_data.get("cryptographic_hashes", {})
        entropy = f_data.get("shannon_entropy", {})
        sliding_ent = f_data.get("sliding_window_entropy", {})
        magic = f_data.get("magic_bytes_inspection", {})
        png_data = f_data.get("png_chunk_forensics", {})
        lsb_multi = f_data.get("lsb_steganography_multi_channel", {})
        in_file_carved = f_data.get("in_file_carved_segments", [])
        exif = f_data.get("exif_metadata", {})
        pdf = f_data.get("pdf_forensics", {})
        office = f_data.get("office_forensics", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"       {WHITE}{BOLD}HARDCORE DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR){RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Nama Berkas{RESET}         : {WHITE}{f_info.get('file_name', os.path.basename(target))}{RESET}")
        print(f"  {CYAN}Lokasi Path{RESET}         : {WHITE}{f_info.get('file_path', target)}{RESET}")
        print(f"  {CYAN}Ukuran Berkas{RESET}       : {WHITE}{f_info.get('file_size_formatted', 'N/A')} ({f_info.get('file_size_bytes', 0)} bytes){RESET}")
        print(f"  {CYAN}Ekstensi Berkas{RESET}     : {WHITE}{f_info.get('file_extension', 'N/A')}{RESET}")

        # 1. Kriptografi & Shannon Entropy (Global & Sliding Window)
        print(f"\n{YELLOW}[+] KRIPTOGRAFI & SHANNON ENTROPY DISTRIBUTION:{RESET}")
        print(f"  * MD5               : {WHITE}{hashes.get('md5', 'N/A')}{RESET}")
        print(f"  * SHA-1             : {WHITE}{hashes.get('sha1', 'N/A')}{RESET}")
        print(f"  * SHA-256           : {WHITE}{hashes.get('sha256', 'N/A')}{RESET}")
        
        ent_val = entropy.get("entropy", 0.0)
        ent_rating = entropy.get("rating", "UNKNOWN")
        ent_color = RED if ent_rating == "VERY HIGH" else (YELLOW if ent_rating == "HIGH" else GREEN)
        print(f"  * Global Entropy    : {ent_color}{ent_val} bits/byte [{ent_rating}]{RESET} ({entropy.get('description', 'N/A')})")
        if sliding_ent:
            print(f"  * Sliding Entropy   : {WHITE}Min: {sliding_ent.get('min_entropy', 0.0)} | Max: {sliding_ent.get('max_entropy', 0.0)} | Avg: {sliding_ent.get('avg_entropy', 0.0)} (Blok: {sliding_ent.get('blocks_analyzed', 0)}){RESET}")
            if sliding_ent.get('high_entropy_blocks_count', 0) > 0:
                print(f"  * High Entropy Alert: {RED}{BOLD}Terdeteksi {sliding_ent.get('high_entropy_blocks_count')} blok (>7.5) terenkripsi / terkompresi!{RESET}")

        # 2. Verifikasi Magic Bytes & Anti-Spoofing
        print(f"\n{YELLOW}[+] VERIFIKASI MAGIC BYTES & ANTI-SPOOFING:{RESET}")
        is_spoofed = magic.get("is_extension_spoofed", False)
        spoof_badge = f"{RED}[PERINGATAN] Ekstensi dipalsukan / Spoofed!{RESET}" if is_spoofed else f"{GREEN}Valid (Sesuai signature) [OK]{RESET}"
        print(f"  * Tipe Berkas Asli  : {WHITE}{magic.get('detected_file_type', 'Unknown')}{RESET}")
        print(f"  * Status Ekstensi   : {spoof_badge}")

        # 3. PNG Chunk Walker & Anomaly Inspector (CTF Artifacts)
        if png_data.get("is_png"):
            print(f"\n{YELLOW}[+] PNG CHUNK WALKER & ANOMALY INSPECTOR:{RESET}")
            print(f"  * Total Chunks      : {WHITE}{png_data.get('total_chunks_found', 0)} chunks ditemukan{RESET}")
            if png_data.get("tampered_crc_detected"):
                print(f"  * Status CRC-32     : {RED}{BOLD}[TAMPERED] Terdeteksi Mismatch CRC! (Potensi Image Crop Trick / CTF Artifact){RESET}")
            else:
                print(f"  * Status CRC-32     : {GREEN}Valid (Seluruh CRC-32 chunk konsisten) [OK]{RESET}")

            if png_data.get("custom_chunks"):
                print(f"  * Custom Chunks     : {YELLOW}{len(png_data.get('custom_chunks'))} Non-Standard / Private Chunks Terdeteksi!{RESET}")
                for cc in png_data.get("custom_chunks"):
                    print(f"    - [{CYAN}{cc.get('chunk_type')}{RESET}] Offset: {cc.get('offset')} | Ukuran: {cc.get('length')} B | Data: {WHITE}{cc.get('printable_preview')}{RESET}")
                    if cc.get("xor_findings"):
                        for xf in cc.get("xor_findings"):
                            print(f"      {RED}[XOR Hit]{RESET} {xf.get('method')} -> {GREEN}{xf.get('decrypted_snippet')}{RESET}")

            if png_data.get("anomalies"):
                for anom in png_data.get("anomalies"):
                    print(f"  * {RED}{anom}{RESET}")

        # 4. Multi-Channel LSB Steganography Engine
        if lsb_multi.get("lsb_extracted"):
            print(f"\n{YELLOW}[+] MULTI-CHANNEL LSB STEGANOGRAPHY ENGINE (RGB & ALPHA):{RESET}")
            if lsb_multi.get("flag_patterns_found"):
                print(f"  * Flag / Key Sniffer: {RED}{BOLD}[MATCH] TERDETEKSI POLA FLAG CTF / KREDENSIAL!{RESET}")
                for fp in lsb_multi.get("flag_patterns_found"):
                    print(f"    - {GREEN}{BOLD}{fp}{RESET}")
            else:
                print(f"  * Flag / Key Sniffer: {GREEN}Bersih (Tidak ditemukan pola flag plaintext pada LSB) [OK]{RESET}")

            if lsb_multi.get("extracted_urls"):
                print(f"  * Extracted URLs    : {CYAN}{', '.join(lsb_multi.get('extracted_urls')[:3])}{RESET}")
            if lsb_multi.get("extracted_base64"):
                print(f"  * Base64 Encoded    : {WHITE}{', '.join(lsb_multi.get('extracted_base64')[:2])}{RESET}")

        # 5. In-File Deep Carving (Embedded Segments)
        print(f"\n{YELLOW}[+] IN-FILE DEEP CARVING & EMBEDDED PAYLOAD EXTRACTION:{RESET}")
        if in_file_carved:
            print(f"  * Status In-File    : {RED}{BOLD}[ALERT] DITEMUKAN {len(in_file_carved)} EMBEDDED FILE / SEGMENT TERSEMBUNYI!{RESET}")
            for idx, c_seg in enumerate(in_file_carved, 1):
                print(f"  [{idx}] {YELLOW}{c_seg.get('detected_type')}{RESET} (Offset: {c_seg.get('offset')} | Ukuran: {c_seg.get('size_formatted')})")
                print(f"      - Carved File   : {GREEN}{c_seg.get('carved_file_path')}{RESET}")
                print(f"      - MD5 Hash      : {WHITE}{c_seg.get('md5')}{RESET}")
                if c_seg.get("interesting_strings"):
                    print(f"      - Strings Sample: {CYAN}{', '.join(c_seg.get('interesting_strings')[:3])}{RESET}")
                if c_seg.get("xor_findings"):
                    for xf in c_seg.get("xor_findings"):
                        print(f"      - {RED}[XOR Hit]{RESET} {xf.get('method')}: {GREEN}{xf.get('decrypted_snippet')}{RESET}")
        else:
            print(f"  * Status In-File    : {GREEN}Bersih (Tidak ditemukan file tertanam di dalam berkas) [OK]{RESET}")

        # 6. EXIF Kamera & GPS
        if exif.get("has_exif"):
            print(f"\n{YELLOW}[+] METADATA KAMERA, OPTIK & PENGAMBILAN GAMBAR:{RESET}")
            camera = f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
            print(f"  * Perangkat/Kamera  : {WHITE}{camera or 'N/A'}{RESET}")
            if exif.get("lens_model"):
                print(f"  * Model Lensa       : {WHITE}{exif.get('lens_model')}{RESET}")
            if exif.get("artist") or exif.get("copyright"):
                print(f"  * Author / Hak Cipta: {WHITE}{exif.get('artist') or 'N/A'} (© {exif.get('copyright') or 'N/A'}){RESET}")
            gps = exif.get("gps_coordinates")
            if gps:
                print(f"  * Koordinat GPS     : {GREEN}Lat: {gps.get('latitude')}, Lon: {gps.get('longitude')}{RESET}")
                print(f"  * Google Maps URL   : {CYAN}{gps.get('google_maps_url')}{RESET}")

        # 7. Dokumen PDF & Office Deep Parsers
        if pdf.get("is_pdf"):
            print(f"\n{YELLOW}[+] METADATA DOKUMEN PDF & AUDIT KEAMANAN:{RESET}")
            print(f"  * Format / Versi    : {WHITE}{pdf.get('pdf_version', 'PDF')}{RESET}")
            print(f"  * Judul / Author    : {WHITE}{pdf.get('title') or 'N/A'} (Author: {pdf.get('author') or 'N/A'}){RESET}")
            print(f"  * Total Halaman     : {WHITE}{pdf.get('page_count', 0)} Halaman{RESET}")
            if pdf.get("suspicious_actions"):
                print(f"  * Temuan Keamanan   : {RED}{BOLD}{' | '.join(pdf.get('suspicious_actions'))}{RESET}")

        if office.get("is_office_doc"):
            print(f"\n{YELLOW}[+] METADATA DOKUMEN MICROSOFT OFFICE & AUDIT MACRO:{RESET}")
            print(f"  * Tipe Dokumen      : {WHITE}{office.get('doc_type')}{RESET}")
            print(f"  * Author / Editor   : {WHITE}{office.get('creator') or 'N/A'} (Last: {office.get('last_modified_by') or 'N/A'}){RESET}")
            if office.get("hidden_worksheets"):
                print(f"  * Hidden Sheets     : {RED}{BOLD}[STEALTH] Terdeteksi {', '.join(office.get('hidden_worksheets'))}!{RESET}")
            macro_status = f"{RED}{BOLD}[PERINGATAN] Terdeteksi VBA Macros!{RESET}" if office.get("has_vba_macros") else f"{GREEN}Bersih (No Macros) [OK]{RESET}"
            print(f"  * Status VBA Macros : {macro_status}")

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
    
    # 1. Deteksi Target Berkas / File Forensics
    file_extensions = [
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".pdf", ".tiff", ".tif",
        ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2",
        ".elf", ".exe", ".dll", ".so", ".bin", ".sqlite", ".db", ".sqlite3"
    ]
    if os.path.exists(target_clean) or any(target_clean.lower().endswith(ext) for ext in file_extensions):
        return "file"

    # 2. Deteksi Alamat IP Mentah (IPv4 / IPv6) -> Mode Web & Infra OSINT
    host_candidate = target_clean
    if host_candidate.startswith("http://") or host_candidate.startswith("https://"):
        try:
            parsed = urllib.parse.urlparse(host_candidate)
            host_candidate = parsed.netloc or parsed.path
        except Exception:
            pass
    if ":" in host_candidate and not host_candidate.startswith("["):
        host_candidate = host_candidate.split(":")[0]
    if "/" in host_candidate:
        host_candidate = host_candidate.split("/")[0]

    try:
        import ipaddress
        ipaddress.ip_address(host_candidate)
        return "web"
    except (ValueError, ImportError):
        pass

    # 3. Deteksi Skema URL atau Domain Web Valid
    if target_clean.startswith("http://") or target_clean.startswith("https://"):
        return "web"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+(/.*)?$", target_clean) and not target_clean.startswith("+"):
        return "web"

    # 4. Deteksi Nomor Telepon Standar (Phone Intelligence)
    digits_only = re.sub(r'[^0-9]', '', target_clean)
    if target_clean.startswith("+") or (len(digits_only) >= 7 and len(digits_only) <= 16 and (target_clean.startswith("0") or target_clean.startswith("62") or digits_only == target_clean or "-" in target_clean or " " in target_clean)):
        return "phone"

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
