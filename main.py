#!/usr/bin/env python3
# ============================================================
# PATRICT-OSINT FRAMEWORK - MONOREPO ORCHESTRATOR
# VERSION: 2.2.0
# ============================================================

import os
import sys
import re
import json
import asyncio
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from core.config_manager import ConfigManager
from core.async_client import AsyncHttpClient
from core.plugin_loader import PluginLoader
from visualizers.graph_engine import GraphEngine
from reports.report_generator import ReportGenerator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "2.2.0"

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
    
    def __init__(self, config_path: str = None, timeout: Optional[int] = None):
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
        
        # Override timeout jika diberikan via CLI flag -T
        if timeout:
            self.config_manager.set("app.timeout", timeout)
            
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

    def _print_phone_terminal(self, target: str, results: Dict[str, Any]):
        p_data = results.get("phone_osint", {}).get("data", {})
        c_data = results.get("caller_id_osint", {}).get("data", {})
        l_data = results.get("location_osint", {}).get("data", {})
        s_data = results.get("social_osint", {}).get("data", {})
        e_data = results.get("email_osint", {}).get("data", {})
        w_data = results.get("whatsapp_osint", {}).get("data", {})
        d_data = results.get("dorking_osint", {}).get("data", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL RECONNAISSANCE TELEKOMUNIKASI (PHONE){RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target Recon{RESET}        : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Format Internasional{RESET}: {WHITE}{p_data.get('formatted_e164', target)}{RESET}")
        print(f"  {CYAN}Format Nasional{RESET}     : {WHITE}{p_data.get('formatted_national', 'N/A')}{RESET}")
        print(f"  {CYAN}Operator / Carrier{RESET}  : {GREEN}{p_data.get('carrier', 'Tidak Teridentifikasi')}{RESET}")
        print(f"  {CYAN}Wilayah / Negara{RESET}    : {WHITE}{p_data.get('country', 'N/A')} ({p_data.get('timezone', ['N/A'])[0] if isinstance(p_data.get('timezone'), list) and p_data.get('timezone') else 'N/A'}){RESET}")
        print(f"  {CYAN}Status Validasi{RESET}     : {GREEN}ITU-T E.164 VALID [OK]{RESET}" if p_data.get("valid") else f"  {CYAN}Status Validasi{RESET}     : {RED}TIDAK VALID [FAIL]{RESET}")
        
        if l_data.get("latitude") and l_data.get("longitude"):
            print(f"  {CYAN}Estimasi Lokasi HLR{RESET} : {WHITE}{l_data.get('city', '')} {l_data.get('region', '')} (Lat: {l_data.get('latitude')}, Lon: {l_data.get('longitude')}){RESET}")

        # Caller ID
        print(f"\n{YELLOW}[+] IDENTITAS & CALLER DIRECTORY:{RESET}")
        owner_name = c_data.get("name") or c_data.get("caller_name") or "Tidak ditemukan di direktori publik"
        spam_score = c_data.get("spam_score", "0%")
        print(f"  * Nama Teridentifikasi : {WHITE}{owner_name}{RESET}")
        print(f"  * Skor Reputasi/Spam   : {GREEN}{spam_score}{RESET}")

        # WhatsApp
        if w_data:
            wa_status = "Aktif [OK]" if w_data.get("is_registered") or w_data.get("valid") else "Tidak Terdeteksi"
            print(f"\n{YELLOW}[+] WHATSAPP RECONNAISSANCE:{RESET}")
            print(f"  * Status WhatsApp      : {GREEN if 'Aktif' in wa_status else WHITE}{wa_status}{RESET}")
            print(f"  * Link Profil          : {CYAN}https://wa.me/{target.replace('+', '')}{RESET}")

        # Social Media
        accounts = s_data.get("accounts", []) if isinstance(s_data, dict) else []
        print(f"\n{YELLOW}[+] AKUN MEDIA SOSIAL TERHUBUNG ({len(accounts)} Ditemukan):{RESET}")
        if accounts:
            for acc in accounts:
                print(f"  * {acc.get('platform', 'Platform') : <20} : {GREEN}Terdeteksi{RESET} ({acc.get('url', '')})")
        else:
            print(f"  * {WHITE}Tidak ditemukan akun media sosial publik dengan signature nomor ini.{RESET}")

        # Emails
        emails = e_data.get("emails", []) if isinstance(e_data, dict) else []
        print(f"\n{YELLOW}[+] POTENSI ALAMAT EMAIL TERKAIT ({len(emails)}):{RESET}")
        if emails:
            for em in emails[:5]:
                print(f"  * {WHITE}{em.get('email', '')}{RESET} {GREEN}({em.get('source', 'OSINT')}){RESET}")
        else:
            print(f"  * {WHITE}Tidak ada permutasi email yang aktif.{RESET}")

        # Dorks
        findings = d_data.get("findings", []) if isinstance(d_data, dict) else []
        if findings:
            print(f"\n{YELLOW}[+] TEMUAN DORKING & DOKUMEN PUBLIK ({len(findings)}):{RESET}")
            for item in findings[:4]:
                print(f"  * [{item.get('category', 'Info')}] {WHITE}{item.get('title', '')}{RESET} -> {CYAN}{item.get('url', '')}{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_web_terminal(self, target: str, results: Dict[str, Any]):
        w_data = results.get("web_osint", {}).get("data", {})
        meta = w_data.get("page_metadata", {})
        geo = w_data.get("server_geoip", {})
        stack = w_data.get("tech_stack", {})
        auth = w_data.get("auth_intelligence", {})
        dns_rec = w_data.get("dns_records", {})
        endpoints = w_data.get("interesting_endpoints", [])

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL RECONNAISSANCE WEB & WHATWEB FINGERPRINT{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target URL{RESET}          : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Domain Asli{RESET}         : {WHITE}{w_data.get('domain', 'N/A')}{RESET}")
        print(f"  {CYAN}Status HTTP{RESET}         : {GREEN}{w_data.get('final_status', 200)} OK{RESET}")
        print(f"  {CYAN}Final Destination{RESET}   : {WHITE}{w_data.get('final_url', target)}{RESET}")
        
        if meta.get("title"):
            print(f"  {CYAN}Page Title{RESET}        : {WHITE}{meta.get('title')}{RESET}")
            
        methods = w_data.get("http_methods_allowed", [])
        print(f"  {CYAN}Allowed Methods{RESET}     : {GREEN}{', '.join(methods) if methods else 'GET, HEAD'}{RESET}")

        # Server GeoIP
        print(f"\n{YELLOW}[+] SERVER & NETWORK GEOIP:{RESET}")
        print(f"  * IP Publik Server  : {WHITE}{geo.get('ip', 'N/A')}{RESET}")
        print(f"  * Lokasi Server     : {WHITE}{geo.get('city', '')}, {geo.get('country', '')} (Lat: {geo.get('latitude', '-')}, Lon: {geo.get('longitude', '-')}){RESET}")
        print(f"  * ISP / Organisasi  : {WHITE}{geo.get('isp') or geo.get('organization') or 'N/A'}{RESET}")
        if geo.get("asn"):
            print(f"  * ASN Jaringan      : {WHITE}{geo.get('asn')}{RESET}")
        if geo.get("maps_url"):
            print(f"  * Lokasi Google Maps: {CYAN}{geo.get('maps_url')}{RESET}")

        # Tech Stack ala WhatWeb
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

        # Auth & Security
        print(f"\n{YELLOW}[+] AUTHENTICATION & COOKIE SECURITY:{RESET}")
        auth_types = auth.get("auth_type_detected", ["Standard / Stateless"])
        print(f"  * Tipe Auth/Session : {WHITE}{', '.join(auth_types)}{RESET}")
        
        flags = auth.get("security_flags", {})
        httponly = f"{GREEN}Aktif [OK]{RESET}" if flags.get("httponly") else f"{RED}Tidak Aktif [FAIL]{RESET}"
        secure = f"{GREEN}Aktif [OK]{RESET}" if flags.get("secure") else f"{RED}Tidak Aktif [FAIL]{RESET}"
        samesite = flags.get("samesite") or "Default"
        print(f"  * Cookie Flags      : HttpOnly: {httponly} | Secure: {secure} | SameSite: {WHITE}{samesite}{RESET}")

        # Endpoints & Discovery
        if endpoints:
            print(f"\n{YELLOW}[+] ENDPOINT & SERVICE DISCOVERY:{RESET}")
            for ep in endpoints:
                print(f"  * {ep.get('name') : <18}: {GREEN}[{ep.get('status')}]{RESET} {WHITE}{ep.get('url')}{RESET}")

        if meta.get("emails_found"):
            print(f"\n{YELLOW}[+] EMAIL TERSEKRAP DARI HALAMAN:{RESET}")
            for em in meta.get("emails_found")[:5]:
                print(f"  * {WHITE}{em}{RESET}")

        # DNS Records
        if any(dns_rec.values()):
            print(f"\n{YELLOW}[+] DNS RECORDS MATRIX:{RESET}")
            for r_type in ["A", "MX", "NS", "TXT"]:
                r_val = dns_rec.get(r_type, [])
                if r_val:
                    print(f"  * {r_type : <18}: {WHITE}{', '.join(r_val[:3])}{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_file_terminal(self, target: str, results: Dict[str, Any]):
        f_data = results.get("file_forensics", {}).get("data", {})
        f_info = f_data.get("file_info", {})
        hashes = f_data.get("cryptographic_hashes", {})
        magic = f_data.get("magic_bytes_inspection", {})
        exif = f_data.get("exif_metadata", {})
        stego = f_data.get("steganography_and_integrity", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL FORENSIK MEDIA & BERKAS{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Nama Berkas{RESET}         : {WHITE}{f_info.get('file_name', os.path.basename(target))}{RESET}")
        print(f"  {CYAN}Lokasi Path{RESET}         : {WHITE}{f_info.get('file_path', target)}{RESET}")
        print(f"  {CYAN}Ukuran Berkas{RESET}       : {WHITE}{f_info.get('file_size_formatted', 'N/A')} ({f_info.get('file_size_bytes', 0)} bytes){RESET}")
        print(f"  {CYAN}Ekstensi File{RESET}       : {WHITE}{f_info.get('file_extension', 'N/A')}{RESET}")

        # Hashes
        print(f"\n{YELLOW}[+] KRIPTOGRAFI & HASH INTEGRITAS:{RESET}")
        print(f"  * MD5               : {WHITE}{hashes.get('md5', 'N/A')}{RESET}")
        print(f"  * SHA-1             : {WHITE}{hashes.get('sha1', 'N/A')}{RESET}")
        print(f"  * SHA-256           : {WHITE}{hashes.get('sha256', 'N/A')}{RESET}")

        # Magic Bytes
        print(f"\n{YELLOW}[+] VERIFIKASI MAGIC BYTES:{RESET}")
        is_spoofed = magic.get("is_extension_spoofed", False)
        spoof_badge = f"{RED}[PERINGATAN] Ekstensi dipalsukan / Spoofed!{RESET}" if is_spoofed else f"{GREEN}Valid (Sesuai signature) [OK]{RESET}"
        print(f"  * Tipe File Asli    : {WHITE}{magic.get('detected_file_type', 'Unknown')}{RESET}")
        print(f"  * Status Ekstensi   : {spoof_badge}")

        # EXIF
        print(f"\n{YELLOW}[+] METADATA KAMERA & EXIF:{RESET}")
        if exif.get("has_exif"):
            camera = f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
            print(f"  * Perangkat/Kamera  : {WHITE}{camera or 'N/A'}{RESET}")
            print(f"  * Software Editor   : {WHITE}{exif.get('software', 'N/A')}{RESET}")
            print(f"  * Waktu Pemotretan  : {WHITE}{exif.get('datetime_original', 'N/A')}{RESET}")
            gps = exif.get("gps_coordinates")
            if gps:
                print(f"  * Koordinat GPS     : {GREEN}Lat: {gps.get('latitude')}, Lon: {gps.get('longitude')}{RESET}")
                print(f"  * Google Maps URL   : {CYAN}{gps.get('google_maps_url')}{RESET}")
        else:
            print(f"  * {WHITE}Tidak ditemukan metadata EXIF pada berkas ini.{RESET}")

        # Steganography & Appended Data
        print(f"\n{YELLOW}[+] DETEKSI STEGANOGRAFI & INTEGRITAS BINARY:{RESET}")
        if stego.get("appended_data_detected"):
            print(f"  * Appended Data     : {YELLOW}[PERINGATAN] Terdeteksi {stego.get('appended_data_size_bytes')} bytes setelah marker EOF (Potensi payload tersembunyi!){RESET}")
        else:
            print(f"  * Appended Data     : {GREEN}Bersih (Tidak ada data tersembunyi setelah EOF) [OK]{RESET}")

        if stego.get("embedded_zip_detected"):
            print(f"  * Embedded Archive  : {RED}[PERINGATAN] Terdeteksi arsip ZIP tersembunyi di dalam gambar!{RESET}")

        strings_sample = stego.get("embedded_hidden_strings_sample", [])
        if strings_sample:
            print(f"  * Extracted Strings : {CYAN}{', '.join(strings_sample[:3])}{RESET}")

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
        save_html: bool = False
    ) -> Dict[str, Any]:
        if show_banner:
            self.print_banner()

        type_labels = {
            "phone": "Phone Intelligence",
            "web": "Web & Tech Recon",
            "file": "Media & File Forensics",
            "all": "All Domains"
        }
        
        print(f"[*] Target Reconnaissance : {WHITE}{target}{RESET}")
        print(f"[*] Tipe Domain          : {CYAN}{type_labels.get(target_type, target_type.upper())}{RESET}")
        print(f"[*] Scope Penyelidikan   : {GREEN}{scope.upper()}{RESET}")
        print(f"[*] Waktu Mulai          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"[*] Memuat Modul Dinamis...")
        
        # 1. Dynamic Discovery & Loading Modul
        modules = self.plugin_loader.discover_and_load(target_type=target_type, module_filter=module_filter)
        print(f"[*] Total {len(modules)} Modul Siap Dijalankan.\n")
        
        results: Dict[str, Any] = {
            "meta": {
                "target": target,
                "target_type": target_type,
                "scope": scope,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "total_modules": len(modules)
            }
        }
        
        context: Dict[str, Any] = {}
        
        # 2. Eksekusi Modul Secara Terstruktur
        for module in modules:
            print(f"  [>] Menjalankan: {module.name}...")
            try:
                mod_result = await module.run(target, context=context)
                results[module.module_id] = mod_result
                context[module.module_id] = mod_result
            except Exception as e:
                print(f"  [!] Error pada modul {module.name}: {e}")
                results[module.module_id] = module.error_response(str(e))
                
        # Tutup async session setelah scanning selesai
        await self.async_client.close()
        
        print(f"\n{GREEN}[+] Pemindaian Selesai.{RESET}")
        
        # 3. Cetak Hasil Lengkap Langsung di Layar Terminal
        if target_type == "phone":
            self._print_phone_terminal(target, results)
        elif target_type == "web":
            self._print_web_terminal(target, results)
        elif target_type == "file":
            self._print_file_terminal(target, results)
        else:
            if "phone_osint" in results or "caller_id_osint" in results:
                self._print_phone_terminal(target, results)
            if "web_osint" in results:
                self._print_web_terminal(target, results)
            if "file_forensics" in results:
                self._print_file_terminal(target, results)

        # 4. Simpan File JSON di Direktori Tempat Terminal Aktif Dijalankan
        if save_json:
            if output_file:
                cwd_json_path = os.path.abspath(output_file)
            else:
                safe_name = target.replace("+", "").replace("://", "_").replace("/", "_").replace(":", "_").replace(" ", "_")
                cwd_json_path = os.path.join(os.getcwd(), f"report_{target_type}_{safe_name}.json")
                
            try:
                with open(cwd_json_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                print(f"  {GREEN}[+] File JSON tersimpan di : {WHITE}{cwd_json_path}{RESET}")
            except Exception as e:
                print(f"  [!] Gagal menyimpan file JSON di {cwd_json_path}: {e}")

        # 5. Opsi Ekspor HTML jika diminta secara spesifik
        if save_html:
            reports = self.report_generator.generate_all_reports(
                target=target,
                full_data=results,
                target_type=target_type
            )
            html_file = reports.get("html")
            if html_file:
                print(f"  {GREEN}[+] Laporan HTML (Opsional): {WHITE}{html_file}{RESET}")

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
            sys.stdout.write(f"\033[{num_options + 2}F")
        sys.stdout.write(f"{YELLOW}[+] PILIH DOMAIN PENYELIDIKAN:{RESET}\033[K\n\n")
        for idx, opt in enumerate(options):
            if idx == selected_idx:
                sys.stdout.write(f"  {CYAN}>  {WHITE}{opt}{RESET}\033[K\n")
            else:
                sys.stdout.write(f"     {WHITE}{opt}{RESET}\033[K\n")
        sys.stdout.flush()

    draw(first=True)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
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
            elif ch in ("\r", "\n"):
                break
            elif ch in ("k", "w", "K", "W"):
                selected_idx = (selected_idx - 1) % num_options
                draw()
            elif ch in ("j", "s", "J", "S"):
                selected_idx = (selected_idx + 1) % num_options
                draw()
            elif ch in ("q", "Q", "\x03"):
                selected_idx = num_options - 1
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        # Tampilkan kembali kursor
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    return selected_idx

def print_help_menu():
    help_text = rf"""
{BLUE}==================================================================={RESET}
{BLUE}  ____       _  _____ ____  ___ ____ _____ {RESET}       {WHITE} ___  ____ ___ _   _ _____ {RESET}
{BLUE} |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|{RESET}      {WHITE}/ _ \/ ___|_ _| \ | |_   _|{RESET}
{BLUE} | |_) |   / _ \ | | | |_) || | |     | |  {CYAN}____ {WHITE}| | | \___ \| ||  \| | | |  {RESET}
{BLUE} |  __/   / ___ \| | |  _ < | | |___  | | {CYAN}|____|{WHITE}| |_| |___) | || |\  | | |  {RESET}
{BLUE} |_|     /_/   \_\_| |_| \_\___\____| |_|  {RESET}      {WHITE}\___/|____/___|_| \_| |_|  {RESET}
{BLUE}==================================================================={RESET}
                        {BLUE}PATRICT{WHITE}-{CYAN}OSINT {WHITE}v{VERSION}{RESET}
{BLUE}==================================================================={RESET}

{YELLOW}PENGGUNAAN:{RESET}
  osint [target] [opsi]
  osint -t <target> -m <mode> [opsi]

{YELLOW}DESKRIPSI:{RESET}
  PATRICT-OSINT adalah framework intelijen sumber terbuka (OSINT) dan forensik
  digital modular generasi baru untuk investigasi multi-domain profesional.

{YELLOW}DOMAIN TARGET:{RESET}
  {CYAN}phone{RESET}       Penyelidikan nomor telepon internasional, HLR, operator dan sosmed
  {CYAN}web{RESET}         Reconnaissance web, WhatWeb tech stack, WAF, redirect dan DNS
  {CYAN}file{RESET}        Forensik media/gambar, EXIF, GPS coordinates, hash dan steganografi
  {CYAN}all{RESET}         Jalankan seluruh modul tanpa batasan domain

{YELLOW}OPSI / FLAGS:{RESET}
  {GREEN}-t, --target <str>{RESET}        Target input (Nomor Telepon, URL Web, atau Path Berkas)
  {GREEN}-m, --mode <mode>{RESET}         Domain mode: phone, web, file, all (Default: auto-detect)
  {GREEN}-M, --modules <list>{RESET}      Pilih modul spesifik (contoh: -M web_osint atau -M phone_osint,social_osint)
  {GREEN}-S, --scope <level>{RESET}       Cakupan pemindaian: quick, default, deep, full (Default: default)
  {GREEN}-T, --timeout <int>{RESET}       Batas waktu koneksi HTTP dalam detik (Default: 10)
  {GREEN}-c, --config <path>{RESET}       Path ke file konfigurasi YAML kustom
  {GREEN}-o, --output <path>{RESET}       Kustom path / nama file penyimpanan JSON
      {GREEN}--html{RESET}                Buat file laporan HTML interaktif di folder output/
      {GREEN}--no-json{RESET}             Jangan simpan file laporan JSON ke disk
  {GREEN}-v, --version{RESET}             Tampilkan informasi versi framework
  {GREEN}-h, --help{RESET}                Tampilkan menu bantuan lengkap ini

{YELLOW}PROFIL CAKUPAN (SCOPE):{RESET}
  {WHITE}quick{RESET}       Pemindaian cepat: validasi dasar, header, dan metadata inti.
  {WHITE}default{RESET}     Pemindaian standar: seluruh modul aktif dalam domain target.
  {WHITE}deep{RESET}        Pemindaian mendalam: probe endpoint, permutasi email & reverse DNS.
  {WHITE}full{RESET}        Pemindaian penuh: aktifkan seluruh modul & dorking agresif.

{YELLOW}CONTOH PENGGUNAAN:{RESET}
  # Penyelidikan Nomor Telepon
  osint +6281234567890
  osint -t +6281234567890 -m phone -S deep

  # Reconnaissance Web & Tech Stack ala WhatWeb
  osint https://target.com
  osint -t https://target.com -m web -T 15 -S full

  # Analisis Forensik Gambar & Steganografi
  osint /path/to/foto.jpg
  osint -t /path/to/foto.jpg -m file

  # Eksekusi Modul Spesifik & Output Kustom
  osint -t +6281234567890 -M phone_osint,whatsapp_osint -o hasil_wa.json
"""
    print(help_text)

async def main_async():
    # Periksa -h atau --help atau -help
    if any(arg in sys.argv for arg in ["-h", "--help", "-help", "help"]):
        print_help_menu()
        sys.exit(0)

    if any(arg in sys.argv for arg in ["-v", "--version", "-version", "version"]):
        print(f"PATRICT-OSINT Framework v{VERSION}")
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="PATRICT-OSINT Framework v2.2.0 - Automated Multi-Domain Intelligence & Forensics",
        usage="osint [target] [options]",
        add_help=False
    )
    parser.add_argument("target_pos", nargs="?", help="Target penyelidikan", default=None)
    parser.add_argument("-t", "--target", help="Target penyelidikan", default=None)
    parser.add_argument("-m", "--mode", choices=["phone", "web", "file", "all"], help="Mode penyelidikan", default=None)
    parser.add_argument("-M", "--modules", help="Daftar modul spesifik", default=None)
    parser.add_argument("-S", "--scope", choices=["quick", "default", "deep", "full"], help="Cakupan penyelidikan", default="default")
    parser.add_argument("-T", "--timeout", type=int, help="Timeout koneksi HTTP dalam detik", default=None)
    parser.add_argument("-c", "--config", help="Path ke file konfigurasi YAML", default="config/config.yaml")
    parser.add_argument("-o", "--output", help="Path / nama file output JSON kustom", default=None)
    parser.add_argument("--html", action="store_true", help="Ekspor laporan HTML ke folder output/", default=False)
    parser.add_argument("--no-json", action="store_true", help="Jangan simpan file JSON di direktori aktif", default=False)
    args = parser.parse_args()
    
    orchestrator = PATRICTOrchestrator(config_path=args.config, timeout=args.timeout)
    
    target = args.target_pos or args.target
    mode = args.mode
    
    # Parse module filter jika ada
    module_filter = None
    if args.modules:
        module_filter = [m.strip() for m in args.modules.split(",") if m.strip()]
    
    EXIT_KEYWORDS = {"exit", "quit", "q", ":q", "keluar", "stop", "bye", "cancel", "0"}
    
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
        
        try:
            target = input(f"\n{YELLOW}[?]{RESET} Masukkan Target: ").strip()
        except EOFError:
            target = ""
            
    if not target:
        print("\n[!] Error: Target tidak boleh kosong.")
        sys.exit(1)

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
            sys.exit(1)

        if target.startswith("08"):
            target = "+62" + target[1:]
        elif target.startswith("62") and not target.startswith("+"):
            target = "+" + target
        elif not target.startswith("+") and digits:
            target = "+" + digits
            
    elif mode == "web":
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
            
    elif mode == "file":
        if not os.path.exists(target):
            print(f"\n[!] Error: File '{target}' tidak ditemukan di sistem.")
            sys.exit(1)

    print("")
    await orchestrator.run(
        target,
        target_type=mode,
        module_filter=module_filter,
        scope=args.scope,
        show_banner=False,
        save_json=not args.no_json,
        output_file=args.output,
        save_html=args.html
    )

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan oleh pengguna.")
        sys.exit(0)

if __name__ == "__main__":
    main()
