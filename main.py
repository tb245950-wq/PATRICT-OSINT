#!/usr/bin/env python3
# ============================================================
# PATRICT-OSINT FRAMEWORK - MONOREPO ORCHESTRATOR
# VERSION: 2.0.0
# ============================================================

import os
import sys
import re
import json
import asyncio
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from core.config_manager import ConfigManager
from core.async_client import AsyncHttpClient
from core.plugin_loader import PluginLoader
from visualizers.graph_engine import GraphEngine
from reports.report_generator import ReportGenerator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ANSI Colors
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
    Mengatur konfigurasi, plugin loader dinamis multi-domain, eksekusi async,
    pencetakan hasil kaya langsung di terminal, serta penyimpanan JSON di direktori aktif.
    """
    
    def __init__(self, config_path: str = None):
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
                        {BLUE}PATRICT{WHITE}-{CYAN}OSINT {WHITE}v2.0{RESET}
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
        print(f"  {CYAN}Status Validasi{RESET}     : {GREEN}ITU-T E.164 VALID ✔{RESET}" if p_data.get("valid") else f"  {CYAN}Status Validasi{RESET}     : {RED}TIDAK VALID ✘{RESET}")
        
        if l_data.get("latitude") and l_data.get("longitude"):
            print(f"  {CYAN}Estimasi Lokasi HLR{RESET} : {WHITE}{l_data.get('city', '')} {l_data.get('region', '')} (Lat: {l_data.get('latitude')}, Lon: {l_data.get('longitude')}){RESET}")

        # Caller ID
        print(f"\n{YELLOW}[+] IDENTITAS & CALLER DIRECTORY:{RESET}")
        owner_name = c_data.get("name") or c_data.get("caller_name") or "Tidak ditemukan di direktori publik"
        spam_score = c_data.get("spam_score", "0%")
        print(f"  • Nama Teridentifikasi : {WHITE}{owner_name}{RESET}")
        print(f"  • Skor Reputasi/Spam   : {GREEN}{spam_score}{RESET}")

        # WhatsApp
        if w_data:
            wa_status = "Aktif ✔" if w_data.get("is_registered") or w_data.get("valid") else "Tidak Terdeteksi"
            print(f"\n{YELLOW}[+] WHATSAPP RECONNAISSANCE:{RESET}")
            print(f"  • Status WhatsApp      : {GREEN if 'Aktif' in wa_status else WHITE}{wa_status}{RESET}")
            print(f"  • Link Profil          : {CYAN}https://wa.me/{target.replace('+', '')}{RESET}")

        # Social Media
        accounts = s_data.get("accounts", []) if isinstance(s_data, dict) else []
        print(f"\n{YELLOW}[+] AKUN MEDIA SOSIAL TERHUBUNG ({len(accounts)} Ditemukan):{RESET}")
        if accounts:
            for acc in accounts:
                print(f"  • {acc.get('platform', 'Platform') : <20} : {GREEN}Terdeteksi{RESET} ({acc.get('url', '')})")
        else:
            print(f"  • {WHITE}Tidak ditemukan akun media sosial publik dengan signature nomor ini.{RESET}")

        # Emails
        emails = e_data.get("emails", []) if isinstance(e_data, dict) else []
        print(f"\n{YELLOW}[+] POTENSI ALAMAT EMAIL TERKAIT ({len(emails)}):{RESET}")
        if emails:
            for em in emails[:5]:
                print(f"  • {WHITE}{em.get('email', '')}{RESET} {GREEN}({em.get('source', 'OSINT')}){RESET}")
        else:
            print(f"  • {WHITE}Tidak ada permutasi email yang aktif.{RESET}")

        # Dorks
        findings = d_data.get("findings", []) if isinstance(d_data, dict) else []
        if findings:
            print(f"\n{YELLOW}[+] TEMUAN DORKING & DOKUMEN PUBLIK ({len(findings)}):{RESET}")
            for item in findings[:4]:
                print(f"  • [{item.get('category', 'Info')}] {WHITE}{item.get('title', '')}{RESET} -> {CYAN}{item.get('url', '')}{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    def _print_web_terminal(self, target: str, results: Dict[str, Any]):
        w_data = results.get("web_osint", {}).get("data", {})
        geo = w_data.get("server_geoip", {})
        stack = w_data.get("tech_stack", {})
        auth = w_data.get("auth_intelligence", {})
        dns_rec = w_data.get("dns_records", {})

        print(f"\n{BLUE}{'='*67}{RESET}")
        print(f"             {WHITE}{BOLD}HASIL RECONNAISSANCE WEB & INFRASTRUKTUR{RESET}")
        print(f"{BLUE}{'='*67}{RESET}")
        print(f"  {CYAN}Target URL{RESET}          : {WHITE}{target}{RESET}")
        print(f"  {CYAN}Domain Asli{RESET}         : {WHITE}{w_data.get('domain', 'N/A')}{RESET}")
        print(f"  {CYAN}Status HTTP{RESET}         : {GREEN}{w_data.get('final_status', 200)} OK{RESET}")
        print(f"  {CYAN}Final Destination{RESET}   : {WHITE}{w_data.get('final_url', target)}{RESET}")
        
        methods = w_data.get("http_methods_allowed", [])
        print(f"  {CYAN}Allowed Methods{RESET}     : {GREEN}{', '.join(methods) if methods else 'GET, HEAD'}{RESET}")

        # Server GeoIP
        print(f"\n{YELLOW}[+] SERVER & NETWORK GEOIP:{RESET}")
        print(f"  • IP Publik Server  : {WHITE}{geo.get('ip', 'N/A')}{RESET}")
        print(f"  • Lokasi Server     : {WHITE}{geo.get('city', '')}, {geo.get('country', '')} (Lat: {geo.get('latitude', '-')}, Lon: {geo.get('longitude', '-')}){RESET}")
        print(f"  • ISP / Organisasi  : {WHITE}{geo.get('isp') or geo.get('organization') or 'N/A'}{RESET}")
        if geo.get("asn"):
            print(f"  • ASN Jaringan      : {WHITE}{geo.get('asn')}{RESET}")
        if geo.get("maps_url"):
            print(f"  • Lokasi Google Maps: {CYAN}{geo.get('maps_url')}{RESET}")

        # Tech Stack
        print(f"\n{YELLOW}[+] STACK TEKNOLOGI:{RESET}")
        servers = stack.get("web_servers", [])
        backends = stack.get("backend_frameworks", [])
        frontends = stack.get("frontend_libraries", [])
        cms_list = stack.get("cms_and_platforms", [])
        cdns = stack.get("analytics_and_cdn", [])

        print(f"  • Web Servers       : {WHITE}{', '.join(servers) if servers else 'Hidden / Generic'}{RESET}")
        if backends:
            print(f"  • Backend Framework : {WHITE}{', '.join(backends)}{RESET}")
        if frontends:
            print(f"  • Frontend Tech     : {WHITE}{', '.join(frontends)}{RESET}")
        if cms_list:
            print(f"  • CMS / Platform    : {WHITE}{', '.join(cms_list)}{RESET}")
        if cdns:
            print(f"  • CDN / Analytics   : {WHITE}{', '.join(cdns)}{RESET}")

        # Auth & Security
        print(f"\n{YELLOW}[+] AUTHENTICATION & COOKIE SECURITY:{RESET}")
        auth_types = auth.get("auth_type_detected", ["Standard / Stateless"])
        print(f"  • Tipe Auth/Session : {WHITE}{', '.join(auth_types)}{RESET}")
        
        flags = auth.get("security_flags", {})
        httponly = f"{GREEN}Aktif ✔{RESET}" if flags.get("httponly") else f"{RED}Tidak Aktif ✘{RESET}"
        secure = f"{GREEN}Aktif ✔{RESET}" if flags.get("secure") else f"{RED}Tidak Aktif ✘{RESET}"
        samesite = flags.get("samesite") or "Default"
        print(f"  • Cookie Flags      : HttpOnly: {httponly} | Secure: {secure} | SameSite: {WHITE}{samesite}{RESET}")

        # DNS Records
        if any(dns_rec.values()):
            print(f"\n{YELLOW}[+] DNS RECORDS MATRIX:{RESET}")
            for r_type in ["A", "MX", "NS", "TXT"]:
                r_val = dns_rec.get(r_type, [])
                if r_val:
                    print(f"  • {r_type : <18}: {WHITE}{', '.join(r_val[:3])}{RESET}")

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
        print(f"  • MD5               : {WHITE}{hashes.get('md5', 'N/A')}{RESET}")
        print(f"  • SHA-1             : {WHITE}{hashes.get('sha1', 'N/A')}{RESET}")
        print(f"  • SHA-256           : {WHITE}{hashes.get('sha256', 'N/A')}{RESET}")

        # Magic Bytes
        print(f"\n{YELLOW}[+] VERIFIKASI MAGIC BYTES:{RESET}")
        is_spoofed = magic.get("is_extension_spoofed", False)
        spoof_badge = f"{RED}⚠️ SPOOFED (Ekstensi dipalsukan!){RESET}" if is_spoofed else f"{GREEN}Valid (Tidak ada pemalsuan) ✔{RESET}"
        print(f"  • Tipe File Asli    : {WHITE}{magic.get('detected_file_type', 'Unknown')}{RESET}")
        print(f"  • Status Ekstensi   : {spoof_badge}")

        # EXIF
        print(f"\n{YELLOW}[+] METADATA KAMERA & EXIF:{RESET}")
        if exif.get("has_exif"):
            camera = f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
            print(f"  • Perangkat/Kamera  : {WHITE}{camera or 'N/A'}{RESET}")
            print(f"  • Software Editor   : {WHITE}{exif.get('software', 'N/A')}{RESET}")
            print(f"  • Waktu Pemotretan  : {WHITE}{exif.get('datetime_original', 'N/A')}{RESET}")
            gps = exif.get("gps_coordinates")
            if gps:
                print(f"  • Koordinat GPS     : {GREEN}Lat: {gps.get('latitude')}, Lon: {gps.get('longitude')}{RESET}")
                print(f"  • Google Maps URL   : {CYAN}{gps.get('google_maps_url')}{RESET}")
        else:
            print(f"  • {WHITE}Tidak ditemukan metadata EXIF pada berkas ini.{RESET}")

        # Steganography & Appended Data
        print(f"\n{YELLOW}[+] DETEKSI STEGANOGRAFI & INTEGRITAS BINARY:{RESET}")
        if stego.get("appended_data_detected"):
            print(f"  • Appended Data     : {YELLOW}Terdeteksi {stego.get('appended_data_size_bytes')} bytes setelah marker EOF (Potensi payload tersembunyi!) ⚠️{RESET}")
        else:
            print(f"  • Appended Data     : {GREEN}Bersih (Tidak ada data tambahan setelah EOF) ✔{RESET}")

        if stego.get("embedded_zip_detected"):
            print(f"  • Embedded Archive  : {RED}Terdeteksi arsip ZIP tersembunyi di dalam gambar! ⚠️{RESET}")

        strings_sample = stego.get("embedded_hidden_strings_sample", [])
        if strings_sample:
            print(f"  • Extracted Strings : {CYAN}{', '.join(strings_sample[:3])}{RESET}")

        print(f"{BLUE}{'='*67}{RESET}\n")

    async def run(self, target: str, target_type: str = "phone", show_banner: bool = True, save_json: bool = True, save_html: bool = False) -> Dict[str, Any]:
        if show_banner:
            self.print_banner()

        type_labels = {
            "phone": "Phone Intelligence (Telekomunikasi & Sosmed)",
            "web": "Web & Infrastructure Intelligence (DNS, Tech Stack, Auth)",
            "file": "Media & File Forensics (EXIF, Hash, Stego, Integrity)"
        }
        
        print(f"[*] Target Reconnaissance : {WHITE}{target}{RESET}")
        print(f"[*] Tipe Domain          : {CYAN}{type_labels.get(target_type, target_type.upper())}{RESET}")
        print(f"[*] Waktu Mulai          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"[*] Memuat Modul Dinamis...")
        
        # 1. Dynamic Discovery & Loading Modul berdasarkan target_type
        modules = self.plugin_loader.discover_and_load(target_type=target_type)
        print(f"[*] Total {len(modules)} Modul Siap Dijalankan.\n")
        
        results: Dict[str, Any] = {
            "meta": {
                "target": target,
                "target_type": target_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": self.config_manager.get("app.version", "2.0.0"),
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
        
        print(f"\n{GREEN}[✔] Pemindaian Intelijen Selesai.{RESET}")
        
        # 3. Cetak Hasil Lengkap Langsung di Layar Terminal
        if target_type == "phone":
            self._print_phone_terminal(target, results)
        elif target_type == "web":
            self._print_web_terminal(target, results)
        elif target_type == "file":
            self._print_file_terminal(target, results)

        # 4. Simpan File JSON di Direktori Tempat Terminal Aktif Dijalankan (Current Working Directory)
        if save_json:
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

async def main_async():
    parser = argparse.ArgumentParser(
        description="PATRICT-OSINT Framework v2.0 - Automated Multi-Domain Intelligence & Forensics",
        usage="osint [target] [options]"
    )
    parser.add_argument("target_pos", nargs="?", help="Target penyelidikan (nomor telepon, URL/domain, atau file gambar)", default=None)
    parser.add_argument("-t", "--target", help="Target penyelidikan (opsional jika menggunakan positional argument)", default=None)
    parser.add_argument("-m", "--mode", choices=["phone", "web", "file"], help="Mode penyelidikan (phone, web, file)", default=None)
    parser.add_argument("-c", "--config", help="Path ke file konfigurasi YAML", default="config/config.yaml")
    parser.add_argument("--html", action="store_true", help="Ekspor laporan HTML ke folder output/", default=False)
    parser.add_argument("--no-json", action="store_true", help="Jangan simpan file JSON di direktori aktif", default=False)
    args = parser.parse_args()
    
    orchestrator = PATRICTOrchestrator(config_path=args.config)
    
    target = args.target_pos or args.target
    mode = args.mode
    
    EXIT_KEYWORDS = {"exit", "quit", "q", ":q", "keluar", "stop", "bye", "cancel", "0"}
    
    if not target:
        orchestrator.print_banner()
        print(f"{YELLOW}[+] PILIH DOMAIN PENYELIDIKAN:{RESET}")
        print(f"  {CYAN}[1]{RESET} 📞 Phone Intelligence       (Nomor Telepon Global / ITU-T E.164)")
        print(f"  {CYAN}[2]{RESET} 🌐 Web & Tech Recon         (URL / Domain / Tech Stack / Network / Auth)")
        print(f"  {CYAN}[3]{RESET} 🖼️ Media & File Forensics   (Image EXIF / Steganografi / Hash / Metadata)")
        print(f"  {CYAN}[0]{RESET} 🚪 Keluar (Exit)\n")
        
        try:
            choice = input(f"{YELLOW}[?]{RESET} Masukkan Pilihan [1-3 / 0]: ").strip()
        except EOFError:
            choice = "0"
            
        if choice in EXIT_KEYWORDS:
            print("\n[*] Keluar dari PATRICT-OSINT.")
            sys.exit(0)
            
        if choice == "1":
            mode = "phone"
            try:
                target = input(f"\n{YELLOW}[?]{RESET} Masukkan Nomor Telepon Target (contoh: +6281234567890): ").strip()
            except EOFError:
                target = ""
        elif choice == "2":
            mode = "web"
            try:
                target = input(f"\n{YELLOW}[?]{RESET} Masukkan URL / Domain Target (contoh: https://example.com): ").strip()
            except EOFError:
                target = ""
        elif choice == "3":
            mode = "file"
            try:
                target = input(f"\n{YELLOW}[?]{RESET} Masukkan Path File Gambar/Media (contoh: download/foto.jpg): ").strip()
            except EOFError:
                target = ""
        else:
            print("\n[!] Pilihan tidak valid.")
            sys.exit(1)
            
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
            print("    Contoh format yang didukung: +6281234567890 atau 081234567890")
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
        show_banner=False,
        save_json=not args.no_json,
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
