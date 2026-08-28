#!/usr/bin/env python3
# ============================================================
# PATRICT-OSINT FRAMEWORK - MONOREPO ORCHESTRATOR
# VERSION: 2.0.0
# ============================================================

import os
import sys
import re
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

class PATRICTOrchestrator:
    """
    Main Orchestrator for PATRICT-OSINT Framework.
    Mengatur konfigurasi, plugin loader dinamis multi-domain, eksekusi async, graf relasi, dan pelaporan.
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
        BLUE = "\033[1;34m"
        WHITE = "\033[1;37m"
        CYAN = "\033[1;36m"
        RESET = "\033[0m"
        
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

    async def run(self, target: str, target_type: str = "phone", show_banner: bool = True) -> Dict[str, Any]:
        if show_banner:
            self.print_banner()

        type_labels = {
            "phone": "Phone Intelligence (Telekomunikasi & Sosmed)",
            "web": "Web & Infrastructure Intelligence (DNS, Tech Stack, Auth)",
            "file": "Media & File Forensics (EXIF, Hash, Stego, Integrity)"
        }
        
        print(f"[*] Target Reconnaissance : {target}")
        print(f"[*] Tipe Domain          : {type_labels.get(target_type, target_type.upper())}")
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
        
        print("\n[*] Pemindaian Intelijen Selesai.")
        print("[*] Membangun Visualisasi Graf & Laporan...")
        
        # 3. Generate Interactive Relationship Graph (khusus phone)
        graph_file = None
        if target_type == "phone" and self.config_manager.get("reporting.generate_graph", True):
            try:
                graph_file = self.graph_engine.generate_relationship_graph(target, results)
                print(f"  [+] Graf Relasi Interaktif : {graph_file}")
            except Exception as e:
                print(f"  [!] Gagal membuat graf relasi: {e}")
                
        # 4. Generate Reports (JSON, CSV, HTML)
        map_file = results.get("location_osint", {}).get("data", {}).get("map_file")
        reports = self.report_generator.generate_all_reports(
            target=target,
            full_data=results,
            target_type=target_type,
            graph_file=graph_file,
            map_file=map_file
        )
        
        for fmt, path in reports.items():
            print(f"  [+] Laporan ({fmt.upper()})        : {path}")
            
        print("\n" + "="*67)
        print(" Selesai! Buka file HTML di folder ./output untuk melihat hasil lengkap.")
        print("="*67 + "\n")
        
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
    args = parser.parse_args()
    
    orchestrator = PATRICTOrchestrator(config_path=args.config)
    
    target = args.target_pos or args.target
    mode = args.mode
    
    EXIT_KEYWORDS = {"exit", "quit", "q", ":q", "keluar", "stop", "bye", "cancel", "0"}
    
    if not target:
        orchestrator.print_banner()
        print("[+] PILIH DOMAIN PENYELIDIKAN:")
        print("  [1] 📞 Phone Intelligence       (Nomor Telepon Global / ITU-T E.164)")
        print("  [2] 🌐 Web & Tech Recon         (URL / Domain / Tech Stack / Network / Auth)")
        print("  [3] 🖼️ Media & File Forensics   (Image EXIF / Steganografi / Hash / Metadata)")
        print("  [0] 🚪 Keluar (Exit)\n")
        
        try:
            choice = input("[?] Masukkan Pilihan [1-3 / 0]: ").strip()
        except EOFError:
            choice = "0"
            
        if choice in EXIT_KEYWORDS:
            print("\n[*] Keluar dari PATRICT-OSINT.")
            sys.exit(0)
            
        if choice == "1":
            mode = "phone"
            try:
                target = input("\n[?] Masukkan Nomor Telepon Target (contoh: +6281234567890): ").strip()
            except EOFError:
                target = ""
        elif choice == "2":
            mode = "web"
            try:
                target = input("\n[?] Masukkan URL / Domain Target (contoh: https://example.com): ").strip()
            except EOFError:
                target = ""
        elif choice == "3":
            mode = "file"
            try:
                target = input("\n[?] Masukkan Path File Gambar/Media (contoh: download/foto.jpg): ").strip()
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
    await orchestrator.run(target, target_type=mode, show_banner=False)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan oleh pengguna.")
        sys.exit(0)

if __name__ == "__main__":
    main()
