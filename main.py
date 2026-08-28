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
from typing import Dict, Any

from core.config_manager import ConfigManager
from core.async_client import AsyncHttpClient
from core.plugin_loader import PluginLoader
from visualizers.graph_engine import GraphEngine
from reports.report_generator import ReportGenerator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class PATRICTOrchestrator:
    """
    Main Orchestrator for PATRICT-OSINT Framework.
    Mengatur konfigurasi, plugin loader dinamis, eksekusi async, graf relasi, dan pelaporan.
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

    async def run(self, target_phone: str, show_banner: bool = True) -> Dict[str, Any]:
        if show_banner:
            self.print_banner()
        print(f"[*] Target Reconnaissance : {target_phone}")
        print(f"[*] Waktu Mulai          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"[*] Memuat Modul Dinamis...")
        
        # 1. Dynamic Discovery & Loading Modul
        modules = self.plugin_loader.discover_and_load()
        print(f"[*] Total {len(modules)} Modul Siap Dijalankan.\n")
        
        results: Dict[str, Any] = {
            "meta": {
                "target": target_phone,
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
                mod_result = await module.run(target_phone, context=context)
                results[module.module_id] = mod_result
                context[module.module_id] = mod_result
            except Exception as e:
                print(f"  [!] Error pada modul {module.name}: {e}")
                results[module.module_id] = module.error_response(str(e))
                
        # Tutup async session setelah scanning selesai
        await self.async_client.close()
        
        print("\n[*] Pemindaian Intelijen Selesai.")
        print("[*] Membangun Visualisasi Graf & Laporan...")
        
        # 3. Generate Interactive Relationship Graph
        graph_file = None
        if self.config_manager.get("reporting.generate_graph", True):
            try:
                graph_file = self.graph_engine.generate_relationship_graph(target_phone, results)
                print(f"  [+] Graf Relasi Interaktif : {graph_file}")
            except Exception as e:
                print(f"  [!] Gagal membuat graf relasi: {e}")
                
        # 4. Generate Reports (JSON, CSV, HTML)
        map_file = results.get("location_osint", {}).get("data", {}).get("map_file")
        reports = self.report_generator.generate_all_reports(
            target=target_phone,
            full_data=results,
            graph_file=graph_file,
            map_file=map_file
        )
        
        for fmt, path in reports.items():
            print(f"  [+] Laporan ({fmt.upper()})        : {path}")
            
        print("\n" + "="*67)
        print(" Selesai! Buka file HTML di folder ./output untuk melihat hasil lengkap.")
        print("="*67 + "\n")
        
        return results

async def main_async():
    parser = argparse.ArgumentParser(
        description="PATRICT-OSINT Framework v2.0 - Automated OSINT Reconnaissance",
        usage="osint [target] [options]"
    )
    parser.add_argument("target_pos", nargs="?", help="Target nomor telepon (contoh: +6281234567890)", default=None)
    parser.add_argument("-t", "--target", help="Target nomor telepon (opsional jika menggunakan positional argument)", default=None)
    parser.add_argument("-c", "--config", help="Path ke file konfigurasi YAML", default="config/config.yaml")
    args = parser.parse_args()
    
    orchestrator = PATRICTOrchestrator(config_path=args.config)
    
    target = args.target_pos or args.target
    is_interactive = not target
    
    if is_interactive:
        orchestrator.print_banner()
        print("[+] Mode Interaktif PATRICT-OSINT\n")
        try:
            target = input("[?] Masukkan Nomor Telepon Target (contoh: +6281234567890, 'exit' untuk keluar): ").strip()
        except EOFError:
            target = ""
            
    if not target:
        print("\n[!] Error: Nomor telepon target tidak boleh kosong.")
        sys.exit(1)

    # Periksa perintah keluar
    EXIT_KEYWORDS = {"exit", "quit", "q", ":q", "keluar", "stop", "bye", "cancel"}
    if target.lower() in EXIT_KEYWORDS:
        print("\n[*] Keluar dari PATRICT-OSINT.")
        sys.exit(0)

    # Validasi bahwa input berisi format nomor yang masuk akal
    digits = re.sub(r"\D", "", target)
    if not digits or len(digits) < 5:
        print(f"\n[!] Error: Input '{target}' bukan format nomor telepon yang valid.")
        print("    Contoh format yang didukung: +6281234567890 atau 081234567890")
        sys.exit(1)

    # Normalisasi nomor lokal (08xx -> +628xx atau 62xx -> +62xx)
    if target.startswith("08"):
        target = "+62" + target[1:]
    elif target.startswith("62") and not target.startswith("+"):
        target = "+" + target
    elif not target.startswith("+") and digits:
        target = "+" + digits

    if is_interactive:
        print("")
        await orchestrator.run(target, show_banner=False)
    else:
        await orchestrator.run(target, show_banner=True)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan oleh pengguna.")
        sys.exit(0)

if __name__ == "__main__":
    main()
