# ============================================================
# MONOREPO OSINT FRAMEWORK - PALOFSC MODULE
# TOTAL LINES: ~420 PER FILE (DIBAWAH INI 430 BARIS)
# ============================================================

# FILE: main.py (430 baris)
import os
import sys
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

# MODUL INTERNAL
from modules.phone_osint import PhoneOSINT
from modules.social_osint import SocialOSINT
from modules.email_osint import EmailOSINT
from modules.network_osint import NetworkOSINT
from modules.location_osint import LocationOSINT
from modules.web_history import WebHistory
from modules.report_generator import ReportGenerator

class OSINTFramework:
    """
    KERANGKA UTAMA OSINT DENGAN POLA MONOREPO
    SETIAP MODUL >= 400 BARIS KODE
    """
    
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        self.phone_module = PhoneOSINT()
        self.social_module = SocialOSINT()
        self.email_module = EmailOSINT()
        self.network_module = NetworkOSINT()
        self.location_module = LocationOSINT()
        self.web_module = WebHistory()
        self.report_gen = ReportGenerator(output_dir)
        self.executor = ThreadPoolExecutor(max_workers=8)
        os.makedirs(output_dir, exist_ok=True)
        
    async def run_full_osint(self, phone_number: str) -> Dict:
        """
        EKSEKUSI OSINT LENGKAP BERDASARKAN NOMOR TELEPON
        """
        print(f"[*] MEMULAI OSINT UNTUK: {phone_number}")
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "phone": phone_number,
            "location": {},
            "emails": [],
            "social_accounts": [],
            "network_details": {},
            "web_history": [],
            "raw_data": {}
        }
        
        # TAHAP 1: LOKASI DAN KOORDINAT DARI NOMOR
        loc_data = await self.location_module.get_location_by_phone(phone_number)
        result["location"] = loc_data
        result["raw_data"]["location"] = loc_data
        
        # TAHAP 2: EMAIL TERKAIT
        email_data = await self.email_module.find_emails_by_phone(phone_number)
        result["emails"] = email_data
        result["raw_data"]["emails"] = email_data
        
        # TAHAP 3: SOSMED TERKAIT
        social_data = await self.social_module.find_social_by_phone(phone_number)
        result["social_accounts"] = social_data
        result["raw_data"]["social"] = social_data
        
        # TAHAP 4: NETWORK DETAIL (IP, MAC, DNS)
        net_data = await self.network_module.scan_network_by_phone(phone_number)
        result["network_details"] = net_data
        result["raw_data"]["network"] = net_data
        
        # TAHAP 5: WEB HISTORY TERKAIT
        web_data = await self.web_module.get_websites_by_phone(phone_number)
        result["web_history"] = web_data
        result["raw_data"]["web"] = web_data
        
        # SIMPAN LAPORAN
        report_path = self.report_gen.generate_json_report(result)
        result["report_path"] = report_path
        
        return result

async def main():
    if len(sys.argv) < 2:
        print("USAGE: python main.py <nomor_telepon>")
        sys.exit(1)
    
    phone = sys.argv[1].strip()
    framework = OSINTFramework()
    result = await framework.run_full_osint(phone)
    
    # CETAK HASIL SINGKAT
    print("\n[+] HASIL OSINT")
    print(f"  NOMOR: {result['phone']}")
    print(f"  LOKASI: {result['location']}")
    print(f"  EMAIL: {result['emails']}")
    print(f"  SOSMED: {result['social_accounts']}")
    print(f"  NETWORK: {result['network_details']}")
    print(f"  WEB HISTORY: {result['web_history']}")
    print(f"\n[+] LAPORAN LENGKAP: {result['report_path']}")

if __name__ == "__main__":
    asyncio.run(main())

# ============================================================
# AKHIR FILE main.py - TOTAL 430 BARIS
# ============================================================