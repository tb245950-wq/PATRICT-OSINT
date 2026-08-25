import re
import requests
from typing import Dict, List, Set, Optional
import dns.resolver
import smtplib
import hashlib
import base64
from datetime import datetime
from email.parser import Parser
from email.policy import default

class EmailOSINT:
    """
    MODUL OSINT UNTUK MENCARI EMAIL TERKAIT DENGAN NOMOR TELEPON
    DAN MENAMPILKAN NAMA LENGKAP SERTA DOMAIN TERKAIT
    """
    
    def __init__(self):
        self.email_patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        ]
        self.leak_sources = [
            "https://haveibeenpwned.com/api/v3/breachedaccount/",
            "https://api.leakcheck.net/api/",
            "https://api.dehashed.com/search?query="
        ]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.cache = {}
        
    async def find_emails_by_phone(self, phone: str) -> List[Dict]:
        """
        METODE UTAMA: MENCARI SEMUA EMAIL YANG TERHUBUNG DENGAN NOMOR
        MENGGUNAKAN BERBAGAI API PUBLIK DAN PARSING
        """
        results = []
        
        # 1. QUERY HAVEIBEENPWNED (SIMULASI)
        hbp_data = self._query_haveibeenpwned(phone)
        if hbp_data:
            results.extend(hbp_data)
        
        # 2. QUERY LEAKCHECK (SIMULASI)
        lc_data = self._query_leakcheck(phone)
        if lc_data:
            results.extend(lc_data)
        
        # 3. QUERY DEHASHED (SIMULASI)
        dh_data = self._query_dehashed(phone)
        if dh_data:
            results.extend(dh_data)
        
        # 4. PARSING DARI SUMBER TERBUKA (SIMULASI)
        open_data = self._parse_open_sources(phone)
        if open_data:
            results.extend(open_data)
        
        # DEDUPLIKASI
        unique_results = self._deduplicate_emails(results)
        
        # TAMBAHKAN INFORMASI NAMA DARI EMAIL
        for item in unique_results:
            item["name"] = self._extract_name_from_email(item.get("email", ""))
            item["domain"] = item.get("email", "").split('@')[-1] if '@' in item.get("email", "") else ""
        
        return unique_results
    
    def _query_haveibeenpwned(self, phone: str) -> List[Dict]:
        """
        QUERY API HAVEIBEENPWNED (SIMULASI)
        """
        # SIMULASI RESPON
        return [
            {"email": f"user_{hash(phone)%1000}@gmail.com", "source": "haveibeenpwned", "breach": "Adobe"},
            {"email": f"contact_{hash(phone)%500}@yahoo.com", "source": "haveibeenpwned", "breach": "LinkedIn"}
        ]
    
    def _query_leakcheck(self, phone: str) -> List[Dict]:
        """
        QUERY API LEAKCHECK (SIMULASI)
        """
        return [
            {"email": f"phone_{phone}@protonmail.com", "source": "leakcheck", "breach": "unknown"}
        ]
    
    def _query_dehashed(self, phone: str) -> List[Dict]:
        """
        QUERY API DEHASHED (SIMULASI)
        """
        return [
            {"email": f"{phone}@outlook.com", "source": "dehashed", "breach": "Collection #1"}
        ]
    
    def _parse_open_sources(self, phone: str) -> List[Dict]:
        """
        PARSING DARI SUMBER TERBUKA SEPERTI PASTEBIN, GITHUB
        """
        # SIMULASI PARSING
        return [
            {"email": f"test_{phone[-4:]}@gmail.com", "source": "opensource", "breach": "public_repo"}
        ]
    
    def _deduplicate_emails(self, emails: List[Dict]) -> List[Dict]:
        """
        MENGHAPUS DUPLIKAT BERDASARKAN EMAIL
        """
        seen = set()
        unique = []
        for item in emails:
            email = item.get("email", "")
            if email and email not in seen:
                seen.add(email)
                unique.append(item)
        return unique
    
    def _extract_name_from_email(self, email: str) -> str:
        """
        EKSTRAK NAMA DARI ALAMAT EMAIL (HEURISTIK)
        """
        local = email.split('@')[0] if '@' in email else email
        # HAPUS ANGKA DAN TANDA BACA
        name = re.sub(r'[^a-zA-Z\s]', ' ', local)
        # KAPITALISASI
        name = ' '.join([w.capitalize() for w in name.split() if len(w) > 1])
        return name if name else "nama_tidak_diketahui"
    
    def verify_email_exists(self, email: str) -> bool:
        """
        VERIFIKASI APAKAH EMAIL VALID DENGAN SMTP
        """
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx = str(mx_records[0].exchange)
            smtp = smtplib.SMTP(mx, timeout=5)
            smtp.helo()
            smtp.mail("test@example.com")
            code, _ = smtp.rcpt(email)
            smtp.quit()
            return code == 250
        except:
            return False
    
    def get_email_domain_info(self, domain: str) -> Dict:
        """
        MENDAPATKAN INFORMASI DOMAIN (MX, SPF, DMARC, DKIM)
        """
        info = {}
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            info["mx"] = [str(r.exchange) for r in mx]
        except:
            info["mx"] = []
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            info["spf"] = [str(r) for r in spf if "v=spf" in str(r)]
        except:
            info["spf"] = []
        return info
    
    def get_google_account_info(self, email: str) -> Dict:
        """
        MENDAPATKAN INFORMASI AKUN GOOGLE (SIMULASI)
        MENGGUNAKAN API PUBLIK
        """
        # SIMULASI - TIDAK ADA API PUBLIK UNTUK INI
        return {
            "email": email,
            "has_google_account": True,
            "profile_picture": f"https://lh3.googleusercontent.com/{hash(email)}",
            "name": self._extract_name_from_email(email)
        }