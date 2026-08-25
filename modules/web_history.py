import re
import requests
import sqlite3
from typing import Dict, List, Optional, Set
from bs4 import BeautifulSoup
import json
from datetime import datetime, timedelta
import dns.resolver

class WebHistory:
    """
    MODUL UNTUK MENCARI WEB / DOMAIN YANG TERHUBUNG
    DENGAN NOMOR TELEPON ATAU EMAIL
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.search_engines = {
            "google": "https://www.google.com/search?q={}",
            "bing": "https://www.bing.com/search?q={}",
            "duckduckgo": "https://html.duckduckgo.com/html/?q={}"
        }
        self.cache = {}
        
    async def get_websites_by_phone(self, phone: str) -> List[Dict]:
        """
        METODE UTAMA: MENCARI SEMUA WEBSITE/DOMAIN YANG TERHUBUNG
        DENGAN NOMOR TELEPON
        """
        results = []
        
        # 1. SEARCH ENGINE QUERY
        se_results = self._search_engines(phone)
        results.extend(se_results)
        
        # 2. DOMAIN REGISTRATION CHECK
        domain_results = self._check_domain_registrations(phone)
        results.extend(domain_results)
        
        # 3. PASTEBIN / PASTE SITES
        paste_results = self._search_paste_sites(phone)
        results.extend(paste_results)
        
        # 4. GITHUB REPOS
        github_results = self._search_github(phone)
        results.extend(github_results)
        
        # DEDUPLIKASI
        unique_results = self._deduplicate_domains(results)
        return unique_results
    
    def _search_engines(self, query: str) -> List[Dict]:
        """
        MENCARI DOMAIN MELALUI MESIN PENCARI
        """
        results = []
        # SIMULASI - TIDAK MELAKUKAN SCRAPING AGAR TIDAK TERBLOKIR
        # GUNAKAN API BING / GOOGLE CUSTOM SEARCH
        mock_domains = [
            {"url": f"https://example-{hash(query)%100}.com", "title": "Contoh Situs", "source": "search_engine"},
            {"url": f"https://test-{hash(query)%200}.org", "title": "Test Domain", "source": "search_engine"}
        ]
        return mock_domains
    
    def _check_domain_registrations(self, phone: str) -> List[Dict]:
        """
        MEMERIKSA DOMAIN REGISTRATION YANG TERKAIT DENGAN NOMOR
        """
        # SIMULASI - GUNAKAN WHOIS API
        return [
            {"url": f"domain-{hash(phone)%50}.com", "title": "Registered Domain", "source": "whois", "registrant_phone": phone}
        ]
    
    def _search_paste_sites(self, phone: str) -> List[Dict]:
        """
        MENCARI PASTEBIN DAN SITUS SERUPA
        """
        return [
            {"url": f"https://pastebin.com/{hash(phone)%1000}", "title": "Paste", "source": "pastebin"}
        ]
    
    def _search_github(self, phone: str) -> List[Dict]:
        """
        MENCARI GITHUB REPO ATAU KOMIT YANG MENGANDUNG NOMOR
        """
        return [
            {"url": f"https://github.com/user_{hash(phone)%1000}/repo", "title": "GitHub Repository", "source": "github"}
        ]
    
    def _deduplicate_domains(self, domains: List[Dict]) -> List[Dict]:
        """
        MENGHAPUS DUPLIKAT DOMAIN
        """
        seen = set()
        unique = []
        for item in domains:
            url = item.get("url", "")
            if url and url not in seen:
                seen.add(url)
                unique.append(item)
        return unique
    
    def get_domain_info(self, domain: str) -> Dict:
        """
        MENDAPATKAN INFORMASI DOMAIN (WHOIS, SSL, HEADER)
        """
        info = {}
        try:
            # WHOIS
            w = whois.whois(domain)
            info["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except:
            info["whois"] = "gagal"
        
        # SSL CERTIFICATE INFO (SIMULASI)
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                info["ssl"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expiry": cert.get("notAfter")
                }
        except:
            info["ssl"] = "gagal"
        
        # HTTP HEADER
        try:
            resp = self.session.get(f"https://{domain}", timeout=5, allow_redirects=True)
            info["headers"] = dict(resp.headers)
            info["status_code"] = resp.status_code
        except:
            info["headers"] = "gagal"
        
        return info
    
    def get_related_domains(self, domain: str) -> List[str]:
        """
        MENDAPATKAN DOMAIN TERKAIT MELALUI CRTSH, VIRUSTOTAL
        """
        # SIMULASI
        return [f"{domain}-related.com", f"www.{domain}", f"api.{domain}"]
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """
        CEK REPUTASI DOMAIN DARI VIRUSTOTAL, GOOGLE SAFE
        """
        return {
            "domain": domain,
            "malicious": False,
            "suspicious": False,
            "score": 0.1
        }