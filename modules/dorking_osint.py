import re
import urllib.parse
import json
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from core.base_module import BaseOSINTModule

class DorkingOSINT(BaseOSINTModule):
    name: str = "Search Engine Dorking Intelligence"
    module_id: str = "dorking_osint"
    description: str = "Pencarian jejak digital publik terverifikasi via Google/Bing Dorking khusus region Indonesia."
    version: str = "2.1.0"
    priority: int = 5

    def _get_target_variations(self, raw_target: str) -> List[str]:
        cleaned = re.sub(r'[^0-9]', '', raw_target)
        variations = [cleaned]
        
        if cleaned.startswith("62"):
            local_num = "0" + cleaned[2:]
            variations.append(local_num)
            if len(local_num) >= 10:
                variations.append(f"{local_num[:4]}-{local_num[4:8]}-{local_num[8:]}")
                variations.append(f"{local_num[:4]} {local_num[4:8]} {local_num[8:]}")
        elif cleaned.startswith("0"):
            intl_num = "62" + cleaned[1:]
            variations.append(intl_num)
            variations.append(f"+{intl_num}")
            
        return list(set(variations))

    def _generate_dork_queries(self, raw_target: str, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        variations = self._get_target_variations(raw_target)
        primary_query = " OR ".join([f'"{v}"' for v in variations[:3]])
        
        return [
            {
                "category": "Marketplace & Jual Beli (ID)",
                "dork": f'(site:olx.co.id OR site:tokopedia.com OR site:shopee.co.id OR site:kaskus.co.id) ({primary_query})',
                "description": "Iklan, transaksi jual beli, dan lapak marketplace Indonesia"
            },
            {
                "category": "Media Sosial & Profil",
                "dork": f'(site:instagram.com OR site:facebook.com OR site:twitter.com OR site:tiktok.com OR site:linkedin.com) ({primary_query})',
                "description": "Postingan profil, bio, dan kontak di media sosial"
            },
            {
                "category": "Reputasi & Cek Penipuan",
                "dork": f'(site:kredibel.co.id OR site:tellows.co.id OR site:lapor.go.id OR site:cekrekening.id) ({primary_query})',
                "description": "Pengecekan reputasi nomor dan laporan masyarakat"
            },
            {
                "category": "Dokumen Publik (.PDF/.Doc)",
                "dork": f'(filetype:pdf OR filetype:docx OR filetype:xlsx) ({primary_query})',
                "description": "Dokumen resmi, daftar kontak, atau surat pengumuman publik"
            },
            {
                "category": "Jejak Web Umum",
                "dork": f'{primary_query} loc:ID',
                "description": "Pencarian jejak umum terfokus pada domain dan server Indonesia"
            }
        ]

    def _is_relevant_match(self, text: str, variations: List[str]) -> bool:
        """
        Validasi Ketat: Memastikan hasil pencarian benar-benar mengandung 
        salah satu format nomor target, bukan hasil fallback acak dari search engine.
        """
        clean_text = re.sub(r'[^0-9]', '', text)
        for v in variations:
            clean_v = re.sub(r'[^0-9]', '', v)
            if len(clean_v) >= 9 and clean_v in clean_text:
                return True
        return False

    async def _search_serper_api(self, query: str, api_key: str, variations: List[str]) -> List[Dict[str, str]]:
        results = []
        if not self.async_client:
            return results
        try:
            session = await self.async_client.get_session()
            headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
            payload = json.dumps({"q": query, "gl": "id", "hl": "id", "num": 10})
            async with session.post("https://google.serper.dev/search", headers=headers, data=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("organic", []):
                        title = item.get("title", "")
                        snippet = item.get("snippet", "")
                        full_content = f"{title} {snippet} {item.get('link', '')}"
                        
                        # Filter ketat nomor target
                        if self._is_relevant_match(full_content, variations):
                            results.append({
                                "title": title,
                                "url": item.get("link", ""),
                                "snippet": snippet,
                                "engine": "Google Indonesia (Official API)"
                            })
        except Exception as e:
            self.logger.warning(f"Serper API Error: {e}")
        return results

    async def _search_free_engine(self, query: str, variations: List[str]) -> List[Dict[str, str]]:
        results = []
        if not self.async_client:
            return results

        # Parameter khusus Region Indonesia (setmkt=id-ID & cc=ID)
        encoded_q = urllib.parse.quote_plus(query)
        search_url = f"https://www.bing.com/search?q={encoded_q}&setmkt=id-ID&setlang=id&cc=ID&count=15"
        custom_headers = {
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": "https://www.bing.com/"
        }
        
        try:
            status, html_text, _ = await self.async_client.get(search_url, headers=custom_headers)
            if status == 200:
                soup = BeautifulSoup(html_text, "html.parser")
                for li in soup.find_all("li", class_="b_algo"):
                    h2 = li.find("h2")
                    a = h2.find("a") if h2 else None
                    p = li.find("p") or li.find("div", class_="b_caption")
                    if a and a.get("href"):
                        link = a.get("href", "")
                        title = a.text.strip()
                        snippet = p.text.strip() if p else ""
                        full_content = f"{title} {snippet} {link}"
                        
                        # VALIDASI KETAT:
                        # Hanya simpan jika nomor target BENAR-BENAR ada di judul, cuplikan, atau URL!
                        if self._is_relevant_match(full_content, variations):
                            results.append({
                                "title": title,
                                "url": link,
                                "snippet": snippet,
                                "engine": "Bing Indonesia (Verified Match)"
                            })
        except Exception as e:
            self.logger.warning(f"Free Dorking Error: {e}")

        return results

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        variations = self._get_target_variations(target)
        dork_queries = self._generate_dork_queries(target, context)
        
        serper_key = self.config.get("api_keys.serper", "") or self.config.get("api_keys.serper_api_key", "")
        active_mode = "API Key (Serper)" if serper_key else "Free Web Scraper (ID Localized)"
        all_findings = []
        
        for q_info in dork_queries:
            query = q_info["dork"]
            category = q_info["category"]
            
            if serper_key:
                findings = await self._search_serper_api(query, serper_key, variations)
                if not findings:
                    findings = await self._search_free_engine(query, variations)
            else:
                findings = await self._search_free_engine(query, variations)

            for f in findings:
                f["category"] = category
                f["dork_used"] = query
                all_findings.append(f)

        # Deduplikasi berdasarkan judul / link
        unique_findings = []
        seen = set()
        for f in all_findings:
            key = f["title"].strip()
            if key and key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return self.success_response({
            "mode": active_mode,
            "target_variations": variations,
            "queries_executed": len(dork_queries),
            "total_results": len(unique_findings),
            "findings": unique_findings,
            "dork_patterns": dork_queries
        }, f"Dorking selesai ({active_mode}). Ditemukan {len(unique_findings)} jejak terverifikasi.")
