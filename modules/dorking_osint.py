import re
import urllib.parse
import json
from typing import Dict, Any, List, Optional
import phonenumbers
from bs4 import BeautifulSoup
from core.base_module import BaseOSINTModule

class DorkingOSINT(BaseOSINTModule):
    name: str = "Search Engine Dorking Intelligence"
    module_id: str = "dorking_osint"
    description: str = "Pencarian jejak digital publik terverifikasi via Google/Bing Dorking berbasis ITU-T global dinamis."
    version: str = "2.2.0"
    priority: int = 5
    target_type: str = "phone"

    def _get_target_variations(self, raw_target: str) -> tuple[List[str], int, str]:
        """Menghasilkan variasi format nomor telepon ITU-T global (E.164, Nasional, Internasional)."""
        target_str = raw_target.strip()
        variations = [target_str, re.sub(r'[^0-9]', '', target_str)]
        country_code = 62
        region_code = "ID"

        try:
            if target_str.startswith("0"):
                parsed = phonenumbers.parse(target_str, "ID")
            else:
                parsed = phonenumbers.parse(target_str if target_str.startswith("+") else f"+{target_str}", None)

            country_code = parsed.country_code
            region_code = phonenumbers.region_code_for_number(parsed) or "ID"

            e164_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            intl_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            nat_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            digits_intl = f"{parsed.country_code}{parsed.national_number}"
            digits_nat = str(parsed.national_number)

            variations.extend([
                e164_val,
                intl_val,
                nat_val,
                digits_intl,
                digits_nat,
                intl_val.replace(" ", "-"),
                intl_val.replace("-", " ")
            ])
            if country_code == 62:
                variations.append(f"0{parsed.national_number}")
                variations.append(f"0{parsed.national_number}"[:4] + "-" + f"0{parsed.national_number}"[4:8] + "-" + f"0{parsed.national_number}"[8:])
        except Exception:
            pass

        unique_vars = [v for v in set(variations) if v and len(v) >= 5]
        return unique_vars, country_code, region_code

    def _generate_dork_queries(self, raw_target: str, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        variations, country_code, region_code = self._get_target_variations(raw_target)
        primary_query = " OR ".join([f'"{v}"' for v in variations[:3]])

        dork_list = []

        # 1. Marketplace & Classifieds (Dinamis ID vs Global)
        if country_code == 62:
            dork_list.append({
                "category": "Marketplace & Jual Beli (Indonesia)",
                "dork": f'(site:olx.co.id OR site:tokopedia.com OR site:shopee.co.id OR site:kaskus.co.id) ({primary_query})',
                "description": "Iklan, transaksi jual beli, dan lapak marketplace Indonesia"
            })
            dork_list.append({
                "category": "Reputasi & Cek Penipuan (Indonesia)",
                "dork": f'(site:kredibel.co.id OR site:tellows.co.id OR site:lapor.go.id OR site:cekrekening.id) ({primary_query})',
                "description": "Pengecekan reputasi nomor dan laporan masyarakat Indonesia"
            })
        else:
            dork_list.append({
                "category": f"Marketplace & Public Classifieds ({region_code})",
                "dork": f'(site:ebay.com OR site:craigslist.org OR site:amazon.com) ({primary_query})',
                "description": f"Public listings, commercial ads, and commerce profiles ({region_code})"
            })
            dork_list.append({
                "category": f"Reputation & Spam Reports ({region_code})",
                "dork": f'(site:tellows.com OR site:whocallsme.com OR site:800notes.com OR site:sync.me) ({primary_query})',
                "description": "Global phone lookup, scam alerts, and consumer report forums"
            })

        # 2. Social Media & Profiles (Global)
        dork_list.append({
            "category": "Media Sosial & Profil Publik",
            "dork": f'(site:instagram.com OR site:facebook.com OR site:twitter.com OR site:tiktok.com OR site:linkedin.com) ({primary_query})',
            "description": "Postingan profil, bio, dan kontak di media sosial utama"
        })

        # 3. Public Documents & Leaks
        dork_list.append({
            "category": "Dokumen Publik (.PDF/.Doc/.Xlsx)",
            "dork": f'(filetype:pdf OR filetype:docx OR filetype:xlsx) ({primary_query})',
            "description": "Dokumen resmi, daftar kontak, invoice, atau surat pengumuman publik"
        })

        # 4. Pastebins & Data Dumps
        dork_list.append({
            "category": "Paste sites & Public Text Logs",
            "dork": f'(site:pastebin.com OR site:justpaste.it OR site:rentry.co OR site:ghostbin.com) ({primary_query})',
            "description": "Public text snippets, configuration files, or data dumps"
        })

        return dork_list

    def _is_relevant_match(self, text: str, variations: List[str]) -> bool:
        """Validasi Ketat: Memastikan hasil pencarian benar-benar memuat nomor target."""
        clean_text = re.sub(r'[^0-9]', '', text)
        for v in variations:
            clean_v = re.sub(r'[^0-9]', '', v)
            if len(clean_v) >= 7 and clean_v in clean_text:
                return True
        return False

    async def _search_serper_api(self, query: str, api_key: str, variations: List[str]) -> List[Dict[str, str]]:
        results = []
        if not self.async_client:
            return results
        try:
            session = await self.async_client.get_session()
            headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
            payload = json.dumps({"q": query, "num": 10})
            async with session.post("https://google.serper.dev/search", headers=headers, data=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("organic", []):
                        title = item.get("title", "")
                        snippet = item.get("snippet", "")
                        full_content = f"{title} {snippet} {item.get('link', '')}"

                        if self._is_relevant_match(full_content, variations):
                            results.append({
                                "title": title,
                                "url": item.get("link", ""),
                                "snippet": snippet,
                                "engine": "Google (Official API)"
                            })
        except Exception:
            pass
        return results

    async def _search_bing_public(self, query: str, variations: List[str]) -> List[Dict[str, str]]:
        results = []
        if not self.async_client:
            return results
        try:
            encoded_q = urllib.parse.quote_plus(query)
            url = f"https://www.bing.com/search?q={encoded_q}&setmkt=en-US"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            }
            status, html, _ = await self.async_client.get(url, headers=headers)
            if status == 200 and html:
                soup = BeautifulSoup(html, "html.parser")
                for li in soup.find_all("li", class_="b_algo"):
                    h2 = li.find("h2")
                    a = h2.find("a") if h2 else None
                    snippet_div = li.find("div", class_="b_caption")
                    snippet_p = snippet_div.find("p") if snippet_div else None

                    title = a.get_text().strip() if a else ""
                    link = a.get("href", "") if a else ""
                    snippet = snippet_p.get_text().strip() if snippet_p else ""
                    full_content = f"{title} {snippet} {link}"

                    if link and self._is_relevant_match(full_content, variations):
                        results.append({
                            "title": title,
                            "url": link,
                            "snippet": snippet,
                            "engine": "Bing Search (Public Scraping)"
                        })
        except Exception:
            pass
        return results

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        variations, country_code, region_code = self._get_target_variations(target)
        dork_queries = self._generate_dork_queries(target, context)

        api_key = self.config.get("api_keys.serper", "") if self.config else ""
        findings = []

        for dork_info in dork_queries[:3]:
            q = dork_info["dork"]
            res = []
            if api_key:
                res = await self._search_serper_api(q, api_key, variations)
            if not res:
                res = await self._search_bing_public(q, variations)
            findings.extend(res)

        # Deduplikasi hasil
        seen_urls = set()
        unique_findings = []
        for f in findings:
            if f["url"] not in seen_urls:
                seen_urls.add(f["url"])
                unique_findings.append(f)

        data = {
            "query_target": target,
            "target_country_code": country_code,
            "target_region": region_code,
            "variations": variations,
            "dork_queries_generated": dork_queries,
            "total_dorks": len(dork_queries),
            "findings_count": len(unique_findings),
            "findings": unique_findings
        }
        return self.success_response(data, f"Dorking Intelligence selesai ({len(unique_findings)} hasil terverifikasi).")
