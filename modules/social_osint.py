import re
import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from core.base_module import BaseOSINTModule

class SocialOSINT(BaseOSINTModule):
    name: str = "Social Media Reconnaissance (Sherlock Engine)"
    module_id: str = "social_osint"
    description: str = "Pencarian jejak akun media sosial publik dan platform perpesanan."
    version: str = "2.0.0"
    priority: int = 4

    def __init__(self, config: Optional[Dict[str, Any]] = None, async_client: Optional[Any] = None):
        super().__init__(config, async_client)
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Dict[str, Any]]:
        sig_path = "data/social_signatures.json"
        if not os.path.exists(sig_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sig_path = os.path.join(base_dir, "data", "social_signatures.json")

        if os.path.exists(sig_path):
            try:
                with open(sig_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("platforms", [])
            except Exception as e:
                self.logger.warning(f"Gagal memuat signatures: {e}")
        return []

    async def _check_platform(self, platform: Dict[str, Any], query: str) -> Optional[Dict[str, Any]]:
        url = platform["url"].format(query)
        check_type = platform.get("check_type", "status_code")
        
        if not self.async_client:
            # Fallback jika async client belum di-inject
            return {
                "platform": platform["name"],
                "url": url,
                "category": platform.get("category", "General"),
                "icon": platform.get("icon", "🌐"),
                "status": "Potential Link"
            }

        try:
            status_code, text, _ = await self.async_client.get(url)
            
            # Validasi berdasarkan status code atau respon teks
            if check_type == "status_code":
                valid_code = platform.get("valid_code", 200)
                if status_code == valid_code:
                    return {
                        "platform": platform["name"],
                        "url": url,
                        "category": platform.get("category", "General"),
                        "icon": platform.get("icon", "🌐"),
                        "status": "Detected"
                    }
            elif check_type == "response_text":
                error_text = platform.get("error_text", "")
                if status_code == 200 and (not error_text or error_text not in text):
                    return {
                        "platform": platform["name"],
                        "url": url,
                        "category": platform.get("category", "General"),
                        "icon": platform.get("icon", "🌐"),
                        "status": "Detected"
                    }
        except Exception as e:
            self.logger.debug(f"Error checking {platform['name']}: {e}")
            
        return None

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cleaned_num = re.sub(r'[^0-9]', '', target)
        
        # Ekstrak calon username jika ada nama/email dari modul lain
        queries = [cleaned_num]
        if context and "email_osint" in context:
            e_data = context["email_osint"].get("data", {}).get("emails", [])
            for em in e_data:
                email_val = em.get("email", "") if isinstance(em, dict) else str(em)
                if "@" in email_val:
                    queries.append(email_val.split("@")[0])

        tasks = []
        for q in set(queries):
            for plat in self.signatures:
                tasks.append(self._check_platform(plat, q))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        detected_accounts = [r for r in results if isinstance(r, dict) and r is not None]
        
        # Deduplikasi berdasarkan URL
        seen_urls = set()
        unique_accounts = []
        for acc in detected_accounts:
            if acc["url"] not in seen_urls:
                seen_urls.add(acc["url"])
                unique_accounts.append(acc)

        return self.success_response({
            "target_queries": list(set(queries)),
            "platforms_checked": len(self.signatures),
            "detected_count": len(unique_accounts),
            "accounts": unique_accounts
        }, f"Berhasil memindai {len(self.signatures)} platform sosial.")
