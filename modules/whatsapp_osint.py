import re
from typing import Dict, Any, Optional
import phonenumbers
from core.base_module import BaseOSINTModule

class WhatsAppOSINT(BaseOSINTModule):
    name: str = "WhatsApp & Messaging Reconnaissance"
    module_id: str = "whatsapp_osint"
    description: str = "Deteksi profil WhatsApp, status tautan langsung wa.me, dan info akun bisnis global."
    version: str = "2.1.0"
    priority: int = 3
    target_type: str = "phone"

    def _normalize_phone(self, target: str) -> str:
        """Normalisasi nomor target ke format digit internasional E.164 tanpa tanda '+'."""
        target_str = target.strip()
        try:
            if target_str.startswith("0"):
                parsed = phonenumbers.parse(target_str, "ID")
            else:
                parsed = phonenumbers.parse(target_str if target_str.startswith("+") else f"+{target_str}", None)
            return f"{parsed.country_code}{parsed.national_number}"
        except Exception:
            return re.sub(r'[^0-9]', '', target_str)

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cleaned = self._normalize_phone(target)

        wa_me_url = f"https://wa.me/{cleaned}"
        wa_api_url = f"https://api.whatsapp.com/send/?phone={cleaned}&text&type=phone_number&app_absent=0"

        status = "Active / Available Link"
        is_business = False

        if self.async_client:
            try:
                code, html, _ = await self.async_client.get(wa_api_url)
                if code == 200:
                    if any(phrase in html for phrase in ["Chat on WhatsApp", "Send Message", "Buka WhatsApp", "Lanjutkan ke Chat"]):
                        status = "Active WhatsApp Account"
                    if any(phrase in html for phrase in ["Business Account", "Akun Bisnis"]):
                        is_business = True
            except Exception:
                pass

        data = {
            "whatsapp_id": f"{cleaned}@s.whatsapp.net",
            "direct_chat_link": wa_me_url,
            "status": status,
            "is_business_account": is_business,
            "telegram_link": f"https://t.me/+{cleaned}"
        }
        return self.success_response(data, "Pemeriksaan WhatsApp selesai.")
