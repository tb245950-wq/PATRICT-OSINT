import re
from typing import Dict, Any, Optional
from core.base_module import BaseOSINTModule

class WhatsAppOSINT(BaseOSINTModule):
    name: str = "WhatsApp & Messaging Reconnaissance"
    module_id: str = "whatsapp_osint"
    description: str = "Deteksi profil WhatsApp, status tautan langsung wa.me, dan info perpesanan instan."
    version: str = "2.0.0"
    priority: int = 3

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cleaned = re.sub(r'[^0-9]', '', target)
        if cleaned.startswith("0"):
            cleaned = "62" + cleaned[1:]
        elif not cleaned.startswith("62"):
            cleaned = "62" + cleaned

        wa_me_url = f"https://wa.me/{cleaned}"
        wa_api_url = f"https://api.whatsapp.com/send/?phone={cleaned}&text&type=phone_number&app_absent=0"
        
        status = "Active / Available Link"
        is_business = False
        
        if self.async_client:
            try:
                code, html, _ = await self.async_client.get(wa_api_url)
                if code == 200:
                    if "Chat on WhatsApp" in html or "Send Message" in html or "Buka WhatsApp" in html:
                        status = "Active WhatsApp Account"
                    if "Business Account" in html or "Akun Bisnis" in html:
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
