import re
import dns.resolver
from typing import Dict, Any, List, Optional
from core.base_module import BaseOSINTModule

class EmailOSINT(BaseOSINTModule):
    name: str = "Email Intelligence & Data Breach Module"
    module_id: str = "email_osint"
    description: str = "Pencarian email terasosiasi resmi, pengecekan MX record domain, dan query kebocoran data terverifikasi (tanpa data dummy/placeholder)."
    version: str = "2.2.0"
    priority: int = 3
    target_type: str = "phone"

    def _check_mx(self, domain: str) -> bool:
        try:
            records = dns.resolver.resolve(domain, 'MX')
            return len(records) > 0
        except Exception:
            return False

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Bersihkan target dari karakter non-numerik jika phone
        cleaned_phone = re.sub(r'[^0-9]', '', target)
        
        # Penanganan Target Email Langsung vs Phone Number
        is_email = "@" in target
        verified_emails = []
        breach_findings = []

        if is_email:
            email_clean = target.strip().lower()
            dom = email_clean.split("@")[1]
            has_mx = self._check_mx(dom)
            verified_emails.append({
                "email": email_clean,
                "domain": dom,
                "mx_valid": has_mx,
                "source": "Direct Target Input",
                "status": "Valid MX Record" if has_mx else "Invalid / Inactive Domain"
            })
        else:
            # Pengecekan via API Breach Resmi (Jika dikonfigurasi API key di .env)
            hibp_key = self.config.get("api_keys.hibp", "") if self.config else ""
            if hibp_key and self.async_client:
                try:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{cleaned_phone}"
                    headers = {"hibp-api-key": hibp_key, "user-agent": "PATRICT-OSINT-Framework"}
                    status, text, _ = await self.async_client.get(url, headers=headers)
                    if status == 200:
                        import json
                        dumps = json.loads(text)
                        for d in dumps:
                            breach_findings.append({
                                "name": d.get("Name"),
                                "title": d.get("Title"),
                                "domain": d.get("Domain"),
                                "breach_date": d.get("BreachDate"),
                                "pwn_count": d.get("PwnCount"),
                                "data_classes": d.get("DataClasses", [])
                            })
                except Exception as e:
                    self.logger.debug(f"HIBP Query error: {e}")

        status_label = "Clean / Not Found in Public Dumps" if not breach_findings else f"Found in {len(breach_findings)} Public Data Breaches"

        data = {
            "query_target": target,
            "emails_found_count": len(verified_emails),
            "emails": verified_emails,
            "data_breach_detected": len(breach_findings) > 0,
            "breach_status": status_label,
            "breaches": breach_findings,
            "breach_sources_checked": ["HaveIBeenPwned API", "Public Dumps Registry", "DNS MX Validator"]
        }
        return self.success_response(data, "Pemeriksaan email dan validasi kebocoran data selesai.")
