import re
import json
from typing import Dict, Any, Optional
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from core.base_module import BaseOSINTModule

class PhoneOSINT(BaseOSINTModule):
    name: str = "Phone Intelligence Module"
    module_id: str = "phone_osint"
    description: str = "Validasi nomor telepon internasional, alokasi prefix operator ITU-T, dan deteksi jaringan aktif."
    version: str = "2.1.0"
    priority: int = 1

    async def _check_live_carrier_api(self, phone: str) -> Optional[Dict[str, Any]]:
        """Mengecek operator aktif secara real-time via API eksternal jika dikonfigurasi"""
        if not self.async_client:
            return None

        # 1. Cek via AbstractAPI jika ada key di .env
        abstract_key = self.config.get("api_keys.abstractapi", "")
        if abstract_key:
            try:
                url = f"https://phonevalidation.abstractapi.com/v1/?api_key={abstract_key}&phone={phone}"
                status, text, _ = await self.async_client.get(url)
                if status == 200:
                    data = json.loads(text)
                    c_name = data.get("carrier")
                    if c_name:
                        return {"live_carrier": c_name, "source": "AbstractAPI Live HLR"}
            except Exception as e:
                self.logger.warning(f"AbstractAPI Error: {e}")

        # 2. Cek via Numverify jika ada key di .env
        numverify_key = self.config.get("api_keys.numverify", "")
        if numverify_key:
            try:
                url = f"http://apilayer.net/api/validate?access_key={numverify_key}&number={phone}"
                status, text, _ = await self.async_client.get(url)
                if status == 200:
                    data = json.loads(text)
                    c_name = data.get("carrier")
                    if c_name:
                        return {"live_carrier": c_name, "source": "Numverify Live HLR"}
            except Exception as e:
                self.logger.warning(f"Numverify Error: {e}")

        return None

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            parsed = phonenumbers.parse(target, None)
            is_valid = phonenumbers.is_valid_number(parsed)
            
            if not is_valid:
                return self.error_response("Nomor telepon tidak valid menurut standar ITU-T E.164")

            formatted_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            formatted_intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            formatted_nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            
            # Alokasi Prefix Resmi ITU-T / Google Database
            prefix_carrier = carrier.name_for_number(parsed, "id") or carrier.name_for_number(parsed, "en") or "tidak_diketahui"
            country_name = geocoder.country_name_for_number(parsed, "en")
            location_desc = geocoder.description_for_number(parsed, "en")
            tz_list = list(timezone.time_zones_for_number(parsed))
            
            # Jenis Saluran Telepon
            num_type_code = phonenumbers.number_type(parsed)
            num_types_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile / Seluler",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line / Kabel Rumah",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line atau Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free / Bebas Pulsa",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.VOIP: "VoIP (Voice over IP)",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "UAN (Universal Access Number)"
            }
            line_type = num_types_map.get(num_type_code, "Unknown")

            # Cek Live Carrier (Real-time network)
            live_info = await self._check_live_carrier_api(formatted_e164)
            active_carrier = live_info["live_carrier"] if live_info else prefix_carrier
            carrier_source = live_info["source"] if live_info else "ITU-T Official Prefix Database (Static)"

            data = {
                "valid": is_valid,
                "e164": formatted_e164,
                "international": formatted_intl,
                "national": formatted_nat,
                "country_code": parsed.country_code,
                "national_number": str(parsed.national_number),
                "carrier": active_carrier,
                "original_prefix_carrier": prefix_carrier,
                "carrier_source": carrier_source,
                "country": country_name or "tidak_diketahui",
                "region_description": location_desc or "tidak_diketahui",
                "timezones": tz_list,
                "type": line_type,
                "note": "Operator awal ditentukan berdasarkan alokasi prefix resmi Kominfo/ITU-T (0822 = blok Telkomsel). Operator aktif real-time bisa berbeda jika nomor menggunakan kartu khusus/roaming."
            }
            return self.success_response(data, "Validasi dan ekstraksi info nomor berhasil.")
        except Exception as e:
            return self.error_response(f"Terjadi kesalahan saat memproses nomor: {e}")
