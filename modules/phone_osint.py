import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from core.base_module import BaseOSINTModule

# ============================================================
# DATABASE OFFLINE HLR & CARRIER TELEKOMUNIKASI INDONESIA
# ============================================================
INDONESIA_HLR_DATABASE = {
    # ------------------ TELKOMSEL (MCC: 510, MNC: 10) ------------------
    "0811": {"carrier": "Telkomsel", "brand": "Kartu Halo (Postpaid/Corporate)", "mcc": "510", "mnc": "10", "region": "Nasional / Korporat", "network": "GSM / 4G / 5G"},
    "0812": {"carrier": "Telkomsel", "brand": "simPATI / Kartu Halo", "mcc": "510", "mnc": "10", "region": "Jabodetabek / Jawa / Nasional", "network": "GSM / 4G / 5G"},
    "0813": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa & Sumatera / Nasional", "network": "GSM / 4G / 5G"},
    "0821": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jabodetabek / Jawa Barat / Banten", "network": "GSM / 4G / 5G"},
    "0822": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Regional Barat & Nasional", "network": "GSM / 4G / 5G"},
    "0823": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Barat / Jawa Tengah / Luar Jawa", "network": "GSM / 4G / 5G"},
    "0852": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera / Kalimantan / Jawa", "network": "GSM / 4G / 5G"},
    "0853": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Timur / Bali / Nusa Tenggara", "network": "GSM / 4G / 5G"},
    "0851": {"carrier": "Telkomsel", "brand": "by.U (Digital Telkomsel) / Flexi", "mcc": "510", "mnc": "10", "region": "Nasional (Digital Telco)", "network": "GSM / 4G / 5G"},

    # ------------ INDOSAT OOREDOO HUTCHISON (MCC: 510, MNC: 01 / 89) ------------
    "0814": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Indosat M2 / Broadband 3G-4G", "mcc": "510", "mnc": "01", "region": "Nasional (Data Network)", "network": "Broadband / GSM"},
    "0815": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek / Jawa", "network": "GSM / 4G / 5G"},
    "0816": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix Postpaid / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek / Nasional", "network": "GSM / 4G / 5G"},
    "0855": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix Auto / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek / Pasca Bayar", "network": "GSM / 4G / 5G"},
    "0856": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek / Jawa Barat / Nasional", "network": "GSM / 4G / 5G"},
    "0857": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Barat / Jawa Tengah / Nasional", "network": "GSM / 4G / 5G"},
    "0858": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Mentari Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Timur / Jawa Tengah", "network": "GSM / 4G / 5G"},
    "0895": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jabodetabek / Jawa / Nasional", "network": "GSM / 4G / 5G"},
    "0896": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Barat / Jawa Tengah", "network": "GSM / 4G / 5G"},
    "0897": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Sumatera / Jawa Barat", "network": "GSM / 4G / 5G"},
    "0898": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Timur / Bali / Lombok", "network": "GSM / 4G / 5G"},
    "0899": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jabodetabek / Luar Jawa", "network": "GSM / 4G / 5G"},

    # ------------------- XL AXIATA (MCC: 510, MNC: 11 / 08) -------------------
    "0817": {"carrier": "XL Axiata", "brand": "XL Prioritas / Postpaid", "mcc": "510", "mnc": "11", "region": "Jabodetabek / Jawa", "network": "GSM / 4G / 5G"},
    "0818": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek / Jawa Barat", "network": "GSM / 4G / 5G"},
    "0819": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jawa / Bali / Nusa Tenggara", "network": "GSM / 4G / 5G"},
    "0859": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Sumatera / Jawa Timur", "network": "GSM / 4G / 5G"},
    "0877": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek / Jawa Tengah", "network": "GSM / 4G / 5G"},
    "0878": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek / Jawa Timur", "network": "GSM / 4G / 5G"},
    "0831": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Sumatera / Jawa Barat", "network": "GSM / 4G / 5G"},
    "0832": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jawa Tengah & DI Yogyakarta", "network": "GSM / 4G / 5G"},
    "0833": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jawa Timur & Bali", "network": "GSM / 4G / 5G"},
    "0838": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jabodetabek & Banten", "network": "GSM / 4G / 5G"},

    # ------------------- SMARTFREN (MCC: 510, MNC: 09 / 28) -------------------
    "0881": {"carrier": "Smartfren", "brand": "Smartfren 4G / VoLTE", "mcc": "510", "mnc": "09", "region": "Jabodetabek / Jawa", "network": "CDMA/LTE/5G"},
    "0882": {"carrier": "Smartfren", "brand": "Smartfren 4G / VoLTE", "mcc": "510", "mnc": "09", "region": "Jawa Barat & Banten", "network": "4G LTE / 5G"},
    "0883": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Sumatera / Riau", "network": "4G LTE / 5G"},
    "0884": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Kalimantan / Sulawesi", "network": "4G LTE / 5G"},
    "0885": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Bali & Nusa Tenggara", "network": "4G LTE / 5G"},
    "0886": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Jawa Tengah & DIY", "network": "4G LTE / 5G"},
    "0887": {"carrier": "Smartfren", "brand": "Smartfren 4G / eSIM", "mcc": "510", "mnc": "09", "region": "Jawa Tengah & DIY", "network": "4G LTE / 5G"},
    "0888": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Jawa Timur & Madura", "network": "4G LTE / 5G"},
    "0889": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Nasional (Data Roaming)", "network": "4G LTE / 5G"},

    # ------------------- SAMPOERNA TELECOM / NET1 (MNC: 07) -------------------
    "0828": {"carrier": "Sampoerna Telecom (Net1)", "brand": "Net1 Indonesia 450MHz", "mcc": "510", "mnc": "07", "region": "Rural / 4G 450MHz", "network": "LTE 450"}
}

class PhoneOSINT(BaseOSINTModule):
    name: str = "Phone Intelligence Module"
    module_id: str = "phone_osint"
    description: str = "Validasi ITU-T E.164, offline HLR & Carrier Intelligence, deep messaging verification links, dan Google Dork generator."
    version: str = "2.4.0"
    priority: int = 1
    target_type: str = "phone"

    def _lookup_indonesia_hlr(self, national_number: str) -> Dict[str, Any]:
        """
        Database HLR Offline Indonesia:
        Mencocokkan prefix nomor telepon (4 digit awal) dengan operator resmi, brand, MCC, MNC, dan region.
        """
        prefix_clean = national_number.strip()
        if not prefix_clean.startswith("0"):
            prefix_clean = "0" + prefix_clean

        # Cek 4 digit prefix (contoh: 0822, 0812, 0857, dll)
        prefix_4 = prefix_clean[:4]
        if prefix_4 in INDONESIA_HLR_DATABASE:
            info = INDONESIA_HLR_DATABASE[prefix_4]
            return {
                "matched": True,
                "prefix": prefix_4,
                "carrier": info["carrier"],
                "card_brand": info["brand"],
                "mcc": info["mcc"],
                "mnc": info["mnc"],
                "hlr_region": info["region"],
                "network_type": info["network"]
            }

        return {
            "matched": False,
            "prefix": prefix_4 if len(prefix_clean) >= 4 else prefix_clean,
            "carrier": "Operator Seluler Indonesia",
            "card_brand": "Unknown Prepaid/Postpaid",
            "mcc": "510",
            "mnc": "Unknown",
            "hlr_region": "Indonesia (Nasional)",
            "network_type": "Cellular"
        }

    def _generate_permutations(self, parsed_obj: phonenumbers.PhoneNumber) -> Dict[str, str]:
        """Menghasilkan variasi format nomor standar telekomunikasi dan dorking"""
        e164 = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.NATIONAL)
        rfc3966 = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.RFC3966)
        
        raw_digits = re.sub(r'[^0-9]', '', e164)
        nat_digits = re.sub(r'[^0-9]', '', nat)

        # Spaced & Hyphenated format
        nat_spaced = " ".join([nat_digits[:4], nat_digits[4:8], nat_digits[8:]]).strip()
        nat_hyphen = "-".join([nat_digits[:4], nat_digits[4:8], nat_digits[8:]]).strip("-")

        return {
            "e164": e164,
            "international": intl,
            "national": nat,
            "rfc3966": rfc3966,
            "raw_e164_digits": raw_digits,
            "raw_national_digits": nat_digits,
            "national_spaced": nat_spaced,
            "national_hyphenated": nat_hyphen
        }

    def _generate_osint_dorks(self, perms: Dict[str, str]) -> List[Dict[str, str]]:
        """Menghasilkan daftar link Google Dorking siap klik untuk penelusuran jejak digital publik"""
        # Query dasar menggunakan variasi format paling umum
        query_variants = [
            f'"{perms["national"]}"',
            f'"{perms["national_hyphenated"]}"',
            f'"{perms["e164"]}"',
            f'"{perms["raw_national_digits"]}"'
        ]
        base_or_query = " OR ".join(list(set(query_variants)))

        dork_templates = [
            {
                "category": "Dokumen Publik & Arsip (.PDF / .XLSX / .DOCX)",
                "description": "Mencari daftar kontak, absensi, SK pengangkatan, atau dokumen resmi",
                "dork": f'(filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv) ({base_or_query})'
            },
            {
                "category": "Marketplace & Jual Beli Online",
                "description": "Mencari jejak lapak di Tokopedia, Shopee, OLX, Bukalapak, Kaskus",
                "dork": f'(site:tokopedia.com OR site:shopee.co.id OR site:olx.co.id OR site:bukalapak.com OR site:kaskus.co.id) ({base_or_query})'
            },
            {
                "category": "Media Sosial & Direktori Profil",
                "description": "Mencari bio, postingan kontak di Instagram, Facebook, LinkedIn, Twitter/X, TikTok",
                "dork": f'(site:instagram.com OR site:facebook.com OR site:linkedin.com OR site:twitter.com OR site:tiktok.com) ({base_or_query})'
            },
            {
                "category": "Paste Sites & Teks Bocor",
                "description": "Mencari kebocoran teks publik di Pastebin, Ghostbin, JustPaste, Rentry",
                "dork": f'(site:pastebin.com OR site:ghostbin.com OR site:justpaste.it OR site:rentry.co) ({base_or_query})'
            },
            {
                "category": "Reputasi Nomor & Laporan Penipuan",
                "description": "Cek rekam jejak spam dan penipuan di Kredibel, Tellows, CekRekening, Lapor.go.id",
                "dork": f'(site:kredibel.co.id OR site:tellows.id OR site:cekrekening.id OR site:lapor.go.id) ("{perms["national"]}" OR "{perms["raw_national_digits"]}")'
            }
        ]

        # Tambahkan clickable URL untuk setiap dork
        dork_list = []
        for d in dork_templates:
            encoded_q = urllib.parse.quote(d["dork"])
            google_url = f"https://www.google.com/search?q={encoded_q}"
            duckduckgo_url = f"https://duckduckgo.com/?q={encoded_q}"
            dork_list.append({
                "category": d["category"],
                "description": d["description"],
                "dork_query": d["dork"],
                "google_search_url": google_url,
                "duckduckgo_search_url": duckduckgo_url
            })

        return dork_list

    def _generate_endpoint_links(self, perms: Dict[str, str], country_code: int) -> Dict[str, str]:
        """Menghasilkan direct deep links ke platform perpesanan dan direktori verifikasi"""
        clean_e164 = perms["raw_e164_digits"]
        clean_nat = perms["raw_national_digits"]

        return {
            "whatsapp_direct": f"https://wa.me/{clean_e164}",
            "whatsapp_api": f"https://api.whatsapp.com/send/?phone={clean_e164}&text&type=phone_number&app_absent=0",
            "telegram_direct": f"https://t.me/+{clean_e164}",
            "truecaller_search": f"https://www.truecaller.com/search/{'id' if country_code == 62 else 'global'}/{clean_nat}",
            "syncme_search": f"https://sync.me/search/?number=+{clean_e164}"
        }

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            # 1. Parsing Standar ITU-T E.164
            # Default region 'ID' jika user memasukkan nomor lokal (08xx)
            default_reg = "ID" if (target.strip().startswith("0") or target.strip().startswith("8")) else None
            parsed = phonenumbers.parse(target, default_reg)
            
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)

            if not is_possible:
                return self.error_response(f"Format nomor '{target}' tidak mungkin valid menurut standar telekomunikasi dunia.")

            # 2. Ekstraksi Permutasi Format
            permutations = self._generate_permutations(parsed)
            
            # 3. Klasifikasi Tipe Saluran (Line Type)
            num_type_code = phonenumbers.number_type(parsed)
            num_types_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile / Seluler (GSM/LTE/5G)",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line / PSTN (Telepon Rumah/Kantor)",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line atau Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free (Bebas Pulsa)",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate (Layanan Berbayar Khusus)",
                phonenumbers.PhoneNumberType.VOIP: "VoIP (Voice over IP / Virtual Number)",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "UAN (Universal Access Number)"
            }
            line_type = num_types_map.get(num_type_code, "Unknown / Specialized Number")

            # 4. Ekstraksi Geo & Carrier Bawaan ITU-T
            itu_carrier = carrier.name_for_number(parsed, "id") or carrier.name_for_number(parsed, "en") or "Unknown"
            country_name = geocoder.country_name_for_number(parsed, "id") or geocoder.country_name_for_number(parsed, "en") or "Indonesia"
            location_desc = geocoder.description_for_number(parsed, "id") or geocoder.description_for_number(parsed, "en") or ""
            tz_list = list(timezone.time_zones_for_number(parsed))

            # 5. Database Offline HLR Khusus Indonesia
            hlr_intelligence = {}
            if parsed.country_code == 62:
                hlr_intelligence = self._lookup_indonesia_hlr(str(parsed.national_number))
                carrier_display = hlr_intelligence.get("carrier", itu_carrier)
                card_brand = hlr_intelligence.get("card_brand", "Unknown Prepaid/Postpaid")
            else:
                carrier_display = itu_carrier
                card_brand = "International Mobile Carrier"
                hlr_intelligence = {
                    "matched": False,
                    "carrier": itu_carrier,
                    "card_brand": card_brand,
                    "mcc": str(parsed.country_code),
                    "mnc": "N/A",
                    "hlr_region": location_desc or country_name,
                    "network_type": line_type
                }

            # 6. Messaging & Endpoint Verification Links
            endpoint_links = self._generate_endpoint_links(permutations, parsed.country_code)

            # 7. Automated OSINT Google Dorking List
            osint_dorks = self._generate_osint_dorks(permutations)

            data = {
                "validation": {
                    "is_valid_e164": is_valid,
                    "is_possible_number": is_possible,
                    "status_label": "VALID [ITU-T E.164]" if is_valid else "POSSIBLE / UNCONFIRMED"
                },
                "formatting": permutations,
                "telecom_meta": {
                    "country_code": parsed.country_code,
                    "national_number": str(parsed.national_number),
                    "line_type": line_type,
                    "country": country_name,
                    "location_description": location_desc or hlr_intelligence.get("hlr_region", "Indonesia"),
                    "timezones": tz_list
                },
                "hlr_carrier_intelligence": {
                    "carrier_name": carrier_display,
                    "card_brand": card_brand,
                    "mcc": hlr_intelligence.get("mcc", "N/A"),
                    "mnc": hlr_intelligence.get("mnc", "N/A"),
                    "hlr_region": hlr_intelligence.get("hlr_region", location_desc or "Nasional"),
                    "network_technology": hlr_intelligence.get("network_type", "GSM/LTE/5G"),
                    "source": "Offline HLR Prefix Database & ITU-T Registry"
                },
                "endpoint_links": endpoint_links,
                "osint_dorks": osint_dorks,
                # Backward compatibility keys for main.py / report generators
                "e164": permutations["e164"],
                "international": permutations["international"],
                "national": permutations["national"],
                "carrier": carrier_display,
                "country": country_name,
                "type": line_type,
                "valid": is_valid
            }

            return self.success_response(data, f"Analisis Intelijen Nomor {permutations['e164']} Berhasil.")
        except Exception as e:
            return self.error_response(f"Gagal memproses nomor telepon '{target}': {e}")
