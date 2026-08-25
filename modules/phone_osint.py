import re
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from typing import Dict, Optional, List
import hashlib
import hmac
import base64
import json
from datetime import datetime

class PhoneOSINT:
    """
    MODUL KHUSUS UNTUK OSINT BERBASIS NOMOR TELEPON
    MENGGUNAKAN API PUBLIK DAN PARSING DATA TERBUKA
    """
    
    def __init__(self):
        self.api_keys = {
            "numverify": "dummy_key_here",
            "abstractapi": "dummy_key_here",
            "veriphone": "dummy_key_here"
        }
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.cache = {}
        
    def validate_phone(self, phone: str) -> Optional[str]:
        """
        VALIDASI DAN FORMAT NOMOR TELEPON KE FORMAT INTERNASIONAL
        """
        try:
            parsed = phonenumbers.parse(phone, None)
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            return None
        except:
            return None
    
    def get_carrier_info(self, phone: str) -> Dict:
        """
        MENDAPATKAN INFORMASI OPERATOR DAN JENIS NOMOR
        """
        try:
            parsed = phonenumbers.parse(phone, None)
            carrier_name = carrier.name_for_number(parsed, "en")
            country_code = geocoder.country_name_for_number(parsed, "en")
            time_zones = timezone.time_zones_for_number(parsed)
            number_type = self._get_number_type(parsed)
            
            return {
                "carrier": carrier_name or "tidak_diketahui",
                "country": country_code or "tidak_diketahui",
                "timezones": list(time_zones),
                "type": number_type,
                "valid": phonenumbers.is_valid_number(parsed)
            }
        except Exception as e:
            return {"error": str(e), "valid": False}
    
    def _get_number_type(self, parsed) -> str:
        if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE:
            return "mobile"
        elif phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.FIXED_LINE:
            return "fixed_line"
        elif phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.VOIP:
            return "voip"
        else:
            return "unknown"
    
    def query_numverify(self, phone: str) -> Dict:
        """
        QUERY API NUMVERIFY UNTUK DATA LOKASI DAN VALIDASI
        """
        url = "http://apilayer.net/api/validate"
        params = {
            "access_key": self.api_keys["numverify"],
            "number": phone,
            "format": 1
        }
        try:
            resp = self.session.get(url, params=params, timeout=10)
            return resp.json()
        except:
            return {"success": False, "error": "api_failed"}
    
    def query_abstractapi(self, phone: str) -> Dict:
        """
        QUERY ABSTRACTAPI UNTUK DATA LENGKAP LOKASI
        """
        url = f"https://phonevalidation.abstractapi.com/v1/"
        params = {
            "api_key": self.api_keys["abstractapi"],
            "phone": phone
        }
        try:
            resp = self.session.get(url, params=params, timeout=10)
            return resp.json()
        except:
            return {"success": False}
    
    def get_phone_geolocation(self, phone: str) -> Dict:
        """
        MENDAPATKAN KOORDINAT (LAT/LON) DARI NOMOR
        MENGGUNAKAN DATA CARRIER DAN LOKASI PERKIRAAN
        """
        carrier_info = self.get_carrier_info(phone)
        # SIMULASI DATA KOORDINAT DARI CARRIER + PARSING
        # DALAM IMPLEMENTASI NYATA, GUNAKAN API GEOLOKASI KHUSUS
        mock_coords = {
            "lat": -6.2088 + (hash(phone) % 1000) / 10000,
            "lon": 106.8456 + (hash(phone) % 1000) / 10000,
            "accuracy": "perkiraan_berdasarkan_carrier"
        }
        return {
            "phone": phone,
            "carrier": carrier_info.get("carrier"),
            "country": carrier_info.get("country"),
            "coordinates": mock_coords,
            "raw_carrier": carrier_info
        }
    
    def search_phone_in_leaks(self, phone: str) -> List[Dict]:
        """
        MENCARI NOMOR DALAM DATABASE KEBOCORAN DATA PUBLIK
        (SIMULASI - GUNAKAN API SEPERTI HAVEIBEENPWND)
        """
        # SIMULASI HASIL
        return [
            {"source": "leak_db_2020", "date": "2020-06-01", "fields": ["phone", "email"]},
            {"source": "leak_db_2021", "date": "2021-12-15", "fields": ["phone", "name", "address"]}
        ]
    
    def extract_metadata(self, phone: str) -> Dict:
        """
        EKSTRAK METADATA LENGKAP DARI NOMOR
        """
        validated = self.validate_phone(phone)
        if not validated:
            return {"error": "nomor_tidak_valid"}
        
        carrier_info = self.get_carrier_info(validated)
        numverify = self.query_numverify(validated)
        abstract = self.query_abstractapi(validated)
        geo = self.get_phone_geolocation(validated)
        leaks = self.search_phone_in_leaks(validated)
        
        return {
            "phone": validated,
            "carrier_info": carrier_info,
            "numverify_data": numverify,
            "abstract_data": abstract,
            "geolocation": geo,
            "leak_sources": leaks,
            "timestamp": datetime.utcnow().isoformat()
        }