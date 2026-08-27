import os
import re
import folium
from typing import Dict, Any, Optional, Tuple
from geopy.geocoders import Nominatim
from core.base_module import BaseOSINTModule

class LocationOSINT(BaseOSINTModule):
    name: str = "Geospatial & HLR Area Intelligence"
    module_id: str = "location_osint"
    description: str = "Analisis Home Location Register (HLR) telekomunikasi Indonesia, penentuan kota/provinsi registrasi, dan peta interaktif Folium."
    version: str = "2.2.0"
    priority: int = 2

    # Database HLR Wilayah Indonesia
    HLR_DATABASE = {
        # Telkomsel Prefixes
        "082260": {"city": "Jabodetabek / Jawa Barat", "province": "DKI Jakarta & Jawa Barat", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel SimPATI/Loop"},
        "0822": {"city": "Wilayah Regional Barat (Jabodetabek / Jabar)", "province": "Jawa Barat / DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel SimPATI"},
        "0821": {"city": "Jabodetabek / Banten", "province": "DKI Jakarta", "lat": -6.1754, "lon": 106.8272, "brand": "Telkomsel SimPATI"},
        "0823": {"city": "Jawa Barat / Jawa Tengah", "province": "Jawa Barat", "lat": -6.9175, "lon": 107.6191, "brand": "Telkomsel As"},
        "0811": {"city": "Nasional / Korporat", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel Halo"},
        "0812": {"city": "Jabodetabek / Jawa", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel SimPATI / Halo"},
        "0813": {"city": "Jawa & Sumatera", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel SimPATI"},
        "0852": {"city": "Sumatera & Jawa Barat", "province": "Sumatera Utara / Jabar", "lat": 3.5952, "lon": 98.6722, "brand": "Telkomsel As"},
        "0853": {"city": "Jawa Timur & Bali", "province": "Jawa Timur", "lat": -7.2575, "lon": 112.7521, "brand": "Telkomsel As"},
        "0851": {"city": "By.U Digital Telkomsel", "province": "Nasional (Digital)", "lat": -6.2088, "lon": 106.8456, "brand": "Telkomsel by.U"},

        # Indosat Ooredoo
        "0857": {"city": "Jawa Barat & Jawa Tengah", "province": "Jawa Barat", "lat": -6.9175, "lon": 107.6191, "brand": "Indosat IM3"},
        "0856": {"city": "Jabodetabek / Jabar", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Indosat IM3"},
        "0858": {"city": "Jawa Timur / Jateng", "province": "Jawa Timur", "lat": -7.2575, "lon": 112.7521, "brand": "Indosat Mentari"},
        "0814": {"city": "Data / Broadband", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Indosat Broadband"},
        "0815": {"city": "Jabodetabek / Jawa", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Indosat Matrix/Mentari"},
        "0816": {"city": "Jabodetabek", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Indosat Matrix"},

        # XL & AXIS
        "0831": {"city": "Sumatera & Jawa Barat", "province": "Jawa Barat / Sumatera", "lat": -6.9175, "lon": 107.6191, "brand": "AXIS"},
        "0832": {"city": "Jawa Tengah & DI Yogyakarta", "province": "DI Yogyakarta", "lat": -7.7956, "lon": 110.3695, "brand": "AXIS"},
        "0838": {"city": "Jabodetabek & Banten", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "AXIS"},
        "0817": {"city": "Jabodetabek", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "XL Axiata"},
        "0818": {"city": "Jabodetabek & Jabar", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "XL Axiata"},
        "0819": {"city": "Jawa & Bali", "province": "Jawa Barat / Bali", "lat": -6.9175, "lon": 107.6191, "brand": "XL Axiata"},
        "0877": {"city": "Jabodetabek & Jateng", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "XL Axiata"},
        "0878": {"city": "Jabodetabek & Jatim", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "XL Axiata"},

        # Tri (3)
        "0895": {"city": "Jabodetabek & Jawa", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Tri (3) Indonesia"},
        "0896": {"city": "Jawa Barat & Jateng", "province": "Jawa Barat", "lat": -6.9175, "lon": 107.6191, "brand": "Tri (3) Indonesia"},
        "0897": {"city": "Sumatera & Jawa", "province": "Sumatera Utara", "lat": 3.5952, "lon": 98.6722, "brand": "Tri (3) Indonesia"},
        "0898": {"city": "Jawa Timur & Bali", "province": "Jawa Timur", "lat": -7.2575, "lon": 112.7521, "brand": "Tri (3) Indonesia"},
        "0899": {"city": "Jabodetabek", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Tri (3) Indonesia"},

        # Smartfren
        "0881": {"city": "Jabodetabek", "province": "DKI Jakarta", "lat": -6.2088, "lon": 106.8456, "brand": "Smartfren"},
        "0882": {"city": "Jawa Barat & Banten", "province": "Jawa Barat", "lat": -6.9175, "lon": 107.6191, "brand": "Smartfren"},
        "0887": {"city": "Jawa Tengah & DIY", "province": "Jawa Tengah", "lat": -6.9667, "lon": 110.4167, "brand": "Smartfren"},
        "0888": {"city": "Jawa Timur", "province": "Jawa Timur", "lat": -7.2575, "lon": 112.7521, "brand": "Smartfren"}
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None, async_client: Optional[Any] = None):
        super().__init__(config, async_client)
        self.geolocator = Nominatim(user_agent="patrict_osint_framework")
        self.output_dir = self.config.get("app.output_dir", "./output") if self.config else "./output"
        os.makedirs(self.output_dir, exist_ok=True)

    def _lookup_hlr(self, phone: str) -> Dict[str, Any]:
        cleaned = re.sub(r'[^0-9]', '', phone)
        if cleaned.startswith("62"):
            local_num = "0" + cleaned[2:]
        else:
            local_num = cleaned

        # 1. Cek prefix 6 digit (Paling Akurat)
        if len(local_num) >= 6 and local_num[:6] in self.HLR_DATABASE:
            return self.HLR_DATABASE[local_num[:6]]
            
        # 2. Cek prefix 4 digit
        if len(local_num) >= 4 and local_num[:4] in self.HLR_DATABASE:
            return self.HLR_DATABASE[local_num[:4]]

        return {
            "city": "Indonesia (Nasional)",
            "province": "Indonesia",
            "lat": -6.2088,
            "lon": 106.8456,
            "brand": "Operator Seluler Indonesia"
        }

    def _generate_folium_map(self, target: str, lat: float, lon: float, location_name: str, hlr_info: Dict[str, Any]) -> str:
        # Buat Peta Gelap Elegan dengan Folium
        m = folium.Map(location=[lat, lon], zoom_start=11, tiles="CartoDB dark_matter")
        
        # Lingkaran Radius Area HLR (15 km)
        folium.Circle(
            radius=15000,
            location=[lat, lon],
            color="#10B981",
            fill=True,
            fill_color="#10B981",
            fill_opacity=0.18,
            popup=f"Area HLR Registrasi: {location_name}"
        ).add_to(m)
        
        # Marker Titik Pusat Regional
        folium.Marker(
            [lat, lon],
            popup=f"<b>Target:</b> {target}<br><b>Area HLR:</b> {hlr_info.get('city')}<br><b>Provinsi:</b> {hlr_info.get('province')}<br><b>Brand:</b> {hlr_info.get('brand')}",
            tooltip=f"Pusat Area HLR: {hlr_info.get('city')}",
            icon=folium.Icon(color="green", icon="tower-cell", prefix="fa")
        ).add_to(m)
        
        safe_name = target.replace("+", "").replace(" ", "_")
        map_path = os.path.join(self.output_dir, f"map_{safe_name}.html")
        m.save(map_path)
        return map_path

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        hlr_info = self._lookup_hlr(target)
        lat = hlr_info["lat"]
        lon = hlr_info["lon"]
        location_name = f"{hlr_info['city']}, {hlr_info['province']}"

        map_file = self._generate_folium_map(target, lat, lon, location_name, hlr_info)

        data = {
            "hlr_area": hlr_info["city"],
            "province": hlr_info["province"],
            "operator_brand": hlr_info["brand"],
            "coordinates": {"lat": lat, "lon": lon},
            "location_name": location_name,
            "accuracy_level": "HLR City/Province Region Level",
            "map_file": map_file,
            "disclaimer": "Titik koordinat merepresentasikan pusat area HLR kartu seluler, bukan posisi GPS real-time pengguna."
        }
        return self.success_response(data, f"HLR teridentifikasi: {location_name}")
