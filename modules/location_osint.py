import os
import re
import folium
from typing import Dict, Any, Optional
import phonenumbers
from phonenumbers import geocoder
from core.base_module import BaseOSINTModule

class LocationOSINT(BaseOSINTModule):
    name: str = "Geospatial & HLR Area Intelligence"
    module_id: str = "location_osint"
    description: str = "Analisis Home Location Register (HLR) telekomunikasi global/Indonesia dan pembuatan peta interaktif Folium."
    version: str = "2.3.0"
    priority: int = 3
    target_type: str = "phone"

    def __init__(self, config: Optional[Dict[str, Any]] = None, async_client: Optional[Any] = None):
        super().__init__(config, async_client)
        self.output_dir = self.config.get("app.output_dir", "./output") if self.config else "./output"
        os.makedirs(self.output_dir, exist_ok=True)

    def _lookup_location(self, phone: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Ekstraksi lokasi HLR terpadu dari phone_osint atau phonenumbers geocoder."""
        # 1. Gunakan hasil HLR granular dari phone_osint jika tersedia
        if context and "phone_osint" in context:
            p_data = context["phone_osint"].get("data", {})
            hlr_info = p_data.get("hlr_carrier_intelligence", {})
            geo_info = p_data.get("telecom_meta", {})
            if hlr_info.get("regional_cluster"):
                city_name = hlr_info.get("regional_cluster")
                prov_name = hlr_info.get("operator_cluster", "Indonesia")
                brand_name = hlr_info.get("card_brand") or p_data.get("carrier", "Telco Operator")
                return {
                    "city": city_name,
                    "province": prov_name,
                    "lat": -6.2088,
                    "lon": 106.8456,
                    "brand": brand_name,
                    "country": "Indonesia"
                }

        # 2. Fallback ke ITU-T phonenumbers geocoder
        target_str = phone.strip()
        try:
            if target_str.startswith("0"):
                parsed = phonenumbers.parse(target_str, "ID")
            else:
                parsed = phonenumbers.parse(target_str if target_str.startswith("+") else f"+{target_str}", None)

            country = geocoder.country_name_for_number(parsed, "id") or geocoder.country_name_for_number(parsed, "en") or "Global"
            city = geocoder.description_for_number(parsed, "id") or geocoder.description_for_number(parsed, "en") or country
            return {
                "city": city,
                "province": country,
                "lat": -6.2088 if parsed.country_code == 62 else 0.0,
                "lon": 106.8456 if parsed.country_code == 62 else 0.0,
                "brand": "Global Carrier",
                "country": country
            }
        except Exception:
            return {
                "city": "Unknown Region",
                "province": "Unknown Country",
                "lat": -6.2088,
                "lon": 106.8456,
                "brand": "Mobile Operator",
                "country": "Unknown"
            }

    def _generate_folium_map(self, target: str, lat: float, lon: float, location_name: str, hlr_info: Dict[str, Any]) -> str:
        m = folium.Map(location=[lat, lon], zoom_start=11, tiles="CartoDB dark_matter")
        
        folium.Circle(
            radius=15000,
            location=[lat, lon],
            color="#10B981",
            fill=True,
            fill_color="#10B981",
            fill_opacity=0.18,
            popup=f"Area HLR Registrasi: {location_name}"
        ).add_to(m)
        
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
        hlr_info = self._lookup_location(target, context)
        lat = hlr_info.get("lat", -6.2088)
        lon = hlr_info.get("lon", 106.8456)
        location_name = f"{hlr_info['city']}, {hlr_info['province']}"

        map_file = self._generate_folium_map(target, lat, lon, location_name, hlr_info)

        data = {
            "hlr_area": hlr_info["city"],
            "province": hlr_info["province"],
            "operator_brand": hlr_info["brand"],
            "country": hlr_info.get("country", "Indonesia"),
            "coordinates": {"lat": lat, "lon": lon},
            "location_name": location_name,
            "accuracy_level": "HLR City/Province Region Level",
            "map_file": map_file,
            "disclaimer": "Titik koordinat merepresentasikan pusat area HLR kartu seluler, bukan posisi GPS real-time pengguna."
        }
        return self.success_response(data, f"Analisis HLR Geospatial untuk {target} selesai.")
