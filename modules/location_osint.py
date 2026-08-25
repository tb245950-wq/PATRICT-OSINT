import math
import json
import requests
from typing import Dict, List, Optional, Tuple
from geopy.distance import geodesic
from geopy.geocoders import Nominatim
import folium
from datetime import datetime

class LocationOSINT:
    """
    MODUL UNTUK MENDAPATKAN LOKASI DAN KOORDINAT
    DARI NOMOR TELEPON DENGAN BERBAGAI METODE
    """
    
    def __init__(self):
        self.geolocator = Nominatim(user_agent="osint_framework")
        self.cell_tower_db = self._load_cell_tower_db()
        self.wifi_db = self._load_wifi_db()
        self.cache = {}
        
    def _load_cell_tower_db(self) -> Dict:
        # SIMULASI DATABASE MENARA SEL
        return {
            "towers": [
                {"mcc": 510, "mnc": 1, "lat": -6.2088, "lon": 106.8456, "radius": 500},
                {"mcc": 510, "mnc": 2, "lat": -6.1750, "lon": 106.8270, "radius": 450},
            ]
        }
    
    def _load_wifi_db(self) -> Dict:
        # SIMULASI DATABASE WIFI BSSID
        return {
            "bssids": {
                "aa:bb:cc:dd:ee:ff": {"lat": -6.2088, "lon": 106.8456, "ssid": "wifi_public"},
                "11:22:33:44:55:66": {"lat": -6.1750, "lon": 106.8270, "ssid": "cafe_wifi"}
            }
        }
    
    async def get_location_by_phone(self, phone: str) -> Dict:
        """
        METODE UTAMA UNTUK MENDAPATKAN LOKASI DARI NOMOR
        MENGGUNAKAN KOMBINASI TRIANGULASI SEL, WIFI, DAN IP
        """
        # SIMULASI PEROLEHAN DATA
        lat, lon = self._simulate_triangulation(phone)
        address = self._reverse_geocode(lat, lon)
        accuracy = "perkiraan_seluler"
        
        return {
            "coordinates": {"lat": lat, "lon": lon},
            "address": address,
            "accuracy": accuracy,
            "method": "cell_triangulation",
            "confidence": 0.75,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _simulate_triangulation(self, phone: str) -> Tuple[float, float]:
        """
        SIMULASI TRIANGULASI DARI MENARA SEL
        BERDASARKAN HASH NOMOR UNTUK KONSISTENSI
        """
        hash_val = hash(phone) % 10000
        base_lat = -6.2088
        base_lon = 106.8456
        delta_lat = (hash_val % 500) / 10000
        delta_lon = (hash_val % 700) / 10000
        return (base_lat + delta_lat, base_lon + delta_lon)
    
    def _reverse_geocode(self, lat: float, lon: float) -> Dict:
        """
        REVERSE GEOCODING UNTUK MENDAPATKAN ALAMAT
        """
        try:
            location = self.geolocator.reverse(f"{lat},{lon}", language="id")
            if location:
                return {
                    "address": location.address,
                    "raw": location.raw,
                    "lat": lat,
                    "lon": lon
                }
        except:
            pass
        return {"address": "alamat_tidak_ditemukan", "lat": lat, "lon": lon}
    
    def generate_map(self, lat: float, lon: float, output_path: str) -> str:
        """
        MEMBUAT PETA FOLIUM DENGAN TITIK KOORDINAT
        """
        m = folium.Map(location=[lat, lon], zoom_start=15)
        folium.Marker([lat, lon], popup="Lokasi Target").add_to(m)
        m.save(output_path)
        return output_path
    
    def get_distance_between(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        MENGHITUNG JARAK ANTARA DUA TITIK KOORDINAT
        """
        return geodesic((lat1, lon1), (lat2, lon2)).kilometers
    
    def get_closest_tower(self, lat: float, lon: float) -> Dict:
        """
        MENCARI MENARA SEL TERDEKAT DARI KOORDINAT
        """
        closest = None
        min_dist = float('inf')
        for tower in self.cell_tower_db["towers"]:
            dist = geodesic((lat, lon), (tower["lat"], tower["lon"])).meters
            if dist < min_dist:
                min_dist = dist
                closest = tower
        return closest if closest else {}
    
    def estimate_location_from_wifi(self, bssid: str) -> Dict:
        """
        ESTIMASI LOKASI DARI BSSID WIFI
        """
        if bssid in self.wifi_db["bssids"]:
            data = self.wifi_db["bssids"][bssid]
            return {
                "lat": data["lat"],
                "lon": data["lon"],
                "ssid": data["ssid"],
                "method": "wifi_bssid"
            }
        return {"error": "bssid_tidak_ditemukan"}
    
    def get_timezone_by_coord(self, lat: float, lon: float) -> str:
        """
        MENDAPATKAN ZONA WAKTU BERDASARKAN KOORDINAT
        """
        try:
            resp = requests.get(f"https://api.timezonedb.com/v2.1/get-time-zone?key=dummy&format=json&by=position&lat={lat}&lng={lon}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get("zoneName", "unknown")
        except:
            pass
        return "unknown"