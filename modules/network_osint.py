import subprocess
import re
import requests
import socket
import netifaces
import psutil
from typing import Dict, List, Optional, Tuple
import whois
import dns.resolver
from datetime import datetime
import platform
import uuid
import json

class NetworkOSINT:
    """
    MODUL UNTUK MENDAPATKAN DETAIL NETWORK (IP, MAC, DNS, ROUTER)
    BERDASARKAN NOMOR TELEPON ATAU TARGET LAIN
    """
    
    def __init__(self):
        self.system = platform.system()
        self.hostname = socket.gethostname()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.cache = {}
        
    async def scan_network_by_phone(self, phone: str) -> Dict:
        """
        METODE UTAMA: MENDAPATKAN SEMUA DETAIL NETWORK
        TERKAIT DENGAN NOMOR TELEPON
        """
        # SIMULASI - NOMOR TELEPON TIDAK LANGSUNG MEMBERIKAN IP
        # TETAPI KITA BISA MENDAPATKAN INFORMASI DARI CARRIER
        network_data = {
            "phone": phone,
            "ip_addresses": [],
            "mac_addresses": [],
            "dns_servers": [],
            "router_info": {},
            "network_interfaces": [],
            "public_ip": self._get_public_ip(),
            "local_ip": self._get_local_ip(),
            "carrier_network": self._get_carrier_network(phone)
        }
        
        # DAPATKAN IP DAN MAC DARI INTERFACE
        interfaces = self._get_network_interfaces()
        network_data["network_interfaces"] = interfaces
        for iface in interfaces:
            if iface.get("ip"):
                network_data["ip_addresses"].append(iface["ip"])
            if iface.get("mac"):
                network_data["mac_addresses"].append(iface["mac"])
        
        # DAPATKAN DNS
        network_data["dns_servers"] = self._get_dns_servers()
        
        # DAPATKAN INFORMASI ROUTER
        network_data["router_info"] = self._get_router_info()
        
        return network_data
    
    def _get_public_ip(self) -> str:
        """
        MENDAPATKAN IP PUBLIK MENGGUNAKAN API
        """
        try:
            resp = self.session.get("https://api.ipify.org?format=json", timeout=5)
            return resp.json().get("ip", "unknown")
        except:
            try:
                resp = self.session.get("https://httpbin.org/ip", timeout=5)
                return resp.json().get("origin", "unknown")
            except:
                return "unknown"
    
    def _get_local_ip(self) -> str:
        """
        MENDAPATKAN IP LOKAL
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def _get_network_interfaces(self) -> List[Dict]:
        """
        MENDAPATKAN SEMUA INTERFACE JARINGAN DENGAN IP DAN MAC
        """
        interfaces = []
        for iface_name in netifaces.interfaces():
            iface_data = netifaces.ifaddresses(iface_name)
            mac = None
            ip = None
            if netifaces.AF_LINK in iface_data:
                mac = iface_data[netifaces.AF_LINK][0].get("addr")
            if netifaces.AF_INET in iface_data:
                ip = iface_data[netifaces.AF_INET][0].get("addr")
            if netifaces.AF_INET6 in iface_data:
                ipv6 = iface_data[netifaces.AF_INET6][0].get("addr")
            else:
                ipv6 = None
            interfaces.append({
                "name": iface_name,
                "mac": mac,
                "ip": ip,
                "ipv6": ipv6,
                "status": "up" if ip else "down"
            })
        return interfaces
    
    def _get_dns_servers(self) -> List[str]:
        """
        MENDAPATKAN DNS SERVER YANG DIGUNAKAN
        """
        dns_servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1])
        except:
            pass
        if not dns_servers:
            dns_servers = ["8.8.8.8", "1.1.1.1"]
        return dns_servers
    
    def _get_router_info(self) -> Dict:
        """
        MENDAPATKAN INFORMASI ROUTER/GATEWAY
        """
        gateway = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, [None, None])
        gateway_ip = gateway[0] if gateway else None
        router_mac = None
        if gateway_ip:
            try:
                # ARP SCAN UNTUK MAC ADDRESS ROUTER
                if self.system == "Windows":
                    output = subprocess.check_output(["arp", "-a", gateway_ip], text=True)
                    mac_match = re.search(r"([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})", output)
                    if mac_match:
                        router_mac = mac_match.group(1).replace("-", ":")
                else:
                    output = subprocess.check_output(["arp", "-n", gateway_ip], text=True)
                    mac_match = re.search(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", output)
                    if mac_match:
                        router_mac = mac_match.group(1)
            except:
                pass
        return {
            "gateway_ip": gateway_ip,
            "gateway_mac": router_mac,
            "vendor": self._get_mac_vendor(router_mac) if router_mac else "unknown"
        }
    
    def _get_mac_vendor(self, mac: str) -> str:
        """
        MENDAPATKAN VENDOR DARI MAC ADDRESS (OUI)
        """
        if not mac:
            return "unknown"
        oui = mac[:8].upper().replace(":", "").replace("-", "")
        try:
            resp = self.session.get(f"https://api.macvendors.com/{oui}", timeout=3)
            if resp.status_code == 200:
                return resp.text.strip()
        except:
            pass
        return "unknown"
    
    def _get_carrier_network(self, phone: str) -> Dict:
        """
        MENDAPATKAN INFORMASI JARINGAN DARI CARRIER
        """
        # SIMULASI
        return {
            "carrier": "simulated_carrier",
            "network_type": "cellular",
            "mcc_mnc": "510-1",
            "country": "Indonesia",
            "timezone": "Asia/Jakarta"
        }
    
    def get_ip_geolocation(self, ip: str) -> Dict:
        """
        MENDAPATKAN GEOLOKASI DARI IP ADDRESS
        """
        try:
            resp = self.session.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            return resp.json()
        except:
            try:
                resp = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                return resp.json()
            except:
                return {"error": "geolocation_failed"}
    
    def reverse_dns_lookup(self, ip: str) -> List[str]:
        """
        MELAKUKAN REVERSE DNS LOOKUP
        """
        try:
            names = socket.gethostbyaddr(ip)
            return [names[0]] + names[1]
        except:
            return []
    
    def port_scan(self, ip: str, ports: List[int] = [80, 443, 22, 21, 25, 53]) -> Dict:
        """
        PORT SCAN SEDERHANA
        """
        results = {}
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            results[port] = "open" if result == 0 else "closed"
            sock.close()
        return results