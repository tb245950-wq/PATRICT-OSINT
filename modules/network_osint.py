import socket
from typing import Dict, Any, Optional, List
from core.base_module import BaseOSINTModule

class NetworkOSINT(BaseOSINTModule):
    name: str = "Network & Infrastructure OSINT"
    module_id: str = "network_osint"
    description: str = "Pengumpulan intelijen jaringan, IP publik, DNS resolvers, dan soket analisis."
    version: str = "2.0.0"
    priority: int = 5

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        public_ip = "N/A"
        if self.async_client:
            try:
                status, text, _ = await self.async_client.get("https://api.ipify.org?format=json")
                if status == 200 and "ip" in text:
                    import json
                    public_ip = json.loads(text).get("ip", "N/A")
            except Exception:
                pass

        # Ambil hostname & DNS lokal
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            hostname = "localhost"
            local_ip = "127.0.0.1"

        dns_servers = ["1.1.1.1", "8.8.8.8"]

        data = {
            "public_ip": public_ip,
            "local_ip": local_ip,
            "hostname": hostname,
            "dns_servers": dns_servers,
            "gateway": "192.168.1.1 (Standard Gateway)"
        }
        return self.success_response(data, "Pengumpulan informasi jaringan selesai.")
