import re
import socket
import asyncio
import urllib.parse
from typing import Dict, Any, Optional, List
from core.base_module import BaseOSINTModule

class NetworkOSINT(BaseOSINTModule):
    name: str = "Network & Infrastructure OSINT"
    module_id: str = "network_osint"
    description: str = "Pengumpulan intelijen infrastruktur jaringan target: Resolusi IP/IPv6, Reverse DNS (PTR), ASN/ISP Lookup, dan Quick Port Probing."
    version: str = "2.1.0"
    priority: int = 4
    target_type: str = "web"

    def _extract_target_host(self, target: str) -> str:
        """Ekstrak hostname murni atau alamat IP dari target URL/domain."""
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlparse(target)
            host = parsed.netloc or parsed.path
        else:
            host = target.split("/")[0]

        if ":" in host:
            host = host.split(":")[0]
        return host.strip()

    async def _resolve_target_ips(self, host: str) -> Dict[str, List[str]]:
        """Resolusi alamat IPv4 dan IPv6 target."""
        ipv4_list = []
        ipv6_list = []
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(host, None)
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_list:
                    ipv4_list.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_list:
                    ipv6_list.append(ip)
        except Exception:
            pass
        return {"ipv4": ipv4_list, "ipv6": ipv6_list}

    async def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Melakukan reverse DNS (PTR) lookup pada IP target."""
        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return host
        except Exception:
            return None

    async def _lookup_asn_and_isp(self, ip: str) -> Dict[str, Any]:
        """Query informasi ASN, ISP, dan Organisasi pemilik IP target."""
        asn_info = {
            "query_ip": ip,
            "isp": "N/A",
            "org": "N/A",
            "as_number": "N/A",
            "country": "N/A",
            "city": "N/A"
        }
        if not self.async_client or ip in ("127.0.0.1", "localhost", "::1"):
            return asn_info

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query"
            status, text, _ = await self.async_client.get(url)
            if status == 200:
                import json
                data = json.loads(text)
                if data.get("status") == "success":
                    asn_info["isp"] = data.get("isp", "N/A")
                    asn_info["org"] = data.get("org", "N/A")
                    asn_info["as_number"] = data.get("as", "N/A")
                    asn_info["country"] = data.get("country", "N/A")
                    asn_info["city"] = data.get("city", "N/A")
        except Exception:
            pass
        return asn_info

    async def _probe_port(self, ip: str, port: int, timeout: float = 0.6) -> Optional[int]:
        """Non-blocking TCP socket connect probe untuk memeriksa keterbukaan port."""
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:
            return None

    async def _quick_port_scan(self, ip: str) -> List[Dict[str, Any]]:
        """Pemeriksaan cepat port umum standar pada target IP."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        tasks = [self._probe_port(ip, port) for port in common_ports.keys()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, res in zip(common_ports.keys(), results):
            if isinstance(res, int):
                open_ports.append({
                    "port": port,
                    "service": common_ports[port],
                    "state": "OPEN"
                })
        return open_ports

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        host = self._extract_target_host(target)
        if not host:
            return self.error_response("Format target hostname/IP tidak valid.")

        # 1. Resolusi IP target
        ips = await self._resolve_target_ips(host)
        primary_ip = ips["ipv4"][0] if ips["ipv4"] else (ips["ipv6"][0] if ips["ipv6"] else host)

        # 2. Reverse DNS lookup target
        reverse_ptr = None
        if ips["ipv4"] or ips["ipv6"]:
            reverse_ptr = await self._reverse_dns_lookup(primary_ip)

        # 3. ASN & ISP Info Target
        asn_data = {}
        if primary_ip and primary_ip != host:
            asn_data = await self._lookup_asn_and_isp(primary_ip)

        # 4. Quick Port Probe pada Primary IP target
        open_ports = []
        if primary_ip and primary_ip not in ("127.0.0.1", "localhost", "::1"):
            open_ports = await self._quick_port_scan(primary_ip)

        data = {
            "target_host": host,
            "resolved_ipv4": ips["ipv4"],
            "resolved_ipv6": ips["ipv6"],
            "primary_ip": primary_ip,
            "reverse_dns_ptr": reverse_ptr or "No PTR Record Found",
            "asn_and_isp": asn_data,
            "open_ports_summary": open_ports,
            "open_ports_count": len(open_ports)
        }
        return self.success_response(data, f"Intelijen infrastruktur jaringan {host} selesai.")
