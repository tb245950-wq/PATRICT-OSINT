import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from core.base_module import BaseOSINTModule

class WebHistoryOSINT(BaseOSINTModule):
    name: str = "Web Presence & Domain History"
    module_id: str = "web_history"
    description: str = "Analisis jejak domain dan riwayat arsip web via query pasif Wayback Machine (Internet Archive CDX API)."
    version: str = "2.1.0"
    priority: int = 5
    target_type: str = "web"

    def _extract_domain(self, target: str) -> str:
        """Ekstrak nama domain dari target URL/domain."""
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlparse(target)
            domain = parsed.netloc or parsed.path
        else:
            domain = target.split("/")[0]

        if ":" in domain:
            domain = domain.split(":")[0]
        return domain.strip()

    def _format_cdx_timestamp(self, ts: str) -> str:
        """Format timestamp CDX YYYYMMDDhhmmss ke format ISO UTC manusiawi."""
        if not ts or len(ts) < 8:
            return ts or "N/A"
        try:
            year = ts[0:4]
            month = ts[4:6]
            day = ts[6:8]
            hour = ts[8:10] if len(ts) >= 10 else "00"
            minute = ts[10:12] if len(ts) >= 12 else "00"
            second = ts[12:14] if len(ts) >= 14 else "00"
            return f"{year}-{month}-{day} {hour}:{minute}:{second} UTC"
        except Exception:
            return ts

    async def _query_wayback_cdx(self, domain: str) -> Dict[str, Any]:
        """Query data snapshot historis dari Wayback Machine CDX API secara pasif."""
        history_data = {
            "has_history": False,
            "first_snapshot": None,
            "last_snapshot": None,
            "total_snapshots_found": 0,
            "historical_urls": [],
            "status": "No Historical Archive Found"
        }

        if not self.async_client:
            return history_data

        try:
            # Query recent snapshots
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=12&fl=timestamp,original,mimetype,statuscode"
            status, text, _ = await self.async_client.get(url)

            if status == 200 and text.strip().startswith("["):
                rows = json.loads(text)
                if len(rows) > 1:
                    headers = rows[0]
                    records = rows[1:]

                    history_data["has_history"] = True
                    history_data["total_snapshots_found"] = len(records)
                    history_data["status"] = f"Found {len(records)} Historical Snapshots in Wayback Machine"

                    for r in records:
                        if len(r) >= 4:
                            ts, orig_url, mime, code = r[0], r[1], r[2], r[3]
                            history_data["historical_urls"].append({
                                "timestamp": self._format_cdx_timestamp(ts),
                                "original_url": orig_url,
                                "mime_type": mime,
                                "status_code": code,
                                "wayback_url": f"https://web.archive.org/web/{ts}/{orig_url}"
                            })

                    if history_data["historical_urls"]:
                        history_data["first_snapshot"] = history_data["historical_urls"][0]["timestamp"]
                        history_data["last_snapshot"] = history_data["historical_urls"][-1]["timestamp"]

            # Query earliest snapshot for historical timeline
            if not history_data["first_snapshot"]:
                url_first = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp,original"
                st_first, txt_first, _ = await self.async_client.get(url_first)
                if st_first == 200 and txt_first.strip().startswith("["):
                    f_rows = json.loads(txt_first)
                    if len(f_rows) > 1:
                        history_data["has_history"] = True
                        history_data["first_snapshot"] = self._format_cdx_timestamp(f_rows[1][0])
                        history_data["status"] = "Historical Archive Found"

        except Exception as e:
            history_data["status"] = f"Archive Query Error: {e}"

        return history_data

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        domain = self._extract_domain(target)
        if not domain:
            return self.error_response("Target domain tidak valid untuk pemeriksaan riwayat web.")

        history = await self._query_wayback_cdx(domain)

        data = {
            "query_domain": domain,
            "has_history": history.get("has_history", False),
            "status": history.get("status", "No Historical Archive Found"),
            "first_snapshot": history.get("first_snapshot"),
            "last_snapshot": history.get("last_snapshot"),
            "total_snapshots": history.get("total_snapshots_found", 0),
            "historical_urls": history.get("historical_urls", []),
            "archive_sources": ["Wayback Machine (Internet Archive CDX API)"]
        }
        return self.success_response(data, f"Pemeriksaan riwayat arsip web {domain} selesai.")
