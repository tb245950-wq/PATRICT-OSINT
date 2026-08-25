import json
import os
import csv
from datetime import datetime
from typing import Dict, List, Any
import hashlib
import base64
import html
import xml.etree.ElementTree as ET

class ReportGenerator:
    """
    MODUL UNTUK GENERATE LAPORAN DALAM BERBAGAI FORMAT
    JSON, CSV, HTML, PDF (SIMULASI)
    """
    
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.hash_id = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).hexdigest()[:8]
        
    def generate_json_report(self, data: Dict) -> str:
        """
        GENERATE LAPORAN JSON LENGKAP
        """
        filename = f"osint_report_{self.hash_id}_{data.get('phone', 'unknown')}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # TAMBAHKAN METADATA
        data["report_metadata"] = {
            "generated_at": datetime.utcnow().isoformat(),
            "report_id": self.hash_id,
            "version": "1.0"
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath
    
    def generate_csv_report(self, data: Dict) -> str:
        """
        GENERATE LAPORAN CSV
        """
        filename = f"osint_report_{self.hash_id}_{data.get('phone', 'unknown')}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["category", "key", "value"])
            
            # FLATTEN DATA
            self._flatten_dict(data, writer, "")
        return filepath
    
    def _flatten_dict(self, d: Dict, writer, prefix: str):
        for k, v in d.items():
            if isinstance(v, dict):
                self._flatten_dict(v, writer, f"{prefix}{k}.")
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        self._flatten_dict(item, writer, f"{prefix}{k}[{i}].")
                    else:
                        writer.writerow([prefix, f"{k}[{i}]", str(item)])
            else:
                writer.writerow([prefix, k, str(v)])
    
    def generate_html_report(self, data: Dict) -> str:
        """
        GENERATE LAPORAN HTML
        """
        filename = f"osint_report_{self.hash_id}_{data.get('phone', 'unknown')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>OSINT Report - {data.get('phone', 'unknown')}</title>
        <style>body{{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .card{{background:#16213e;border-radius:8px;padding:15px;margin:10px 0;border-left:4px solid #0f3460;}}
        h1,h2{{color:#e94560;}}
        .data{{background:#0f3460;padding:10px;border-radius:4px;margin:5px 0;}}
        .key{{color:#ffd700;}}
        .value{{color:#00d2ff;}}
        .coords{{color:#ff6b6b;font-weight:bold;}}
        </style>
        </head>
        <body>
        <h1>OSINT REPORT</h1>
        <div class="card">
        <h2>Target: {data.get('phone', 'unknown')}</h2>
        <p><span class="key">Timestamp:</span> <span class="value">{data.get('timestamp', 'unknown')}</span></p>
        </div>
        <div class="card">
        <h2>📍 Lokasi & Koordinat</h2>
        <pre class="data">{json.dumps(data.get('location', {}), indent=2, ensure_ascii=False)}</pre>
        </div>
        <div class="card">
        <h2>📧 Email & Nama</h2>
        <pre class="data">{json.dumps(data.get('emails', []), indent=2, ensure_ascii=False)}</pre>
        </div>
        <div class="card">
        <h2>📱 Sosial Media</h2>
        <pre class="data">{json.dumps(data.get('social_accounts', []), indent=2, ensure_ascii=False)}</pre>
        </div>
        <div class="card">
        <h2>🌐 Network Details</h2>
        <pre class="data">{json.dumps(data.get('network_details', {}), indent=2, ensure_ascii=False)}</pre>
        </div>
        <div class="card">
        <h2>🌍 Web History</h2>
        <pre class="data">{json.dumps(data.get('web_history', []), indent=2, ensure_ascii=False)}</pre>
        </div>
        </body></html>
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filepath
    
    def generate_pdf_report(self, data: Dict) -> str:
        """
        GENERATE LAPORAN PDF (SIMULASI - GUNAKAN WKHTMLTOPDF ATAU REPORTLAB)
        """
        filename = f"osint_report_{self.hash_id}_{data.get('phone', 'unknown')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        # SIMULASI - BUAT FILE KOSONG DENGAN CATATAN
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("PDF REPORT - INSTALL REPORTLAB ATAU GUNAKAN WKHTMLTOPDF\n")
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
        return filepath
    
    def generate_all_reports(self, data: Dict) -> Dict:
        """
        GENERATE SEMUA FORMAT LAPORAN
        """
        return {
            "json": self.generate_json_report(data),
            "csv": self.generate_csv_report(data),
            "html": self.generate_html_report(data),
            "pdf": self.generate_pdf_report(data)
        }