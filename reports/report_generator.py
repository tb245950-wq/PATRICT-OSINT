import os
import json
import csv
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """
    Mesin Pembuat Laporan Komprehensif (JSON, CSV, HTML, & Graf Interaktif).
    """
    
    def __init__(self, output_dir: str = "./output", template_dir: str = "reports/templates"):
        self.output_dir = output_dir
        self.template_dir = template_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup Jinja2 Environment
        if os.path.exists(self.template_dir):
            self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        else:
            self.jinja_env = None

    def _get_safe_filename(self, target: str) -> str:
        return target.replace("+", "").replace(" ", "_").replace("/", "_")

    def generate_all_reports(self, target: str, full_data: Dict[str, Any], graph_file: Optional[str] = None, map_file: Optional[str] = None) -> Dict[str, str]:
        safe_name = self._get_safe_filename(target)
        generated_files = {}
        
        # 1. JSON Report
        json_path = os.path.join(self.output_dir, f"report_{safe_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(full_data, f, indent=2, ensure_ascii=False)
        generated_files["json"] = json_path
        
        # 2. CSV Summary Report
        csv_path = os.path.join(self.output_dir, f"report_{safe_name}.csv")
        self._export_csv(target, full_data, csv_path)
        generated_files["csv"] = csv_path
        
        # 3. Modern Dark HTML Report
        if self.jinja_env:
            html_path = os.path.join(self.output_dir, f"report_{safe_name}.html")
            self._export_html(target, full_data, html_path, graph_file, map_file)
            generated_files["html"] = html_path
            
        return generated_files

    def _export_csv(self, target: str, data: Dict[str, Any], filepath: str):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Entity", "Details", "Source/Status"])
            writer.writerow(["Target", "Phone Number", target, "User Input"])
            
            # Phone Info
            p_data = data.get("phone_osint", {}).get("data", {})
            if p_data:
                writer.writerow(["Phone", "Carrier", p_data.get("carrier", "N/A"), "phonenumbers"])
                writer.writerow(["Phone", "Country", p_data.get("country", "N/A"), "geocoder"])
                
            # Social Accounts
            s_data = data.get("social_osint", {}).get("data", {})
            accounts = s_data.get("accounts", []) if isinstance(s_data, dict) else []
            for acc in accounts:
                writer.writerow(["Social", acc.get("platform", "Unknown"), acc.get("url", ""), "Detected"])
                
            # Emails
            e_data = data.get("email_osint", {}).get("data", {})
            emails = e_data.get("emails", []) if isinstance(e_data, dict) else []
            for em in emails:
                writer.writerow(["Email", em.get("email", ""), em.get("name", ""), em.get("source", "OSINT")])
                
            # Dorking Findings
            d_data = data.get("dorking_osint", {}).get("data", {})
            findings = d_data.get("findings", []) if isinstance(d_data, dict) else []
            for item in findings:
                writer.writerow(["Dorking", item.get("category", "General"), item.get("title", ""), item.get("url", "")])

    def _export_html(self, target: str, data: Dict[str, Any], filepath: str, graph_file: Optional[str], map_file: Optional[str]):
        try:
            template = self.jinja_env.get_template("report_dark.html")
            target_hash = hashlib.md5(target.encode()).hexdigest()[:8].upper()
            
            # Ekstrak data untuk template
            phone_info = data.get("phone_osint", {}).get("data", {})
            social_accounts = data.get("social_osint", {}).get("data", {}).get("accounts", [])
            emails = data.get("email_osint", {}).get("data", {}).get("emails", [])
            network_info = data.get("network_osint", {}).get("data", {})
            web_history = data.get("web_history", {}).get("data", {}).get("domains", [])
            dorking_data = data.get("dorking_osint", {}).get("data", {})
            dorking_findings = dorking_data.get("findings", [])
            
            # Format path relatif agar iframe berfungsi dengan baik
            rel_graph = os.path.basename(graph_file) if graph_file else None
            rel_map = os.path.basename(map_file) if map_file else None
            
            html_content = template.render(
                target=target,
                target_id=target_hash,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                phone_info=phone_info,
                social_accounts=social_accounts,
                emails=emails,
                network_info=network_info,
                web_history=web_history,
                dorking_data=dorking_data,
                dorking_findings=dorking_findings,
                graph_file=rel_graph,
                map_file=rel_map
            )
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[!] Gagal membuat laporan HTML: {e}")
