import os
import json
import csv
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """
    Mesin Pembuat Laporan Komprehensif (JSON, CSV, HTML, & Graf Interaktif)
    Mendukung laporan spesifik per domain: Phone, Web Recon, dan Media Forensics.
    """
    
    def __init__(self, output_dir: str = "./output", template_dir: str = "reports/templates"):
        self.output_dir = output_dir
        
        if not os.path.isabs(template_dir) and not os.path.exists(template_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidate = os.path.join(base_dir, template_dir)
            if os.path.exists(candidate):
                template_dir = candidate

        self.template_dir = template_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup Jinja2 Environment
        if os.path.exists(self.template_dir):
            self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        else:
            self.jinja_env = None

    def _get_safe_filename(self, target: str) -> str:
        return target.replace("+", "").replace("://", "_").replace("/", "_").replace(":", "_").replace(" ", "_")

    def generate_all_reports(self, target: str, full_data: Dict[str, Any], target_type: str = "phone", graph_file: Optional[str] = None, map_file: Optional[str] = None) -> Dict[str, str]:
        safe_name = self._get_safe_filename(target)
        generated_files = {}
        
        prefix = "report"
        if target_type == "web":
            prefix = "report_web"
        elif target_type == "file":
            prefix = "report_file"

        # 1. JSON Report
        json_path = os.path.join(self.output_dir, f"{prefix}_{safe_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(full_data, f, indent=2, ensure_ascii=False)
        generated_files["json"] = json_path
        
        # 2. CSV Summary Report
        csv_path = os.path.join(self.output_dir, f"{prefix}_{safe_name}.csv")
        if target_type == "web":
            self._export_web_csv(target, full_data, csv_path)
        elif target_type == "file":
            self._export_file_csv(target, full_data, csv_path)
        else:
            self._export_phone_csv(target, full_data, csv_path)
        generated_files["csv"] = csv_path
        
        # 3. Modern Dark HTML Report
        if self.jinja_env:
            html_path = os.path.join(self.output_dir, f"{prefix}_{safe_name}.html")
            if target_type == "web":
                self._export_web_html(target, full_data, html_path)
            elif target_type == "file":
                self._export_file_html(target, full_data, html_path)
            else:
                self._export_phone_html(target, full_data, html_path, graph_file, map_file)
            generated_files["html"] = html_path
            
        return generated_files

    def _export_phone_csv(self, target: str, data: Dict[str, Any], filepath: str):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Entity", "Details", "Source/Status"])
            writer.writerow(["Target", "Phone Number", target, "User Input"])
            
            p_data = data.get("phone_osint", {}).get("data", {})
            if p_data:
                writer.writerow(["Phone", "Carrier", p_data.get("carrier", "N/A"), "phonenumbers"])
                writer.writerow(["Phone", "Country", p_data.get("country", "N/A"), "geocoder"])
                
            s_data = data.get("social_osint", {}).get("data", {})
            accounts = s_data.get("accounts", []) if isinstance(s_data, dict) else []
            for acc in accounts:
                writer.writerow(["Social", acc.get("platform", "Unknown"), acc.get("url", ""), "Detected"])
                
            e_data = data.get("email_osint", {}).get("data", {})
            emails = e_data.get("emails", []) if isinstance(e_data, dict) else []
            for em in emails:
                writer.writerow(["Email", em.get("email", ""), em.get("name", ""), em.get("source", "OSINT")])

    def _export_web_csv(self, target: str, data: Dict[str, Any], filepath: str):
        web_info = data.get("web_osint", {}).get("data", {})
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Key", "Value", "Source"])
            writer.writerow(["Target", "URL", target, "Input"])
            writer.writerow(["Web", "Domain", web_info.get("domain", ""), "Extracted"])
            writer.writerow(["Web", "Final Destination", web_info.get("final_url", ""), "HTTP"])
            writer.writerow(["Web", "Allowed Methods", ", ".join(web_info.get("http_methods_allowed", [])), "OPTIONS"])
            
            # Server GeoIP
            geo = web_info.get("server_geoip", {})
            writer.writerow(["Server", "IP Address", geo.get("ip", ""), "DNS"])
            writer.writerow(["Server", "Location", f"{geo.get('city','')}, {geo.get('country','')}", "GeoIP"])
            writer.writerow(["Server", "Coordinates", f"{geo.get('latitude','')}, {geo.get('longitude','')}", "GeoIP"])
            writer.writerow(["Server", "ISP", geo.get("isp", ""), "GeoIP"])

            # Tech Stack
            stack = web_info.get("tech_stack", {})
            for cat, items in stack.items():
                writer.writerow(["Tech Stack", cat, ", ".join(items), "Fingerprint"])

    def _export_file_csv(self, target: str, data: Dict[str, Any], filepath: str):
        f_info = data.get("file_forensics", {}).get("data", {})
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Property", "Value"])
            
            file_meta = f_info.get("file_info", {})
            writer.writerow(["File Info", "File Name", file_meta.get("file_name", "")])
            writer.writerow(["File Info", "File Size", file_meta.get("file_size_formatted", "")])
            writer.writerow(["File Info", "Full Path", file_meta.get("file_path", "")])

            hashes = f_info.get("cryptographic_hashes", {})
            for h_type, h_val in hashes.items():
                writer.writerow(["Hashes", h_type.upper(), h_val])

            magic = f_info.get("magic_bytes_inspection", {})
            writer.writerow(["Inspection", "Detected Type", magic.get("detected_file_type", "")])
            writer.writerow(["Inspection", "Spoofed Extension", str(magic.get("is_extension_spoofed", False))])

            exif = f_info.get("exif_metadata", {})
            writer.writerow(["EXIF", "Camera", f"{exif.get('camera_make','')} {exif.get('camera_model','')}".strip()])
            writer.writerow(["EXIF", "Datetime", exif.get("datetime_original", "")])

    def _export_phone_html(self, target: str, data: Dict[str, Any], filepath: str, graph_file: Optional[str], map_file: Optional[str]):
        try:
            template = self.jinja_env.get_template("report_dark.html")
            target_hash = hashlib.md5(target.encode()).hexdigest()[:8].upper()
            
            html_content = template.render(
                target=target,
                target_id=target_hash,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                phone_info=data.get("phone_osint", {}).get("data", {}),
                social_accounts=data.get("social_osint", {}).get("data", {}).get("accounts", []),
                emails=data.get("email_osint", {}).get("data", {}).get("emails", []),
                network_info=data.get("network_osint", {}).get("data", {}),
                web_history=data.get("web_history", {}).get("data", {}).get("domains", []),
                dorking_data=data.get("dorking_osint", {}).get("data", {}),
                dorking_findings=data.get("dorking_osint", {}).get("data", {}).get("findings", []),
                graph_file=os.path.basename(graph_file) if graph_file else None,
                map_file=os.path.basename(map_file) if map_file else None
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[!] Gagal membuat laporan HTML Phone: {e}")

    def _export_web_html(self, target: str, data: Dict[str, Any], filepath: str):
        try:
            template = self.jinja_env.get_template("report_web.html")
            web_data = data.get("web_osint", {}).get("data", {})
            
            html_content = template.render(
                target_url=target,
                domain=web_data.get("domain", target),
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                web_data=web_data,
                server_geoip=web_data.get("server_geoip", {})
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[!] Gagal membuat laporan HTML Web: {e}")

    def _export_file_html(self, target: str, data: Dict[str, Any], filepath: str):
        try:
            template = self.jinja_env.get_template("report_forensics.html")
            forensics_data = data.get("file_forensics", {}).get("data", {})
            file_info = forensics_data.get("file_info", {"file_name": os.path.basename(target)})
            
            html_content = template.render(
                file_info=file_info,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                forensics_data=forensics_data
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[!] Gagal membuat laporan HTML Forensics: {e}")
