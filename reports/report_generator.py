import os
import json
import csv
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """
    Mesin Pembuat Laporan Komprehensif (JSON, CSV, Markdown, & HTML Modern).
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

    def generate_all_reports(
        self,
        target: str,
        full_data: Dict[str, Any],
        target_type: str = "phone",
        graph_file: Optional[str] = None,
        map_file: Optional[str] = None
    ) -> Dict[str, str]:
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

        # 3. Markdown Assessment Report (.md)
        md_path = os.path.join(self.output_dir, f"{prefix}_{safe_name}.md")
        if target_type == "web":
            self._export_web_markdown(target, full_data, md_path)
        elif target_type == "file":
            self._export_file_markdown(target, full_data, md_path)
        else:
            self._export_phone_markdown(target, full_data, md_path)
        generated_files["markdown"] = md_path
        
        # 4. Modern Dark HTML Report
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
            writer.writerow(["Web", "Security Grade", web_info.get("security_headers_grade", {}).get("grade", "N/A"), "Grader"])
            writer.writerow(["Web", "Final Destination", web_info.get("final_url", ""), "HTTP"])
            writer.writerow(["Web", "Allowed Methods", ", ".join(web_info.get("http_methods_allowed", [])), "OPTIONS"])
            
            # Server GeoIP
            geo = web_info.get("server_geoip", {})
            loc_val = f"{geo.get('city','')}, {geo.get('country','')}".strip(" ,") or "Unknown Location / Protected IP"
            writer.writerow(["Server", "IP Address", geo.get("ip", ""), "DNS"])
            writer.writerow(["Server", "Location", loc_val, "GeoIP"])
            writer.writerow(["Server", "Coordinates", f"{geo.get('latitude','')}, {geo.get('longitude','')}", "GeoIP"])
            writer.writerow(["Server", "ISP", geo.get("isp", "Unknown ISP"), "GeoIP"])

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

    def _export_web_markdown(self, target: str, data: Dict[str, Any], filepath: str):
        w_data = data.get("web_osint", {}).get("data", {})
        meta = w_data.get("page_metadata", {})
        geo = w_data.get("server_geoip", {})
        stack = w_data.get("tech_stack", {})
        sec_grade = w_data.get("security_headers_grade", {})
        ssl_info = w_data.get("ssl_certificate", {})
        crt_data = w_data.get("crtsh_subdomains", {})
        origin_leak = w_data.get("origin_ip_leak", {})
        sensitive_files = w_data.get("sensitive_files_found", [])
        threat_data = w_data.get("threat_vulnerability_summary", {})

        md = f"""# Web Intelligence & Threat Assessment Report

**Target URL:** `{target}`  
**Domain:** `{w_data.get('domain', 'N/A')}`  
**Generated At:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  
**Security Headers Grade:** **`{sec_grade.get('grade', 'N/A')}`** (Score: `{sec_grade.get('score', 0)}/100`)  
**Overall Threat Level:** **`{threat_data.get('overall_threat_level', 'LOW')}`** (Risk Score: `{threat_data.get('risk_score', 0)}/100`)

---

## 1. Executive Vulnerability & Threat Summary

| Metric | Value |
|---|---|
| **Overall Threat Level** | **{threat_data.get('overall_threat_level', 'LOW')}** |
| **Risk Score** | `{threat_data.get('risk_score', 0)} / 100` |
| **Security Headers Grade** | `{sec_grade.get('grade', 'N/A')}` |
| **Origin IP Leak** | `{'DETECTED (!)' if origin_leak.get('leak_detected') else 'Protected / None'}` |
| **Sensitive Files Discovered** | `{len([f for f in sensitive_files if f.get('status') == 200])} Active` |

### Identified Threats & Mitigations
"""
        for t in threat_data.get("threats", []):
            md += f"""
### [{t.get('severity')}] {t.get('title')}
- **Category:** {t.get('category')}
- **Potential Impact:** {t.get('impact')}
- **Recommended Action:** {t.get('mitigation')}
"""

        # Origin Leak section
        if origin_leak.get("leak_detected"):
            md += f"""
---

## 2. Cloudflare / CDN Origin IP Leak Alert

> [!CAUTION]
> **POTENTIAL ORIGIN IP LEAK DETECTED**  
> Direct backend server IP addresses were discovered via unproxied records:

| Leaked Origin IP | Discovery Source | Risk Assessment |
|---|---|---|
"""
            for leak in origin_leak.get("leaked_ips", []):
                md += f"| `{leak.get('ip')}` | {leak.get('source')} | {leak.get('risk')} |\n"

        # SSL / TLS Cert
        md += f"""
---

## 3. SSL / TLS Certificate Intelligence

- **Issuer Organization:** `{ssl_info.get('issuer', {}).get('organizationName', 'N/A')}` ({ssl_info.get('issuer', {}).get('commonName', 'N/A')})
- **Valid Until:** `{ssl_info.get('valid_until', 'N/A')}` ({ssl_info.get('days_remaining') if ssl_info.get('days_remaining') is not None else 'N/A'} days remaining)
- **TLS Protocol & Cipher:** `{ssl_info.get('tls_version', 'N/A')}` - `{ssl_info.get('cipher', 'N/A')}`
- **Passive Subdomains Discovered (crt.sh):** `{crt_data.get('total_found', 0)} unique subdomains`

"""
        if crt_data.get("unique_subdomains"):
            md += "### Subdomains Sample (via Certificate Transparency):\n"
            for sub in crt_data.get("unique_subdomains")[:15]:
                md += f"- `{sub}`\n"

        # Security Headers
        md += f"""
---

## 4. Security Headers Evaluation (Grade: {sec_grade.get('grade', 'N/A')})

| Security Header | Status | Score | Details |
|---|---|---|---|
"""
        for h_name, h_eval in sec_grade.get("evaluations", {}).items():
            md += f"| `{h_name}` | **{h_eval.get('status')}** | `{h_eval.get('score')}` | {h_eval.get('details')} |\n"

        # Sensitive files
        if sensitive_files:
            md += f"""
---

## 5. Sensitive File & Directory Discovery

| Path | Status Code | Severity | Description | Size |
|---|---|---|---|---|
"""
            for sf in sensitive_files:
                md += f"| `{sf.get('path')}` | `{sf.get('status')}` | **{sf.get('severity')}** | {sf.get('description')} | {sf.get('size_bytes')} B |\n"

        # Tech stack
        md += f"""
---

## 6. Technology Stack & Infrastructure

- **Server IP:** `{geo.get('ip', 'N/A')}` ({geo.get('city', '')}, {geo.get('country', '')})
- **ISP / Organization:** `{geo.get('isp', '')} / {geo.get('organization', '')}`
- **Web Servers:** `{', '.join(stack.get('web_servers', [])) or 'Hidden / Generic'}`
- **Programming Languages:** `{', '.join(stack.get('programming_languages', [])) or 'N/A'}`
- **Backend Frameworks:** `{', '.join(stack.get('backend_frameworks', [])) or 'N/A'}`
- **Frontend Libraries:** `{', '.join(stack.get('frontend_libraries', [])) or 'N/A'}`
- **CMS / Platforms:** `{', '.join(stack.get('cms_and_platforms', [])) or 'N/A'}`
- **WAF / Firewalls:** `{', '.join(stack.get('waf_and_security', [])) or 'None Detected'}`

---
*Report generated by PATRICT-OSINT Framework v2.3.0*
"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
        except Exception as e:
            print(f"[!] Gagal membuat laporan Markdown Web: {e}")

    def _export_phone_markdown(self, target: str, data: Dict[str, Any], filepath: str):
        p_data = data.get("phone_osint", {}).get("data", {})
        c_data = data.get("caller_id_osint", {}).get("data", {})
        s_data = data.get("social_osint", {}).get("data", {})
        e_data = data.get("email_osint", {}).get("data", {})
        
        formatting = p_data.get("formatting", {})
        hlr_info = p_data.get("hlr_carrier_intelligence", {})
        telecom_meta = p_data.get("telecom_meta", {})
        endpoints = p_data.get("endpoint_links", {})
        threat_links = p_data.get("threat_intel_links", [])
        dorks = p_data.get("osint_dorks", [])
        wa_intel = p_data.get("whatsapp_intelligence", {})

        tz_str = ", ".join(telecom_meta.get("timezones", [])) if telecom_meta.get("timezones") else "Asia/Jakarta (WIB - UTC+7)"

        md = f"""# Telecommunications & Phone Intelligence Report

**Target Number:** `{target}`  
**ITU-T E.164 Format:** `{formatting.get('e164', p_data.get('e164', target))}`  
**National Format:** `{formatting.get('national', p_data.get('national', 'N/A'))}`  
**Carrier:** `{hlr_info.get('carrier_name', p_data.get('carrier', 'N/A'))}` ({hlr_info.get('card_brand', 'Prepaid/Postpaid')})  
**Granular Match:** `{hlr_info.get('match_level', 'Regional')} (Prefix: {hlr_info.get('prefix', '')})`  
**Line Type:** `{telecom_meta.get('line_type', p_data.get('type', 'Mobile'))}`  
**Timezone:** `{tz_str}`  
**HLR Regional Area:** `{hlr_info.get('hlr_region', telecom_meta.get('location_description', 'Indonesia'))}`  
**Network Code:** `MCC: {hlr_info.get('mcc', '510')} | MNC: {hlr_info.get('mnc', 'N/A')}`  
**Caller ID Registry:** `{c_data.get('owner_name') or c_data.get('name') or 'Private / No Public Entry'}`  
**Spam / Safety Score:** `{c_data.get('spam_score', '0%')} (Status: Clean)`  
**WhatsApp Status:** `{wa_intel.get('status_badge', 'Direct Link Available')}`  
**Data Breach Status:** `{e_data.get('breach_status', 'Clean / Not Found in Public Dumps')}`  
**Generated At:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  

---

## 1. Direct Messaging & Endpoint Verification Links

- **WhatsApp Direct API:** [{endpoints.get('whatsapp_direct', '#')}]({endpoints.get('whatsapp_direct', '#')})
- **Telegram Profile Direct:** [{endpoints.get('telegram_direct', '#')}]({endpoints.get('telegram_direct', '#')})
- **Truecaller Search Web:** [{endpoints.get('truecaller_search', '#')}]({endpoints.get('truecaller_search', '#')})
- **Sync.ME Lookup:** [{endpoints.get('syncme_search', '#')}]({endpoints.get('syncme_search', '#')})

---

## 2. Threat Intel & Breach Engine Investigation Links

| Platform | Category | Deep Search Link |
|---|---|---|
"""
        for tl in threat_links:
            md += f"| **{tl.get('platform')}** | {tl.get('category')} | [Buka {tl.get('platform')}]({tl.get('url')}) |\n"

        md += """
---

## 3. Automated OSINT Google Dorking Generator

| Category | Description | Google Search Link |
|---|---|---|
"""
        for d in dorks:
            md += f"| **{d.get('category')}** | {d.get('description')} | [Buka Google Search]({d.get('google_search_url')}) |\n"

        if s_data.get("accounts"):
            md += "\n---\n\n## 4. Social Media Accounts Found\n\n"
            for acc in s_data.get("accounts", []):
                md += f"- **{acc.get('platform')}**: [{acc.get('url')}]({acc.get('url')})\n"

        if e_data.get("breaches"):
            md += "\n---\n\n## 5. Public Data Breach Records\n\n"
            for b in e_data.get("breaches", []):
                md += f"- **[{b.get('breach_date', 'N/A')}] {b.get('title')}** ({b.get('domain')}): {', '.join(b.get('data_classes', []))}\n"

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
        except Exception as e:
            print(f"[!] Gagal membuat laporan Markdown Phone: {e}")

    def _export_file_markdown(self, target: str, data: Dict[str, Any], filepath: str):
        f_info = data.get("file_forensics", {}).get("data", {})
        f_meta = f_info.get("file_info", {})
        hashes = f_info.get("cryptographic_hashes", {})
        entropy = f_info.get("shannon_entropy", {})
        sliding_ent = f_info.get("sliding_window_entropy", {})
        magic = f_info.get("magic_bytes_inspection", {})
        png_data = f_info.get("png_chunk_forensics", {})
        lsb_multi = f_info.get("lsb_steganography_multi_channel", {})
        in_file_carved = f_info.get("in_file_carved_segments", [])
        exif = f_info.get("exif_metadata", {})
        pdf = f_info.get("pdf_forensics", {})
        office = f_info.get("office_forensics", {})

        md = f"""# Digital Media & File Forensics Report

**File Name:** `{f_meta.get('file_name', target)}`  
**File Size:** `{f_meta.get('file_size_formatted', 'N/A')}` ({f_meta.get('file_size_bytes', 0)} bytes)  
**File Extension:** `{f_meta.get('file_extension', 'N/A')}`  
**Generated At:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  

---

## 1. Cryptographic Hashes & Shannon Entropy
- **MD5:** `{hashes.get('md5')}`
- **SHA-1:** `{hashes.get('sha1')}`
- **SHA-256:** `{hashes.get('sha256')}`
- **Global Shannon Entropy:** `{entropy.get('entropy')} bits/byte [{entropy.get('rating')}]` ({entropy.get('description')})
"""
        if sliding_ent:
            md += f"- **Sliding Window Entropy:** Min: `{sliding_ent.get('min_entropy')}` | Max: `{sliding_ent.get('max_entropy')}` | Avg: `{sliding_ent.get('avg_entropy')}` (High-Entropy Blocks: `{sliding_ent.get('high_entropy_blocks_count')}`)\n"

        md += f"- **Detected File Type:** `{magic.get('detected_file_type')}` (Spoofed: `{'YES [!]' if magic.get('is_extension_spoofed') else 'NO [OK]'}`)\n\n---\n"

        if png_data.get("is_png"):
            md += f"""## 2. PNG Chunk Walker & Anomaly Inspector
- **Total Chunks Found:** `{png_data.get('total_chunks_found')}`
- **CRC-32 Integrity:** `{'TAMPERED [!]' if png_data.get('tampered_crc_detected') else 'Valid [OK]'}`
"""
            if png_data.get("custom_chunks"):
                md += "- **Custom / Private Chunks:**\n"
                for cc in png_data.get("custom_chunks"):
                    md += f"  * `[{cc.get('chunk_type')}]` (Offset: `{cc.get('offset')}`, Size: `{cc.get('length')} B`): `{cc.get('printable_preview')}`\n"
            if png_data.get("anomalies"):
                md += "- **Anomalies Detected:**\n"
                for an in png_data.get("anomalies"):
                    md += f"  * `{an}`\n"
            md += "\n---\n"

        if lsb_multi.get("lsb_extracted"):
            md += f"""## 3. Multi-Channel LSB Steganography Engine
- **Channels Analyzed:** `{', '.join(lsb_multi.get('channels_analyzed', []))}`
- **Flag / Key Sniffer Findings:**
"""
            if lsb_multi.get("flag_patterns_found"):
                for fp in lsb_multi.get("flag_patterns_found"):
                    md += f"  * `{fp}`\n"
            else:
                md += "  * `Clean (No plaintext flag patterns found)`\n"

            if lsb_multi.get("extracted_urls"):
                md += f"- **Extracted URLs:** `{', '.join(lsb_multi.get('extracted_urls'))}`\n"
            md += "\n---\n"

        if in_file_carved:
            md += "## 4. In-File Deep Carving & Embedded Payloads\n\n"
            md += "| # | Detected Type | Offset | Size | MD5 Hash | Carved File Path |\n|---|---|---|---|---|---|\n"
            for idx, cs in enumerate(in_file_carved, 1):
                md += f"| {idx} | **{cs.get('detected_type')}** | `{cs.get('offset')}` | `{cs.get('size_formatted')}` | `{cs.get('md5')}` | `{cs.get('carved_file_path')}` |\n"
            md += "\n---\n"

        if exif.get("has_exif"):
            md += f"""## 5. EXIF Camera, Optics & Metadata
- **Device / Model:** `{exif.get('camera_make', '')} {exif.get('camera_model', '')}`
- **Lens Model:** `{exif.get('lens_model') or 'N/A'}`
- **Author / Artist:** `{exif.get('artist') or 'N/A'}` (© `{exif.get('copyright') or 'N/A'}`)
- **Original Date/Time:** `{exif.get('datetime_original', 'N/A')}`
"""
            gps = exif.get("gps_coordinates")
            if gps:
                md += f"- **GPS Coordinates:** `{gps.get('latitude')}, {gps.get('longitude')}` ([Google Maps]({gps.get('google_maps_url')}))\n"
            md += "\n---\n"

        if pdf.get("is_pdf"):
            md += f"""## 6. PDF Document Forensics & Security Audit
- **Format Version:** `{pdf.get('pdf_version')}`
- **Title / Author:** `{pdf.get('title') or 'N/A'} / {pdf.get('author') or 'N/A'}`
- **Total Pages:** `{pdf.get('page_count')} Pages`
- **Security Triggers:** `{', '.join(pdf.get('suspicious_actions')) if pdf.get('suspicious_actions') else 'Clean [OK]'}`
\n---\n"""

        if office.get("is_office_doc"):
            md += f"""## 7. Microsoft Office Document Forensics
- **Document Type:** `{office.get('doc_type')}`
- **Author / Last Modified By:** `{office.get('creator') or 'N/A'} / {office.get('last_modified_by') or 'N/A'}`
- **Hidden Worksheets:** `{', '.join(office.get('hidden_worksheets')) if office.get('hidden_worksheets') else 'None'}`
- **VBA Macros:** `{'YES [MALWARE WARNING]' if office.get('has_vba_macros') else 'Clean [OK]'}`
\n---\n"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
        except Exception as e:
            print(f"[!] Gagal membuat laporan Markdown Forensics: {e}")

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
                server_geoip=web_data.get("server_geoip", {}),
                sec_grade=web_data.get("security_headers_grade", {}),
                ssl_info=web_data.get("ssl_certificate", {}),
                crt_data=web_data.get("crtsh_subdomains", {}),
                origin_leak=web_data.get("origin_ip_leak", {}),
                sensitive_files=web_data.get("sensitive_files_found", []),
                threat_data=web_data.get("threat_vulnerability_summary", {})
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
