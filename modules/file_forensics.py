import os
import re
import math
import struct
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

from core.base_module import BaseOSINTModule

# ============================================================
# UTILITY HELPER: SHANNON ENTROPY CALCULATION
# ============================================================
def calculate_shannon_entropy(data: bytes) -> Dict[str, Any]:
    """
    Menghitung Shannon Entropy dari sekumpulan byte (0.0000 - 8.0000 bits/byte).
    Digunakan untuk mendeteksi data terenkripsi, terkompresi, atau plaintext.
    """
    if not data:
        return {
            "entropy": 0.0,
            "rating": "EMPTY",
            "description": "Berkas kosong / 0 bytes"
        }

    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    entropy_val = round(entropy, 4)
    if entropy_val < 5.0:
        rating = "LOW"
        desc = "Plaintext / Uncompressed / Simple Formatted Data"
    elif entropy_val <= 7.2:
        rating = "MEDIUM"
        desc = "Structured Binary / Code / Rich Document"
    elif entropy_val <= 7.5:
        rating = "HIGH"
        desc = "Compressed Media / Standard Compressed Archive"
    else:
        rating = "VERY HIGH"
        desc = "Encrypted Payload / Cryptographic Keys / Packed Binary"

    return {
        "entropy": entropy_val,
        "rating": rating,
        "description": desc
    }


class FileForensics(BaseOSINTModule):
    name: str = "Media & File Forensics"
    module_id: str = "file_forensics"
    description: str = "Forensik mendalam gambar/media, PDF, Office: EXIF & GPS presisi, Shannon Entropy, multi-format parser, LSB stego probing, dan automatic binary carving."
    version: str = "2.5.0"
    priority: int = 1
    target_type: str = "file"

    # Signature Magic Bytes Database
    MAGIC_SIGNATURES = {
        b"\xFF\xD8\xFF": ("JPEG / JPG Image", [".jpg", ".jpeg"]),
        b"\x89PNG\r\n\x1a\n": ("PNG Image", [".png"]),
        b"GIF87a": ("GIF Image (87a)", [".gif"]),
        b"GIF89a": ("GIF Image (89a)", [".gif"]),
        b"RIFF": ("WebP Image / RIFF Media", [".webp", ".wav", ".avi"]),
        b"BM": ("BMP Bitmap Image", [".bmp"]),
        b"II*\x00": ("TIFF Image (Little Endian)", [".tiff", ".tif"]),
        b"MM\x00*": ("TIFF Image (Big Endian)", [".tiff", ".tif"]),
        b"%PDF-": ("PDF Document", [".pdf"]),
        b"PK\x03\x04": ("ZIP Archive / Office Document", [".zip", ".docx", ".xlsx", ".pptx", ".jar"]),
        b"Rar!\x1a\x07": ("RAR Archive", [".rar"]),
        b"7z\xbc\xaf\x27\x1c": ("7-Zip Archive", [".7z"]),
        b"\x1f\x8b": ("GZIP Compressed Archive", [".gz", ".tgz"]),
        b"BZh": ("BZIP2 Compressed Archive", [".bz2"]),
        b"\x7fELF": ("Linux ELF Executable", [".elf", ".bin", ".so"]),
        b"MZ": ("Windows PE Executable / DLL", [".exe", ".dll", ".sys"])
    }

    # Signature Trailing Payload Carving Headers
    CARVE_SIGNATURES = [
        (b"PK\x03\x04", "ZIP Archive / Office Container", ".zip"),
        (b"Rar!\x1a\x07\x00", "RAR 4.x Archive", ".rar"),
        (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive", ".rar"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Compressed Archive", ".7z"),
        (b"%PDF-", "Embedded PDF Document", ".pdf"),
        (b"\x7fELF", "Linux ELF Executable", ".elf"),
        (b"MZ", "Windows PE Executable / DLL", ".exe"),
        (b"\x1f\x8b", "GZIP Compressed Stream", ".gz"),
        (b"BZh", "BZIP2 Compressed Stream", ".bz2"),
        (b"\x89PNG\r\n\x1a\n", "Embedded PNG Image", ".png"),
        (b"\xFF\xD8\xFF", "Embedded JPEG Image", ".jpg"),
        (b"RIFF", "Embedded RIFF / WebP Media", ".riff"),
        (b"Salted__", "OpenSSL Encrypted Binary Blob", ".enc")
    ]

    def _calculate_hashes(self, file_bytes: bytes) -> Dict[str, str]:
        """Menghitung hash MD5, SHA-1, SHA-256, SHA-512"""
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "sha512": hashlib.sha512(file_bytes).hexdigest()
        }

    def _verify_magic_bytes(self, file_bytes: bytes, file_ext: str) -> Dict[str, Any]:
        """Memverifikasi signature magic bytes asli vs ekstensi file"""
        detected_type = "Unknown / Raw Binary"
        expected_exts: List[str] = []
        is_spoofed = False

        for sig, (type_name, exts) in self.MAGIC_SIGNATURES.items():
            if file_bytes.startswith(sig):
                detected_type = type_name
                expected_exts = exts
                break

        if expected_exts and file_ext.lower() not in expected_exts:
            is_spoofed = True

        return {
            "detected_file_type": detected_type,
            "expected_extensions": expected_exts,
            "is_extension_spoofed": is_spoofed
        }

    def _decode_user_comment(self, raw_val: Any) -> Optional[str]:
        """Decode UserComment EXIF field secara aman (menangani ASCII, Unicode, undefined)"""
        if not raw_val:
            return None
        if isinstance(raw_val, str):
            return raw_val.strip()
        if isinstance(raw_val, bytes):
            # Check for standard EXIF UserComment prefix
            if raw_val.startswith(b"ASCII\x00\x00\x00"):
                return raw_val[8:].decode("ascii", errors="ignore").strip()
            elif raw_val.startswith(b"UNICODE\x00"):
                return raw_val[8:].decode("utf-16le", errors="ignore").strip()
            elif raw_val.startswith(b"\x00" * 8):
                return raw_val[8:].decode("utf-8", errors="ignore").strip()
            try:
                return raw_val.decode("utf-8").strip()
            except Exception:
                return raw_val.decode("latin-1", errors="ignore").strip()
        return str(raw_val)

    def _format_exposure_time(self, val: Any) -> Optional[str]:
        """Formatting exposure time (e.g. 1/125s or 0.5s)"""
        if not val:
            return None
        try:
            if isinstance(val, (int, float)):
                if val < 1.0 and val > 0:
                    inv = round(1.0 / float(val))
                    return f"1/{inv}s ({val}s)"
                return f"{val}s"
            # IFD Rational object
            if hasattr(val, "numerator") and hasattr(val, "denominator"):
                return f"{val.numerator}/{val.denominator}s"
            if isinstance(val, tuple) and len(val) == 2:
                return f"{val[0]}/{val[1]}s"
        except Exception:
            pass
        return str(val)

    def _format_f_number(self, val: Any) -> Optional[str]:
        """Formatting f-number (e.g. f/2.8)"""
        if not val:
            return None
        try:
            if isinstance(val, (int, float)):
                return f"f/{round(float(val), 2)}"
            if hasattr(val, "numerator") and hasattr(val, "denominator"):
                return f"f/{round(val.numerator / val.denominator, 2)}"
            if isinstance(val, tuple) and len(val) == 2:
                return f"f/{round(val[0] / val[1], 2)}"
        except Exception:
            pass
        return str(val)

    def _format_focal_length(self, val: Any) -> Optional[str]:
        """Formatting focal length (e.g. 50.0 mm)"""
        if not val:
            return None
        try:
            if isinstance(val, (int, float)):
                return f"{round(float(val), 1)} mm"
            if hasattr(val, "numerator") and hasattr(val, "denominator"):
                return f"{round(val.numerator / val.denominator, 1)} mm"
            if isinstance(val, tuple) and len(val) == 2:
                return f"{round(val[0] / val[1], 1)} mm"
        except Exception:
            pass
        return str(val)

    def _extract_exif_metadata(self, file_path: str, file_bytes: bytes) -> Dict[str, Any]:
        """
        Ekstraksi metadata EXIF gambar lengkap & presisi:
        Artist, Copyright, UserComment, Lens, Focal Length, Exposure, Flash, dan GPS Decimal/DMS.
        """
        exif_info = {
            "has_exif": False,
            "camera_make": None,
            "camera_model": None,
            "lens_model": None,
            "lens_make": None,
            "software": None,
            "artist": None,
            "copyright": None,
            "image_description": None,
            "user_comment": None,
            "datetime_original": None,
            "datetime_digitized": None,
            "datetime_modified": None,
            "exposure_time": None,
            "f_number": None,
            "iso_speed": None,
            "focal_length": None,
            "focal_length_35mm": None,
            "flash": None,
            "exposure_program": None,
            "metering_mode": None,
            "white_balance": None,
            "image_dimensions": None,
            "color_space": None,
            "gps_coordinates": None,
            "raw_tags": {}
        }

        try:
            from PIL import Image, ExifTags
            with Image.open(file_path) as img:
                # Dimensi gambar
                exif_info["image_dimensions"] = f"{img.width} x {img.height} px"
                
                raw_exif = img._getexif()
                if raw_exif:
                    exif_info["has_exif"] = True
                    gps_data = {}

                    for tag_id, value in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        if tag_name == "GPSInfo":
                            for gps_tag_id in value:
                                sub_name = ExifTags.GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                                gps_data[sub_name] = value[gps_tag_id]
                        else:
                            if isinstance(value, (str, int, float)):
                                exif_info["raw_tags"][tag_name] = str(value)
                            elif isinstance(value, bytes):
                                exif_info["raw_tags"][tag_name] = repr(value)

                    # 1. Identitas Perangkat & Optik
                    exif_info["camera_make"] = exif_info["raw_tags"].get("Make")
                    exif_info["camera_model"] = exif_info["raw_tags"].get("Model")
                    exif_info["lens_model"] = exif_info["raw_tags"].get("LensModel") or exif_info["raw_tags"].get("Lens")
                    exif_info["lens_make"] = exif_info["raw_tags"].get("LensMake")
                    exif_info["software"] = exif_info["raw_tags"].get("Software")

                    # 2. Hak Cipta & Author
                    exif_info["artist"] = exif_info["raw_tags"].get("Artist") or exif_info["raw_tags"].get("Author") or exif_info["raw_tags"].get("XPAuthor")
                    exif_info["copyright"] = exif_info["raw_tags"].get("Copyright")
                    exif_info["image_description"] = exif_info["raw_tags"].get("ImageDescription") or exif_info["raw_tags"].get("XPTitle")
                    
                    user_comm_raw = raw_exif.get(37510) or raw_exif.get("UserComment")
                    exif_info["user_comment"] = self._decode_user_comment(user_comm_raw)

                    # 3. Waktu Pemotretan
                    exif_info["datetime_original"] = exif_info["raw_tags"].get("DateTimeOriginal")
                    exif_info["datetime_digitized"] = exif_info["raw_tags"].get("DateTimeDigitized")
                    exif_info["datetime_modified"] = exif_info["raw_tags"].get("DateTime")

                    # 4. Parameter Pengambilan Gambar
                    exif_info["exposure_time"] = self._format_exposure_time(raw_exif.get(33434) or raw_exif.get("ExposureTime"))
                    exif_info["f_number"] = self._format_f_number(raw_exif.get(33437) or raw_exif.get("FNumber"))
                    exif_info["iso_speed"] = exif_info["raw_tags"].get("ISOSpeedRatings") or exif_info["raw_tags"].get("PhotographicSensitivity")
                    exif_info["focal_length"] = self._format_focal_length(raw_exif.get(37386) or raw_exif.get("FocalLength"))
                    if raw_exif.get(41989) or raw_exif.get("FocalLengthIn35mmFilm"):
                        exif_info["focal_length_35mm"] = f"{raw_exif.get(41989) or raw_exif.get('FocalLengthIn35mmFilm')} mm"
                    
                    flash_val = raw_exif.get(37385) or raw_exif.get("Flash")
                    if flash_val is not None:
                        exif_info["flash"] = "Flash Fired" if (isinstance(flash_val, int) and (flash_val & 1)) else "Flash Did Not Fire"
                    
                    exif_info["exposure_program"] = exif_info["raw_tags"].get("ExposureProgram")
                    exif_info["metering_mode"] = exif_info["raw_tags"].get("MeteringMode")
                    exif_info["white_balance"] = exif_info["raw_tags"].get("WhiteBalance")
                    
                    cs_val = raw_exif.get(40961) or raw_exif.get("ColorSpace")
                    if cs_val == 1:
                        exif_info["color_space"] = "sRGB"
                    elif cs_val == 65535 or cs_val == 2:
                        exif_info["color_space"] = "Adobe RGB / Uncalibrated"

                    # 5. Konversi GPS Presisi (Decimal Degrees, DMS & Map Links)
                    if gps_data and "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
                        try:
                            def to_decimal(val_tuple: Tuple) -> float:
                                d, m, s = val_tuple
                                d_val = float(d.numerator) / float(d.denominator) if hasattr(d, "numerator") else float(d)
                                m_val = float(m.numerator) / float(m.denominator) if hasattr(m, "numerator") else float(m)
                                s_val = float(s.numerator) / float(s.denominator) if hasattr(s, "numerator") else float(s)
                                return d_val + (m_val / 60.0) + (s_val / 3600.0)

                            def to_dms_str(val_tuple: Tuple, ref: str) -> str:
                                d, m, s = val_tuple
                                d_val = int(float(d.numerator) / float(d.denominator) if hasattr(d, "numerator") else float(d))
                                m_val = int(float(m.numerator) / float(m.denominator) if hasattr(m, "numerator") else float(m))
                                s_val = float(s.numerator) / float(s.denominator) if hasattr(s, "numerator") else float(s)
                                return f"{d_val}°{m_val}'{s_val:.2f}\"{ref}"

                            lat_deg = to_decimal(gps_data["GPSLatitude"])
                            lat_ref = gps_data.get("GPSLatitudeRef", "N").upper()
                            if lat_ref == "S":
                                lat_deg = -lat_deg

                            lon_deg = to_decimal(gps_data["GPSLongitude"])
                            lon_ref = gps_data.get("GPSLongitudeRef", "E").upper()
                            if lon_ref == "W":
                                lon_deg = -lon_deg

                            dms_str = f"{to_dms_str(gps_data['GPSLatitude'], lat_ref)} {to_dms_str(gps_data['GPSLongitude'], lon_ref)}"

                            # Altitude calculation
                            altitude_str = None
                            if "GPSAltitude" in gps_data:
                                alt_val = gps_data["GPSAltitude"]
                                alt_num = float(alt_val.numerator) / float(alt_val.denominator) if hasattr(alt_val, "numerator") else float(alt_val)
                                alt_ref = gps_data.get("GPSAltitudeRef", 0)
                                if alt_ref == 1 or str(alt_ref) == "1":
                                    altitude_str = f"-{alt_num:.1f} m (Below Sea Level)"
                                else:
                                    altitude_str = f"{alt_num:.1f} m (Above Sea Level)"

                            exif_info["gps_coordinates"] = {
                                "latitude": round(lat_deg, 6),
                                "longitude": round(lon_deg, 6),
                                "dms_formatted": dms_str,
                                "altitude": altitude_str,
                                "google_maps_url": f"https://www.google.com/maps?q={round(lat_deg,6)},{round(lon_deg,6)}",
                                "openstreetmap_url": f"https://www.openstreetmap.org/?mlat={round(lat_deg,6)}&mlon={round(lon_deg,6)}#map=16/{round(lat_deg,6)}/{round(lon_deg,6)}"
                            }
                        except Exception:
                            pass
        except Exception:
            pass

        return exif_info

    def _parse_pdf_forensics(self, file_bytes: bytes) -> Dict[str, Any]:
        """Mengekstrak metadata forensik dan audit keamanan dari file PDF"""
        pdf_info = {
            "is_pdf": False,
            "pdf_version": None,
            "title": None,
            "author": None,
            "creator": None,
            "producer": None,
            "creation_date": None,
            "mod_date": None,
            "page_count": 0,
            "is_encrypted": False,
            "embedded_javascript": False,
            "suspicious_actions": []
        }

        if not file_bytes.startswith(b"%PDF-"):
            return pdf_info

        pdf_info["is_pdf"] = True
        
        # Ekstrak versi PDF
        v_match = re.search(rb"%PDF-([0-9\.]+)", file_bytes[:32])
        if v_match:
            pdf_info["pdf_version"] = f"PDF {v_match.group(1).decode('ascii', errors='ignore')}"

        # Ekstrak metadata Info Dictionary
        def extract_pdf_field(tag: bytes) -> Optional[str]:
            m = re.search(rb"/" + tag + rb"\s*\((.*?)\)", file_bytes)
            if m:
                return m.group(1).decode("utf-8", errors="ignore").strip()
            # Cek format hex string <feff...>
            m_hex = re.search(rb"/" + tag + rb"\s*<([0-9A-Fa-f]+)>", file_bytes)
            if m_hex:
                try:
                    return bytes.fromhex(m_hex.group(1).decode('ascii')).decode("utf-16be", errors="ignore").strip()
                except Exception:
                    pass
            return None

        pdf_info["title"] = extract_pdf_field(b"Title")
        pdf_info["author"] = extract_pdf_field(b"Author")
        pdf_info["creator"] = extract_pdf_field(b"Creator")
        pdf_info["producer"] = extract_pdf_field(b"Producer")
        
        raw_cdate = extract_pdf_field(b"CreationDate")
        if raw_cdate:
            pdf_info["creation_date"] = raw_cdate.replace("D:", "").replace("'", "")
        raw_mdate = extract_pdf_field(b"ModDate")
        if raw_mdate:
            pdf_info["mod_date"] = raw_mdate.replace("D:", "").replace("'", "")

        # Hitung jumlah halaman (/Type /Page atau /Count)
        pages_count = len(re.findall(rb"/Type\s*/Page\b", file_bytes))
        if pages_count == 0:
            count_match = re.search(rb"/Count\s+(\d+)", file_bytes)
            if count_match:
                pages_count = int(count_match.group(1))
        pdf_info["page_count"] = pages_count

        # Audit Keamanan PDF
        if b"/Encrypt" in file_bytes:
            pdf_info["is_encrypted"] = True
        if b"/JS" in file_bytes or b"/JavaScript" in file_bytes:
            pdf_info["embedded_javascript"] = True
            pdf_info["suspicious_actions"].append("Embedded JavaScript Detected (/JS /JavaScript)")
        if b"/Launch" in file_bytes:
            pdf_info["suspicious_actions"].append("Direct OS Launch Action Detected (/Launch)")
        if b"/EmbeddedFiles" in file_bytes:
            pdf_info["suspicious_actions"].append("Embedded Files / Attachment Detected (/EmbeddedFiles)")

        return pdf_info

    def _parse_office_forensics(self, file_path: str) -> Dict[str, Any]:
        """Mengekstrak metadata dokumen Office (.docx, .xlsx, .pptx) dari docProps/core.xml & app.xml"""
        office_info = {
            "is_office_doc": False,
            "doc_type": None,
            "creator": None,
            "last_modified_by": None,
            "revision": None,
            "created": None,
            "modified": None,
            "application": None,
            "app_version": None,
            "total_editing_time_minutes": None,
            "pages": None,
            "words": None,
            "characters": None,
            "has_vba_macros": False
        }

        if not zipfile.is_zipfile(file_path):
            return office_info

        try:
            with zipfile.ZipFile(file_path, "r") as z:
                namelist = z.namelist()
                
                # Cek apakah container berkas Office
                is_docx = any("word/" in n for n in namelist)
                is_xlsx = any("xl/" in n for n in namelist)
                is_pptx = any("ppt/" in n for n in namelist)

                if is_docx or is_xlsx or is_pptx:
                    office_info["is_office_doc"] = True
                    office_info["doc_type"] = "Microsoft Word Document (.docx)" if is_docx else ("Microsoft Excel Spreadsheet (.xlsx)" if is_xlsx else "Microsoft PowerPoint Presentation (.pptx)")

                # Cek VBA Macros
                if any("vbaProject.bin" in n.lower() for n in namelist):
                    office_info["has_vba_macros"] = True

                # Parse docProps/core.xml
                if "docProps/core.xml" in namelist:
                    core_xml = z.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    # Namespace map
                    ns = {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        "dcterms": "http://purl.org/dc/terms/"
                    }
                    creator_node = root.find("dc:creator", ns)
                    if creator_node is not None and creator_node.text:
                        office_info["creator"] = creator_node.text.strip()
                    
                    last_mod_node = root.find("cp:lastModifiedBy", ns)
                    if last_mod_node is not None and last_mod_node.text:
                        office_info["last_modified_by"] = last_mod_node.text.strip()

                    rev_node = root.find("cp:revision", ns)
                    if rev_node is not None and rev_node.text:
                        office_info["revision"] = rev_node.text.strip()

                    created_node = root.find("dcterms:created", ns)
                    if created_node is not None and created_node.text:
                        office_info["created"] = created_node.text.strip()

                    mod_node = root.find("dcterms:modified", ns)
                    if mod_node is not None and mod_node.text:
                        office_info["modified"] = mod_node.text.strip()

                # Parse docProps/app.xml
                if "docProps/app.xml" in namelist:
                    app_xml = z.read("docProps/app.xml")
                    root = ET.fromstring(app_xml)
                    ns_app = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    
                    app_node = root.find("ep:Application", ns_app) or root.find(".//Application")
                    if app_node is not None and app_node.text:
                        office_info["application"] = app_node.text.strip()

                    app_ver_node = root.find("ep:AppVersion", ns_app) or root.find(".//AppVersion")
                    if app_ver_node is not None and app_ver_node.text:
                        office_info["app_version"] = app_ver_node.text.strip()

                    time_node = root.find("ep:TotalTime", ns_app) or root.find(".//TotalTime")
                    if time_node is not None and time_node.text:
                        office_info["total_editing_time_minutes"] = f"{time_node.text.strip()} menit"

                    pages_node = root.find("ep:Pages", ns_app) or root.find(".//Pages")
                    if pages_node is not None and pages_node.text:
                        office_info["pages"] = pages_node.text.strip()

                    words_node = root.find("ep:Words", ns_app) or root.find(".//Words")
                    if words_node is not None and words_node.text:
                        office_info["words"] = words_node.text.strip()
        except Exception:
            pass

        return office_info

    def _probe_lsb_steganography(self, file_path: str) -> Dict[str, Any]:
        """
        Quick Probing Least Significant Bit (LSB) pada bidang warna Red, Green, Blue
        untuk mendeteksi header payload atau teks tersembunyi.
        """
        lsb_result = {
            "lsb_probed": False,
            "suspicious_stego_detected": False,
            "printable_ascii_ratio": 0.0,
            "detected_signatures": [],
            "recovered_preview": ""
        }

        try:
            from PIL import Image
            with Image.open(file_path) as img:
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

                pixels = list(img.getdata())
                max_pixels = min(len(pixels), 10000)
                
                # Ekstraksi bit 0 dari channel R, G, B
                extracted_bits = []
                for i in range(max_pixels):
                    r, g, b = pixels[i][:3]
                    extracted_bits.append(r & 1)
                    extracted_bits.append(g & 1)
                    extracted_bits.append(b & 1)

                # Rekonstruksi byte dari bit stream
                byte_chunks = bytearray()
                for i in range(0, len(extracted_bits) - 7, 8):
                    byte_val = 0
                    for bit_idx in range(8):
                        byte_val = (byte_val << 1) | extracted_bits[i + bit_idx]
                    byte_chunks.append(byte_val)

                raw_recovered = bytes(byte_chunks)
                lsb_result["lsb_probed"] = True

                # Hitung rasio karakter ASCII
                printable_count = sum(1 for b in raw_recovered if 32 <= b <= 126 or b in (9, 10, 13))
                ascii_ratio = round(printable_count / len(raw_recovered), 4) if raw_recovered else 0.0
                lsb_result["printable_ascii_ratio"] = ascii_ratio

                # Cari signature magic bytes dalam LSB
                detected_sigs = []
                for sig, sig_name, _ in self.CARVE_SIGNATURES:
                    if sig in raw_recovered:
                        detected_sigs.append(sig_name)

                # Cari pola teks tersembunyi
                text_matches = re.findall(rb"[A-Za-z0-9_\-\.]{5,}", raw_recovered)
                clean_strings = []
                for tm in text_matches:
                    try:
                        s_dec = tm.decode("ascii", errors="ignore")
                        if any(kw in s_dec.lower() for kw in ["flag", "http", "pass", "secret", "key", "admin", "token", "root"]):
                            clean_strings.append(s_dec)
                    except Exception:
                        pass

                if detected_sigs or clean_strings or ascii_ratio > 0.75:
                    lsb_result["suspicious_stego_detected"] = True
                    lsb_result["detected_signatures"] = detected_sigs
                    lsb_result["recovered_preview"] = ", ".join(clean_strings[:3]) if clean_strings else repr(raw_recovered[:40])
        except Exception:
            pass

        return lsb_result

    def _carve_and_extract_payload(self, file_bytes: bytes, file_ext: str, target_path: str) -> Dict[str, Any]:
        """
        Deteksi trailing bytes setelah marker EOF resmi, inspeksi signature,
        ekstraksi Shannon Entropy, dan simpan/carve payload otomatis ke subfolder `output/carved/`.
        """
        carve_result = {
            "eof_detected": False,
            "eof_offset": 0,
            "has_trailing_payload": False,
            "trailing_size_bytes": 0,
            "trailing_size_formatted": "0 B",
            "trailing_entropy": 0.0,
            "trailing_entropy_rating": "N/A",
            "detected_payload_type": "None",
            "carved_file_path": None,
            "carved_file_md5": None,
            "carved_file_sha256": None,
            "interesting_strings": []
        }

        total_len = len(file_bytes)
        eof_idx = -1

        # 1. Tentukan offset EOF berdasarkan format file
        ext_lower = file_ext.lower()
        if ext_lower in [".jpg", ".jpeg"]:
            # JPEG End-of-Image marker: \xFF\xD9
            last_eoi = file_bytes.rfind(b"\xFF\xD9")
            if last_eoi != -1:
                eof_idx = last_eoi + 2
                carve_result["eof_detected"] = True
        elif ext_lower == ".png":
            # PNG IEND chunk: IEND\xaeB`\x82 (offset + 8 bytes)
            iend_pos = file_bytes.find(b"IEND\xaeB`\x82")
            if iend_pos != -1:
                eof_idx = iend_pos + 8
                carve_result["eof_detected"] = True
        elif ext_lower == ".gif":
            # GIF trailer: \x00\x3B (atau \x3B di akhir)
            gif_pos = file_bytes.rfind(b"\x3B")
            if gif_pos != -1:
                eof_idx = gif_pos + 1
                carve_result["eof_detected"] = True
        elif ext_lower == ".pdf":
            # PDF %%EOF marker
            pdf_eof = file_bytes.rfind(b"%%EOF")
            if pdf_eof != -1:
                eof_idx = pdf_eof + 5
                carve_result["eof_detected"] = True

        carve_result["eof_offset"] = eof_idx

        # 2. Jika terdeteksi trailing bytes signifikan (> 8 bytes)
        if eof_idx != -1 and (total_len - eof_idx) > 8:
            trailing_data = file_bytes[eof_idx:]
            trailing_len = len(trailing_data)
            
            carve_result["has_trailing_payload"] = True
            carve_result["trailing_size_bytes"] = trailing_len
            carve_result["trailing_size_formatted"] = f"{trailing_len / 1024:.2f} KB" if trailing_len < 1024*1024 else f"{trailing_len / (1024*1024):.2f} MB"

            # Hitung Shannon Entropy Trailing Data
            t_entropy = calculate_shannon_entropy(trailing_data)
            carve_result["trailing_entropy"] = t_entropy["entropy"]
            carve_result["trailing_entropy_rating"] = f"{t_entropy['rating']} ({t_entropy['description']})"

            # Identifikasi Signature Payload
            payload_desc = "Raw Appended Binary Data"
            file_extension = ".bin"

            for sig, sig_name, ext in self.CARVE_SIGNATURES:
                if trailing_data.startswith(sig):
                    payload_desc = sig_name
                    file_extension = ext
                    break

            carve_result["detected_payload_type"] = payload_desc

            # 3. Otomasi Penyimpanan / Carving ke Subfolder `output/carved/`
            try:
                carved_dir = os.path.join(os.getcwd(), "output", "carved")
                os.makedirs(carved_dir, exist_ok=True)

                timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                payload_md5 = hashlib.md5(trailing_data).hexdigest()
                payload_sha256 = hashlib.sha256(trailing_data).hexdigest()

                carved_filename = f"carved_{timestamp_str}_{payload_md5[:8]}{file_extension}"
                carved_path = os.path.join(carved_dir, carved_filename)

                with open(carved_path, "wb") as f_carved:
                    f_carved.write(trailing_data)

                carve_result["carved_file_path"] = carved_path
                carve_result["carved_file_md5"] = payload_md5
                carve_result["carved_file_sha256"] = payload_sha256
            except Exception as e:
                self.logger.debug(f"Carving save warning: {e}")

            # 4. Ekstraksi String ASCII Menarik dari Trailing Data
            strings_found = re.findall(rb"[\x20-\x7E]{5,}", trailing_data)
            interesting_list = []
            for s in strings_found:
                try:
                    dec_str = s.decode("utf-8", errors="ignore").strip()
                    if any(k in dec_str.lower() for k in ["http://", "https://", "flag{", "password", "token", "secret", "user", "admin", "key", "eval("]):
                        interesting_list.append(dec_str)
                except Exception:
                    pass

            carve_result["interesting_strings"] = list(set(interesting_list))[:15]

        return carve_result

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        file_path = os.path.abspath(target.strip())

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.error_response(f"File tidak ditemukan pada path: {file_path}")

        file_size = os.path.getsize(file_path)
        _, file_ext = os.path.splitext(file_path)

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        # 1. Shannon Entropy Analysis (File Penuh)
        file_entropy = calculate_shannon_entropy(file_bytes)

        # 2. Hashes Kriptografi
        hashes = self._calculate_hashes(file_bytes)

        # 3. Verifikasi Magic Bytes
        magic_check = self._verify_magic_bytes(file_bytes, file_ext)

        # 4. Ekstraksi Metadata EXIF & GPS
        exif_meta = self._extract_exif_metadata(file_path, file_bytes)

        # 5. Multi-Format Parsers (PDF & Office)
        pdf_meta = self._parse_pdf_forensics(file_bytes)
        office_meta = self._parse_office_forensics(file_path)

        # 6. LSB Steganography Probing
        lsb_stego = self._probe_lsb_steganography(file_path)

        # 7. Deep Binary Carving & Trailing Payload Extraction
        carving_data = self._carve_and_extract_payload(file_bytes, file_ext, file_path)

        results = {
            "file_info": {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_extension": file_ext,
                "file_size_bytes": file_size,
                "file_size_formatted": f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB"
            },
            "cryptographic_hashes": hashes,
            "shannon_entropy": file_entropy,
            "magic_bytes_inspection": magic_check,
            "exif_metadata": exif_meta,
            "pdf_forensics": pdf_meta,
            "office_forensics": office_meta,
            "lsb_steganography": lsb_stego,
            "binary_carving_and_payload": carving_data,
            # Backward compatibility key
            "steganography_and_integrity": {
                "appended_data_detected": carving_data.get("has_trailing_payload", False),
                "appended_data_size_bytes": carving_data.get("trailing_size_bytes", 0),
                "embedded_zip_detected": "ZIP" in carving_data.get("detected_payload_type", ""),
                "embedded_hidden_strings_sample": carving_data.get("interesting_strings", [])
            }
        }

        return self.success_response(results, f"Analisis Forensik Berkas {os.path.basename(file_path)} Berhasil Diselesaikan.")
