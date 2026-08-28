import os
import re
import struct
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from core.base_module import BaseOSINTModule

class FileForensics(BaseOSINTModule):
    name: str = "Media & File Forensics"
    module_id: str = "file_forensics"
    description: str = "Forensik file gambar/media: Hash kriptografi, metadata EXIF, GPS koordinat, magic bytes, deteksi stego & appended data."
    version: str = "2.0.0"
    priority: int = 1
    target_type: str = "file"

    # Signature Magic Bytes Database
    MAGIC_SIGNATURES = {
        b"\xFF\xD8\xFF": ("JPEG / JPG Image", ".jpg", ".jpeg"),
        b"\x89PNG\r\n\x1a\n": ("PNG Image", ".png"),
        b"GIF87a": ("GIF Image (87a)", ".gif"),
        b"GIF89a": ("GIF Image (89a)", ".gif"),
        b"RIFF": ("WebP Image / Audio", ".webp", ".wav", ".avi"),
        b"BM": ("BMP Bitmap Image", ".bmp"),
        b"II*\x00": ("TIFF Image (Little Endian)", ".tiff", ".tif"),
        b"MM\x00*": ("TIFF Image (Big Endian)", ".tiff", ".tif"),
        b"%PDF-": ("PDF Document", ".pdf"),
        b"PK\x03\x04": ("ZIP Archive / Office Doc", ".zip", ".docx", ".xlsx"),
        b"\x7fELF": ("Linux ELF Executable", ".elf", ".bin"),
        b"MZ": ("Windows PE Executable / DLL", ".exe", ".dll")
    }

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
        detected_type = "Unknown / Binary"
        expected_exts = []
        is_spoofed = False

        for sig, (type_name, *exts) in self.MAGIC_SIGNATURES.items():
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

    def _extract_exif_metadata(self, file_path: str, file_bytes: bytes) -> Dict[str, Any]:
        """Mengekstrak metadata EXIF dan koordinat GPS dari gambar"""
        exif_info = {
            "has_exif": False,
            "camera_make": None,
            "camera_model": None,
            "software": None,
            "datetime_original": None,
            "gps_coordinates": None,
            "raw_tags": {}
        }

        # Coba menggunakan Pillow jika terinstall
        try:
            from PIL import Image, ExifTags
            with Image.open(file_path) as img:
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

                    exif_info["camera_make"] = exif_info["raw_tags"].get("Make")
                    exif_info["camera_model"] = exif_info["raw_tags"].get("Model")
                    exif_info["software"] = exif_info["raw_tags"].get("Software")
                    exif_info["datetime_original"] = exif_info["raw_tags"].get("DateTimeOriginal") or exif_info["raw_tags"].get("DateTime")

                    # Konversi GPS ke format desimal
                    if gps_data and "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
                        try:
                            def to_degrees(val):
                                d, m, s = val
                                return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)

                            lat = to_degrees(gps_data["GPSLatitude"])
                            if gps_data.get("GPSLatitudeRef") == "S":
                                lat = -lat

                            lon = to_degrees(gps_data["GPSLongitude"])
                            if gps_data.get("GPSLongitudeRef") == "W":
                                lon = -lon

                            exif_info["gps_coordinates"] = {
                                "latitude": round(lat, 6),
                                "longitude": round(lon, 6),
                                "google_maps_url": f"https://www.google.com/maps?q={round(lat,6)},{round(lon,6)}"
                            }
                        except Exception:
                            pass
        except Exception:
            # Fallback jika Pillow tidak terinstall atau format non-JPEG
            pass

        return exif_info

    def _check_appended_data_and_stego(self, file_bytes: bytes, file_ext: str) -> Dict[str, Any]:
        """Mendeteksi data biner tersembunyi setelah End-of-File (EOF) atau embedded ZIP"""
        findings = {
            "appended_data_detected": False,
            "appended_data_size_bytes": 0,
            "embedded_zip_detected": False,
            "embedded_hidden_strings_sample": []
        }

        # 1. Cek JPEG EOF (\xFF\xD9)
        if file_ext.lower() in [".jpg", ".jpeg"]:
            eoi_idx = file_bytes.rfind(b"\xFF\xD9")
            if eoi_idx != -1 and (eoi_idx + 2) < len(file_bytes):
                appended_len = len(file_bytes) - (eoi_idx + 2)
                if appended_len > 16:  # Ukuran signifikan
                    findings["appended_data_detected"] = True
                    findings["appended_data_size_bytes"] = appended_len

        # 2. Cek PNG IEND chunk
        elif file_ext.lower() == ".png":
            iend_idx = file_bytes.find(b"IEND\xaeB`\x82")
            if iend_idx != -1 and (iend_idx + 8) < len(file_bytes):
                appended_len = len(file_bytes) - (iend_idx + 8)
                if appended_len > 16:
                    findings["appended_data_detected"] = True
                    findings["appended_data_size_bytes"] = appended_len

        # 3. Cek Embedded ZIP (PK\x03\x04) di dalam file gambar
        if file_bytes.find(b"PK\x03\x04", 100) != -1:
            findings["embedded_zip_detected"] = True

        # 4. Ekstraksi String ASCII Menarik (URLs, Base64, Kunci, Email)
        ascii_strings = re.findall(rb"[\x20-\x7E]{6,}", file_bytes)
        interesting_patterns = []
        for s in ascii_strings:
            try:
                decoded = s.decode("utf-8", errors="ignore").strip()
                if any(p in decoded.lower() for p in ["http://", "https://", "flag{", "password", "token", "secret", "user", "@", "eval("]):
                    interesting_patterns.append(decoded)
            except Exception:
                pass

        findings["embedded_hidden_strings_sample"] = list(set(interesting_patterns))[:20]
        return findings

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        file_path = os.path.abspath(target.strip())

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.error_response(f"File tidak ditemukan pada path: {file_path}")

        file_size = os.path.getsize(file_path)
        _, file_ext = os.path.splitext(file_path)

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        results = {
            "file_info": {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_extension": file_ext,
                "file_size_bytes": file_size,
                "file_size_formatted": f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB"
            },
            "cryptographic_hashes": self._calculate_hashes(file_bytes),
            "magic_bytes_inspection": self._verify_magic_bytes(file_bytes, file_ext),
            "exif_metadata": self._extract_exif_metadata(file_path, file_bytes),
            "steganography_and_integrity": self._check_appended_data_and_stego(file_bytes, file_ext)
        }

        return self.success_response(results, f"Analisis Forensik File {os.path.basename(file_path)} Selesai.")
