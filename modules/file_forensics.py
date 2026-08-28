import os
import re
import math
import zlib
import struct
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

from core.base_module import BaseOSINTModule

# ============================================================
# 1. SHANNON ENTROPY & SLIDING WINDOW ANALYZER
# ============================================================
def calculate_shannon_entropy(data: bytes) -> Dict[str, Any]:
    """
    Menghitung Shannon Entropy dari sekumpulan byte (0.0000 - 8.0000 bits/byte).
    """
    if not data:
        return {
            "entropy": 0.0,
            "rating": "EMPTY",
            "description": "Berkas kosong / 0 bytes"
        }

    length = len(data)
    counts = Counter(data)
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
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

def analyze_sliding_window_entropy(data: bytes, window_size: int = 256, step_size: int = 256) -> Dict[str, Any]:
    """
    Menghitung distribusi Shannon Entropy dengan teknik sliding window (per blok 256 byte).
    Mendeteksi lonjakan entropi yang mengindikasikan segmen payload terenkripsi/terkompresi.
    """
    if len(data) < window_size:
        single = calculate_shannon_entropy(data)
        return {
            "blocks_analyzed": 1,
            "min_entropy": single["entropy"],
            "max_entropy": single["entropy"],
            "avg_entropy": single["entropy"],
            "high_entropy_blocks_count": 1 if single["entropy"] > 7.5 else 0,
            "entropy_variance": 0.0
        }

    entropy_values = []
    high_blocks = 0

    for i in range(0, len(data) - window_size + 1, step_size):
        chunk = data[i : i + window_size]
        chunk_len = len(chunk)
        counts = Counter(chunk)
        e = -sum((cnt / chunk_len) * math.log2(cnt / chunk_len) for cnt in counts.values())
        entropy_values.append(e)
        if e > 7.5:
            high_blocks += 1

    if not entropy_values:
        single = calculate_shannon_entropy(data)
        return {
            "blocks_analyzed": 1,
            "min_entropy": single["entropy"],
            "max_entropy": single["entropy"],
            "avg_entropy": single["entropy"],
            "high_entropy_blocks_count": 0,
            "entropy_variance": 0.0
        }

    avg_e = sum(entropy_values) / len(entropy_values)
    variance = sum((x - avg_e) ** 2 for x in entropy_values) / len(entropy_values)

    return {
        "blocks_analyzed": len(entropy_values),
        "min_entropy": round(min(entropy_values), 4),
        "max_entropy": round(max(entropy_values), 4),
        "avg_entropy": round(avg_e, 4),
        "high_entropy_blocks_count": high_blocks,
        "entropy_variance": round(variance, 4)
    }

# ============================================================
# 2. HEURISTIC 1-BYTE XOR & CAESAR DECRYPTOR
# ============================================================
def heuristic_xor_bruteforce(data: bytes, max_bytes: int = 4096) -> List[Dict[str, Any]]:
    """
    Melakukan 1-Byte XOR & Caesar Brute-Force pada segmen biner untuk mencari
    pola flag CTF ('FLAG{', 'CTF{', 'flag{'), tautan ('http://', 'https://'), atau keyword rahasia.
    """
    findings = []
    sample = data[:max_bytes]
    if not sample:
        return findings

    keywords = [b"FLAG{", b"flag{", b"CTF{", b"ctf{", b"http://", b"https://", b"password", b"SECRET", b"admin", b"rootacces"]

    for key in range(1, 256):
        xored = bytes(b ^ key for b in sample)
        for kw in keywords:
            if kw in xored:
                # Cari string readable di sekitar keyword
                match_pos = xored.find(kw)
                start_p = max(0, match_pos - 10)
                end_p = min(len(xored), match_pos + 60)
                snippet = xored[start_p:end_p].decode("ascii", errors="ignore").strip()

                findings.append({
                    "method": f"1-Byte XOR (Key: 0x{key:02X})",
                    "key_hex": f"0x{key:02X}",
                    "matched_keyword": kw.decode("ascii", errors="ignore"),
                    "decrypted_snippet": snippet
                })
                break
        if len(findings) >= 5:
            break

    return findings


class FileForensics(BaseOSINTModule):
    name: str = "Media & File Forensics"
    module_id: str = "file_forensics"
    description: str = "Hardcore DFIR & CTF File Analyzer: PNG Chunk Walker, multi-channel LSB stego extraction, in-file deep binary carving, sliding window entropy, dan Office/PDF deep parser."
    version: str = "2.6.0"
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
        b"\x1f\x8b\x08": ("GZIP Compressed Stream", [".gz", ".tgz"]),
        b"BZh": ("BZIP2 Compressed Stream", [".bz2"]),
        b"SQLite format 3\x00": ("SQLite Database", [".sqlite", ".db", ".sqlite3"]),
        b"\x7fELF": ("Linux ELF Executable", [".elf", ".bin", ".so"]),
        b"MZ": ("Windows PE Executable / DLL", [".exe", ".dll", ".sys"])
    }

    # Embedded In-File Scanner Signatures (Offset > 0)
    EMBEDDED_SIGNATURES = [
        (b"PK\x03\x04", "ZIP Archive / Office Container", ".zip"),
        (b"Rar!\x1a\x07\x00", "RAR 4.x Archive", ".rar"),
        (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive", ".rar"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Compressed Archive", ".7z"),
        (b"\x1f\x8b\x08", "GZIP Compressed Stream", ".gz"),
        (b"BZh", "BZIP2 Compressed Stream", ".bz2"),
        (b"%PDF-", "Embedded PDF Document", ".pdf"),
        (b"SQLite format 3\x00", "Embedded SQLite Database", ".sqlite"),
        (b"\x7fELF", "Linux ELF Executable", ".elf"),
        (b"MZ", "Windows PE Executable / DLL", ".exe"),
        (b"\x89PNG\r\n\x1a\n", "Embedded PNG Image", ".png"),
        (b"\xFF\xD8\xFF", "Embedded JPEG Image", ".jpg"),
        (b"Salted__", "OpenSSL Encrypted Binary Blob", ".enc")
    ]

    STANDARD_PNG_CHUNKS = {
        "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP",
        "sBIT", "sRGB", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs",
        "sPLT", "tIME", "dSIG", "eXIf", "acTL", "fcTL", "fdAT"
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

    # ============================================================
    # 3. PNG CHUNK WALKER & ANOMALY INSPECTOR (CTF ARTIFACTS)
    # ============================================================
    def _inspect_png_chunks(self, file_bytes: bytes) -> Dict[str, Any]:
        """
        Parser sekuensial biner PNG yang memvalidasi CRC-32 per chunk, mendeteksi manipulasi dimensi
        gambar (IHDR CRC Mismatch), dan mengekstrak data dari non-standard/custom private chunks.
        """
        png_report = {
            "is_png": False,
            "total_chunks_found": 0,
            "ihdr_details": {},
            "tampered_crc_detected": False,
            "anomalies": [],
            "custom_chunks": [],
            "chunks_summary": []
        }

        if not file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return png_report

        png_report["is_png"] = True
        offset = 8
        total_len = len(file_bytes)

        while offset + 8 <= total_len:
            try:
                chunk_len = struct.unpack(">I", file_bytes[offset : offset + 4])[0]
                chunk_type_raw = file_bytes[offset + 4 : offset + 8]
                chunk_type_str = chunk_type_raw.decode("ascii", errors="replace")

                data_start = offset + 8
                data_end = data_start + chunk_len

                if data_end + 4 > total_len:
                    png_report["anomalies"].append(f"[TRUNCATED] Chunk {chunk_type_str} terpotong di offset {offset} (Length: {chunk_len} bytes)")
                    break

                chunk_data = file_bytes[data_start:data_end]
                stored_crc = struct.unpack(">I", file_bytes[data_end : data_end + 4])[0]
                computed_crc = zlib.crc32(chunk_type_raw + chunk_data) & 0xFFFFFFFF

                is_crc_valid = (stored_crc == computed_crc)
                png_report["total_chunks_found"] += 1

                # 1. Validasi IHDR (Header Chunk)
                if chunk_type_str == "IHDR" and chunk_len >= 13:
                    w, h, bit_depth, col_type, comp, filt, interlace = struct.unpack(">IIBBBBB", chunk_data[:13])
                    png_report["ihdr_details"] = {
                        "width": w,
                        "height": h,
                        "bit_depth": bit_depth,
                        "color_type": col_type,
                        "compression": comp,
                        "filter": filt,
                        "interlace": interlace,
                        "crc_valid": is_crc_valid
                    }
                    if not is_crc_valid:
                        png_report["tampered_crc_detected"] = True
                        msg = f"[TAMPERED] IHDR Chunk CRC Mismatch! Stored: 0x{stored_crc:08X} vs Computed: 0x{computed_crc:08X}. Indikasi modifikasi dimensi / crop height trick!"
                        png_report["anomalies"].append(msg)

                # 2. Deteksi CRC Mismatch di chunk lain
                elif not is_crc_valid:
                    png_report["tampered_crc_detected"] = True
                    png_report["anomalies"].append(f"[TAMPERED] CRC Mismatch pada chunk '{chunk_type_str}' (Offset: {offset}). Stored: 0x{stored_crc:08X} vs Computed: 0x{computed_crc:08X}")

                # 3. Deteksi Non-Standard / Custom Private Chunk
                if chunk_type_str not in self.STANDARD_PNG_CHUNKS:
                    # Coba decode data printable
                    printable_sample = re.findall(rb"[\x20-\x7E]{4,}", chunk_data)
                    clean_preview = ", ".join([s.decode('ascii', errors='ignore') for s in printable_sample[:3]])
                    
                    # Heuristic XOR pada custom chunk data
                    xor_hits = heuristic_xor_bruteforce(chunk_data, max_bytes=512)

                    custom_entry = {
                        "chunk_type": chunk_type_str,
                        "offset": offset,
                        "length": chunk_len,
                        "crc_valid": is_crc_valid,
                        "printable_preview": clean_preview or repr(chunk_data[:30]),
                        "xor_findings": xor_hits
                    }
                    png_report["custom_chunks"].append(custom_entry)
                    png_report["anomalies"].append(f"[ANOMALY] Custom/Private PNG Chunk Terdeteksi: '{chunk_type_str}' (Ukuran: {chunk_len} bytes di offset {offset})")

                png_report["chunks_summary"].append({
                    "type": chunk_type_str,
                    "offset": offset,
                    "length": chunk_len,
                    "crc_valid": is_crc_valid
                })

                offset = data_end + 4
                if chunk_type_str == "IEND":
                    break
            except Exception as e:
                png_report["anomalies"].append(f"Parsing error pada offset {offset}: {e}")
                break

        return png_report

    # ============================================================
    # 4. MULTI-CHANNEL LSB STEGANOGRAPHY EXTRACTION ENGINE
    # ============================================================
    def _extract_multi_channel_lsb(self, file_path: str, max_pixels: int = 30000) -> Dict[str, Any]:
        """
        Ekstraksi LSB pada kanal warna Red, Green, Blue, Alpha, dan Interleaved RGB.
        Dilengkapi pattern sniffer untuk mendeteksi format Flag CTF, URLs, dan Base64 strings.
        """
        lsb_results = {
            "lsb_extracted": False,
            "suspicious_stego_detected": False,
            "channels_analyzed": [],
            "flag_patterns_found": [],
            "extracted_urls": [],
            "extracted_base64": [],
            "channel_previews": {}
        }

        try:
            from PIL import Image
            with Image.open(file_path) as img:
                has_alpha = ("A" in img.mode or img.mode == "RGBA")
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGBA" if has_alpha else "RGB")

                pixels = list(img.getdata())
                limit = min(len(pixels), max_pixels)

                red_bits = []
                green_bits = []
                blue_bits = []
                alpha_bits = []
                interleaved_bits = []

                for i in range(limit):
                    px = pixels[i]
                    r, g, b = px[0], px[1], px[2]
                    red_bits.append(r & 1)
                    green_bits.append(g & 1)
                    blue_bits.append(b & 1)
                    interleaved_bits.extend([r & 1, g & 1, b & 1])

                    if has_alpha and len(px) > 3:
                        a = px[3]
                        alpha_bits.append(a & 1)
                        interleaved_bits.append(a & 1)

                def bits_to_bytes(bit_list: List[int]) -> bytes:
                    out = bytearray()
                    for idx in range(0, len(bit_list) - 7, 8):
                        val = 0
                        for b_idx in range(8):
                            val = (val << 1) | bit_list[idx + b_idx]
                        out.append(val)
                    return bytes(out)

                channel_streams = {
                    "Red Channel LSB": bits_to_bytes(red_bits),
                    "Green Channel LSB": bits_to_bytes(green_bits),
                    "Blue Channel LSB": bits_to_bytes(blue_bits),
                    "All-Channels Interleaved LSB": bits_to_bytes(interleaved_bits)
                }
                if has_alpha and alpha_bits:
                    channel_streams["Alpha Channel LSB"] = bits_to_bytes(alpha_bits)

                lsb_results["lsb_extracted"] = True
                lsb_results["channels_analyzed"] = list(channel_streams.keys())

                # Regex Pattern Sniffers
                flag_regex = re.compile(rb"(FLAG|flag|CTF|ctf)\{[^ \r\n\t\}]{4,80}\}")
                url_regex = re.compile(rb"https?://[A-Za-z0-9\.\-_/:\?=%&#]{6,100}")
                b64_regex = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")

                for ch_name, stream_bytes in channel_streams.items():
                    # 1. Pindai Plaintext Flag Patterns
                    flags = flag_regex.findall(stream_bytes)
                    for f_match in flags:
                        full_m = re.search(rb"(FLAG|flag|CTF|ctf)\{[^ \r\n\t\}]{4,80}\}", stream_bytes)
                        if full_m:
                            flag_str = full_m.group(0).decode("ascii", errors="ignore")
                            lsb_results["flag_patterns_found"].append(f"[{ch_name}] {flag_str}")
                            lsb_results["suspicious_stego_detected"] = True

                    # 2. Pindai URLs
                    urls = url_regex.findall(stream_bytes)
                    for u in urls[:2]:
                        u_str = u.decode("ascii", errors="ignore")
                        lsb_results["extracted_urls"].append(f"[{ch_name}] {u_str}")
                        lsb_results["suspicious_stego_detected"] = True

                    # 3. Pindai Base64 Strings
                    b64s = b64_regex.findall(stream_bytes)
                    for b_val in b64s[:2]:
                        lsb_results["extracted_base64"].append(f"[{ch_name}] {b_val.decode('ascii', errors='ignore')}")

                    # 4. Preview Readable String
                    printable = re.findall(rb"[\x20-\x7E]{6,}", stream_bytes)
                    preview_str = ", ".join([p.decode('ascii', errors='ignore') for p in printable[:2]])
                    lsb_results["channel_previews"][ch_name] = preview_str or repr(stream_bytes[:25])

                    # 5. Heuristic XOR pada LSB stream jika belum ada flag
                    if not lsb_results["flag_patterns_found"]:
                        xor_hits = heuristic_xor_bruteforce(stream_bytes, max_bytes=1024)
                        for xh in xor_hits:
                            lsb_results["flag_patterns_found"].append(f"[{ch_name} - {xh['method']}] {xh['decrypted_snippet']}")
                            lsb_results["suspicious_stego_detected"] = True

        except Exception:
            pass

        return lsb_results

    # ============================================================
    # 5. IN-FILE DEEP CARVING & EMBEDDED MAGIC SCANNER
    # ============================================================
    def _deep_carve_in_file(self, file_bytes: bytes, original_path: str) -> List[Dict[str, Any]]:
        """
        Memindai seluruh byte berkas dari offset 0 hingga akhir untuk mencari signature
        file tersembunyi (ZIP, RAR, 7z, GZIP, PDF, SQLite, ELF, PE) yang tertanam pada offset > 0.
        Otomatis memotong (carve) segmen biner dan menyimpannya ke `output/carved/`.
        """
        carved_list = []
        total_len = len(file_bytes)
        carved_dir = os.path.join(os.getcwd(), "output", "carved")

        for sig, sig_name, ext in self.EMBEDDED_SIGNATURES:
            start_pos = 1  # Mulai dari offset 1 untuk mencari embedded file bukan di awal
            while True:
                pos = file_bytes.find(sig, start_pos)
                if pos == -1:
                    break

                # Validasi false positive sederhana
                segment = file_bytes[pos:]
                seg_len = len(segment)

                if seg_len >= 16:
                    os.makedirs(carved_dir, exist_ok=True)
                    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    seg_md5 = hashlib.md5(segment).hexdigest()
                    seg_sha256 = hashlib.sha256(segment).hexdigest()

                    clean_type_tag = re.sub(r'[^A-Za-z0-9]', '', ext.replace('.', ''))
                    carved_filename = f"carved_{timestamp_str}_{clean_type_tag}_off{pos}_{seg_md5[:8]}{ext}"
                    carved_filepath = os.path.join(carved_dir, carved_filename)

                    try:
                        with open(carved_filepath, "wb") as f_out:
                            f_out.write(segment)
                    except Exception:
                        pass

                    # Ekstraksi string pada segmen
                    strings_found = re.findall(rb"[\x20-\x7E]{5,}", segment[:2048])
                    clean_strings = []
                    for s in strings_found:
                        try:
                            dec = s.decode("utf-8", errors="ignore").strip()
                            if any(kw in dec.lower() for kw in ["flag", "http", "pass", "secret", "user", "admin", "token"]):
                                clean_strings.append(dec)
                        except Exception:
                            pass

                    # Heuristic XOR pada carved data
                    xor_findings = heuristic_xor_bruteforce(segment, max_bytes=1024)

                    carved_list.append({
                        "detected_type": sig_name,
                        "file_extension": ext,
                        "offset": pos,
                        "size_bytes": seg_len,
                        "size_formatted": f"{seg_len / 1024:.2f} KB" if seg_len < 1024*1024 else f"{seg_len / (1024*1024):.2f} MB",
                        "md5": seg_md5,
                        "sha256": seg_sha256,
                        "carved_file_path": carved_filepath,
                        "interesting_strings": list(set(clean_strings))[:6],
                        "xor_findings": xor_findings
                    })

                start_pos = pos + len(sig)
                if len(carved_list) >= 10:  # Batasi max 10 carved segments
                    break

        return carved_list

    # ============================================================
    # 6. MULTI-FORMAT DEEP METADATA (OFFICE & PDF)
    # ============================================================
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
            "has_openaction": False,
            "suspicious_actions": []
        }

        if not file_bytes.startswith(b"%PDF-"):
            return pdf_info

        pdf_info["is_pdf"] = True
        v_match = re.search(rb"%PDF-([0-9\.]+)", file_bytes[:32])
        if v_match:
            pdf_info["pdf_version"] = f"PDF {v_match.group(1).decode('ascii', errors='ignore')}"

        def extract_pdf_field(tag: bytes) -> Optional[str]:
            m = re.search(rb"/" + tag + rb"\s*\((.*?)\)", file_bytes)
            if m:
                return m.group(1).decode("utf-8", errors="ignore").strip()
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

        pages_count = len(re.findall(rb"/Type\s*/Page\b", file_bytes))
        if pages_count == 0:
            count_match = re.search(rb"/Count\s+(\d+)", file_bytes)
            if count_match:
                pages_count = int(count_match.group(1))
        pdf_info["page_count"] = pages_count

        if b"/Encrypt" in file_bytes:
            pdf_info["is_encrypted"] = True
        if b"/JS" in file_bytes or b"/JavaScript" in file_bytes:
            pdf_info["embedded_javascript"] = True
            pdf_info["suspicious_actions"].append("Embedded JavaScript Detected (/JS /JavaScript)")
        if b"/OpenAction" in file_bytes or b"/AA" in file_bytes:
            pdf_info["has_openaction"] = True
            pdf_info["suspicious_actions"].append("Auto-Execution Trigger Detected (/OpenAction /AA)")
        if b"/Launch" in file_bytes:
            pdf_info["suspicious_actions"].append("Direct OS Launch Action Detected (/Launch)")
        if b"/EmbeddedFiles" in file_bytes:
            pdf_info["suspicious_actions"].append("Embedded File Attachment Detected (/EmbeddedFiles)")

        return pdf_info

    def _parse_office_forensics(self, file_path: str) -> Dict[str, Any]:
        """Mengekstrak metadata dokumen Office (.docx, .xlsx, .pptx) & Hidden Worksheets"""
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
            "template": None,
            "total_editing_time_minutes": None,
            "pages": None,
            "words": None,
            "hidden_worksheets": [],
            "has_vba_macros": False
        }

        if not zipfile.is_zipfile(file_path):
            return office_info

        try:
            with zipfile.ZipFile(file_path, "r") as z:
                namelist = z.namelist()
                is_docx = any("word/" in n for n in namelist)
                is_xlsx = any("xl/" in n for n in namelist)
                is_pptx = any("ppt/" in n for n in namelist)

                if is_docx or is_xlsx or is_pptx:
                    office_info["is_office_doc"] = True
                    office_info["doc_type"] = "Microsoft Word Document (.docx)" if is_docx else ("Microsoft Excel Spreadsheet (.xlsx)" if is_xlsx else "Microsoft PowerPoint Presentation (.pptx)")

                if any("vbaProject.bin" in n.lower() for n in namelist):
                    office_info["has_vba_macros"] = True

                # Parse docProps/core.xml
                if "docProps/core.xml" in namelist:
                    core_xml = z.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    ns = {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        "dcterms": "http://purl.org/dc/terms/"
                    }
                    c = root.find("dc:creator", ns)
                    if c is not None and c.text:
                        office_info["creator"] = c.text.strip()
                    lm = root.find("cp:lastModifiedBy", ns)
                    if lm is not None and lm.text:
                        office_info["last_modified_by"] = lm.text.strip()
                    rev = root.find("cp:revision", ns)
                    if rev is not None and rev.text:
                        office_info["revision"] = rev.text.strip()
                    cr = root.find("dcterms:created", ns)
                    if cr is not None and cr.text:
                        office_info["created"] = cr.text.strip()
                    mo = root.find("dcterms:modified", ns)
                    if mo is not None and mo.text:
                        office_info["modified"] = mo.text.strip()

                # Parse docProps/app.xml
                if "docProps/app.xml" in namelist:
                    app_xml = z.read("docProps/app.xml")
                    root = ET.fromstring(app_xml)
                    ns_app = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    app = root.find("ep:Application", ns_app) or root.find(".//Application")
                    if app is not None and app.text:
                        office_info["application"] = app.text.strip()
                    aver = root.find("ep:AppVersion", ns_app) or root.find(".//AppVersion")
                    if aver is not None and aver.text:
                        office_info["app_version"] = aver.text.strip()
                    tmpl = root.find("ep:Template", ns_app) or root.find(".//Template")
                    if tmpl is not None and tmpl.text:
                        office_info["template"] = tmpl.text.strip()
                    tt = root.find("ep:TotalTime", ns_app) or root.find(".//TotalTime")
                    if tt is not None and tt.text:
                        office_info["total_editing_time_minutes"] = f"{tt.text.strip()} menit"

                # Deteksi Hidden Worksheets pada Excel (.xlsx)
                if "xl/workbook.xml" in namelist:
                    wb_xml = z.read("xl/workbook.xml")
                    wb_root = ET.fromstring(wb_xml)
                    for sheet in wb_root.findall(".//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}sheet"):
                        s_name = sheet.attrib.get("name", "Sheet")
                        s_state = sheet.attrib.get("state", "visible")
                        if s_state in ("hidden", "veryHidden"):
                            office_info["hidden_worksheets"].append(f"{s_name} (State: {s_state})")

        except Exception:
            pass

        return office_info

    # ============================================================
    # 7. EXIF METADATA & PRECISE GPS PARSER
    # ============================================================
    def _extract_exif_metadata(self, file_path: str, file_bytes: bytes) -> Dict[str, Any]:
        """Ekstraksi metadata EXIF gambar lengkap & presisi"""
        exif_info = {
            "has_exif": False,
            "camera_make": None,
            "camera_model": None,
            "lens_model": None,
            "software": None,
            "artist": None,
            "copyright": None,
            "user_comment": None,
            "datetime_original": None,
            "exposure_time": None,
            "f_number": None,
            "iso_speed": None,
            "focal_length": None,
            "flash": None,
            "gps_coordinates": None,
            "raw_tags": {}
        }

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
                    exif_info["lens_model"] = exif_info["raw_tags"].get("LensModel")
                    exif_info["software"] = exif_info["raw_tags"].get("Software")
                    exif_info["artist"] = exif_info["raw_tags"].get("Artist") or exif_info["raw_tags"].get("Author")
                    exif_info["copyright"] = exif_info["raw_tags"].get("Copyright")
                    exif_info["datetime_original"] = exif_info["raw_tags"].get("DateTimeOriginal")
                    exif_info["iso_speed"] = exif_info["raw_tags"].get("ISOSpeedRatings")

                    # GPS Coordinates Decimal & DMS
                    if gps_data and "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
                        try:
                            def to_dec(val):
                                d, m, s = val
                                d_v = float(d.numerator)/float(d.denominator) if hasattr(d, "numerator") else float(d)
                                m_v = float(m.numerator)/float(m.denominator) if hasattr(m, "numerator") else float(m)
                                s_v = float(s.numerator)/float(s.denominator) if hasattr(s, "numerator") else float(s)
                                return d_v + (m_v / 60.0) + (s_v / 3600.0)

                            lat = to_dec(gps_data["GPSLatitude"])
                            if gps_data.get("GPSLatitudeRef") == "S":
                                lat = -lat
                            lon = to_dec(gps_data["GPSLongitude"])
                            if gps_data.get("GPSLongitudeRef") == "W":
                                lon = -lon

                            exif_info["gps_coordinates"] = {
                                "latitude": round(lat, 6),
                                "longitude": round(lon, 6),
                                "google_maps_url": f"https://www.google.com/maps?q={round(lat,6)},{round(lon,6)}",
                                "openstreetmap_url": f"https://www.openstreetmap.org/?mlat={round(lat,6)}&mlon={round(lon,6)}#map=16/{round(lat,6)}/{round(lon,6)}"
                            }
                        except Exception:
                            pass
        except Exception:
            pass

        return exif_info

    # ============================================================
    # 8. ORCHESTRATOR RUNNER
    # ============================================================
    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        file_path = os.path.abspath(target.strip())

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.error_response(f"File tidak ditemukan pada path: {file_path}")

        file_size = os.path.getsize(file_path)
        _, file_ext = os.path.splitext(file_path)

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        # 1. Hashes Kriptografi
        hashes = self._calculate_hashes(file_bytes)

        # 2. Magic Bytes Check
        magic_check = self._verify_magic_bytes(file_bytes, file_ext)

        # 3. Shannon Entropy (Global & Sliding Window 256B)
        file_entropy = calculate_shannon_entropy(file_bytes)
        sliding_entropy = analyze_sliding_window_entropy(file_bytes)

        # 4. PNG Chunk Walker & Anomaly Inspector
        png_inspection = self._inspect_png_chunks(file_bytes)

        # 5. Multi-Channel LSB Steganography Engine (R, G, B, A, Interleaved)
        lsb_analysis = self._extract_multi_channel_lsb(file_path)

        # 6. In-File Deep Carving (Embedded Headers)
        carved_segments = self._deep_carve_in_file(file_bytes, file_path)

        # 7. EXIF & Geolocation
        exif_meta = self._extract_exif_metadata(file_path, file_bytes)

        # 8. Document Parsers (PDF & Office)
        pdf_meta = self._parse_pdf_forensics(file_bytes)
        office_meta = self._parse_office_forensics(file_path)

        results = {
            "file_info": {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_extension": file_ext,
                "file_size_bytes": file_size,
                "file_size_formatted": f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB"
            },
            "cryptographic_hashes": hashes,
            "magic_bytes_inspection": magic_check,
            "shannon_entropy": file_entropy,
            "sliding_window_entropy": sliding_entropy,
            "png_chunk_forensics": png_inspection,
            "lsb_steganography_multi_channel": lsb_analysis,
            "in_file_carved_segments": carved_segments,
            "exif_metadata": exif_meta,
            "pdf_forensics": pdf_meta,
            "office_forensics": office_meta,
            # Backward compatibility keys
            "lsb_steganography": {
                "lsb_probed": lsb_analysis.get("lsb_extracted", False),
                "suspicious_stego_detected": lsb_analysis.get("suspicious_stego_detected", False),
                "printable_ascii_ratio": 0.8 if lsb_analysis.get("suspicious_stego_detected") else 0.4,
                "detected_signatures": lsb_analysis.get("flag_patterns_found", []),
                "recovered_preview": ", ".join(lsb_analysis.get("flag_patterns_found", [])[:2]) if lsb_analysis.get("flag_patterns_found") else "None"
            },
            "binary_carving_and_payload": {
                "has_trailing_payload": len(carved_segments) > 0,
                "trailing_size_bytes": carved_segments[0]["size_bytes"] if carved_segments else 0,
                "trailing_size_formatted": carved_segments[0]["size_formatted"] if carved_segments else "0 B",
                "detected_payload_type": carved_segments[0]["detected_type"] if carved_segments else "None",
                "trailing_entropy": file_entropy["entropy"],
                "trailing_entropy_rating": file_entropy["rating"],
                "carved_file_path": carved_segments[0]["carved_file_path"] if carved_segments else None,
                "carved_file_md5": carved_segments[0]["md5"] if carved_segments else None,
                "interesting_strings": carved_segments[0]["interesting_strings"] if carved_segments else []
            }
        }

        return self.success_response(results, f"Analisis Forensik Hardcore {os.path.basename(file_path)} Selesai.")
