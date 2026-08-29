<div align="center">

```text
===================================================================
  ____       _  _____ ____  ___ ____ _____         ___  ____ ___ _   _ _____ 
 |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|      / _ \/ ___|_ _| \ | |_   _|
 | |_) |   / _ \ | | | |_) || | |     | |  ____ | | | \___ \| ||  \| | | |  
 |  __/   / ___ \| | |  _ < | | |___  | | |____|| |_| |___) | || |\  | | |  
 |_|     /_/   \_\_| |_| \_\___\____| |_|        \___/|____/___|_| \_| |_|  
===================================================================
                        PATRICT-OSINT v3.0.0
===================================================================
```

# PATRICT-OSINT

**Advanced Multi-Domain Reconnaissance, Threat Intelligence & Digital Forensics Engine**

[![PyPI Version](https://img.shields.io/pypi/v/patrict-osint.svg?logo=pypi&logoColor=white&color=blue)](https://pypi.org/project/patrict-osint/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muhammad%20Mughni-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muhammad-mughni-ishfi-pratama-6759523aa)
[![Discord Community](https://img.shields.io/badge/Discord-Join%20Community-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/snGDCZT2E)

</div>

---

## 📌 Daftar Isi

- [Tentang PATRICT-OSINT](#-tentang-patrict-osint)
- [Domain Penyelidikan & Modul Intelijen](#-domain-penyelidikan--modul-intelijen)
  - [1. Phone Intelligence](#1--phone-intelligence)
  - [2. Web & Infrastructure Reconnaissance](#2--web--infrastructure-reconnaissance)
  - [3. Media & File Forensics](#3--media--file-forensics)
- [Arsitektur & Struktur Proyek](#-arsitektur--struktur-proyek)
- [Persyaratan Sistem](#-persyaratan-sistem)
- [Panduan Instalasi](#-panduan-instalasi)
- [Cara Penggunaan](#-cara-penggunaan)
- [Konfigurasi Sistem](#-konfigurasi-sistem)
- [Format Output & Laporan](#-format-output--laporan)
- [Dokumentasi & Panduan Komunitas](#-dokumentasi--panduan-komunitas)
- [Disclaimer & Etika](#-disclaimer--etika)

---

## 📖 Tentang PATRICT-OSINT

**PATRICT-OSINT** adalah framework intelijen sumber terbuka (*Open Source Intelligence*) dan forensik digital generasi baru berbasis Python dengan arsitektur **Modular Monorepo**. Dirancang untuk penyelidik keamanan siber, analis ancaman (*threat intelligence*), dan peneliti forensik digital untuk melakukan pengumpulan intelijen otomatis dan terstruktur pada 3 domain utama: **Telekomunikasi (Nomor Telepon)**, **Infrastruktur Web**, dan **Forensik Media/Gambar**.

Framework ini mengadopsi sistem **Plugin Loader Dinamis** (`PluginLoader`) yang secara otomatis memuat modul sesuai tipe domain penyelidikan, serta menghasilkan visualisasi relasi interaktif (*Interactive Network Graph*) dan dashboard laporan bertema gelap (*Dark Mode*) yang disesuaikan untuk masing-masing domain.

---

## ⚡ Domain Penyelidikan & Modul Intelijen

PATRICT-OSINT mendukung 3 domain penyelidikan mandiri:

### 1. 📞 Phone Intelligence
Modul reconnaissance nomor telepon internasional (ITU-T E.164) untuk mengungkap jejak pemilik, operator, dan sebaran akun media sosial:

| Modul | File | Deskripsi Fungsionalitas |
| :--- | :--- | :--- |
| **Phone Recon** | `modules/phone_osint.py` | Parsing standar internasional E.164, validasi nomor, operator (*carrier*), zona waktu, dan data geocoding dasar. |
| **Caller ID** | `modules/caller_id_osint.py` | Resolusi identitas pemilik target, nama panggilan, skor spam, dan reputasi nomor dari berbagai direktori caller intelligence. |
| **Geolocation** | `modules/location_osint.py` | Ekstraksi koordinat lintang/bujur (*lat/long*), reverse geocoding alamat fisik, dan pembuatan peta interaktif berbasis OpenStreetMap (*Folium*). |
| **Social Footprint** | `modules/social_osint.py` | Pemindaian asinkron ke 20+ platform media sosial (WhatsApp, Telegram, GitHub, Instagram, Twitter/X, TikTok, Reddit, Spotify, Steam, Medium, dll). |
| **Email Discovery** | `modules/email_osint.py` | Permutasi pola email potensial berdasarkan nomor dan identitas serta verifikasi record MX domain. |
| **WhatsApp Intel** | `modules/whatsapp_osint.py` | Verifikasi status keaktifan akun WhatsApp dan deteksi profil web signature. |
| **Network Intel** | `modules/network_osint.py` | Resolusi DNS, Reverse DNS, query WHOIS domain terkait, IP Geolocation, dan pemetaan infrastruktur jaringan. |
| **Web Archive** | `modules/web_history.py` | Penelusuran jejak domain historis target melalui Wayback Machine dan arsip web terbuka. |
| **Search Dorking** | `modules/dorking_osint.py` | Pembuatan query Google/DuckDuckGo dorks otomatis untuk mengungkap kebocoran dokumen, pastebin, dan jejak database publik. |

---

### 2. 🌐 Web & Infrastructure Reconnaissance
Modul investigasi mendalam terhadap aplikasi web dan server target:

| Modul | File | Deskripsi Fungsionalitas |
| :--- | :--- | :--- |
| **Web Intelligence** | `modules/web_osint.py` | &bull; **HTTP Methods & Protocol**: Deteksi method yang diizinkan (`OPTIONS`, `HEAD`, `GET`, `POST`, dll) dan security headers (`HSTS`, `CSP`, `X-Frame-Options`, `CORS`).<br>&bull; **Redirect Chain Tracker**: Pelacakan jalur redirect (`301`, `302`, `307`, `308`) dari URL asal hingga tujuan akhir.<br>&bull; **Session & Auth Fingerprint**: Deteksi token `JWT` (auto-decode header & payload), cookies session (Laravel `Sanctum` / `laravel_session`, Django `sessionid`, ASP.NET, PHP `PHPSESSID`, Express `connect.sid`, Spring `JSESSIONID`, Cloudflare `cf_clearance`).<br>&bull; **Tech Stack Fingerprint**: Deteksi Web Server (Nginx, Apache, Cloudflare), Framework Backend (Laravel, Django, Node, Rails), CMS (WordPress, Drupal, Joomla, Shopify), dan Frontend (React, Vue, Tailwind, Bootstrap).<br>&bull; **DNS & GeoIP Server**: Resolusi record `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, IP Publik server, koordinat latitude/longitude, ISP/Org, ASN, dan peta lokasi server. |

---

### 3. 🖼️ Media & File Forensics
Modul analisis forensik berkas gambar/media (JPG, PNG, JPEG, GIF, WebP, PDF):

| Modul | File | Deskripsi Fungsionalitas |
| :--- | :--- | :--- |
| **File Forensics** | `modules/file_forensics.py` | &bull; **Kriptografi & Integritas**: Kalkulasi hash presisi `MD5`, `SHA-1`, `SHA-256`, dan `SHA-512`.<br>&bull; **Magic Bytes Inspection**: Verifikasi signature biner asli vs ekstensi file (deteksi pemalsuan ekstensi file / *extension spoofing*).<br>&bull; **Metadata EXIF & GPS**: Ekstraksi tipe/model kamera, software editor pembuat gambar, timestamp pengambilan, dan ekstraksi koordinat GPS lokasi pemotretan ke Google Maps.<br>&bull; **Steganografi & Appended Data**: Deteksi data biner tersembunyi setelah marker *End-of-File* (`EOF` / `IEND`), deteksi arsip `ZIP` tersemat di dalam gambar, dan ekstraksi string ASCII menarik (URL, email, token, password). |

---

## 📂 Arsitektur & Struktur Proyek

```text
PATRICT-OSINT/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md          # Formulir laporan bug & error
│   │   ├── feature_request.md     # Formulir usulan fitur baru
│   │   └── config.yml             # Konfigurasi antarmuka issue GitHub
│   └── workflows/
│       ├── package.yml            # CI/CD otomatisasi build & pre-release
│       └── python-publish.yml     # Workflow publikasi PyPI
├── config/
│   ├── config.example.yaml        # Template konfigurasi sistem
│   └── config.yaml                # Konfigurasi aktif (timeout, proxy, toggles)
├── core/
│   ├── async_client.py            # HTTP Client Asinkron berbasis aiohttp
│   ├── base_module.py             # Kelas abstrak dasar BaseModule (target_type)
│   ├── config_manager.py          # Manager konfigurasi & environment variable
│   └── plugin_loader.py           # Dynamic discovery multi-domain module loader
├── data/
│   └── social_signatures.json     # Database pola & URL signature platform sosmed
├── modules/                       # Direktori modul-modul OSINT
│   ├── caller_id_osint.py         # [Phone]
│   ├── dorking_osint.py           # [Phone]
│   ├── email_osint.py             # [Phone]
│   ├── file_forensics.py          # [File/Media Forensics]
│   ├── location_osint.py          # [Phone]
│   ├── network_osint.py           # [Phone]
│   ├── phone_osint.py             # [Phone]
│   ├── social_osint.py            # [Phone]
│   ├── web_history.py             # [Phone]
│   ├── web_osint.py               # [Web Intelligence]
│   └── whatsapp_osint.py          # [Phone]
├── reports/                       # Modul pelaporan
│   ├── report_generator.py        # Generator laporan adaptif per domain
│   └── templates/
│       ├── report_dark.html       # Dashboard HTML Phone Recon & Relationship Graph
│       ├── report_web.html        # Dashboard HTML Web Recon, Auth & Tech Stack
│       └── report_forensics.html  # Dashboard HTML Media Forensics, EXIF & Hashes
├── visualizers/                   # Modul visualisasi graf relasi
│   └── graph_engine.py
├── CONTRIBUTING.md                # Panduan standar kontribusi
├── LICENSE                        # Lisensi resmi MIT
├── MANIFEST.in                    # Konfigurasi packaging aset non-Python
├── README.md                      # Dokumentasi utama repositori
├── SECURITY.md                    # Kebijakan pelaporan kerentanan keamanan
├── main.py                        # Entry point orkestrator & CLI framework
├── pyproject.toml                 # Standar packaging PEP 517 / 518
├── requirements.txt               # Daftar dependensi Python
├── run.sh                         # Script runner & installer global CLI
└── setup.py                       # Skrip instalasi setuptools
```

---

## 💻 Persyaratan Sistem

- **Sistem Operasi**: Linux (Ubuntu, Debian, Kali, Fedora), macOS, atau Windows (WSL2 / PowerShell).
- **Python**: Versi `3.8` atau yang lebih baru.
- **Koneksi Internet**: Diperlukan untuk modul Phone dan Web Reconnaissance.

---

## 🚀 Panduan Instalasi

### Metode 1: Instalasi via PyPI (Rekomendasi)

Paket resmi telah tersedia secara global di [PyPI (Python Package Index)](https://pypi.org/project/patrict-osint/):

```bash
# Instalasi langsung ke sistem / environment Anda
pip install patrict-osint

# Atau menggunakan pipx (terisolasi & aman)
pipx install patrict-osint
```

Setelah instalasi, perintah `osint` langsung aktif secara global di terminal Anda!

---

### Metode 2: Instalasi Cepat via One-Line Script (Linux & macOS)

```bash
curl -sSL https://raw.githubusercontent.com/tb245950-wq/PATRICT-OSINT/dev/install.sh | bash
```

---

### Metode 3: Instalasi Manual dari Sumber (Git Clone)

```bash
# 1. Buat dan aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate  # Di Windows: venv\Scripts\activate

# 2. Perbarui pip dan pasang dependensi
pip install --upgrade pip
pip install -r requirements.txt

# 3. Pasang paket ke sistem lokal
pip install -e .

# 4. Siapkan file konfigurasi
cp config/config.example.yaml config/config.yaml
```

---

## 🎯 Cara Penggunaan

### 1. Mode Interaktif (Pilih Domain Langsung)

Ketik `osint` tanpa argumen untuk membuka menu selektor interaktif:

```bash
osint
```

```text
===================================================================
  ____       _  _____ ____  ___ ____ _____         ___  ____ ___ _   _ _____ 
 |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|      / _ \/ ___|_ _| \ | |_   _|
 | |_) |   / _ \ | | | |_) || | |     | |  ____ | | | \___ \| ||  \| | | |  
 |  __/   / ___ \| | |  _ < | | |___  | | |____|| |_| |___) | || |\  | | |  
 |_|     /_/   \_\_| |_| \_\___\____| |_|        \___/|____/___|_| \_| |_|  
===================================================================
                        PATRICT-OSINT v2.2.0
===================================================================

[+] PILIH DOMAIN PENYELIDIKAN:

  >  Phone Intelligence
     Web & Tech Recon
     Media & File Forensics
     Keluar
```

Navigasi menu dapat menggunakan **Page Up / Page Down**, **Arrow Up / Arrow Down**, atau tombol `j`/`k`, lalu tekan **Enter** untuk memilih domain penyelidikan.

---

### 2. Mode Baris Perintah (Direct CLI / Scope Control)

Anda dapat langsung memasukkan target pada perintah terminal dengan berbagai opsi flag:

```bash
# Penyelidikan Nomor Telepon (Auto-detect Phone)
osint +6281234567890

# Penyelidikan Web & WhatWeb Fingerprint dengan Scope Mendalam
osint -t https://target-website.com -m web -S full -T 15

# Forensik Berkas Gambar / Media
osint -t /home/user/Downloads/foto_tersangka.jpg -m file

# Eksekusi Modul Spesifik & Simpan Output Kustom
osint -t +6281234567890 -M phone_osint,whatsapp_osint -o hasil_wa.json
```

---

## 📊 Format Output & Laporan per Domain

Setiap domain menghasilkan laporan yang disesuaikan di folder `./output/`:

1. **Domain Phone Intelligence**:
   - `report_<target>.html`: Dashboard interaktif bertema gelap dengan tab navigasi lengkap, peta lokasi HLR, dan graf hubungan identitas.
   - `graph_<target>.html`: Graf relasi interaktif berbasis PyVis/NetworkX.
   - `report_<target>.json` & `report_<target>.csv`.

2. **Domain Web & Tech Recon**:
   - `report_web_<domain>.html`: Dashboard arsitektur web, security headers, alur redirect, tech stack matrix, record DNS, dan lokasi server GeoIP.
   - `report_web_<domain>.json` & `report_web_<domain>.csv`.

3. **Domain Media & File Forensics**:
   - `report_file_<filename>.html`: Dashboard forensik biner, tabel hash (MD5/SHA1/SHA256/SHA512), verifikasi magic bytes, metadata kamera EXIF, koordinat GPS foto, dan deteksi steganografi/appended data.
   - `report_file_<filename>.json` & `report_file_<filename>.csv`.

---

## 🤝 Dokumentasi & Panduan Komunitas

- 💬 [Komunitas Discord](https://discord.gg/snGDCZT2E) — Bergabunglah ke server Discord kami untuk diskusi, tanya jawab, kolaborasi, dan koordinasi kontribusi.
- 📘 [Panduan Kontribusi (CONTRIBUTING.md)](CONTRIBUTING.md) — Alur kerja git branch, standar kode, dan cara menambahkan modul baru.
- 🛡️ [Kebijakan Keamanan (SECURITY.md)](SECURITY.md) — Prosedur pelaporan celah keamanan dan *responsible disclosure*.
- 📜 [Lisensi Proyek (LICENSE)](LICENSE) — Lisensi lisensi terbuka MIT.
- 🐛 [Laporkan Bug / Error](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=bug_report.md) — Buat tiket laporan masalah teknis.
- 💡 [Usulkan Fitur Baru](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=feature_request.md) — Ajukan ide atau modul reconnaissance baru.

---

---

## 👨‍💻 Pembuat & Pengembang (Author & Creator)

Proyek **PATRICT-OSINT** diciptakan, dirancang, dan dikembangkan oleh:

* **Nama Pengembang / Creator**: **Muhammad Mughni (Muhammad Mughni Ishfi Pratama)**
* **LinkedIn**: [Muhammad Mughni Ishfi Pratama](https://www.linkedin.com/in/muhammad-mughni-ishfi-pratama-6759523aa)
* **GitHub**: [@tb245950-wq](https://github.com/tb245950-wq)
* **Paket Resmi PyPI**: [patrict-osint](https://pypi.org/project/patrict-osint/)
* **Komunitas Riset**: [Discord Server PATRICT](https://discord.gg/snGDCZT2E)

> **Tentang Pembuat**: Muhammad Mughni adalah peneliti keamanan siber dan pengembang perangkat lunak sumber terbuka (*open-source software developer*) yang berfokus pada otomatisasi intelijen ancaman (*threat intelligence*), OSINT investigatif, dan forensik digital.

---

## ⚠️ Disclaimer & Etika

> **PENTING**: Framework **PATRICT-OSINT** dikembangkan secara khusus untuk tujuan penelitian keamanan informasi, edukasi, investigasi pertahanan (*defensive reconnaissance*), dan analisis intelijen yang sah (*authorized OSINT analysis*).
> 
> Pengembang dan kontributor tidak bertanggung jawab atas segala bentuk penyalahgunaan, aktivitas ilegal, atau pelanggaran privasi yang dilakukan oleh pengguna pihak ketiga. Selalu patuhi hukum dan regulasi privasi data yang berlaku di yurisdiksi Anda.

---

<div align="center">
  <sub>Dibangun dengan ❤️ untuk Komunitas Keamanan Siber & Open-Source Intelligence.</sub>
</div>
