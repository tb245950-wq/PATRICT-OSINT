<div align="center">

```text
===================================================================
  ____       _  _____ ____  ___ ____ _____        ___  ____ ___ _   _ _____ 
 |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|      / _ \/ ___|_ _| \ | |_   _|
 | |_) |   / _ \ | | | |_) || | |     | |  ____ | | | \___ \| ||  \| | | |  
 |  __/   / ___ \| | |  _ < | | |___  | | |____|| |_| |___) | || |\  | | |  
 |_|     /_/   \_\_| |_| \_\___\____| |_|        \___/|____/___|_| \_| |_|  
===================================================================
               MODULAR MONOREPO OSINT FRAMEWORK v2.0
===================================================================
```

# PATRICT-OSINT Framework

**Advanced Modular Monorepo Reconnaissance & Threat Intelligence Engine**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)
[![Build Status](https://img.shields.io/badge/GitHub%20Actions-Pre--release-orange.svg?style=flat&logo=githubactions)](https://github.com/tb245950-wq/PATRICT-OSINT/actions)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20Monorepo-purple.svg?style=flat)](#-arsitektur--struktur-proyek)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

</div>

---

## 📌 Daftar Isi

- [Tentang PATRICT-OSINT](#-tentang-patrict-osint)
- [Fitur Utama & Modul Intelijen](#-fitur-utama--modul-intelijen)
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

**PATRICT-OSINT** adalah framework intelijen sumber terbuka (*Open Source Intelligence*) generasi baru berbasis Python dengan arsitektur **Modular Monorepo**. Dirancang untuk penyelidik keamanan siber, analis ancaman (*threat intelligence*), dan peneliti forensik digital untuk melakukan pengumpulan intelijen otomatis dan terstruktur dari target nomor telepon maupun jejak digital terkait.

Framework ini mengadopsi sistem **Plugin Loader Dinamis** (`PluginLoader`) yang secara otomatis mendeteksi, memuat, dan mengeksekusi modul-modul analisis tanpa perlu konfigurasi hardcode, serta menghasilkan visualisasi relasi interaktif (*interactive relationship graph*) dan dashboard laporan bertema gelap (*Dark Mode*).

---

## ⚡ Fitur Utama & Modul Intelijen

Framework dilengkapi dengan rangkaian modul reconnaissance independen dan terintegrasi:

| Modul | File | Deskripsi Fungsionalitas |
| :--- | :--- | :--- |
| **Phone Recon** | `modules/phone_osint.py` | Parsing standar internasional E.164, validasi nomor, deteksi operator seluler (*carrier*), zona waktu, dan data geocoding dasar. |
| **Caller ID** | `modules/caller_id_osint.py` | Resolusi identitas pemilik target, nama panggilan, skor spam, dan reputasi nomor dari berbagai direktori caller intelligence. |
| **Geolocation** | `modules/location_osint.py` | Ekstraksi koordinat lintang/bujur (*lat/long*), reverse geocoding alamat fisik, dan pembuatan peta interaktif berbasis OpenStreetMap (*Folium*). |
| **Social Footprint** | `modules/social_osint.py` | Pemindaian asinkron ke 20+ platform media sosial (WhatsApp, Telegram, GitHub, Instagram, Twitter/X, TikTok, Reddit, Spotify, Steam, Medium, dll) menggunakan *social signatures*. |
| **Email Discovery** | `modules/email_osint.py` | Permutasi pola email potensial berdasarkan nomor dan identitas serta verifikasi record MX domain. |
| **WhatsApp Intel** | `modules/whatsapp_osint.py` | Verifikasi status keaktifan akun WhatsApp dan deteksi profil web signature. |
| **Network Intel** | `modules/network_osint.py` | Resolusi DNS, Reverse DNS, query WHOIS domain terkait, IP Geolocation, dan pemetaan infrastruktur jaringan. |
| **Web Archive** | `modules/web_history.py` | Penelusuran jejak domain historis target melalui Wayback Machine dan arsip web terbuka. |
| **Search Dorking** | `modules/dorking_osint.py` | Pembuatan query Google/DuckDuckGo dorks otomatis untuk mengungkap kebocoran dokumen, pastebin, dan jejak database publik. |
| **Graph Visualizer** | `visualizers/graph_engine.py` | Engine visualisasi relasi interaktif berbasis `NetworkX` dan `PyVis` yang memetakan relasi entitas target. |
| **Report Engine** | `reports/report_generator.py` | Generator laporan multi-format: **HTML Dashboard Dark Mode**, **JSON Terstruktur**, dan **CSV Tabular**. |

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
│   ├── base_module.py             # Kelas abstrak dasar BaseModule
│   ├── config_manager.py          # Manager konfigurasi & environment variable
│   └── plugin_loader.py           # Engine dynamic discovery & loader modul
├── data/
│   └── social_signatures.json     # Database pola & URL signature platform sosmed
├── modules/                       # Direktori modul-modul OSINT
│   ├── caller_id_osint.py
│   ├── dorking_osint.py
│   ├── email_osint.py
│   ├── location_osint.py
│   ├── network_osint.py
│   ├── phone_osint.py
│   ├── social_osint.py
│   ├── web_history.py
│   └── whatsapp_osint.py
├── reports/                       # Modul pelaporan
│   ├── report_generator.py
│   └── templates/
│       └── report_dark.html       # Template HTML dashboard modern
├── visualizers/                   # Modul visualisasi graf
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
- **Koneksi Internet**: Diperlukan untuk melakukan kueri online dan resolusi entitas.

---

## 🚀 Panduan Instalasi

Pilih salah satu metode instalasi di bawah ini:

### Metode 1: Instalasi Cepat Otomatis (Direkomendasikan di Linux/macOS)

Gunakan skrip `run.sh` untuk menyiapkan virtual environment, memasang dependensi, dan mendaftarkan perintah global `osint`:

```bash
# Clone repositori
git clone https://github.com/tb245950-wq/PATRICT-OSINT.git
cd PATRICT-OSINT

# Jalankan installer otomatis
chmod +x run.sh
./run.sh install
```

Setelah instalasi selesai, perintah `osint` dan `patrict` dapat langsung dijalankan dari direktori mana saja di terminal Anda!

---

### Metode 2: Instalasi Manual via Virtual Environment

```bash
# 1. Buat dan aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate  # Di Windows: venv\Scripts\activate

# 2. Perbarui pip dan pasang dependensi
pip install --upgrade pip
pip install -r requirements.txt

# 3. Pasang paket ke sistem lokal (editable mode)
pip install -e .

# 4. Siapkan file konfigurasi
cp config/config.example.yaml config/config.yaml
```

---

### Metode 3: Menggunakan File Distribusi (.whl) dari Pre-release

Unduh file `.whl` dari halaman [GitHub Releases](https://github.com/tb245950-wq/PATRICT-OSINT/releases), lalu install:

```bash
pip install patrict_osint-2.0.0-py3-none-any.whl
osint --help
```

---

## 🎯 Cara Penggunaan

### 1. Mode Baris Perintah (CLI Direct Scan)

Jalankan pemindaian langsung dengan menyertakan nomor telepon target (gunakan format internasional diawali tanda `+`):

```bash
# Menggunakan command global
osint +6281234567890

# Atau menggunakan runner script
./run.sh scan +6281234567890

# Atau menggunakan python langsung
python3 main.py +6281234567890
```

### 2. Mode Interaktif

Cukup ketik `osint` atau jalankan `main.py` tanpa argumen untuk masuk ke antarmuka interaktif:

```bash
osint
```

```text
===================================================================
  ____       _  _____ ____  ___ ____ _____        ___  ____ ___ _   _ _____ 
 |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|      / _ \/ ___|_ _| \ | |_   _|
 | |_) |   / _ \ | | | |_) || | |     | |  ____ | | | \___ \| ||  \| | | |  
 |  __/   / ___ \| | |  _ < | | |___  | | |____|| |_| |___) | || |\  | | |  
 |_|     /_/   \_\_| |_| \_\___\____| |_|        \___/|____/___|_| \_| |_|  
===================================================================
               MODULAR MONOREPO OSINT FRAMEWORK v2.0
===================================================================

[+] Mode Interaktif PATRICT-OSINT

[?] Masukkan Nomor Telepon Target (contoh: +6281234567890): +6281234567890
```

### 3. Menggunakan Konfigurasi Kustom

```bash
osint +6281234567890 -c /path/ke/config.yaml
```

### 4. Perintah Tambahan pada `run.sh`

```bash
./run.sh clean     # Membersihkan file laporan lama di folder output/
./run.sh help      # Menampilkan menu bantuan lengkap
```

---

## ⚙️ Konfigurasi Sistem

Seluruh konfigurasi dapat disesuaikan pada file [`config/config.yaml`](config/config.example.yaml):

```yaml
app:
  name: "PATRICT-OSINT Framework"
  version: "2.2.0"
  timeout: 10              # Batas waktu timeout HTTP request (detik)
  max_concurrency: 25      # Jumlah worker asinkron bersamaan
  rotate_user_agent: true  # Rotasi User-Agent untuk menghindari rate-limit
  output_dir: "./output"   # Folder penyimpanan hasil laporan

# Pengaktifan / Penonaktifan Modul
modules:
  phone_osint: true
  location_osint: true
  caller_id_osint: true
  whatsapp_osint: true
  social_osint: true
  dorking_osint: true
  email_osint: true
  network_osint: true
  web_history: true

# Pengaturan Ekspor Laporan
reporting:
  generate_json: true
  generate_csv: true
  generate_html: true
  generate_graph: true
  theme: "dark"
```

---

## 📊 Format Output & Laporan

Setiap sesi pemindaian akan menghasilkan berkas intelijen di folder `./output/`:

1. **Dashboard Interaktif (`report_<target>.html`)**:
   - Tampilan antarmuka modern bertema gelap (*Dark Mode*).
   - Tab navigasi untuk ringkasan eksekutif, data telekomunikasi, identitas, jaringan, dan dorks.
   - Peta lokasi interaktif (*Folium/OSM*) dan visualisasi graf hubungan (*Network Graph*) tersemat langsung.
2. **Graf Relasi Interaktif (`graph_<target>.html`)**:
   - Peta simpul dinamis berbasis PyVis yang menghubungkan nomor target, email, username sosial media, domain, dan server jaringan.
3. **Peta Geografis (`map_<target>.html`)**:
   - Peta layer satelit dan jalan dengan penanda radius koordinat perkiraan target.
4. **Data Terstruktur (`report_<target>.json`)**:
   - Seluruh raw data hasil intelijen untuk integrasi API atau pipeline SIEM/MISP.
5. **Tabel Ringkasan (`report_<target>.csv`)**:
   - Format tabular untuk analisis spreadsheet cepat.

---

## 🤝 Dokumentasi & Panduan Komunitas

Kami sangat menyambut kontribusi dari komunitas sumber terbuka!

- 📘 [Panduan Kontribusi (CONTRIBUTING.md)](CONTRIBUTING.md) — Alur kerja git branch, standar kode, dan cara menambahkan modul baru.
- 🛡️ [Kebijakan Keamanan (SECURITY.md)](SECURITY.md) — Prosedur pelaporan celah keamanan dan *responsible disclosure*.
- 📜 [Lisensi Proyek (LICENSE)](LICENSE) — Lisensi lisensi terbuka MIT.
- 🐛 [Laporkan Bug / Error](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=bug_report.md) — Buat tiket laporan masalah teknis.
- 💡 [Usulkan Fitur Baru](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=feature_request.md) — Ajukan ide atau modul reconnaissance baru.

---

## ⚠️ Disclaimer & Etika

> **PENTING**: Framework **PATRICT-OSINT** dikembangkan secara khusus untuk tujuan penelitian keamanan informasi, edukasi, investigasi pertahanan (*defensive reconnaissance*), dan analisis intelijen yang sah (*authorized OSINT analysis*).
> 
> Pengembang dan kontributor tidak bertanggung jawab atas segala bentuk penyalahgunaan, aktivitas ilegal, atau pelanggaran privasi yang dilakukan oleh pengguna pihak ketiga. Selalu patuhi hukum dan regulasi privasi data yang berlaku di yurisdiksi Anda.

---

<div align="center">
  <sub>Dibangun dengan ❤️ untuk Komunitas Keamanan Siber & Open-Source Intelligence.</sub>
</div>
