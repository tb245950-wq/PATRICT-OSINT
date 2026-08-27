# PATRICT-OSINT

## Deskripsi

Framework OSINT modular berbasis Python dengan arsitektur monorepo. Dirancang untuk melakukan pencarian informasi terbuka dari nomor telepon, meliputi:
- Koordinat geolokasi (lat/lon) dengan tingkat akurasi perkiraan
- Semua alamat email dan nama pemilik yang terhubung
- Akun media sosial (Facebook, Instagram, Twitter, LinkedIn, Telegram, WhatsApp, Signal, dll)
- Detail jaringan: IP publik & lokal, MAC address, DNS server, gateway/router
- Riwayat web/domain yang terasosiasi dengan nomor

## Struktur Project

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md          # Template laporan bug
│   │   ├── feature_request.md     # Template usulan fitur baru
│   │   └── config.yml             # Konfigurasi issue template
│   └── workflows/
│       └── package.yml            # CI/CD build package & pre-release
├── config/                        # Konfigurasi sistem
├── core/                          # Framework inti & abstraksi modul
├── data/                          # Signatures & dataset
├── modules/                       # Modul-modul reconnaissance OSINT
├── reports/                       # Generator laporan (HTML, JSON, CSV)
├── visualizers/                   # Engine graf relasi interaktif
├── CONTRIBUTING.md                # Panduan kontribusi
├── LICENSE                        # Lisensi proyek (MIT)
├── SECURITY.md                    # Kebijakan & pelaporan keamanan
├── main.py                        # Entry point & orchestrator
├── requirements.txt               # Dependensi Python
└── run.sh                         # Script eksekusi & CLI installer
```

## Persyaratan Sistem

- Python 3.8 atau yang lebih tinggi
- Koneksi internet untuk akses modul pengumpulan intelijen

## Dokumentasi & Komunitas

- [Panduan Kontribusi (CONTRIBUTING.md)](CONTRIBUTING.md)
- [Kebijakan Keamanan (SECURITY.md)](SECURITY.md)
- [Lisensi Proyek (LICENSE)](LICENSE)
- [Laporkan Masalah / Bug](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=bug_report.md)
- [Usulkan Fitur Baru](https://github.com/tb245950-wq/PATRICT-OSINT/issues/new?template=feature_request.md)
