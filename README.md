# PATRICT-OSINT

## Deskripsi

Framework OSINT modular berbasis Python dengan arsitektur monorepo. Dirancang untuk melakukan pencarian informasi terbuka dari nomor telepon, meliputi:
- Koordinat geolokasi (lat/lon) dengan tingkat akurasi perkiraan
- Semua alamat email dan nama pemilik yang terhubung
- Akun media sosial (Facebook, Instagram, Twitter, LinkedIn, Telegram, WhatsApp, Signal, dll)
- Detail jaringan: IP publik & lokal, MAC address, DNS server, gateway/router
- Riwayat web/domain yang terasosiasi dengan nomor

## Strukture Project

```text
.
├── main.py                     # Entry point & orchestrator (430 baris)
├── modules/
│   ├── phone_osint.py          # Validasi, carrier, info dasar nomor
│   ├── location_osint.py       # Koordinat, reverse geocode, peta
│   ├── email_osint.py          # Cari email & nama dari kebocoran data
│   ├── social_osint.py         # Deteksi akun sosmed terhubung
│   ├── network_osint.py        # IP, MAC, DNS, interface, router
│   ├── web_history.py          # Domain/website terkait
│   └── report_generator.py     # Export JSON, CSV, HTML, PDF
├── output/                     # Direktori hasil laporan (dibuat otomatis)
├── requirements.txt            # Dependensi Python
└── run.sh                      # Script eksekusi cepat
```

## Persyaratan Sistem

- Python 3.8 atau bisa yang lebih tinggi
- Koneksi internet untuk akses API eksternal (simulasi)
