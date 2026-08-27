# Panduan Kontribusi (Contributing Guidelines)

Terima kasih atas minat dan ketertarikan Anda untuk berkontribusi pada **PATRICT-OSINT**! Proyek ini terbuka untuk siapa saja yang ingin membantu mengembangkan fitur baru, memperbaiki *bug*, meningkatkan dokumentasi, atau mengoptimalkan performa.

Berikut adalah panduan dan alur kerja standar yang perlu diikuti saat berkontribusi pada repositori ini.

---

## 📋 Daftar Isi

1. [Alur Kontribusi (Workflow)](#-alur-kontribusi-workflow)
2. [Standar Penamaan Branch](#-standar-penamaan-branch)
3. [Setup Lingkungan Pengembangan (Development Setup)](#-setup-lingkungan-pengembangan-development-setup)
4. [Standar Penulisan Kode & Arsitektur](#-standar-penulisan-kode--arsitektur)
5. [Menambahkan Modul OSINT Baru](#-menambahkan-modul-osint-baru)
6. [Konvensi Pesan Commit](#-konvensi-pesan-commit)
7. [Membuat Pull Request (PR)](#-membuat-pull-request-pr)
8. [Pelaporan Masalah (Issues)](#-pelaporan-masalah-issues)
9. [Etika & Disclaimer](#-etika--disclaimer)

---

## 🔄 Alur Kontribusi (Workflow)

Berikut langkah-langkah berkontribusi dari awal hingga *merge*:

```text
[Fork Repo] ──> [Clone Lokal] ──> [Checkout Branch Baru] ──> [Coding & Testing]
                                                                    │
[Merge ke Dev/Main] <── [Review PR] <── [Buka Pull Request] <── [Commit & Push]
```

### 1. Fork & Clone Repository
1. Lakukan **Fork** pada repositori [PATRICT-OSINT](https://github.com/tb245950-wq/PATRICT-OSINT).
2. *Clone* hasil fork ke komputer lokal Anda:
   ```bash
   git clone https://github.com/<username-github-anda>/PATRICT-OSINT.git
   cd PATRICT-OSINT
   ```
3. Tambahkan repositori utama sebagai `upstream`:
   ```bash
   git remote add upstream https://github.com/tb245950-wq/PATRICT-OSINT.git
   ```

### 2. Buat Branch Baru
Pastikan Anda selalu membuat *branch* baru dari branch `dev` (atau `main` jika `dev` belum digunakan) sebelum mulai melakukan perubahan:
```bash
git checkout -b <tipe-branch>/<deskripsi-singkat>
```
*Contoh:* `git checkout -b feat/tambah-modul-telegram`

---

## 🌿 Standar Penamaan Branch

Gunakan format penamaan branch berikut agar terstruktur:

| Tipe Prefix | Kegunaan | Contoh |
| :--- | :--- | :--- |
| `feat/` | Fitur baru atau modul baru | `feat/tambah-modul-telegram` |
| `fix/` | Perbaikan bug atau error | `fix/reverse-geocode-timeout` |
| `docs/` | Perubahan atau pembaruan dokumentasi | `docs/update-contributing` |
| `refactor/` | Refactoring struktur kode tanpa mengubah fungsionalitas | `refactor/optimasi-report-gen` |
| `perf/` | Peningkatan performa kode / async | `perf/async-dns-lookup` |
| `test/` | Penambahan atau perbaikan unit test | `test/unit-test-phone-osint` |

---

## 🛠 Setup Lingkungan Pengembangan (Development Setup)

1. **Pastikan Python 3.8+ terpasang:**
   ```bash
   python3 --version
   ```

2. **Buat dan aktifkan Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Di Linux / macOS
   # venv\Scripts\activate   # Di Windows
   ```

3. **Install Dependensi Proyek:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Jalankan Aplikasi untuk Pengujian Awal:**
   ```bash
   python3 main.py
   ```

---

## 📐 Standar Penulisan Kode & Arsitektur

- **Python PEP 8:** Ikuti panduan gaya penulisan kode standar Python (PEP 8).
- **Asynchronous Pattern:** Gunakan pola `async` / `await` untuk fungsi-fungsi I/O, network request, dan pemrosesan modul agar performa tetap cepat.
- **Type Hinting:** Sertakan *type hint* pada parameter dan *return value* fungsi/method.
- **Error Handling:** Pastikan setiap fungsi memiliki blok `try-except` yang baik dan memberikan nilai *fallback* atau log yang jelas tanpa membuat aplikasi crash.
- **Komentar & Docstrings:** Tulis docstrings dan komentar penjelasan pada fungsi atau class yang dibuat.

---

## 🧩 Menambahkan Modul OSINT Baru

PATRICT-OSINT menggunakan arsitektur monorepo modular. Untuk menambahkan modul OSINT baru:

1. **Buat file modul baru** di dalam folder `modules/`:
   ```text
   modules/
   └── nama_fitur_osint.py
   ```

2. **Gunakan struktur class standar:**
   ```python
   # modules/nama_fitur_osint.py

   import asyncio
   from typing import Dict, Any

   class NamaFiturOSINT:
       def __init__(self):
           # Inisialisasi konfigurasi modul
           pass

       async def scan(self, target: str) -> Dict[str, Any]:
           """
           Fungsi utama untuk melakukan pengumpulan data
           """
           try:
               # Logika OSINT
               return {
                   "status": "success",
                   "data": {}
               }
           except Exception as e:
               return {
                   "status": "error",
                   "message": str(e)
               }
   ```

3. **Daftarkan modul baru di `main.py`:**
   - Import class modul Anda di bagian header `main.py`.
   - Inisialisasi modul di dalam `__init__` pada `OSINTFramework`.
   - Tambahkan tahap eksekusi modul pada method `run_full_osint`.

---

## 📝 Konvensi Pesan Commit

Gunakan standar [Conventional Commits](https://www.conventionalcommits.org/) dalam bahasa Inggris atau Indonesia yang jelas:

Format: `<tipe>(<cakupan opsional>): <deskripsi singkat>`

**Contoh:**
- `feat(modules): tambah modul verifikasi whatsapp`
- `fix(network): tangani timeout pada dns resolver`
- `docs(readme): perbaiki struktur dokumentasi`
- `refactor(main): optimasi eksekusi threadpool executor`
- `chore: update dependensi requirements.txt`

---

## 🚀 Membuat Pull Request (PR)

1. **Sinkronkan branch Anda** dengan repositori utama terlebih dahulu:
   ```bash
   git fetch upstream
   git merge upstream/dev
   ```

2. **Push branch ke fork repositori Anda:**
   ```bash
   git push origin <nama-branch-anda>
   ```

3. **Buka Pull Request di GitHub:**
   - Masuk ke repositori [PATRICT-OSINT](https://github.com/tb245950-wq/PATRICT-OSINT).
   - Klik tombol **Compare & pull request**.
   - Arahkan *base branch* ke branch target (misal: `dev` atau `main`).
   - Berikan judul yang deskriptif dan jelaskan perubahan yang Anda lakukan pada deskripsi PR.
   - Cantumkan nomor issue terkait jika ada (contoh: `Fixes #12`).

4. **Tinjauan (Code Review):**
   - Maintainer akan meninjau kode Anda.
   - Jika ada masukan/revisi, lakukan perbaikan di branch lokal yang sama, lalu push kembali.

---

## 🐛 Pelaporan Masalah (Issues)

Jika Anda menemukan *bug* atau memiliki ide perbaikan/fitur baru:
1. Periksa tab **Issues** untuk memastikan masalah tersebut belum dilaporkan sebelumnya.
2. Buat issue baru dengan template yang jelas:
   - **Deskripsi Bug/Fitur**: Penjelasan mengenai masalah atau fitur yang diusulkan.
   - **Langkah Reproduksi**: Langkah-langkah untuk memicu bug (jika bug).
   - **Ekspektasi vs Realitas**: Apa yang diharapkan terjadi dan apa yang sebenarnya terjadi.
   - **Lingkungan**: Versi Python, OS, dan dependensi terkait.

---

## ⚖️ Etika & Disclaimer

Framework PATRICT-OSINT dikembangkan hanya untuk **tujuan edukasi, riset keamanan siber, dan analisis data intelijen sumber terbuka (OSINT) yang sah secara hukum**. Segala bentuk penggunaan untuk tindakan ilegal, pelanggaran privasi, atau pelecehan berada di luar tanggung jawab pengembang dan kontributor proyek ini.

---

## 💬 Diskusi & Komunitas Discord

Ingin berdiskusi mengenai ide fitur baru, arsitektur modul, atau butuh bantuan saat berkontribusi?
Bergabunglah bersama komunitas pengembang kami di Discord:
👉 **[Server Discord PATRICT-OSINT](https://discord.gg/snGDCZT2E)**

---
Terima kasih telah berkontribusi dan membuat **PATRICT-OSINT** menjadi lebih baik! 🚀
