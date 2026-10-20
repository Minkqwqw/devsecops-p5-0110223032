# SecureTask API — DevSecOps CI/CD & SAST Pipeline (`devsecops-p5-0110223032`)

**Identitas Mahasiswa:**
- **Nama:** Muhammad Amir Al Aqwa
- **NIM:** 0110223032
- **Mata Kuliah:** DevSecOps (DE-261-A) — Tugas Pertemuan Ke-5
- **Program Studi:** S1 Teknik Informatika — STT Terpadu Nurul Fikri

---

## 1. Nama Aplikasi & Fungsinya

**SecureTask API** adalah aplikasi manajemen tugas dan autentikasi pengguna berbasis layanan (*backend service*) yang dirancang dengan pendekatan *Security by Design* dan *Shift-Left Security*.

Fungsi utama aplikasi ini meliputi:
1. **Manajemen Autentikasi & Sesi Pengguna (`src/auth_service.py`)**: Melayani registrasi pengguna baru, verifikasi login menggunakan *constant-time comparison*, serta penerbitan token sesi kriptografis.
2. **Utilitas Kriptografi & Sanitasi Input (`src/security.py`)**: Menerapkan algoritma *password hashing* **PBKDF2-HMAC-SHA256** (100.000 iterasi) dengan *random salt* menggunakan modul `secrets` (CSPRNG), serta sanitasi input untuk mencegah serangan *Injection* dan XSS.
3. **Manajemen Tugas dengan Kontrol Akses Kepemilikan (`src/task_service.py`)**: Menyediakan operasi *Create, Read, Update* tugas kerja dengan validasi kepemilikan (*Role-Based & Ownership Access Control*) untuk mencegah celah *Insecure Direct Object Reference* (IDOR / *Broken Access Control* - OWASP A01:2021).
4. **Lapisan Database Anti-SQL Injection (`src/database.py`)**: Mengelola penyimpanan data pengguna, daftar tugas, dan pencatatan jejak audit keamanan (*Security Audit Log*) pada database SQLite dengan menerapkan *Parameterized Query* secara ketat (mencegah *SQL Injection* - OWASP A03:2021).
5. **Manajemen Konfigurasi & Rahasia (`src/config.py`)**: Mengelola konfigurasi berbasis *Environment Variables* agar tidak ada kredensial atau *secret key* yang di-*hardcode* di dalam *source code* (mencegah *Cryptographic Failures* - OWASP A02:2021).

### Struktur Direktori & Daftar File Source Code

```text
devsecops-p5-0110223032/
├── .github/
│   └── workflows/
│       └── devsecops.yml        # Konfigurasi Pipeline CI/CD & SAST GitHub Actions
├── src/
│   ├── __init__.py              # Inisialisasi paket aplikasi
│   ├── app.py                   # Entry point utama & fasad layanan SecureTaskApp
│   ├── auth_service.py          # Layanan registrasi, login, dan manajemen sesi
│   ├── config.py                # Konfigurasi aplikasi berbasis Environment Variables
│   ├── database.py              # Lapisan database SQLite & Security Audit Logger
│   ├── security.py              # Modul hashing PBKDF2-SHA256, CSPRNG token & sanitasi
│   └── task_service.py          # Layanan CRUD tugas & proteksi IDOR/Access Control
├── tests/
│   └── test_app.py              # Unit test komprehensif (Pytest)
├── requirements.txt             # Daftar dependensi proyek & pengujian
├── sonar-project.properties     # Konfigurasi properti analisis SAST
└── README.md                    # Dokumentasi proyek & arsitektur pipeline
```

---

## 2. Bahasa Pemrograman, Framework & Tools yang Digunakan

| Komponen | Teknologi / Tool | Kegunaan |
| :--- | :--- | :--- |
| **Bahasa Pemrograman** | Python 3.11+ | Bahasa utama pengembangan aplikasi layanan *backend* |
| **Database** | SQLite3 (`sqlite3`) | Penyimpanan relasional dengan *Parameterized Queries* |
| **Testing Framework** | `pytest` & `pytest-cov` | Eksekusi *unit testing* otomatis dan pengukuran *code coverage* |
| **CI/CD Platform** | GitHub Actions (`ubuntu-latest`) | Otomasi *workflow* *build*, *unit test*, dan *security scanning* |
| **SAST Tool 1 (Utama)** | **Bandit** (PyCQA) | Analisis AST (*Abstract Syntax Tree*) khusus Python untuk mendeteksi celah keamanan (CWE / OWASP) |
| **SAST Tool 2** | **Semgrep** | Pemindaian SAST berbasis *pattern matching* cepat dengan aturan keamanan OWASP & Python |
| **Quality Gate** | Python Custom Gate + Bandit/Semgrep | *Pipeline blocker* otomatis yang menggagalkan *workflow* jika ditemukan isu keamanan atau *coverage* di bawah ambang batas |

---

## 3. Cara Menjalankan Aplikasi

### Prasyarat
- Python versi 3.10 atau lebih baru
- `pip` (Python Package Installer)

### Langkah-langkah Menjalankan di Lokal

1. **Clone Repository**
   ```bash
   git clone https://github.com/Minkqwqw/devsecops-p5-0110223032.git
   cd devsecops-p5-0110223032
   ```

2. **Instalasi Dependensi**
   ```bash
   pip install -r requirements.txt
   ```

3. **Menjalankan Simulasi Aplikasi**
   ```bash
   python -m src.app
   ```

4. **Menjalankan Unit Test & Coverage**
   ```bash
   pytest tests/ -v --cov=src --cov-report=term-missing
   ```

5. **Menjalankan Pemindaian SAST Secara Lokal (Bandit)**
   ```bash
   bandit -r src/ -f txt
   ```

---

## 4. Overview Pipeline CI/CD & DevSecOps yang Diimplementasikan

Pipeline DevSecOps didefinisikan dalam file [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml) dan berjalan pada runner `ubuntu-latest`.

### Pemicu Workflow (*Triggers*)
Workflow ini terpicu secara otomatis pada dua kejadian utama:
- **`push`** ke branch `main`
- **`pull_request`** ke branch `main`

### Arsitektur Tahapan Job (*Pipeline Stages*)

```mermaid
flowchart LR
    A["Trigger: Push / PR ke main"] --> B["Job 1: build (ubuntu-latest)"]
    B -->|Checkout, Install Deps, Run Pytest & Coverage| C{"Unit Test Lulus?"}
    C -->|Ya (needs: build)| D["Job 2: sast-scan (ubuntu-latest)"]
    C -->|Tidak| E["Pipeline FAILED"]
    D -->|Run Bandit SAST & Semgrep SAST| F{"Quality Gate Check"}
    F -->|0 Vulnerability & Coverage >= 80%| G["Pipeline PASSED"]
    F -->|Ada Vulnerability Medium/High| E
```

1. **Job 1: `build` (Compile, Install Dependencies & Unit Test)**
   - Menggunakan runner `ubuntu-latest` dan Python `3.11`.
   - Melakukan *checkout* kode sumber menggunakan `actions/checkout@v4`.
   - Mengompilasi *bytecode* Python (`python -m py_compile`) untuk memvalidasi sintaks seluruh file di `src/`.
   - Menginstal seluruh dependensi dari `requirements.txt`.
   - Menjalankan *unit test* dengan `pytest` beserta laporan *code coverage* (`coverage.xml`) dan mengunggah artefak hasil *coverage*.

2. **Job 2: `sast-scan` (SAST Security Scanning & Quality Gate Enforcement)**
   - Bergantung pada keberhasilan job `build` melalui konfigurasi `needs: build`.
   - Menjalankan **Bandit SAST** (`bandit -r src/ -f json -o bandit-report.json`) untuk menganalisis *Abstract Syntax Tree* (AST) kode Python terhadap celah seperti *Hardcoded Passwords* (B105/B106), *Weak Cryptographic Hash* (B324), *Dynamic Code Execution `eval()`* (B307), dan *SQL Injection* (B608).
   - Menjalankan **Semgrep SAST** (`semgrep scan --config=auto --error`) untuk mendeteksi pola kode berbahaya lintas standar keamanan OWASP Top 10.
   - **Penerapan Quality Gate (Pipeline Blocker)**: Mengevaluasi hasil JSON dari Bandit SAST dan Semgrep. Jika ditemukan **1 saja kerentanan** (*Medium* / *High* severity) atau *issue* keamanan yang belum diremediasi, langkah *Quality Gate* akan mengembalikan `exit code 1` sehingga memblokir pipeline secara otomatis.
