# Fortinet Automated Backup & Drift Detection Tool

Tool otomatisasi backup tingkat produksi (*production-grade*) berbasis Python untuk perangkat **FortiGate (HA Pair)** dan **FortiWeb (HA Pair)** melalui **Dedicated Management IP**, dilengkapi dengan verifikasi integritas **SHA-256**, penyimpanan *offsite* **S3 (kompatibel NetApp S3 ONTAP/StorageGRID & AWS S3)**, deteksi perubahan cerdas (**Smart Drift Detection**), proteksi *silent truncation*, dan sistem notifikasi email **SMTP**.

---

## 1. Arsitektur & Alur Kerja

```
+-------------------------------------------------------------------------+
|                           Perangkat Target                              |
|                                                                         |
|   [FortiGate Node 1]   [FortiGate Node 2]   (HA Dedicated Mgmt IP)      |
|   [FortiWeb Node 1]    [FortiWeb Node 2]    (HA Dedicated Mgmt IP)      |
+------------------------------------+------------------------------------+
                                     |
                       HTTPS REST API Extraction
                                     |
         +---------------------------+---------------------------+
         |                                                       |
   (FortiGate API)                                         (FortiWeb API)
   POST /api/v2/monitor/system/config/backup               GET /api/v2.0/system/maintenance.
   Bearer Token Authentication                            backupconfiguration?type=entire&ml_backup=1
                                                          Base64 JSON Credentials Auth
         |                                                       |
         v                                                       v
   [ .conf file ]                                          [ .system.conf.zip ]
   (Plain text CLI Config)                                 (Full Backup with Machine Learning)
         |                                                       |
         +---------------------------+---------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                             Backup Engine                               |
|                                                                         |
| 1. Baseline Size Validation (Mencegah Silent Truncation)                |
| 2. SHA-256 Fingerprinting                                               |
| 3. Local Cache Storage (backups/<device_name>/)                         |
| 4. Smart Drift Detection:                                               |
|    - FortiGate: Filter dinamis IV re-encryption noise ("ENC ...")       |
|    - FortiWeb: Ekstrak fwb_system.conf, abaikan blob ML & timestamp split|
+--------------------+-------------------------------+--------------------+
                     |                               |
                     v                               v
+------------------------------------+ +----------------------------------+
|             S3 Storage             | |          SMTP Mailer             |
|                                    | |                                  |
| - NetApp S3 (ONTAP / StorageGRID)  | | - Alert Drift Terdeteksi         |
| - AWS S3 (Standard Region)         | | - Alert Kegagalan / Truncation   |
| - Metadata SHA-256 & Timestamp     | | - Ringkasan HTML & Unified Diff  |
| - ContentType text & zip otomatis  | | - Proteksi Rate Limit & Size     |
+------------------------------------+ +----------------------------------+
```

---

## 2. Fitur Unggulan

* **HA Dedicated Management Support**: Mendukung backup masing-masing node secara independen (Primary & Secondary) melalui Dedicated Management IP.
* **Full FortiWeb Backup (Include Machine Learning)**: Mengunduh konfigurasi lengkap termasuk database *Machine Learning* (`ml_backup=1`) dengan format standar `.system.conf.zip` yang valid dan siap di-*restore* di GUI FortiWeb.
* **S3 Dual Compatibility (NetApp S3 & AWS S3)**: Bekerja mulus baik dengan NetApp ONTAP S3 / StorageGRID on-premise maupun AWS S3 resmi dengan mengatasi isu *flexible checksum* (`x-amz-content-sha256`).
* **Smart Drift Detection**:
  * **FortiGate**: Mengabaikan perubahan token `ENC ...` (IV re-encryption bawaan FortiOS), sehingga email alert hanya dikirim jika ada perubahan konfigurasi riil (policy, route, interface, VIP, dll.).
  * **FortiWeb**: Mengekstrak teks konfigurasi murni dan mengabaikan binary blob ML serta delimiter timestamp dinamis, sehingga proses diff berlangsung dalam hitungan milidetik tanpa false alarm.
* **Baseline Size Protection**: Memvalidasi ukuran byte dan baris minimum sebelum backup dinyatakan sukses (mencegah *silent truncation* akibat hak akses API yang kurang).
* **HTML Email Alert**: Notifikasi otomatis berformat tabel HTML elegan dilengkapi potongan *unified diff* berwarna.
* **Audit Trail (JSON Logging)**: Setiap proses tercatat dalam file `backup_audit.log` berformat JSON terstruktur.

---

## 3. Ringkasan Gotchas & Solusi Teknis

| # | Masalah / Tantangan | Solusi yang Diterapkan di Tool |
|---|---|---|
| **1** | **Silent Truncation di FortiGate**: Jika hak akses profil API admin ada kategori berstatus *None*, file terpotong tanpa ada pesan error. | Validasi baseline ukuran byte (`min_size_bytes`) dan baris minimal di `src/devices/base.py`. Di FortiGate, profil admin wajib `System: Read/Write` dan kategori lain minimal `Read`. |
| **2** | **FortiOS 7.4+ & 7.6+ (HTTP 405)**: Endpoint backup di FortiOS modern tidak lagi mendukung `GET`. | `src/devices/fortigate.py` menggunakan method **`POST`** secara langsung dengan fallback otomatis ke `GET` untuk FortiOS 7.0/7.2. |
| **3** | **FortiWeb API Authentication**: FortiWeb tidak memiliki user khusus API token di GUI seperti FortiGate. | Menggunakan autentikasi Base64-encoded JSON `{"username":"...","password":"...","vdom":"root"}` tanpa prefix `Bearer`. Di `.env`, Anda cukup mengisi user & password, script akan otomatis meng-encode saat runtime. |
| **4** | **FortiWeb Backup Format & ML**: Backup FortiWeb adalah file ZIP biner dan menyertakan data Machine Learning. | Parameter `ml_backup=1` disertakan di API, nama file otomatis diberi ekstensi `_system.conf.zip`, dan saat diff teks murni diekstrak sebelum binary tar archive. |
| **5** | **NetApp S3 Checksum Error**: Boto3 1.36+ mengirim header streaming checksum yang ditolak NetApp S3 (`InvalidArgument: x-amz-content-sha256`). | Mengatur `request_checksum_calculation="when_required"` dan `payload_signing_enabled=True` pada konfigurasi Boto3 di `src/storage/s3_storage.py`. |
| **6** | **Noise Diff Akibat Enkripsi (`ENC ...`)**: Fortinet membuat IV baru pada password setiap ekspor. | Algoritma di `src/drift.py` memfilter baris `ENC ...` dan hanya menandai *drift* jika ada baris konfigurasi fungsional yang berubah. |
| **7** | **Parsing .env**: `python-dotenv` membaca komentar sebaris (*inline comments*) sebagai bagian dari value. | Seluruh file `.env` dirancang bersih tanpa komentar segaris. |

---

## 4. Panduan Konfigurasi Perangkat (Fortinet)

### A. FortiGate (FortiOS)
1. **Admin Profile & API User**:
   ```cli
   config system accprofile
       edit "backup_profile"
           set comments "Profile khusus automated backup API"
           set system-sys-cfg read-write
           set netgrp read
           set firewall read
           set vpngrp read
           set loggrp read
           set authgrp read
       next
   end

   config system api-user
       edit "backup-admin"
           set accprofile "backup_profile"
           set vdom "root"
       next
   end
   ```
   *Generate API token dari user tersebut dan masukkan ke `config/.env`.*

---

### B. FortiWeb
1. **Dedicated Management Port**:
   ```cli
   config system interface
       edit "port1"
           set ip 192.168.2.2/24
           set allowaccess https ping ssh
       next
   end
   ```

2. **Kredensial Administrator**:
   * Cukup gunakan akun admin dengan izin akses System Configuration Read-Write.
   * Masukkan username dan password ke `FWB_NODE1_USER` dan `FWB_NODE1_PASS` di `config/.env`.

---

## 5. Konfigurasi File Proyek

### A. File `config/devices.yaml`
```yaml
devices:
  # FortiGate HA Pair
  - name: "FGT-CORE-01"
    description: "FortiGate Primary Node"
    type: "fortigate"
    host: "192.168.2.1"
    port: 443
    token_env: "FGT_NODE1_TOKEN"
    min_size_bytes: 40000
    min_lines: 500
    verify_ssl: false
    timeout_seconds: 30

  # - name: "FGT-CORE-02"
  #   description: "FortiGate Secondary Node"
  #   type: "fortigate"
  #   host: "192.168.2.3"
  #   port: 443
  #   token_env: "FGT_NODE2_TOKEN"
  #   min_size_bytes: 40000
  #   min_lines: 500
  #   verify_ssl: false
  #   timeout_seconds: 30

  # FortiWeb HA Pair
  - name: "FWB-WAF-01"
    description: "FortiWeb WAF Node 1"
    type: "fortiweb"
    host: "192.168.2.2"
    port: 443
    user_env: "FWB_NODE1_USER"
    pass_env: "FWB_NODE1_PASS"
    vdom: "root"
    ml_backup: "1"             # 1 = Include Machine Learning data
    min_size_bytes: 25000
    min_lines: 300
    verify_ssl: false
    timeout_seconds: 60

  # - name: "FWB-WAF-02"
  #   description: "FortiWeb WAF Node 2"
  #   type: "fortiweb"
  #   host: "192.168.2.4"
  #   port: 443
  #   user_env: "FWB_NODE2_USER"
  #   pass_env: "FWB_NODE2_PASS"
  #   vdom: "root"
  #   ml_backup: "1"
  #   min_size_bytes: 25000
  #   min_lines: 300
  #   verify_ssl: false
  #   timeout_seconds: 60
```

### B. File `config/.env`
> [!IMPORTANT]
> Jangan gunakan komentar sebaris (*inline comments*) di dalam file `.env`.

```ini
# S3 Storage (NetApp S3 atau AWS S3)
# Kosongkan S3_ENDPOINT_URL jika menggunakan AWS S3 resmi
S3_ENDPOINT_URL=https://s3.domainmu.com
S3_BUCKET_NAME=fortinet-api
S3_ACCESS_KEY=s3_access_key
S3_SECRET_KEY=s3_secret_key
S3_VERIFY_SSL=false

# FortiGate Tokens
FGT_NODE1_TOKEN=token_api_fortigate_node1

# FortiWeb Credentials (otomatis di-encode ke Base64)
FWB_NODE1_USER=admin
FWB_NODE1_PASS=password_admin_fortiweb

# SMTP Configuration
SMTP_HOST=192.168.3.10
SMTP_PORT=25
SMTP_USE_TLS=false
SMTP_USE_SSL=false
SMTP_FROM=backup.api@domainmu.com
SMTP_TO=netops@perusahaan.com,security@perusahaan.com
```

---

## 6. Petunjuk Penggunaan

### Instalasi Dependensi
```powershell
pip install -r requirements.txt
```

### Menjalankan Pengujian Koneksi
```powershell
# Uji koneksi S3 (NetApp S3 / AWS S3)
python main.py --test-s3

# Uji koneksi email SMTP
python main.py --test-smtp
```

### Menjalankan Backup
```powershell
# Backup seluruh perangkat yang aktif di devices.yaml
python main.py

# Simulasi tanpa upload S3 dan tanpa kirim email (Dry-Run)
python main.py --dry-run

# Backup perangkat tertentu saja
python main.py --device FGT-CORE-01
python main.py --device FWB-WAF-01
```

### Menjalankan Unit Test
```powershell
python -m unittest tests/test_components.py
```

---

## 7. Struktur Folder Hasil Eksekusi

```text
FortiGate Backup/
│
├── backups/
│   ├── FGT-CORE-01/
│   │   └── FGT-CORE-01_20260918144020_68cd6bb87e70.conf     # File teks CLI FortiOS
│   └── FWB-WAF-01/
│       └── FWB-WAF-01_20260918094125_system.conf.zip        # Valid ZIP (Config + ML Data)
│
├── config/
│   ├── devices.yaml
│   ├── .env
│   └── .env.example
│
├── src/
│   ├── devices/
│   │   ├── base.py
│   │   ├── fortigate.py
│   │   └── fortiweb.py
│   ├── notifier/
│   │   └── smtp_mailer.py
│   ├── storage/
│   │   └── s3_storage.py
│   ├── config_loader.py
│   ├── drift.py
│   └── logger.py
│
├── tests/
│   └── test_components.py
│
├── backup_audit.log       # Log audit format JSON per eksekusi
├── main.py
├── requirements.txt
└── README.md
```

---

## 8. Penjadwalan Otomatis (Scheduling)

### Windows Task Scheduler
1. Buka **Task Scheduler** di Windows Server.
2. Buat **Basic Task**, atur trigger harian atau tiap beberapa jam.
3. Pada tab **Action**:
   * **Program/script**: `python.exe` (atau path lengkap `C:\Python314\python.exe`)
   * **Add arguments**: `main.py`
   * **Start in**: `D:\Fortinet\FortiGate Backup`

### Linux Cron (jika di-deploy di Linux)
```cron
0 */6 * * * cd /path/to/FortiGate\ Backup && /usr/bin/python3 main.py >> /var/log/fortinet_backup.log 2>&1
```
