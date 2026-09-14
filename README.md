# Fortinet Automated Backup & Drift Detection Tool

Tool otomatisasi backup berbasis Python untuk **FortiGate (HA Pair)** dan **FortiWeb (HA Pair)** menggunakan REST API melalui **Dedicated Management IP**, dilengkapi dengan verifikasi integritas **SHA-256**, penyimpanan offsite **S3 (kompatibel AWS S3 & NetApp S3)**, deteksi perubahan (*smart drift detection*), validasi baseline ukuran file, dan notifikasi email **SMTP**.

---

## 1. Arsitektur & Alur Kerja

```
+-------------------------------------------------------------+
|                     Perangkat Target                        |
|                                                             |
|  [FortiGate Node 1]   [FortiGate Node 2]   (HA Dedicated)   |
|  [FortiWeb Node 1]    [FortiWeb Node 2]    (HA Dedicated)   |
+------------------------------+------------------------------+
                               |
                    HTTPS REST API Pull
                               |
                               v
+-------------------------------------------------------------+
|                      Backup Engine                          |
|                                                             |
| 1. Baseline Size Check (Mencegah Silent Truncation)         |
| 2. SHA-256 Fingerprinting                                   |
| 3. Local Cache Storage                                      |
| 4. Smart Drift Detection (Abaikan noise "ENC ...")          |
+---------------+-----------------------------+---------------+
                |                             |
                v                             v
+-------------------------------+ +---------------------------+
|          S3 Storage           | |       SMTP Notifier       |
|                               | |                           |
| - NetApp S3 (Endpoint kustom) | | - Alert Drift Terdeteksi  |
| - AWS S3 (Standard Region)    | | - Alert Backup Failure    |
| - Object Metadata & Versioning| | - Ringkasan Unified Diff  |
+-------------------------------+ +---------------------------+
```

---

## 2. Fitur Utama

1. **Multi-Device & HA Independent Backup**:
   - Mendukung pencadangan masing-masing node secara independen melalui *Dedicated Management IP* (bukan hanya cluster virtual IP), memastikan status kedua unit (Primary & Secondary) tercatat dengan akurat.
2. **S3 Dual Compatibility (NetApp S3 & AWS S3)**:
   - Mendukung on-premise object storage (seperti **NetApp StorageGRID / ONTAP S3**) melalui parameter `endpoint_url`.
   - Mendukung **AWS S3** publik secara langsung dengan mengosongkan parameter endpoint.
   - Menyematkan metadata `sha256`, `device_name`, dan `timestamp` pada object S3.
3. **Smart Drift Detection & Noise Filter**:
   - Membandingkan file konfigurasi terbaru dengan backup sebelumnya menggunakan `difflib.unified_diff`.
   - **Filter Cerdas**: Mengabaikan baris `ENC ...` (re-encryption IV noise bawaan FortiOS/FortiWeb) sehingga email alert hanya dikirim jika ada perubahan konfigurasi riil (firewall policy, routing, address object, certificate, dll.).
4. **Proteksi Silent Truncation (Baseline Check)**:
   - Memvalidasi ukuran file minimum (byte size dan line count) sebelum backup dianggap valid, menghindari file rusak akibat kekurangan izin hak akses API.
5. **SMTP HTML Email Alerts**:
   - Notifikasi email otomatis dengan format tabel HTML rapi jika terdeteksi *drift* atau terjadi kegagalan backup.
6. **Audit Trail (Structured JSON Logging)**:
   - Log tersimpan dalam format JSON terstruktur untuk kemudahan integrasi dengan SIEM / Log Management.

---

## 3. Prasyarat Konfigurasi Perangkat (Fortinet)

### A. FortiGate (FortiOS)
#### 1. Setup Dedicated Management Port untuk HA
Pastikan kedua node memiliki interface manajemen terpisah:
```cli
config system ha
    set ha-direct enable
end

config system interface
    edit "mgmt"
        set ip 192.168.1.10 255.255.255.0   # IP Node 1 (Node 2: 192.168.1.11)
        set allowaccess ping https ssh
        set dedicated-to management
    next
end
```

#### 2. Hak Akses REST API Admin (Krusial: Gotcha #1)
> [!IMPORTANT]
> Admin REST API wajib memiliki hak akses **Read/Write** pada kategori `System`, dan **minimal Read** pada seluruh kategori lainnya. Jika ada kategori berstatus *None*, FortiOS akan memotong file backup secara diam-diam (*silent truncation*).

Konfigurasi via FortiOS CLI:
```cli
config system accprofile
    edit "api_backup_profile"
        set scope global
        set comments "Profile for automated backup tool"
        set system-sys-cfg read-write
        set authgrp read
        set netgrp read
        set vpngrp read
        set firewall read
        set loggrp read
        set admintimeout 10
    next
end

config system api-user
    edit "backup-admin"
        set accprofile "api_backup_profile"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.168.1.50 255.255.255.255  # IP Server Runner Backup
            next
        end
    next
end
```
Setelah user dibuat, generate API token dan simpan token tersebut di file `.env`.

---

### B. FortiWeb
#### 1. Dedicated Management Port
Pastikan port manajemen FortiWeb telah diaktifkan dan dapat diakses melalui HTTPS:
```cli
config system interface
    edit "port1"
        set ip 192.168.1.20/24   # IP Node 1 (Node 2: 192.168.1.21)
        set allowaccess https ssh ping
    next
end
```

#### 2. REST API Authentication (Base64 Encoded Credentials)
Berbeda dengan FortiGate, FortiWeb tidak menyediakan opsi pembuatan user khusus REST API Token di GUI. Autentikasi REST API FortiWeb menggunakan **Base64-encoded JSON** dari akun administrator:
```json
{"username":"admin","password":"your_password","vdom":"root"}
```

**Tool ini sudah mendukung 2 cara praktis di `.env`:**
1. **Otomatis (Direkomendasikan)**: Cukup masukkan username & password admin di `.env` (`FWB_NODE1_USER` & `FWB_NODE1_PASS`), script Python akan otomatis meng-generate Base64 token saat runtime.
2. **Manual**: Jika ingin memasukkan token Base64 yang sudah di-encode sebelumnya ke `FWB_NODE1_TOKEN`.

Header yang dikirimkan ke FortiWeb:
```http
Authorization: <base64_encoded_token>
Content-Type: application/x-www-form-urlencoded
```

---

## 4. Konfigurasi Tool

### A. Struktur File
```text
FortiGate Backup/
├── config/
│   ├── devices.yaml     # Daftar IP, tipe, dan baseline perangkat
│   └── .env             # Kredensial rahasia (S3, SMTP, API Token)
├── backups/             # Cache lokal dan history backup
├── src/                 # Kode sumber modul python
├── main.py              # Script utama
└── requirements.txt     # Dependensi Python
```

### B. Contoh `config/devices.yaml`
```yaml
devices:
  - name: "FGT-CORE-01"
    host: "192.168.1.10"
    port: 443
    type: "fortigate"
    token_env: "FGT_NODE1_TOKEN"
    min_size_bytes: 50000      # Baseline minimal (misal 50 KB)
    verify_ssl: false

  - name: "FGT-CORE-02"
    host: "192.168.1.11"
    port: 443
    type: "fortigate"
    token_env: "FGT_NODE2_TOKEN"
    min_size_bytes: 50000
    verify_ssl: false

  - name: "FWB-WAF-01"
    host: "192.168.1.20"
    port: 443
    type: "fortiweb"
    token_env: "FWB_NODE1_TOKEN"
    min_size_bytes: 30000
    verify_ssl: false

  - name: "FWB-WAF-02"
    host: "192.168.1.21"
    port: 443
    type: "fortiweb"
    token_env: "FWB_NODE2_TOKEN"
    min_size_bytes: 30000
    verify_ssl: false
```

### C. Contoh `config/.env`
> [!CAUTION]
> Jangan gunakan komentar sebaris (*inline comments*) di `.env` karena `python-dotenv` akan menganggap komentar tersebut sebagai bagian dari nilai string (Gotcha #2).

```ini
# S3 Storage Configuration
# Kosongkan S3_ENDPOINT_URL jika menggunakan AWS S3 resmi
# Isi S3_ENDPOINT_URL jika menggunakan NetApp S3 (ONTAP / StorageGRID)
S3_ENDPOINT_URL=https://s3.corp.local:8443
S3_BUCKET_NAME=fortinet-config-backups
S3_ACCESS_KEY=YOUR_S3_ACCESS_KEY
S3_SECRET_KEY=YOUR_S3_SECRET_KEY
S3_REGION=us-east-1
S3_VERIFY_SSL=false

# Fortinet API Tokens
FGT_NODE1_TOKEN=xxxxxx_token_fgt_node1_xxxxxx
FGT_NODE2_TOKEN=xxxxxx_token_fgt_node2_xxxxxx
FWB_NODE1_TOKEN=xxxxxx_token_fwb_node1_xxxxxx
FWB_NODE2_TOKEN=xxxxxx_token_fwb_node2_xxxxxx

# SMTP Mailer Configuration
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=noc-alerts@perusahaan.com
SMTP_PASS=password_smtp_anda
SMTP_FROM=noc-alerts@perusahaan.com
SMTP_TO=netops@perusahaan.com,security@perusahaan.com
```

---

## 5. Menjalankan Tool

### Instalasi Dependensi
```bash
pip install -r requirements.txt
```

### Eksekusi Manual
```bash
# Menjalankan backup reguler untuk seluruh perangkat
python main.py

# Menjalankan simulasi tanpa upload dan tanpa kirim email (Dry Run)
python main.py --dry-run

# Menjalankan hanya untuk perangkat tertentu
python main.py --device FGT-CORE-01
```

### Otomatisasi Terjadwal (Scheduling)
* **Linux (Cron)**: Jalankan setiap 6 jam:
  ```cron
  0 */6 * * * /usr/bin/python3 /path/to/FortiGate\ Backup/main.py >> /var/log/forti_backup.log 2>&1
  ```
* **Windows (Task Scheduler)**:
  Buat Scheduled Task yang menjalankan `python.exe` dengan argumen `d:\Fortinet\FortiGate Backup\main.py`.

