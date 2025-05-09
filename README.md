
# Lazarus - CTF All-in-One Toolkit 🛠️

**Lazarus** adalah tools otomatis serba guna yang dirancang khusus untuk membantu menyelesaikan challenge CTF dari berbagai kategori, mulai dari Web Exploit, Cryptography, Forensik, SSTI Exploit, hingga analisis file log dan EVTX.

---

## 🚀 Fitur Utama

| Modul       | Keterangan                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `crypto`    | Auto decode base64, hex, ROT13                                              |
| `log`       | Analisa file log dan deteksi keyword mencurigakan                          |
| `browser`   | Ekstrak URL dari file browser history                                       |
| `usb`       | Deteksi perangkat USB dari registry dump                                   |
| `web`       | Parsing HTML dan eksternal JS otomatis, cari flag, decode base64           |
| `evtx`      | Parsing Windows Event Log (.evtx) dan ekstrak potongan flag                |
| `flag`      | Rekonstruksi flag dari potongan-potongan yang ditemukan                    |
| `ssti`      | Eksploitasi SSTI otomatis: deteksi, list file, cari dan print flag         |

---

## ⚙️ Instalasi

### 1. Clone Repository
```bash
git clone https://github.com/username/lazarus-ctf-toolkit.git
cd lazarus-ctf-toolkit
```

### 2. Buat Virtual Environment
```bash
python3 -m venv myenv
source myenv/bin/activate        # Linux/macOS
myenv\Scripts\activate.bat     # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Jalankan Tool
```bash
python lazarus_v6.1.py -m <module> -t <target>
```

---

## 📌 Contoh Penggunaan

### Crypto
```bash
python lazarus_v6.1.py -m crypto -t secret.txt
```

### Web
```bash
python lazarus_v6.1.py -m web -t index.html
```

### SSTI Exploit
```bash
python lazarus_v6.1.py -m ssti -t http://target-ctf-url/
```

---

## 📦 Kebutuhan

- Python 3.6+
- Modul: `requests`, `beautifulsoup4`, `python-evtx`

Jika belum punya, install:
```bash
pip install requests beautifulsoup4 python-evtx
```

---

## 📣 Catatan

- Mendukung flag dengan format apa pun (`picoCTF{}`, `HTB{}`, `IDN_CTF{}`, dll)
- Tools akan otomatis deteksi flag dari berbagai format dan sumber (inline script, JS eksternal, EVTX, base64, dll)

---

## ❤️ Kontribusi
Feel free untuk fork, pull request, atau request fitur baru. Tools ini dibuat untuk membantu komunitas CTF.

---

## Lisensi
MIT License
# Lazarus.Toolkit
