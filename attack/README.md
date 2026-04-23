# Hi! U r th one who will "attack" the infra, glhf!

## Network Info

| Role | Host | IP |
|------|------|----|
| Attacker | WSL / Kali Linux (Laptop A) | `192.168.100.160` |
| Victim | Metasploitable 2 VM (Laptop B) | `192.168.100.40` |

---

## Setup

### 1. Set IP Static di Windows (Laptop A)

```
Settings → Network & Internet → WiFi →
klik nama WiFi → Properties → Edit (IP assignment) → Manual → IPv4

IP address  : 192.168.100.160
Subnet mask : 255.255.255.0
Gateway     : 192.168.100.1
DNS         : 8.8.8.8
```

### 2. Set IP Static di WSL / Kali

Setelah Windows di-set, cek apakah WSL sudah dapat IP yang benar:

```bash
ip a | grep 192.168
```

Kalau belum muncul `192.168.100.160`, tambahkan manual:

```bash
sudo ip addr add 192.168.100.160/24 dev eth0
sudo ip route add default via 192.168.100.1
```

## Verifikasi Koneksi

Koordinasi dengan Person B & C, lalu pastikan semua bisa di-ping:

```bash
ping 192.168.100.20   # Laptop B (SOC Server) — harus reply
ping 192.168.100.30   # Laptop C (Response)   — harus reply
ping 192.168.100.40   # Metasploitable VM      — harus reply (VM harus nyala dulu)
```

---

> To execute the attacks, u will need to do these first:

```bash
sudo apt update
sudo apt install python3-venv nmap -y

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Verifikasi:

```bash
pip list | grep -E "nmap|paramiko|impacket"
```

> Alternatif jika `pip install -r requirements.txt` gagal

**A) Install satu per satu (paling umum berhasil):**
```bash
pip install python-nmap
pip install paramiko
pip install impacket
```

**B) Gunakan `pip3` eksplisit (jika `pip` tidak dikenali):**
```bash
pip3 install python-nmap paramiko impacket
```

**C) Kali / Debian — "externally managed environment" error:**

Kali terbaru memblokir `pip` di luar venv. Solusi:
```bash
# Opsi 1 — pastikan kamu sudah di dalam venv (direkomendasikan)
source venv/bin/activate
pip install -r requirements.txt

# Opsi 2 — bypass (gunakan hanya jika venv tidak bisa dibuat)
pip install -r requirements.txt --break-system-packages
```

**D) Jika `python3-venv` tidak tersedia:**
```bash
sudo apt install python3-full python3-pip -y
# lalu ulangi langkah venv di atas
```

---

## Run Attacks

> run an attack? try these commands:

```bash
sudo venv/bin/python run_all.py
```

Or, u can run just one attack:

```bash
sudo venv/bin/python scenario_1_recon.py        # Port Scan (Nmap)
sudo venv/bin/python scenario_2_bruteforce.py   # SSH Brute Force
sudo venv/bin/python scenario_3_reverseshell.py # Reverse Shell
sudo venv/bin/python scenario_4_smbenum.py      # SMB Enumeration
sudo venv/bin/python scenario_5_slowloris.py    # Slowloris DoS (light mode)
```

---

## Skenario

| # | Script | Serangan | MITRE ATT&CK | Deteksi |
|---|--------|----------|--------------|---------|
| 1 | `scenario_1_recon.py` | Nmap SYN scan ke `192.168.100.40` | T1595 | Suricata |
| 2 | `scenario_2_bruteforce.py` | SSH brute force ke `192.168.100.40:22` | T1110.001 | Wazuh |
| 3 | `scenario_3_reverseshell.py` | Reverse shell balik ke `192.168.100.160:4444` | T1059, T1071 | Wazuh + Suricata |
| 4 | `scenario_4_smbenum.py` | SMB share & user enumeration | T1135, T1087 | Wazuh + Suricata |
| 5 | `scenario_5_slowloris.py` | Slowloris DoS ke `192.168.100.40:80` (60s, light) | T1499 | Suricata |