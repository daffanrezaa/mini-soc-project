## Hi! U r th one who will "attack" the infra, woohooo!

To execute the attacks, u will need to do these first:
```bash
sudo apt update
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

then verify the dependencies:
```bash
pip list | grep -E "nmap|paramiko"
```
then have fun!

> run an attack? `sudo venv/bin/python [attack.py]` or just use `sudo venv/bin/python run_all.py`

### also, take attention to this first.
1. Set IP Static di Windows
```
Settings → Network & Internet → WiFi → 
klik nama WiFi → Properties → Edit (IP assignment) → Manual → IPv4

IP address  : 192.168.1.10
Subnet mask : 255.255.255.0
Gateway     : 192.168.1.1
DNS         : 8.8.8.8
```
2. Set IP Static di WSL/Kali

Setelah Windows di-set, cek apakah WSL sudah dapat IP yang benar:
```bash
ip a | grep 192.168
```
Kalau belum muncul `192.168.1.10`, tambahkan manual:
```bash
sudo ip addr add 192.168.1.10/24 dev eth0
sudo ip route add default via 192.168.1.1
```
3. Verifikasi Koneksi (koordinasi dengan Person B & C)

Setelah semua laptop konek ke hotspot yang sama dan IP sudah di-set:
```bash
ping 192.168.1.20   # Laptop B — harus reply
ping 192.168.1.30   # Laptop C — harus reply
ping 192.168.1.40   # Metasploitable VM — harus reply (VM harus nyala dulu)
```

> -persephone