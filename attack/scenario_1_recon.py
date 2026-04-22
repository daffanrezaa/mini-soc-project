#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 1: Reconnaissance / Port Scanning
=============================================================
  Target  : Metasploitable 2 @ 192.168.1.40
  Attacker: Kali Linux       @ 192.168.1.10
  Tactic  : T1595 - Active Scanning (MITRE ATT&CK)
  Tools   : python-nmap (wrapper nmap)
=============================================================
"""

import nmap
import json
import datetime

TARGET_IP   = "192.168.1.40"
ATTACKER_IP = "192.168.1.10"

# Scan arguments — SYN scan + version detection + OS detection
# -sS  : SYN/stealth scan (trigger Suricata)
# -sV  : version detection
# -O   : OS detection
# -p-  : semua port (1-65535) — ubah ke "-p 1-1000" kalau mau cepat
# -T4  : timing aggressive (trigger IDS lebih mudah)
SCAN_ARGS = "-sS -sV -O -p 1-1000 -T4"

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 1: RECONNAISSANCE         ║
║  Target  : {target:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""

def run_recon(target: str) -> dict:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(target=target, time=now))

    nm = nmap.PortScanner()

    print(f"[*] Memulai port scan ke {target}")
    print(f"[*] Scan arguments: {SCAN_ARGS}\n")

    try:
        nm.scan(hosts=target, arguments=SCAN_ARGS)
    except nmap.PortScannerError as e:
        print(f"[!] Scan error: {e}")
        print("[!] Pastikan nmap terinstall dan dijalankan dengan hak yang cukup.")
        raise SystemExit(1)

    results = {}

    for host in nm.all_hosts():
        print(f"[+] Host      : {host}")
        print(f"[+] Status    : {nm[host].state()}")

        # OS Detection
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            os_guess = nm[host]["osmatch"][0]
            print(f"[+] OS Guess  : {os_guess['name']} (akurasi: {os_guess['accuracy']}%)")
        else:
            print(f"[+] OS Guess  : Tidak terdeteksi")

        print(f"\n{'─'*54}")
        print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION'}")
        print(f"{'─'*54}")

        open_ports = []
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            for port in ports:
                svc   = nm[host][proto][port]
                state   = svc["state"]
                service = svc["name"]
                version = svc.get("version", "") + " " + svc.get("extrainfo", "")
                version = version.strip()

                # Hanya tampilkan port yang open
                if state == "open":
                    print(f"  {str(port)+'/'+proto:<10} {state:<10} {service:<15} {version}")
                    open_ports.append({
                        "port"    : port,
                        "proto"   : proto,
                        "state"   : state,
                        "service" : service,
                        "version" : version,
                    })

        results[host] = {
            "status"     : nm[host].state(),
            "open_ports" : open_ports,
        }

    print(f"{'─'*54}")
    print(f"\n[+] Total open ports ditemukan: {sum(len(v['open_ports']) for v in results.values())}")
    print(f"[+] Scan selesai.\n")

    return results


def save_results(results: dict, filename: str = "recon_results.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[*] Hasil disimpan ke: {filename}")


if __name__ == "__main__":
    results = run_recon(TARGET_IP)
    save_results(results)