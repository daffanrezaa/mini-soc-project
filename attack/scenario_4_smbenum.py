#!/usr/bin/env python3
"""
=============================================================
  Mini SOC Project — Person A (Red Team)
  Scenario 4: SMB Enumeration
=============================================================
  Target  : Metasploitable 2 @ 192.168.100.40
  Attacker: Kali Linux       @ 192.168.100.160
  Tactic  : T1135 - Network Share Discovery (MITRE ATT&CK)
            T1087 - Account Discovery
  Tools   : impacket
=============================================================
  Cara kerja:
    1. Enumerate SMB shares yang tersedia di target
    2. Enumerate users via RPC
    3. Coba akses anonymous/null session
    4. Semua aktivitas SMB ter-log dan bisa dideteksi Wazuh + Suricata
=============================================================
"""

import datetime

try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import transport, samr, srvs
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False

# ── Konfigurasi ──────────────────────────────────────────
TARGET_IP   = "192.168.100.40"
ATTACKER_IP = "192.168.100.160"
SMB_PORT    = 445

# Null session — anonymous login (umum di Metasploitable)
USERNAME    = ""
PASSWORD    = ""
DOMAIN      = "WORKGROUP"
# ─────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════╗
║        MINI SOC — SCENARIO 4: SMB ENUMERATION        ║
║  Target  : {target:<38} ║
║  Time    : {time:<38} ║
╚══════════════════════════════════════════════════════╝
"""


def connect_smb(target: str, port: int, username: str, password: str) -> SMBConnection | None:
    """Buat koneksi SMB ke target."""
    try:
        conn = SMBConnection(target, target, sess_port=port, timeout=10)
        conn.login(username, password, DOMAIN)
        auth_type = "anonymous/null session" if not username else f"{username}:{password}"
        print(f"[+] SMB login berhasil via {auth_type}")
        return conn
    except SessionError as e:
        print(f"[!] SMB login gagal: {e}")
        return None
    except Exception as e:
        print(f"[!] Koneksi error: {e}")
        return None


def enumerate_shares(conn: SMBConnection) -> list:
    """Enumerate semua SMB shares yang tersedia."""
    print(f"\n[*] Enumerating SMB shares...")
    print(f"{'─'*54}")
    print(f"  {'SHARE':<20} {'TYPE':<15} {'COMMENT'}")
    print(f"{'─'*54}")

    shares = []
    try:
        share_list = conn.listShares()
        for share in share_list:
            name    = share["shi1_netname"][:-1]
            comment = share["shi1_remark"][:-1] if share["shi1_remark"] else ""
            stype   = share["shi1_type"]

            type_str = {0: "Disk", 1: "Print", 2: "Device", 3: "IPC"}.get(stype & 0xFF, "Unknown")
            print(f"  {name:<20} {type_str:<15} {comment}")

            shares.append({"name": name, "type": type_str, "comment": comment})

    except Exception as e:
        print(f"  [!] Gagal enumerate shares: {e}")

    return shares


def check_share_access(conn: SMBConnection, shares: list) -> None:
    """Coba akses setiap share — cek mana yang readable."""
    print(f"\n[*] Mengecek akses ke setiap share...")
    print(f"{'─'*54}")

    for share in shares:
        name = share["name"]
        if share["type"] == "IPC":
            continue
        try:
            conn.listPath(name, "*")
            print(f"  [+] ✅ READABLE  → \\\\{TARGET_IP}\\{name}")
            share["accessible"] = True
        except Exception:
            print(f"  [-] ❌ No access → \\\\{TARGET_IP}\\{name}")
            share["accessible"] = False


def enumerate_users_rpc(target: str) -> list:
    """Enumerate users via RPC/SAMR (null session)."""
    print(f"\n[*] Enumerating users via RPC (SAMR)...")
    print(f"{'─'*54}")

    users = []
    try:
        rpctransport = transport.SMBTransport(
            target, 445, r"\samr", username="", password=""
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        serverHandle = resp["ServerHandle"]

        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = resp2["Buffer"]["Buffer"]

        for domain in domains:
            domain_name = domain["Name"]
            print(f"  [*] Domain: {domain_name}")

            resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)
            domainSid = resp3["DomainId"]

            resp4 = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainSid)
            domainHandle = resp4["DomainHandle"]

            resp5 = samr.hSamrEnumerateUsersInDomain(dce, domainHandle)
            for user in resp5["Buffer"]["Buffer"]:
                username = user["Name"]
                rid      = user["RelativeId"]
                print(f"  [+] User found: {username:<20} (RID: {rid})")
                users.append({"username": username, "rid": rid})

        dce.disconnect()

    except Exception as e:
        print(f"  [!] RPC enumeration gagal: {e}")
        print(f"  [!] Null session mungkin tidak diizinkan untuk SAMR.")

    return users


def run_smb_enum(target: str) -> dict:
    if not _IMPACKET_OK:
        print("[!] impacket tidak terinstall — skip SMB Enumeration.")
        print("[!] Jalankan: pip install impacket")
        return {"target": target, "shares": [], "users": []}

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(BANNER.format(target=f"{target}:{SMB_PORT}", time=now))

    results = {
        "target"  : target,
        "shares"  : [],
        "users"   : [],
    }

    # Step 1: Koneksi SMB
    print(f"[*] Mencoba null session ke {target}:{SMB_PORT}...")
    conn = connect_smb(target, SMB_PORT, USERNAME, PASSWORD)

    if not conn:
        print(f"\n[*] Mencoba dengan credential msfadmin...")
        conn = connect_smb(target, SMB_PORT, "msfadmin", "msfadmin")

    if not conn:
        print(f"\n[!] Tidak bisa konek ke SMB. Target mungkin down.")
        return results

    # Step 2: Enumerate shares
    shares = enumerate_shares(conn)
    results["shares"] = shares

    # Step 3: Cek akses shares
    if shares:
        check_share_access(conn, shares)

    conn.close()

    # Step 4: Enumerate users via RPC
    users = enumerate_users_rpc(target)
    results["users"] = users

    # Summary
    print(f"\n{'═'*54}")
    print(f"[+] SUMMARY SMB ENUMERATION")
    print(f"[+] Shares ditemukan : {len(shares)}")
    accessible = [s for s in shares if s.get("accessible")]
    print(f"[+] Shares accessible: {len(accessible)}")
    print(f"[+] Users ditemukan  : {len(users)}")
    if users:
        print(f"[+] User list        : {[u['username'] for u in users]}")
    print(f"{'═'*54}\n")

    return results


if __name__ == "__main__":
    results = run_smb_enum(TARGET_IP)