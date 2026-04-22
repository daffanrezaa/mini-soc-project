# Playbook: SSH Brute Force / Credential Attack

## Trigger
Wazuh alert rule group: `authentication_failures` atau `bruteforce`, level >= 10

## Severity: High

## Langkah Response

### 1. Identifikasi (5 menit)
- [ ] Catat source IP dan target account
- [ ] Cek berapa kali percobaan gagal (lihat di Wazuh)
- [ ] Cek: adakah login sukses setelah percobaan gagal?

### 2. Containment SEGERA (< 5 menit)
- [ ] Jika ada login sukses: ISOLASI HOST SEKARANG
- [ ] Lock account yang diserang
- [ ] Block source IP di firewall

### 3. Investigation (20 menit)
- [ ] Review auth.log untuk seluruh sesi dari IP tersebut
- [ ] Cek apakah ada akun lain yang dicoba
- [ ] Cek aktivitas setelah login (jika ada yang berhasil)

### 4. Recovery
- [ ] Reset password akun yang diserang
- [ ] Enable MFA jika belum ada
- [ ] Review SSH config: disable root login, batasi user yang boleh SSH

### 5. Documentation
- [ ] Update case di TheHive
- [ ] Tutup dengan status dan severity final

## Referensi
- MITRE ATT&CK: T1110 - Brute Force