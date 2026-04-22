# Playbook: Reverse Shell / System Compromise

## Trigger
Wazuh alert rule group: `malware` atau `reverse_shell`, level >= 12

## Severity: Critical — TINDAK SEGERA

## Langkah Response

### 1. ISOLASI SEGERA (< 2 menit)
- [ ] Cabut host dari jaringan (disable network adapter)
- [ ] Jangan shutdown — preservasi memory forensik

### 2. Identifikasi Proses (10 menit)
- [ ] Lihat proses mana yang membuka koneksi keluar (dari Wazuh/Sysmon)
- [ ] Catat: PID, nama proses, path executable, parent process
- [ ] Kill proses mencurigakan

### 3. Forensik (30 menit)
- [ ] Ambil file hash yang di-flag (sudah auto di case)
- [ ] Cek VirusTotal result di case description
- [ ] Dump memory proses jika tools tersedia
- [ ] Review registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- [ ] Review startup folder
- [ ] Cek scheduled tasks

### 4. Scope Assessment
- [ ] Apakah ada lateral movement ke host lain?
- [ ] Data apa yang mungkin ter-eksfiltrasi?
- [ ] Berapa lama attacker sudah ada di sistem?

### 5. Recovery
- [ ] Wipe dan reinstall OS, atau restore dari snapshot bersih
- [ ] Change semua kredensial yang pernah ada di host tersebut
- [ ] Patch vulnerability yang dieksploitasi

### 6. Documentation
- [ ] Buat laporan insiden lengkap
- [ ] Timeline dari awal serangan sampai containment
- [ ] Update case di TheHive dan close

## Referensi
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter
- MITRE ATT&CK: T1071 - Application Layer Protocol