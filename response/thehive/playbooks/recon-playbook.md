# Playbook: Reconnaissance / Port Scan

## Trigger
Wazuh alert rule group: `recon` atau `nmap`, level >= 10

## Severity: Medium

## Langkah Response

### 1. Identifikasi (5 menit)
- [ ] Catat source IP dari alert
- [ ] Cek AbuseIPDB score (sudah auto di case description)
- [ ] Tentukan: IP internal atau eksternal?
- [ ] Lihat port apa saja yang di-scan

### 2. Containment (10 menit)
- [ ] Jika IP eksternal dan AbuseIPDB score > 50: block di firewall
- [ ] Jika IP internal: eskalasi ke team network, cari device yang terkompromi

### 3. Investigation (15 menit)
- [ ] Cek log Wazuh: adakah alert lain dari IP yang sama?
- [ ] Cek timeline: berapa lama scan berlangsung?
- [ ] Tentukan apakah scan berhasil (apakah ada koneksi lanjutan setelah scan?)

### 4. Recovery & Documentation
- [ ] Update case di TheHive dengan temuan
- [ ] Tutup case dengan status: True Positive / False Positive
- [ ] Catat lesson learned

## Referensi
- MITRE ATT&CK: T1046 - Network Service Discovery