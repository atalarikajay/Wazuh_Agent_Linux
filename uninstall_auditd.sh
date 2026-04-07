#!/bin/bash

# --- 1. Verifikasi Hak Akses Root ---
if [ "$EUID" -ne 0 ]; then 
  echo -e "\e[31m[ERROR] Harap jalankan script ini dengan sudo!\e[0m"
  exit 1
fi

echo -e "\e[36m=== Auditd Clean Uninstaller (Linux) ===\e[0m"

# --- 2. Hentikan Service ---
echo -e "\n\e[33m[1/4] Menghentikan service Auditd...\e[0m"
# Auditd terkadang sulit dihentikan via systemctl, kita gunakan service command atau auditctl
systemctl stop auditd 2>/dev/null
service auditd stop 2>/dev/null

# Menonaktifkan agar tidak jalan saat reboot
systemctl disable auditd 2>/dev/null

# --- 3. Hapus Paket (Uninstall) ---
echo -e "\e[33m[2/4] Menghapus paket auditd & audispd-plugins...\e[0m"
apt-get purge auditd audispd-plugins -y
apt-get autoremove -y

# --- 4. Bersihkan Sisa Konfigurasi & Log ---
echo -e "\e[33m[3/4] Menghapus folder konfigurasi dan log audit...\e[0m"
# Menghapus folder konfigurasi (/etc/audit)
rm -rf /etc/audit

# Menghapus folder log (/var/log/audit) - Hati-hati, log lama akan hilang selamanya
rm -rf /var/log/audit

# Membersihkan file cache audit jika ada
rm -f /var/run/auditd.pid

# --- 5. Verifikasi Akhir ---
echo -e "\n\e[36m=== VERIFIKASI UNINSTALL ===\e[0m"

echo -n "1. Paket Auditd: "
if ! dpkg -l | grep -q auditd; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] Paket masih ditemukan!\e[0m"
fi

echo -n "2. Folder /etc/audit: "
if [ ! -d "/etc/audit" ]; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] Konfigurasi masih ada!\e[0m"
fi

echo -n "3. Folder /var/log/audit: "
if [ ! -d "/var/log/audit" ]; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] Log masih ada!\e[0m"
fi

echo -e "\n\e[32mSelesai! Auditd telah dihapus secara bersih dari sistem.\e[0m"
