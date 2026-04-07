#!/bin/bash

# --- 1. Verifikasi Hak Akses Root ---
if [ "$EUID" -ne 0 ]; then 
  echo -e "\e[31m[ERROR] Harap jalankan script ini dengan sudo!\e[0m"
  exit 1
fi

echo -e "\e[36m=== Wazuh Agent Clean Uninstaller (Linux) ===\e[0m"

# --- 2. Hentikan Service ---
echo -e "\n\e[33m[1/5] Menghentikan service Wazuh Agent...\e[0m"
systemctl stop wazuh-agent 2>/dev/null
systemctl disable wazuh-agent 2>/dev/null

# --- 3. Hapus Paket (Uninstall) ---
echo -e "\e[33m[2/5] Menghapus paket wazuh-agent...\e[0m"
# Melepas status 'hold' terlebih dahulu agar bisa di-uninstall
echo "wazuh-agent install" | dpkg --set-selections
apt-get purge wazuh-agent -y
apt-get autoremove -y

# --- 4. Hapus File Konfigurasi & Folder Sisa ---
echo -e "\e[33m[3/5] Menghapus folder /var/ossec (Bersih Total)...\e[0m"
rm -rf /var/ossec
rm -f /etc/apt/sources.list.d/wazuh.list
rm -f /usr/share/keyrings/wazuh.gpg

# --- 5. Bersihkan Cache Paket ---
echo -e "\e[33m[4/5] Memperbarui daftar paket (Clean Up)...\e[0m"
apt-get update

# --- 6. Verifikasi Akhir ---
echo -e "\n\e[36m=== VERIFIKASI UNINSTALL ===\e[0m"

echo -n "1. Paket Wazuh-Agent: "
if ! dpkg -l | grep -q wazuh-agent; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] Paket masih ada!\e[0m"
fi

echo -n "2. Folder /var/ossec: "
if [ ! -d "/var/ossec" ]; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] Folder masih ada!\e[0m"
fi

echo -n "3. Wazuh Repo List: "
if [ ! -f "/etc/apt/sources.list.d/wazuh.list" ]; then
    echo -e "\e[32m[DELETED] Terhapus.\e[0m"
else
    echo -e "\e[31m[FAILED] File repo masih ada!\e[0m"
fi

echo -e "\n\e[32mSelesai! Wazuh Agent telah dihapus secara bersih dari sistem Linux ini.\e[0m"
