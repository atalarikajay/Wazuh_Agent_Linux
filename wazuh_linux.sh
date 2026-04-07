#!/bin/bash

# --- 1. Verifikasi Hak Akses Root ---
if [ "$EUID" -ne 0 ]; then 
  echo -e "\e[31m[ERROR] Harap jalankan script ini dengan sudo!\e[0m"
  exit 1
fi

echo -e "\e[36m=== Wazuh Agent & Auditd Installer (Interactive) ===\e[0m"

# --- 2. Input Interaktif ---
read -p "Masukkan IP Wazuh Manager/Worker: " WAZUH_MANAGER
read -p "Masukkan Nama Agent: " WAZUH_AGENT_NAME
WAZUH_AGENT_GROUP="TMMIN"

# --- 3. Install Tools & Repositori ---
echo -e "\n\e[33m[1/8] Menyiapkan Repositori Wazuh...\e[0m"
apt-get update
apt-get install -y gnupg apt-transport-https curl

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update

# --- 4. Instalasi Agent (Versi 4.9.2-1) ---
echo -e "\e[33m[2/8] Menginstall Wazuh Agent 4.9.2-1...\e[0m"
WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" apt-get install -y wazuh-agent=4.9.2-1

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# --- 5. Lock Versi Agent (Hold Update) ---
echo -e "\e[33m[3/8] Menonaktifkan Update Otomatis Wazuh...\e[0m"
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
apt-get update
echo "wazuh-agent hold" | dpkg --set-selections

# --- 6. Instalasi & Konfigurasi Auditd ---
echo -e "\e[33m[4/8] Menginstall dan Mengatur Auditd Rules...\e[0m"
apt-get install -y auditd
systemctl start auditd
systemctl enable auditd

# Menambah rules audit
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/rules.d/audit.rules
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/rules.d/audit.rules

# Reload rules
augenrules --load

# --- 7. Integrasi Log Auditd ke Wazuh (ossec.conf) ---
echo -e "\e[33m[5/8] Mengintegrasikan Log Auditd ke ossec.conf...\e[0m"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

# 1. Cek apakah konfigurasi audit sudah ada (agar tidak dobel)
if ! grep -q "/var/log/audit/audit.log" "$OSSEC_CONF"; then
    
    # 2. Gunakan sed untuk menyisipkan HANYA di kemunculan PERTAMA tag <ossec_config>
    # Kita pakai angka '0,' agar sed berhenti setelah melakukan tugas pertama kali
    sed -i '0,/<ossec_config>/s//<ossec_config>\n  <localfile>\n    <log_format>audit<\/log_format>\n    <location>\/var\/log\/audit\/audit.log<\/location>\n  <\/localfile>/' "$OSSEC_CONF"
    
    echo -e "\e[32m[OK] Konfigurasi Audit disisipkan ke blok ossec_config utama.\e[0m"
else
    echo -e "\e[33m[SKIP] Konfigurasi Audit sudah ada, tidak menduplikat.\e[0m"
fi

# --- 8. Mengaktifkan Remote Commands ---
echo -e "\e[33m[6/8] Mengaktifkan Remote Commands...\e[0m"
INTERNAL_OPT="/var/ossec/etc/internal_options.conf"
LOCAL_OPT="/var/ossec/etc/local_internal_options.conf"

sed -i 's/logcollector.remote_commands=0/logcollector.remote_commands=1/' "$INTERNAL_OPT"
sed -i 's/wazuh_command.remote_commands=0/wazuh_command.remote_commands=1/' "$INTERNAL_OPT"

echo "logcollector.remote_commands=1" > "$LOCAL_OPT"
echo "wazuh_command.remote_commands=1" >> "$LOCAL_OPT"

# --- 9. Restart Service ---
systemctl restart wazuh-agent

# --- 10. BLOK VERIFIKASI OTOMATIS ---
echo -e "\n\e[36m=== VERIFIKASI HASIL INSTALASI ===\e[0m"

# A. Verifikasi Auditd Rules
echo -n "1. Auditd Rules: "
if auditctl -l | grep -q "audit-wazuh-c"; then
    echo -e "\e[32m[OK] Rules ditemukan.\e[0m"
else
    echo -e "\e[31m[FAILED] Rules tidak ditemukan!\e[0m"
fi

# B. Verifikasi Integrasi Log Auditd di ossec.conf
echo -n "2. Integrasi ossec.conf: "
if grep -q "<location>/var/log/audit/audit.log</location>" "$OSSEC_CONF"; then
    echo -e "\e[32m[OK] Konfigurasi log audit ditemukan.\e[0m"
else
    echo -e "\e[31m[FAILED] Konfigurasi log audit tidak ditemukan!\e[0m"
fi

# C. Verifikasi Remote Commands (internal_options)
echo -n "3. Remote Commands (Internal): "
if grep -q "remote_commands=1" "$INTERNAL_OPT"; then
    echo -e "\e[32m[OK] Aktif di internal_options.\e[0m"
else
    echo -e "\e[31m[FAILED] Belum aktif di internal_options!\e[0m"
fi

# D. Verifikasi Remote Commands (local_internal_options)
echo -n "4. Remote Commands (Local): "
if [ -f "$LOCAL_OPT" ] && grep -q "remote_commands=1" "$LOCAL_OPT"; then
    echo -e "\e[32m[OK] Aktif di local_internal_options.\e[0m"
else
    echo -e "\e[31m[FAILED] File local_internal_options bermasalah!\e[0m"
fi

# E. Cek Status Service
STATUS_AGENT=$(systemctl is-active wazuh-agent)
STATUS_AUDITD=$(systemctl is-active auditd)

echo -e "5. Status Wazuh Agent: $([ "$STATUS_AGENT" == "active" ] && echo -e "\e[32m$STATUS_AGENT\e[0m" || echo -e "\e[31m$STATUS_AGENT\e[0m")"
echo -e "6. Status Auditd: $([ "$STATUS_AUDITD" == "active" ] && echo -e "\e[32m$STATUS_AUDITD\e[0m" || echo -e "\e[31m$STATUS_AUDITD\e[0m")"

echo -e "\n\e[36mSelesai! Agent sudah aktif dan terhubung!.\e[0m"
