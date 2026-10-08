#!/bin/bash
# =============================================================================
#  Pencabutan Wazuh Agent - Linux
#
#  Distribusi yang didukung:
#    Debian, Ubuntu                      (apt)
#    RHEL, CentOS, Rocky, AlmaLinux      (dnf atau yum)
#
#  CARA PAKAI
#      bash uninstall_wazuh_linux.sh
#
#  Tanpa konfirmasi, untuk otomasi:
#      ASSUME_YES=1 bash uninstall_wazuh_linux.sh
#
#  VARIABEL LINGKUNGAN
#    ASSUME_YES        isi 1 untuk melewati semua konfirmasi
#    KEEP_AUDIT_RULES  isi 1 untuk MEMBIARKAN aturan audit tetap terpasang
#    KEEP_REPO         isi 1 untuk membiarkan repositori Wazuh terdaftar
#    KEEP_AUDITD       isi 1 untuk membiarkan paket auditd terpasang
#    PURGE_LOGS        isi 1 untuk menghapus juga log pemasangan di /var/log
#
#  KODE KELUAR
#    0  terhapus bersih, tidak ada sisa
#    1  gagal sebelum mulai, misalnya bukan root
#    2  terhapus, ada sisa yang bisa dibereskan tanpa menyalakan ulang
#    3  GAGAL, paket atau folder agent masih ada
#
#  TIDAK PERLU MENYALAKAN ULANG MESIN
#  Aturan audit hidup di kernel dan dilepas seketika oleh auditctl, jadi
#  pencabutan tidak memerlukan mesin dinyalakan ulang. Satu satunya
#  pengecualian adalah auditd yang dikunci dalam mode immutable (-e 2),
#  yang menurut dokumentasi auditctl hanya bisa dibuka dengan menyalakan
#  ulang mesin. Mode itu bukan bawaan dan hanya ada bila diatur sengaja.
#  Skrip membedakan kedua keadaan ini di pesan penutupnya.
#
#  URUTAN PENTING
#  Layanan dihentikan dan proses dimatikan SEBELUM folder dihapus. Tanpa
#  urutan itu, berkas terkunci dan penghapusan gagal diam diam.
#
#  Aturan audit dibuang secara baku. Bila ditinggalkan, kernel terus
#  mencatat setiap eksekusi perintah padahal tidak ada lagi yang
#  mengirimkannya, dan /var/log/audit tumbuh tanpa batas.
# =============================================================================
set -uo pipefail

ASSUME_YES="${ASSUME_YES:-0}"
KEEP_AUDIT_RULES="${KEEP_AUDIT_RULES:-0}"
KEEP_REPO="${KEEP_REPO:-0}"
KEEP_AUDITD="${KEEP_AUDITD:-0}"
PURGE_LOGS="${PURGE_LOGS:-0}"

OSSEC_DIR="/var/ossec"
AUDIT_RULES="/etc/audit/rules.d/wazuh.rules"
LOGFILE="/var/log/wazuh-agent-uninstall-$(date +%Y%m%d-%H%M%S).log"

R='\e[31m'; G='\e[32m'; Y='\e[33m'; B='\e[34m'; GRY='\e[90m'; N='\e[0m'
STEP=0
STEP_TOTAL=8
declare -a PROBLEMS=()

info(){ echo -e "${B}[INFO]${N} $*"; }
ok(){   echo -e "${G}[ OK ]${N} $*"; }
dim(){  echo -e "${GRY}       $*${N}"; }
prob(){ echo -e "${Y}[WARN]${N} $*"; PROBLEMS+=("$*"); }
die(){  echo -e "${R}[FAIL]${N} $*" >&2; exit 1; }
step(){ STEP=$((STEP + 1)); echo; echo -e "${Y}[$STEP/$STEP_TOTAL]${N} $*"; }

[ "$(id -u)" -eq 0 ] || die "Harus dijalankan sebagai root."

exec > >(tee -a "$LOGFILE") 2>&1

ask() {
    local prompt="$1" varname="$2" answer=""
    if [ -r /dev/tty ]; then
        read -r -p "$prompt" answer < /dev/tty
    elif [ -t 0 ]; then
        read -r -p "$prompt" answer
    else
        die "Tidak ada terminal untuk bertanya. Pakai ASSUME_YES=1."
    fi
    printf -v "$varname" '%s' "$answer" 2>/dev/null || eval "$varname=\$answer"
}

# ---------- deteksi distribusi ----------
PKG=""
OS_FAMILY=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian|raspbian|linuxmint|pop) OS_FAMILY="debian"; PKG="apt" ;;
        rhel|centos|rocky|almalinux|ol|oraclelinux|fedora|amzn)
            OS_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
        *)
            case "${ID_LIKE:-}" in
                *debian*) OS_FAMILY="debian"; PKG="apt" ;;
                *rhel*|*fedora*|*centos*)
                    OS_FAMILY="rhel"
                    if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
            esac ;;
    esac
fi

# Bila distribusi tidak dikenali, pembersihan manual tetap bisa dilakukan.
if [ -z "$PKG" ]; then
    if command -v apt-get >/dev/null 2>&1; then OS_FAMILY="debian"; PKG="apt"
    elif command -v dnf >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG="dnf"
    elif command -v yum >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG="yum"
    fi
fi

clear 2>/dev/null || true
echo "=============================================================="
echo "   Pencabutan Wazuh Agent untuk Linux"
echo "=============================================================="
echo
echo "   Mesin        : $(hostname 2>/dev/null || echo '?')"
echo "   Distribusi   : ${PRETTY_NAME:-tidak dikenali}"
echo "   manager paket: ${PKG:-tidak ditemukan}"
echo "   Berkas log   : $LOGFILE"

# =============================================================================
#  Langkah 1: periksa apa yang terpasang
# =============================================================================
step "Memeriksa apa yang terpasang"

FOUND_ANY=0

SVC_STATE="tidak ada"
if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
    SVC_STATE="$(systemctl is-active wazuh-agent 2>/dev/null || echo 'tidak aktif')"
    FOUND_ANY=1
    dim "Layanan wazuh-agent: $SVC_STATE"
else
    dim "Layanan wazuh-agent tidak terdaftar"
fi

if [ -d "$OSSEC_DIR" ]; then
    FOUND_ANY=1
    DIR_SIZE="$(du -sh "$OSSEC_DIR" 2>/dev/null | cut -f1 || echo '?')"
    dim "Folder $OSSEC_DIR ada, ukuran $DIR_SIZE"
else
    dim "Folder $OSSEC_DIR tidak ada"
fi

PKG_PRESENT=0
case "$PKG" in
    apt)
        # Status dpkg tidak hanya 'install ok installed'. Bila pencabutan
        # sebelumnya berhenti di tengah, status menjadi half-installed,
        # half-configured, atau config-files. Semua keadaan itu berarti
        # paket masih tercatat dan tetap perlu dibereskan, jadi tidak
        # boleh dianggap bersih.
        DPKG_STATUS="$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)"
        if [ -n "$DPKG_STATUS" ] && [ "$DPKG_STATUS" != "unknown ok not-installed" ] \
           && [ "$DPKG_STATUS" != "purge ok not-installed" ]; then
            PKG_PRESENT=1; FOUND_ANY=1
            PKG_VER="$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)"
            case "$DPKG_STATUS" in
                "install ok installed")
                    dim "Paket wazuh-agent terpasang, versi $PKG_VER" ;;
                *half-installed*|*half-configured*)
                    dim "Paket wazuh-agent dalam keadaan setengah terpasang: $DPKG_STATUS"
                    dim "Pencabutan sebelumnya berhenti di tengah." ;;
                *config-files*)
                    dim "Paket sudah dicabut tetapi berkas konfigurasi masih tercatat: $DPKG_STATUS" ;;
                *)
                    dim "Paket wazuh-agent berstatus: $DPKG_STATUS" ;;
            esac
        fi ;;
    dnf|yum)
        if rpm -q wazuh-agent >/dev/null 2>&1; then
            PKG_PRESENT=1; FOUND_ANY=1
            dim "Paket terpasang: $(rpm -q wazuh-agent 2>/dev/null)"
        fi ;;
esac
[ "$PKG_PRESENT" -eq 0 ] && dim "Paket wazuh-agent tidak terdaftar di manager paket"

AUDIT_PRESENT=0
if [ -f "$AUDIT_RULES" ]; then
    AUDIT_PRESENT=1; FOUND_ANY=1
    AR_COUNT="$(grep -cE '^-[aw] ' "$AUDIT_RULES" 2>/dev/null || echo 0)"
    dim "Berkas aturan audit ada, $AR_COUNT aturan"
fi
if command -v auditctl >/dev/null 2>&1; then
    LOADED="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
    if [ "$LOADED" -gt 0 ]; then
        AUDIT_PRESENT=1; FOUND_ANY=1
        dim "$LOADED aturan audit Wazuh aktif di kernel"
    fi
fi

# Identitas agent perlu ditampilkan sebelum dihapus, karena entri di
# manager harus dibersihkan manual memakai ID ini.
AGENT_IDENT=""
if [ -s "$OSSEC_DIR/etc/client.keys" ]; then
    AGENT_IDENT="$(awk 'NR==1{print $1" ("$2")"}' "$OSSEC_DIR/etc/client.keys" 2>/dev/null || true)"
    [ -n "$AGENT_IDENT" ] && dim "Terdaftar di manager sebagai: $AGENT_IDENT"
fi

if [ "$FOUND_ANY" -eq 0 ]; then
    echo
    ok "Tidak ada jejak Wazuh Agent di mesin ini. Tidak ada yang perlu dihapus."
    echo
    exit 0
fi

# --- konfirmasi
if [ "$ASSUME_YES" != "1" ]; then
    echo
    echo "   Yang akan dihapus:"
    echo "     Layanan dan paket wazuh-agent"
    echo "     Folder $OSSEC_DIR beserta seluruh isinya"
    [ "$KEEP_AUDIT_RULES" != "1" ] && echo "     Aturan audit Wazuh di $AUDIT_RULES"
    [ "$KEEP_REPO" != "1" ] && echo "     Repositori Wazuh dan kunci GPG"
    [ "$KEEP_AUDITD" = "1" ] && echo "     Paket auditd DIBIARKAN terpasang"
    echo
    echo -e "   ${Y}Kunci pendaftaran agent ikut terhapus.${N}"
    echo -e "   ${Y}Bila agent dipasang ulang, ia mendaftar sebagai entri baru,${N}"
    echo -e "   ${Y}dan entri lama perlu dihapus manual dari dashboard.${N}"
    if [ -n "$AGENT_IDENT" ]; then
        echo -e "   ${Y}Entri saat ini: $AGENT_IDENT${N}"
    fi
    echo
    ask "   Lanjutkan pencabutan? (y/N): " GO
    case "${GO:-N}" in
        [Yy]*) : ;;
        *) echo "   Dibatalkan."; exit 0 ;;
    esac
fi

# =============================================================================
#  Langkah 2: hentikan layanan
# =============================================================================
step "Menghentikan layanan"

if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
    systemctl stop wazuh-agent >/dev/null 2>&1 || true
    systemctl disable wazuh-agent >/dev/null 2>&1 || true

    # Tunggu sampai benar benar berhenti. Tanpa jeda ini, proses masih
    # memegang berkas dan penghapusan folder gagal.
    for _ in $(seq 1 15); do
        systemctl is-active --quiet wazuh-agent 2>/dev/null || break
        sleep 1
    done

    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        prob "Layanan masih aktif setelah 15 detik."
    else
        ok "Layanan dihentikan dan dinonaktifkan"
    fi
else
    dim "Tidak ada unit systemd wazuh-agent"
fi

# Skrip kendali bawaan agent, dipakai bila systemd tidak mengelolanya.
if [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    "$OSSEC_DIR/bin/wazuh-control" stop >/dev/null 2>&1 || true
    dim "wazuh-control stop dijalankan"
fi

# Proses yang tersisa akan mengunci berkas. Dimatikan secara bertahap:
# sinyal biasa lebih dulu, baru paksa.
AGENT_PROCS="wazuh-agentd wazuh-logcollector wazuh-syscheckd wazuh-modulesd wazuh-execd agent-auth ossec-agentd"
KILLED=0
for p in $AGENT_PROCS; do
    if pgrep -x "$p" >/dev/null 2>&1; then
        pkill -TERM -x "$p" >/dev/null 2>&1 || true
        KILLED=$((KILLED + 1))
    fi
done
if [ "$KILLED" -gt 0 ]; then
    sleep 3
    STILL=0
    for p in $AGENT_PROCS; do
        if pgrep -x "$p" >/dev/null 2>&1; then
            pkill -KILL -x "$p" >/dev/null 2>&1 || true
            STILL=$((STILL + 1))
        fi
    done
    sleep 1
    ok "$KILLED proses agent dihentikan$([ "$STILL" -gt 0 ] && echo ", $STILL perlu dipaksa")"
else
    dim "Tidak ada proses agent yang berjalan"
fi

# =============================================================================
#  Langkah 3: aturan audit
# =============================================================================
step "Membersihkan aturan audit"

if [ "$KEEP_AUDIT_RULES" = "1" ]; then
    dim "Dibiarkan karena KEEP_AUDIT_RULES=1"
    dim "Perhatian: kernel terus mencatat eksekusi perintah tanpa ada yang mengirimkannya."
else
    REMOVED_RULES=0

    if [ -f "$AUDIT_RULES" ]; then
        # Cadangan dibuat sebelum dihapus, supaya aturan bisa dipulihkan
        # bila pencabutan ternyata keliru.
        # Cadangan disimpan DI LUAR rules.d. Perintah augenrules membaca
        # setiap berkas di direktori itu tanpa memandang akhiran namanya,
        # sehingga cadangan yang ditaruh di sana akan dimuat kembali ke
        # kernel pada pemuatan berikutnya dan aturan tidak pernah benar
        # benar lepas.
        mkdir -p /var/backups/wazuh-audit 2>/dev/null || true
        cp -a "$AUDIT_RULES" "/var/backups/wazuh-audit/wazuh.rules.removed.$(date +%s)" 2>/dev/null || true
        rm -f "$AUDIT_RULES" && REMOVED_RULES=1
        ok "Berkas aturan dihapus, cadangan disimpan sebagai .removed.*"
    else
        dim "Berkas $AUDIT_RULES tidak ada"
    fi

    # Berkas lain di rules.d yang memuat kunci audit-wazuh. Perintah
    # augenrules membaca SETIAP berkas di direktori itu tanpa memandang
    # nama atau akhirannya, jadi satu salinan tertinggal sudah cukup untuk
    # memuat ulang aturan ke kernel tepat setelah dihapus.
    #
    # Pola *.rules saja tidak cukup: cadangan berakhiran .removed.* dari
    # versi skrip sebelumnya juga ikut terbaca augenrules.
    if [ -d /etc/audit/rules.d ]; then
        OTHER_FILES="$(grep -rl 'audit-wazuh' /etc/audit/rules.d/ 2>/dev/null \
                       | grep -v "^${AUDIT_RULES}$" || true)"
        if [ -n "$OTHER_FILES" ]; then
            prob "Ada berkas lain di rules.d yang memuat kunci audit-wazuh:"
            mkdir -p /var/backups/wazuh-audit 2>/dev/null || true
            printf '%s\n' "$OTHER_FILES" | while IFS= read -r f; do
                [ -n "$f" ] || continue
                base="$(basename "$f")"
                cp -a "$f" "/var/backups/wazuh-audit/${base}.$(date +%s)" 2>/dev/null || true
                case "$base" in
                    wazuh.rules.removed.*|wazuh.rules.bak*)
                        # Cadangan dari versi skrip sebelumnya. Dipindah
                        # keluar dari rules.d, bukan sekadar disunting.
                        rm -f "$f" 2>/dev/null || true
                        dim "  $f (cadangan lama, dipindah ke /var/backups/wazuh-audit)" ;;
                    *)
                        # Berkas milik sistem atau perangkat lain. Hanya
                        # baris Wazuh yang dibuang, isi lain dipertahankan.
                        sed -i '/audit-wazuh/d' "$f" 2>/dev/null || true
                        dim "  $f (baris audit-wazuh dibuang, isi lain tetap)" ;;
                esac
            done
            dim "Cadangan semua berkas disimpan di /var/backups/wazuh-audit"
        fi
    fi

    # Memuat ulang dari berkas aturan yang tersisa. Karena berkas Wazuh
    # sudah dihapus, hasil muat ulang berisi aturan milik perangkat lain
    # saja, dan aturan Wazuh lepas dari kernel seketika.
    #
    # TIDAK PERLU MENYALAKAN ULANG MESIN. Aturan audit hidup di kernel
    # dan dilepas langsung oleh auditctl. Satu satunya pengecualian
    # adalah mode immutable, yang dijelaskan di bawah.
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    fi

    if command -v auditctl >/dev/null 2>&1; then
        if auditctl -s 2>/dev/null | grep -qE '^enabled[[:space:]]+2'; then
            # Mode immutable (-e 2) membekukan seluruh konfigurasi audit.
            # Setiap upaya mengubah akan dicatat lalu ditolak kernel, dan
            # menurut dokumentasi auditctl hanya menyalakan ulang mesin
            # yang bisa membukanya. Mode ini bukan bawaan, jadi hanya
            # muncul bila memang diatur sengaja untuk pengerasan sistem.
            prob "auditd dalam mode immutable (-e 2). Aturan tidak bisa dilepas tanpa menyalakan ulang mesin."
            dim "Berkas aturan sudah dihapus, jadi setelah dinyalakan ulang aturan tidak dimuat lagi."
            dim "Sampai saat itu, kernel masih mencatat sesuai aturan lama."
        else
            LEFT_RULES="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
            if [ "$LEFT_RULES" -eq 0 ]; then
                ok "Tidak ada aturan audit Wazuh yang aktif di kernel"
            else
                # Hapus menurut kunci. Opsi -D menerima -k sehingga hanya
                # aturan bertanda audit-wazuh yang dibuang, dan aturan
                # milik perangkat lain tidak tersentuh.
                #
                # Pendekatan sebelumnya memakai 'auditctl -d' dengan baris
                # hasil 'auditctl -l'. Itu tidak dapat diandalkan karena
                # format keluaran -l berbeda dari format masukan -d.
                for key in audit-wazuh-c audit-wazuh-w audit-wazuh-privesc \
                           audit-wazuh-inject audit-wazuh-kmod audit-wazuh-rootkit \
                           audit-wazuh-persist audit-wazuh-net audit-wazuh-tool \
                           audit-wazuh-antiforensik audit-wazuh-config \
                           audit-wazuh-mount audit-wazuh-netconn; do
                    auditctl -D -k "$key" >/dev/null 2>&1 || true
                done

                # Aturan pemantauan berkas yang dipasang dengan -w tidak
                # selalu lepas lewat penyaring kunci. Bentuk resmi untuk
                # membuangnya adalah -W dengan jalur yang sama persis,
                # jadi jalur itu dibaca kembali dari daftar aturan.
                LEFT_RULES="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
                if [ "$LEFT_RULES" -gt 0 ]; then
                    # Perintah 'auditctl -l' menormalkan aturan pemantauan
                    # berkas menjadi bentuk '-a always,exit -F path=...',
                    # bukan bentuk '-w' seperti saat ditulis. Jadi baris
                    # hasil -l dipakai apa adanya sebagai keterangan untuk
                    # -d, dan untuk aturan berbasis path dicoba juga -W
                    # dengan jalur yang dibaca dari penyaring path.
                    auditctl -l 2>/dev/null | grep 'audit-wazuh' | \
                    while IFS= read -r r; do
                        # Bentuk ternormalisasi selalu diawali '-a'.
                        spec="${r#-a }"
                        # shellcheck disable=SC2086
                        auditctl -d $spec >/dev/null 2>&1 || true

                        # Aturan yang berasal dari -w memuat '-F path=...'.
                        case "$r" in
                            *" -F path="*)
                                wpath="$(printf '%s\n' "$r" | sed -n 's/.*-F path=\([^ ]*\).*/\1/p')"
                                [ -n "$wpath" ] && auditctl -W "$wpath" >/dev/null 2>&1 || true ;;
                        esac
                    done
                    LEFT_RULES="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
                fi

                # Upaya terakhir sebelum menyerah: bila yang tersisa hanya
                # aturan Wazuh dan tidak ada aturan milik perangkat lain,
                # membuang seluruh aturan aman dilakukan.
                if [ "$LEFT_RULES" -gt 0 ]; then
                    OTHER_RULES="$(auditctl -l 2>/dev/null | grep -v 'audit-wazuh' | grep -cE '^-' || true)"
                    if [ "$OTHER_RULES" -eq 0 ]; then
                        dim "Tidak ada aturan audit milik perangkat lain, membuang semuanya"
                        auditctl -D >/dev/null 2>&1 || true
                        LEFT_RULES="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
                    else
                        dim "Ada $OTHER_RULES aturan audit milik perangkat lain, tidak dibuang"
                    fi
                fi

                if [ "$LEFT_RULES" -eq 0 ]; then
                    ok "Aturan audit dilepas dari kernel tanpa perlu menyalakan ulang"
                else
                    prob "$LEFT_RULES aturan audit masih aktif setelah dicoba dilepas."
                    echo
                    dim "Aturan yang tersisa:"
                    auditctl -l 2>/dev/null | grep 'audit-wazuh' | while IFS= read -r r; do
                        dim "  $r"
                    done
                    echo
                    dim "Berkas aturan sudah dihapus, jadi aturan ini tidak dimuat lagi"
                    dim "setelah mesin dinyalakan ulang berikutnya."
                    dim "Untuk melepas sekarang juga, perintah di bawah membuang SEMUA"
                    dim "aturan audit di mesin ini, termasuk milik perangkat lain:"
                    dim "  auditctl -D"
                fi
            fi
        fi
    fi

    # Pengaturan auditd.conf yang diubah installer dipulihkan dari
    # cadangan tertua yang dibuatnya.
    OLDEST_BAK="$(ls -1tr /etc/audit/auditd.conf.bak.* 2>/dev/null | head -1 || true)"
    if [ -n "$OLDEST_BAK" ] && [ -f "$OLDEST_BAK" ]; then
        if [ "$ASSUME_YES" = "1" ]; then
            RESTORE="y"
        else
            echo
            dim "Installer mengubah /etc/audit/auditd.conf (ukuran dan rotasi log)."
            ask "   Pulihkan auditd.conf dari cadangan $OLDEST_BAK? (y/N): " RESTORE
        fi
        case "${RESTORE:-N}" in
            [Yy]*)
                cp -a "$OLDEST_BAK" /etc/audit/auditd.conf && \
                  ok "auditd.conf dipulihkan dari cadangan"
                systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
                ;;
            *) dim "auditd.conf dibiarkan seperti sekarang" ;;
        esac
    fi
fi

# =============================================================================
#  Langkah 4: cabut paket
# =============================================================================
step "Mencabut paket wazuh-agent"

# Skrip prerm bawaan paket memakai 'set -e' lalu memanggil
#
#   /var/ossec/bin/wazuh-control stop
#
# tanpa memeriksa apakah berkas itu ada. Bila folder agen sudah terhapus
# lebih dulu, pemanggilan tersebut berakhir dengan kode 127, prerm
# berhenti, dan dpkg menolak mencabut paket. Akibatnya paket tersangkut:
# tidak bisa dicabut, tidak bisa dipasang ulang.
#
# Berkas boneka di bawah membuat prerm berjalan sampai selesai. Ini bukan
# siasat sembarangan: berkas hanya mengembalikan kode nol, dan folder
# dihapus lagi pada langkah berikutnya.
PRERM_STUB_MADE=0
PKG_REMOVE_FAILED=0
if [ "$PKG_PRESENT" -eq 1 ] && [ ! -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    mkdir -p "$OSSEC_DIR/bin" 2>/dev/null || true
    if printf '#!/bin/sh\nexit 0\n' > "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null; then
        chmod 0755 "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null || true
        PRERM_STUB_MADE=1
        dim "Berkas bantu wazuh-control dibuat agar skrip prerm paket tidak gagal"
    fi
fi

case "$PKG" in
    apt)
        # Status hold harus dilepas lebih dulu, kalau tidak apt menolak
        # mencabut paket.
        if apt-mark showhold 2>/dev/null | grep -q '^wazuh-agent$'; then
            apt-mark unhold wazuh-agent >/dev/null 2>&1 && dim "Status hold dilepas"
        fi
        # Cadangan cara lama, untuk sistem tanpa apt-mark.
        echo "wazuh-agent install" | dpkg --set-selections >/dev/null 2>&1 || true

        if [ "$PKG_PRESENT" -eq 1 ]; then
            PURGE_OUT="$(mktemp)"
            if DEBIAN_FRONTEND=noninteractive apt-get purge -y wazuh-agent > "$PURGE_OUT" 2>&1; then
                ok "Paket dicabut dengan apt-get purge"
            else
                prob "apt-get purge gagal, mencoba dpkg --purge --force-all"
                # Keluaran apt menjelaskan sebabnya, misalnya skrip prerm
                # yang berhenti dengan kode 127.
                tail -8 "$PURGE_OUT" | while IFS= read -r l; do dim "$l"; done
                dpkg --purge --force-all wazuh-agent >/dev/null 2>&1 || true

                # Kode keluar dpkg dengan --force-all tidak dapat
                # diandalkan, jadi status akhir yang diperiksa.
                AFTER="$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)"
                case "$AFTER" in
                    ""|"unknown ok not-installed"|"purge ok not-installed")
                        ok "Paket dicabut dengan dpkg --purge --force-all" ;;
                    *)
                        PKG_REMOVE_FAILED=1
                        prob "Pencabutan paket GAGAL, status tersisa: $AFTER"
                        dim "Folder agent tidak akan dihapus agar keadaan tidak bertambah rumit." ;;
                esac
            fi
            rm -f "$PURGE_OUT"
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1 || true
        else
            dim "Paket tidak terdaftar, pencabutan dilewati"
        fi
        ;;
    dnf|yum)
        # Kunci versi harus dilepas lebih dulu.
        if $PKG versionlock list 2>/dev/null | grep -q 'wazuh-agent'; then
            $PKG versionlock delete wazuh-agent >/dev/null 2>&1 && dim "Kunci versi dilepas"
        fi

        if [ "$PKG_PRESENT" -eq 1 ]; then
            RM_OUT="$(mktemp)"
            if $PKG remove -y wazuh-agent > "$RM_OUT" 2>&1; then
                ok "Paket dicabut dengan $PKG remove"
            else
                prob "$PKG remove gagal, mencoba rpm -e --nodeps"
                tail -8 "$RM_OUT" | while IFS= read -r l; do dim "$l"; done
                if rpm -e --nodeps wazuh-agent >/dev/null 2>&1; then
                    ok "Paket dicabut dengan rpm -e --nodeps"
                else
                    # Skrip preun yang gagal bisa dilewati sepenuhnya.
                    if rpm -e --nodeps --noscripts wazuh-agent >/dev/null 2>&1; then
                        ok "Paket dicabut dengan rpm -e --noscripts"
                    else
                        PKG_REMOVE_FAILED=1
                        prob "Pencabutan paket GAGAL. Folder agent tidak akan dihapus."
                    fi
                fi
            fi
            rm -f "$RM_OUT"
        else
            dim "Paket tidak terdaftar, pencabutan dilewati"
        fi
        ;;
    *)
        prob "manager paket tidak dikenali. Paket perlu dicabut manual."
        ;;
esac

# Unit systemd yang tertinggal setelah paket dicabut.
if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
    rm -f /etc/systemd/system/wazuh-agent.service \
          /usr/lib/systemd/system/wazuh-agent.service \
          /lib/systemd/system/wazuh-agent.service 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed wazuh-agent >/dev/null 2>&1 || true
    dim "Unit systemd yang tertinggal dibersihkan"
fi

# =============================================================================
#  Langkah 5: hapus folder
# =============================================================================
step "Menghapus folder agent"

# Folder TIDAK dihapus bila paket masih tersangkut di basis data dpkg
# atau rpm. Menghapusnya justru memperparah keadaan: skrip prerm paket
# memanggil berkas di dalam folder ini, sehingga pencabutan berikutnya
# gagal dengan kode 127 dan paket menjadi tidak bisa dicabut maupun
# dipasang ulang.
if [ "$PKG_REMOVE_FAILED" -eq 1 ]; then
    prob "Folder $OSSEC_DIR sengaja TIDAK dihapus karena paket masih tersangkut."
    dim "Menghapusnya sekarang membuat paket tidak bisa dicabut sama sekali,"
    dim "karena skrip prerm paket memanggil $OSSEC_DIR/bin/wazuh-control."
    echo
    dim "Bereskan paketnya lebih dulu:"
    case "$PKG" in
        apt)     dim "  dpkg --purge --force-all wazuh-agent" ;;
        dnf|yum) dim "  rpm -e --nodeps --noscripts wazuh-agent" ;;
    esac
    dim "lalu jalankan skrip ini sekali lagi."
elif [ -d "$OSSEC_DIR" ]; then
    if rm -rf "$OSSEC_DIR" 2>/dev/null; then
        ok "Folder $OSSEC_DIR dihapus"
    else
        # Coba sekali lagi setelah jeda. Pegangan berkas kadang butuh
        # waktu untuk dilepas setelah proses berhenti.
        dim "Percobaan pertama gagal, mencoba ulang setelah 5 detik"
        sleep 5
        if rm -rf "$OSSEC_DIR" 2>/dev/null; then
            ok "Folder dihapus pada percobaan kedua"
        else
            prob "Folder $OSSEC_DIR tidak bisa dihapus."
            if command -v lsof >/dev/null 2>&1; then
                HOLDERS="$(lsof +D "$OSSEC_DIR" 2>/dev/null | awk 'NR>1{print $1}' | sort -u | tr '\n' ' ')"
                [ -n "$HOLDERS" ] && dim "Proses yang memegang berkas: $HOLDERS"
            fi
        fi
    fi
else
    dim "Folder $OSSEC_DIR tidak ada"
fi

# Pengguna dan grup sistem yang dibuat paket. Dibiarkan secara sengaja
# karena berkas lain di sistem bisa masih memilikinya, dan menghapus
# pengguna yang masih dipakai menimbulkan berkas tanpa pemilik.
if getent passwd wazuh >/dev/null 2>&1 || getent group wazuh >/dev/null 2>&1; then
    dim "Pengguna dan grup 'wazuh' dibiarkan. Hapus manual bila yakin tidak dipakai:"
    dim "  userdel wazuh 2>/dev/null; groupdel wazuh 2>/dev/null"
fi

# =============================================================================
#  Langkah 6: repositori
# =============================================================================
step "Membersihkan repositori"

if [ "$KEEP_REPO" = "1" ]; then
    dim "Dibiarkan karena KEEP_REPO=1"
else
    case "$OS_FAMILY" in
        debian)
            rm -f /etc/apt/sources.list.d/wazuh.list 2>/dev/null \
              && ok "Daftar repositori apt dihapus" \
              || dim "Berkas daftar repositori tidak ada"
            rm -f /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
            # Versi lama memakai apt-key, kuncinya tersimpan di tempat lain.
            rm -f /etc/apt/trusted.gpg.d/wazuh.gpg 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
            dim "Daftar paket diperbarui"
            ;;
        rhel)
            rm -f /etc/yum.repos.d/wazuh.repo 2>/dev/null \
              && ok "Berkas repositori yum dihapus" \
              || dim "Berkas repositori tidak ada"
            # Kunci GPG yang diimpor ke basis data rpm.
            RPMKEY="$(rpm -qa 'gpg-pubkey*' --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' 2>/dev/null | grep -i wazuh | awk '{print $1}' || true)"
            if [ -n "$RPMKEY" ]; then
                echo "$RPMKEY" | while IFS= read -r k; do
                    rpm -e "$k" >/dev/null 2>&1 || true
                done
                dim "Kunci GPG Wazuh dihapus dari basis data rpm"
            fi
            # Baris exclude dari versi installer lama, bila ada.
            for cf in /etc/yum.conf /etc/dnf/dnf.conf; do
                if [ -f "$cf" ] && grep -qE '^exclude=.*wazuh-agent' "$cf" 2>/dev/null; then
                    sed -i '/^exclude=.*wazuh-agent/d' "$cf"
                    dim "Baris exclude wazuh-agent dibuang dari $cf"
                fi
            done
            $PKG clean all >/dev/null 2>&1 || true
            ;;
        *)
            dim "Keluarga distribusi tidak dikenali, repositori perlu dibersihkan manual"
            ;;
    esac
fi

# =============================================================================
#  Langkah 7: auditd
# =============================================================================
step "Paket auditd"

if [ "$KEEP_AUDITD" = "1" ]; then
    dim "Dibiarkan terpasang karena KEEP_AUDITD=1"
else
    # Dibiarkan secara baku. auditd sering dipakai perangkat lain dan
    # merupakan bagian dari pengerasan sistem, jadi mencabutnya bisa
    # melemahkan mesin di luar urusan Wazuh.
    if command -v auditctl >/dev/null 2>&1; then
        dim "auditd dibiarkan terpasang. Ini disengaja."
        dim "auditd bagian dari pengerasan sistem dan sering dipakai perangkat lain."
        dim "Untuk mencabutnya: KEEP_AUDITD=0 tidak cukup, cabut manual dengan"
        case "$OS_FAMILY" in
            debian) dim "  apt-get purge -y auditd audispd-plugins" ;;
            rhel)   dim "  $PKG remove -y audit" ;;
        esac
    else
        dim "auditd tidak terpasang"
    fi
fi

# Log pemasangan dari skrip installer.
if [ "$PURGE_LOGS" = "1" ]; then
    COUNT="$(find /var/log -maxdepth 1 -name 'wazuh-agent-install-*.log' 2>/dev/null | wc -l)"
    if [ "$COUNT" -gt 0 ]; then
        find /var/log -maxdepth 1 -name 'wazuh-agent-install-*.log' -delete 2>/dev/null || true
        dim "$COUNT berkas log pemasangan dihapus"
    fi
fi

# =============================================================================
#  Langkah 8: verifikasi
# =============================================================================
step "Verifikasi"

declare -a LEFTOVERS=()

# Paket
case "$PKG" in
    apt)
        if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
            LEFTOVERS+=("Paket wazuh-agent masih terpasang")
        else
            ok "Paket tidak terpasang"
        fi
        # Sisa konfigurasi setelah remove tanpa purge.
        if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'deinstall'; then
            LEFTOVERS+=("Konfigurasi paket masih tersisa, jalankan: dpkg --purge wazuh-agent")
        fi ;;
    dnf|yum)
        if rpm -q wazuh-agent >/dev/null 2>&1; then
            LEFTOVERS+=("Paket wazuh-agent masih terpasang")
        else
            ok "Paket tidak terpasang"
        fi ;;
esac

# Folder
if [ -d "$OSSEC_DIR" ]; then
    LEFTOVERS+=("Folder $OSSEC_DIR masih ada")
else
    ok "Folder agent terhapus"
fi

# Layanan
if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
    LEFTOVERS+=("Unit systemd wazuh-agent masih terdaftar")
else
    ok "Unit systemd terhapus"
fi

# Proses
RUNNING=""
for p in $AGENT_PROCS; do
    pgrep -x "$p" >/dev/null 2>&1 && RUNNING="$RUNNING $p"
done
if [ -n "$RUNNING" ]; then
    LEFTOVERS+=("Proses masih berjalan:$RUNNING")
else
    ok "Tidak ada proses agent yang berjalan"
fi

# Aturan audit
if [ "$KEEP_AUDIT_RULES" != "1" ]; then
    if [ -f "$AUDIT_RULES" ]; then
        LEFTOVERS+=("Berkas $AUDIT_RULES masih ada")
    else
        ok "Berkas aturan audit terhapus"
    fi
    if command -v auditctl >/dev/null 2>&1; then
        # Hitung ulang sekaligus simpan isinya, supaya laporan sisa dapat
        # menunjukkan aturan yang dimaksud. Tanpa itu, angka sisa tidak
        # bisa dicocokkan dengan keadaan nyata saat pengguna memeriksanya
        # sendiri beberapa saat kemudian.
        LEFT_LIST="$(auditctl -l 2>/dev/null | grep 'audit-wazuh' || true)"
        if [ -n "$LEFT_LIST" ]; then
            LEFT_K="$(printf '%s\n' "$LEFT_LIST" | wc -l)"
        else
            LEFT_K=0
        fi
        if [ "$LEFT_K" -gt 0 ]; then
            if auditctl -s 2>/dev/null | grep -qE '^enabled[[:space:]]+2'; then
                LEFTOVERS+=("$LEFT_K aturan audit masih aktif karena auditd mode immutable, lepas setelah mesin dinyalakan ulang")
            else
                LEFTOVERS+=("$LEFT_K aturan audit masih aktif di kernel, lepas dengan 'auditctl -D'")
            fi
            # Aturan ditampilkan agar angka sisa dapat dicocokkan dengan
            # keadaan nyata. Bila daftar ini kosong sementara angkanya
            # tidak nol, berarti aturan lepas sendiri di antara kedua
            # pemeriksaan, misalnya karena auditd baru dihentikan.
            echo
            dim "Aturan audit yang masih tercatat:"
            printf '%s\n' "$LEFT_LIST" | while IFS= read -r l; do
                [ -n "$l" ] && dim "  $l"
            done
            dim "Periksa sendiri dengan: auditctl -l | grep audit-wazuh"
        else
            ok "Tidak ada aturan audit yang aktif"
        fi
    fi
fi

# Repositori
if [ "$KEEP_REPO" != "1" ]; then
    REPO_LEFT=""
    [ -f /etc/apt/sources.list.d/wazuh.list ] && REPO_LEFT="apt"
    [ -f /etc/yum.repos.d/wazuh.repo ] && REPO_LEFT="yum"
    if [ -n "$REPO_LEFT" ]; then
        LEFTOVERS+=("Repositori Wazuh ($REPO_LEFT) masih terdaftar")
    else
        ok "Repositori terhapus"
    fi
fi

# =============================================================================
#  Penutup
# =============================================================================
echo
echo "=============================================================="
if [ "${#LEFTOVERS[@]}" -eq 0 ]; then
    echo -e "   ${G}Wazuh Agent terhapus bersih${N}"
    echo "=============================================================="
    echo
    if [ -n "$AGENT_IDENT" ]; then
        echo "   Entri: $AGENT_IDENT"
        echo "   Di manager: /var/ossec/bin/manage_agents -r <id>"
        echo
    fi
    echo "   Berkas log: $LOGFILE"
    echo
    exit 0
else
    # Sisa dipisah menurut keparahan. Paket atau folder yang masih ada
    # berarti pencabutan benar benar gagal. Aturan audit yang masih
    # termuat di kernel hanya menunggu mesin dinyalakan ulang, dan itu
    # keadaan yang berbeda.
    HARD=0
    for l in "${LEFTOVERS[@]}"; do
        case "$l" in
            *"masih terpasang"*|*"Folder"*|*"masih berjalan"*|*"Konfigurasi paket"*)
                HARD=$((HARD + 1)) ;;
        esac
    done

    # Mode immutable adalah satu satunya keadaan yang benar benar
    # memerlukan mesin dinyalakan ulang. Sisa lain bisa dibereskan
    # langsung, dan di server produksi itu perbedaan yang penting.
    NEEDS_REBOOT=0
    if command -v auditctl >/dev/null 2>&1; then
        if auditctl -s 2>/dev/null | grep -qE '^enabled[[:space:]]+2'; then
            NEEDS_REBOOT=1
        fi
    fi

    if [ "$HARD" -gt 0 ]; then
        echo -e "   ${R}GAGAL. Wazuh Agent TIDAK terhapus bersih${N}"
    elif [ "$NEEDS_REBOOT" -eq 1 ]; then
        echo -e "   ${Y}Terhapus. Satu sisa menunggu mesin dinyalakan ulang${N}"
    else
        echo -e "   ${Y}Terhapus, dengan sisa yang bisa dibereskan sekarang${N}"
    fi
    echo "=============================================================="
    echo
    echo -e "   ${Y}Yang masih tertinggal:${N}"
    for l in "${LEFTOVERS[@]}"; do
        echo -e "     ${Y}-${N} $l"
    done
    if [ "${#PROBLEMS[@]}" -gt 0 ]; then
        echo
        echo -e "   ${Y}Masalah selama proses:${N}"
        for p in "${PROBLEMS[@]}"; do
            echo -e "     ${Y}-${N} $p"
        done
    fi
    echo
    if [ "$HARD" -gt 0 ]; then
        echo -e "   ${R}Jangan memasang ulang agent sebelum sisa di atas bersih.${N}"
        echo "   Pemasangan di atas sisa membuat kunci dan konfigurasi bercampur."
        echo
        echo "   Langkah yang disarankan, tanpa perlu menyalakan ulang:"
        echo "     1. Hentikan sisa proses : pkill -KILL -f wazuh"
        echo "     2. Jalankan skrip ini sekali lagi"
        echo "     3. Bila folder tetap terkunci, cari pemegang berkasnya:"
        echo "          lsof +D $OSSEC_DIR"
        echo "          fuser -vm $OSSEC_DIR"
        echo "     4. Bila paket tetap gagal dicabut:"
        case "$PKG" in
            apt)      echo "          dpkg --purge --force-all wazuh-agent" ;;
            dnf|yum)  echo "          rpm -e --nodeps wazuh-agent" ;;
            *)        echo "          cabut manual lewat manager paket distribusi ini" ;;
        esac
        echo
        echo "   Menyalakan ulang mesin hanya diperlukan bila cara di atas gagal,"
        echo "   dan di server produksi itu bisa dijadwalkan terpisah."
    elif [ "$NEEDS_REBOOT" -eq 1 ]; then
        echo "   auditd dikunci dalam mode immutable, sehingga aturan tidak bisa"
        echo "   dilepas dari kernel tanpa menyalakan ulang mesin. Berkas aturan"
        echo "   sudah dihapus, jadi setelah dinyalakan ulang aturan tidak dimuat lagi."
        echo
        echo "   Di server produksi, ini bisa menunggu jadwal pemeliharaan."
        echo "   Sampai saat itu kernel masih mencatat sesuai aturan lama, dan"
        echo "   /var/log/audit tetap tumbuh. Pantau ukurannya:"
        echo "     du -sh /var/log/audit"
    else
        # Aturan audit yang bertahan tidak akan hilang dengan menjalankan
        # skrip ini lagi, karena berkas aturannya sudah terhapus dan tidak
        # ada lagi yang bisa dilepas lewat augenrules. Yang tersisa hanya
        # salinan di memori kernel.
        AUDIT_STUCK=0
        for l in "${LEFTOVERS[@]}"; do
            case "$l" in *"aturan audit masih aktif"*) AUDIT_STUCK=1 ;; esac
        done

        if [ "$AUDIT_STUCK" -eq 1 ]; then
            echo "   Aturan audit yang tersisa hanya ada di memori kernel. Berkas"
            echo "   aturannya sudah terhapus, jadi menjalankan skrip ini lagi TIDAK"
            echo "   akan mengubah apa pun."
            echo
            echo "   Dua cara melepasnya:"
            echo "     1. Buang semua aturan audit di mesin ini, termasuk milik"
            echo "        perangkat lain bila ada:"
            echo "          auditctl -D"
            echo "     2. Biarkan, lalu aturan hilang sendiri saat mesin"
            echo "        dinyalakan ulang pada jadwal pemeliharaan berikutnya."
            echo
            echo "   Periksa dulu apakah ada aturan milik perangkat lain:"
            echo "     auditctl -l | grep -v audit-wazuh"
        else
            echo "   Sisa di atas bisa dibereskan sekarang tanpa menyalakan ulang mesin."
            echo "   Jalankan skrip ini sekali lagi, atau ikuti perintah yang disebut"
            echo "   pada tiap baris sisa."
        fi
    fi
    echo
    echo "   Berkas log: $LOGFILE"
    echo

    # Kode keluar dibedakan supaya otomasi bisa menanggapi berbeda:
    #   0  bersih
    #   2  terhapus, sisa ringan yang lepas setelah dinyalakan ulang
    #   3  gagal, paket atau folder masih ada
    if [ "$HARD" -gt 0 ]; then exit 3; else exit 2; fi
fi
