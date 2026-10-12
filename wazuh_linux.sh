#!/bin/bash
# =============================================================================
#  Instalasi Wazuh Agent - Linux
#
#  Distribusi yang didukung:
#    Debian, Ubuntu                      (apt)
#    RHEL, CentOS, Rocky, AlmaLinux      (dnf atau yum)
#
#  CARA PAKAI
#
#  Interaktif, script menanyakan data yang perlu:
#      bash wazuh_linux.sh
#
#  Tanpa interaksi, lewat variabel lingkungan:
#      WAZUH_MANAGER=10.20.30.40 WAZUH_GROUP=prod-web bash wazuh_linux.sh
#
#  Satu baris dari repo:
#      curl -fsSL https://raw.githubusercontent.com/<user>/<repo>/main/wazuh_linux.sh \
#        | WAZUH_MANAGER=10.20.30.40 WAZUH_GROUP=prod-web bash
#
#  VARIABEL LINGKUNGAN
#    WAZUH_MANAGER     IP atau hostname manager (wajib bila tanpa interaksi)
#    WAZUH_GROUP       satu atau lebih group, pisah koma (wajib bila tanpa interaksi)
#    AGENT_NAME        nama agent, bawaan hostname
#    WAZUH_VERSION     versi paket, bawaan 4.9.2-1
#    WAZUH_REG_PORT    port pendaftaran, bawaan 1515
#    WAZUH_COMM_PORT   port pengiriman event, bawaan 1514
#    CONNECT_TIMEOUT   lama tunggu sambungan, bawaan 60 detik
#    SKIP_AUDIT        isi 1 untuk melewati pemasangan aturan auditd
#    SKIP_FIM          isi 1 untuk melewati aturan FIM tambahan
#    SKIP_VERIFY       isi 1 untuk melewati verifikasi akhir
#    ASSUME_YES        isi 1 untuk melewati semua konfirmasi
#
#  TIDAK PERLU REBOOT. Aturan auditd berlaku seketika lewat augenrules,
#  kecuali auditd dalam mode immutable (-e 2), dan script memberi tahu
#  bila itu terjadi.
# =============================================================================
set -euo pipefail

# ---------- parameter dasar ----------
# Versi agen sebaiknya sama atau lebih rendah daripada versi manajer.
# Agen yang lebih baru dari manajer tidak didukung dan bisa gagal
# mendaftar.
WAZUH_VERSION="${WAZUH_VERSION:-4.9.2-1}"

# Bentuk yang diterima repositori Wazuh adalah X.Y.Z-R, misalnya 4.9.2-1.
# Diperiksa di awal supaya kesalahan ketik tidak baru ketahuan setelah
# repositori disiapkan dan unduhan dimulai.
if ! [[ "$WAZUH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
    echo "[FAIL] Versi '$WAZUH_VERSION' tidak sah." >&2
    echo "       Bentuk yang benar: X.Y.Z-R, misalnya 4.9.2-1" >&2
    exit 1
fi
WAZUH_REG_PORT="${WAZUH_REG_PORT:-1515}"
WAZUH_COMM_PORT="${WAZUH_COMM_PORT:-1514}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-60}"
SKIP_AUDIT="${SKIP_AUDIT:-0}"
SKIP_FIM="${SKIP_FIM:-0}"
SKIP_VERIFY="${SKIP_VERIFY:-0}"
ASSUME_YES="${ASSUME_YES:-0}"

OSSEC_DIR="/var/ossec"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
OSSEC_LOG="$OSSEC_DIR/logs/ossec.log"
LOCAL_OPT="$OSSEC_DIR/etc/local_internal_options.conf"
CLIENT_KEYS="$OSSEC_DIR/etc/client.keys"
AUDIT_RULES="/etc/audit/rules.d/wazuh.rules"
MARK_BEGIN="<!-- BEGIN hardening-baseline (dikelola skrip instalasi) -->"
MARK_END="<!-- END hardening-baseline -->"
LOGFILE="/var/log/wazuh-agent-install-$(date +%Y%m%d-%H%M%S).log"

R='\e[31m'; G='\e[32m'; Y='\e[33m'; B='\e[34m'; GRY='\e[90m'; N='\e[0m'
STEP=0
STEP_TOTAL=10
WARN_COUNT=0
declare -a WARN_LIST=()

info(){ echo -e "${B}[INFO]${N} $*"; }
ok(){   echo -e "${G}[ OK ]${N} $*"; }
dim(){  echo -e "${GRY}       $*${N}"; }
warn(){
  echo -e "${Y}[WARN]${N} $*"
  WARN_LIST+=("$*")
  WARN_COUNT=$((WARN_COUNT + 1))
}
die(){  echo -e "${R}[FAIL]${N} $*" >&2; exit 1; }
step(){
  STEP=$((STEP + 1))
  echo
  echo -e "${Y}[$STEP/$STEP_TOTAL]${N} $*"
}

# $LINENO di dalam trap ber-kutip-tunggal dievaluasi saat error terjadi,
# bukan saat trap dipasang, jadi nomor barisnya memang baris yang gagal.
trap 'echo -e "\n${R}[FAIL]${N} Skrip berhenti di baris $LINENO. Pemasangan TIDAK selesai." >&2' ERR

[ "$(id -u)" -eq 0 ] || die "Harus dijalankan sebagai root."

# Catat seluruh keluaran ke berkas log tanpa menghilangkan tampilan di layar.
exec > >(tee -a "$LOGFILE") 2>&1

# ---------- validasi ----------

# Menerima IP maupun hostname, karena Wazuh mendukung <address> berupa
# FQDN. Versi sebelumnya memaksa IP sehingga manager di belakang DNS
# atau penyeimbang beban tidak bisa dipakai.
validate_host() {
    local h="$1"
    [ -n "$h" ] || return 1

    # Bentuk IPv4. Oktet berawalan nol ditolak karena bukan notasi sah
    # dan sebagian pustaka menafsirkannya sebagai oktal, sehingga
    # 010.1.1.1 bisa berarti alamat yang berbeda dari yang dimaksud.
    if [[ "$h" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]]; then
        local IFS='.'
        read -r -a oct <<< "$h"
        for o in "${oct[@]}"; do
            (( o <= 255 )) || return 1
        done
        # Alamat ini tidak mungkin menjadi manager.
        case "$h" in
            0.0.0.0|255.255.255.255) return 1 ;;
        esac
        return 0
    fi

    # Bentuk yang menyerupai IPv4 tapi cacah oktetnya salah, misalnya
    # 10.0.0 atau 1.2.3.4.5, ditolak di sini. Tanpa pemeriksaan ini
    # bentuk tersebut lolos sebagai hostname karena hanya berisi angka
    # dan titik.
    if [[ "$h" =~ ^[0-9.]+$ ]]; then
        return 1
    fi

    # Bentuk IPv6 sederhana: ada tanda titik dua dan hanya karakter heksa.
    if [[ "$h" == *:* ]] && [[ "$h" =~ ^[0-9A-Fa-f:]+$ ]]; then
        return 0
    fi

    # Bentuk hostname atau FQDN. Tiap label 1 sampai 63 karakter, boleh
    # strip di tengah, tidak boleh di awal atau akhir.
    if [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
        [ "${#h}" -le 253 ] || return 1
        return 0
    fi

    return 1
}

# Nama agent Wazuh boleh memuat titik, strip, dan garis bawah. Versi
# sebelumnya membuang titik sehingga nama berbentuk FQDN menjadi rusak,
# misalnya srv-01.corp.local menjadi srv-01corplocal.
validate_agent_name() {
    local n="$1"
    [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$ ]] || return 1
    return 0
}

# group dipisah koma. Versi sebelumnya membuang koma lewat tr sehingga
# tiga group menjadi satu nama group yang tidak ada di manager, dan
# pendaftaran gagal tanpa penjelasan.
clean_groups() {
    local raw="$1" g
    local -a out=() parts=()
    local IFS=','
    read -r -a parts <<< "$raw"
    for g in "${parts[@]}"; do
        g="${g#"${g%%[![:space:]]*}"}"   # buang spasi di depan
        g="${g%"${g##*[![:space:]]}"}"   # buang spasi di belakang
        [ -n "$g" ] || continue
        [[ "$g" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$ ]] || {
            echo "INVALID:$g"
            return 1
        }
        out+=("$g")
    done
    [ "${#out[@]}" -gt 0 ] || return 1
    # IFS disetel di subkulit agar penggabungan "${out[*]}" memakai koma
    # tanpa mengubah IFS pemanggil.
    printf '%s' "$(IFS=,; echo "${out[*]}")"
    return 0
}

ask() {
    # Membaca masukan dari terminal, bukan dari stdin skrip. Ini penting
    # untuk pemakaian lewat pipa, misalnya curl ... | bash, karena di
    # sana stdin berisi badan skrip itu sendiri.
    local prompt="$1" varname="$2" answer=""
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        die "Tidak ada terminal untuk bertanya. Pakai variabel lingkungan: WAZUH_MANAGER dan WAZUH_GROUP."
    fi
    if [ -r /dev/tty ]; then
        read -r -p "$prompt" answer < /dev/tty
    else
        read -r -p "$prompt" answer
    fi
    printf -v "$varname" '%s' "$answer" 2>/dev/null || eval "$varname=\$answer"
}

# ---------- deteksi distribusi ----------
PKG=""          # apt, dnf, atau yum
OS_FAMILY=""    # debian atau rhel

detect_distro() {
    [ -r /etc/os-release ] || die "/etc/os-release tidak terbaca, distribusi tidak bisa dikenali."
    # shellcheck disable=SC1091
    . /etc/os-release

    local id="${ID:-}" like="${ID_LIKE:-}"

    case "$id" in
        ubuntu|debian|raspbian|linuxmint|pop)
            OS_FAMILY="debian"; PKG="apt" ;;
        rhel|centos|rocky|almalinux|ol|oraclelinux|fedora)
            OS_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
        amzn)
            OS_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
        *)
            # Sebagian turunan hanya menyatakan kekerabatan lewat ID_LIKE.
            case "$like" in
                *debian*) OS_FAMILY="debian"; PKG="apt" ;;
                *rhel*|*fedora*|*centos*)
                    OS_FAMILY="rhel"
                    if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
                *) die "Distribusi '${id:-tidak diketahui}' belum didukung. Yang didukung: Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux." ;;
            esac ;;
    esac

    ok "Distribusi: ${PRETTY_NAME:-$id} (keluarga $OS_FAMILY, manager paket $PKG)"
}

pkg_install() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
        dnf) dnf install -y -q "$@" >/dev/null ;;
        yum) yum install -y -q "$@" >/dev/null ;;
    esac
}

pkg_refresh() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq ;;
        dnf) dnf makecache -q >/dev/null 2>&1 || true ;;
        yum) yum makecache -q >/dev/null 2>&1 || true ;;
    esac
}

# Mengunci versi paket agar tidak ikut terbarui saat pembaruan sistem.
# Pembaruan agent sebaiknya direncanakan, bukan terjadi tanpa sengaja,
# karena versi agent perlu cocok dengan versi manager.
pkg_hold() {
    case "$PKG" in
        apt)
            if apt-mark hold wazuh-agent >/dev/null 2>&1; then
                ok "Paket dikunci dengan apt-mark hold"
            else
                warn "apt-mark hold gagal, paket bisa ikut terbarui tanpa sengaja."
            fi
            ;;
        dnf|yum)
            # Memakai versionlock, bukan exclude. Baris exclude di berkas
            # konfigurasi manager paket membuat paket tidak bisa dipasang
            # ulang maupun diperbarui bahkan secara sengaja, dan itu
            # menyulitkan saat agent perlu dinaikkan versinya.
            local lock_pkg="" locked=0
            case "$PKG" in
                dnf) lock_pkg="python3-dnf-plugin-versionlock" ;;
                yum) lock_pkg="yum-plugin-versionlock" ;;
            esac

            if $PKG versionlock add wazuh-agent >/dev/null 2>&1; then
                locked=1
            else
                # Coba pasang plugin versionlock lalu ulangi sekali.
                if pkg_install "$lock_pkg" 2>/dev/null; then
                    $PKG versionlock add wazuh-agent >/dev/null 2>&1 && locked=1
                fi
            fi

            if [ "$locked" -eq 1 ]; then
                ok "Paket dikunci dengan $PKG versionlock"
            else
                warn "Plugin versionlock tidak tersedia. Paket TIDAK dikunci."
                dim "agent bisa ikut terbarui saat '$PKG update'. Untuk mengunci:"
                dim "  $PKG install -y $lock_pkg && $PKG versionlock add wazuh-agent"
            fi
            ;;
    esac
}

# =============================================================================
#  Langkah 1: data pemasangan
# =============================================================================

echo "=============================================================="
echo "   Pemasangan Wazuh Agent untuk Linux"
echo "   Wazuh $WAZUH_VERSION, cakupan pemantauan penuh"
echo "=============================================================="

detect_distro

command -v systemctl >/dev/null 2>&1 || die "systemd tidak ditemukan. Skrip ini memerlukan systemd."

# Mode tanpa interaksi aktif bila data wajib sudah ada di variabel
# lingkungan, atau bila ASSUME_YES diisi. Penting untuk pemakaian lewat
# pipa, karena di sana tidak selalu ada terminal untuk bertanya.
NONINTERACTIVE=0
if [ "$ASSUME_YES" = "1" ] || { [ -n "${WAZUH_MANAGER:-}" ] && [ -n "${WAZUH_GROUP:-}" ]; }; then
    NONINTERACTIVE=1
fi

step "Mengumpulkan data pemasangan"

# --- alamat manager
if [ -z "${WAZUH_MANAGER:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_MANAGER belum diisi dalam mode tanpa interaksi."
    echo
    dim "Untuk Integrasi Agent dengan Wazuh Manager/Worker. Boleh IP maupun nama domain."
    dim "Contoh IP      : 192.0.2.10"
    dim "Contoh domain  : wazuh.corp.local"
    dim "Contoh domain  : soc-wazuh.perusahaan.co.id"
    dim "Jangan memakai awalan jaringan seperti 192.0.2.0/24,"
    dim "dan jangan menambahkan port seperti 192.0.2.10:1514."
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk alamat manager."
        ask "  IP atau domain Wazuh Manager: " WAZUH_MANAGER
        validate_host "$WAZUH_MANAGER" && break
        echo -e "${R}  '$WAZUH_MANAGER' bukan IP atau nama domain yang sah.${N}"
        case "$WAZUH_MANAGER" in
            */*) echo -e "${R}  Tanda garis miring tidak dipakai. Isi alamat saja, misalnya 192.0.2.10${N}" ;;
            *:*) echo -e "${R}  port tidak perlu ditulis. Isi alamat saja, misalnya 192.0.2.10${N}" ;;
        esac
    done
else
    validate_host "$WAZUH_MANAGER" \
      || die "WAZUH_MANAGER='$WAZUH_MANAGER' bukan IP atau nama domain yang sah. Contoh benar: 192.0.2.10 atau wazuh.corp.local"
fi

# --- group
if [ -z "${WAZUH_GROUP:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_GROUP belum diisi dalam mode tanpa interaksi."
    echo
    dim "group menentukan berkas agent.conf mana yang diterima agent ini."
    dim "group harus SUDAH ADA di manager, skrip ini tidak membuatnya."
    dim "Contoh satu group   : default"
    dim "Contoh satu group   : linux-server"
    dim "Contoh banyak group : linux-server,web,produksi"
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk group."
        ask "  group agent: " WAZUH_GROUP
        if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
            WAZUH_GROUP="$cleaned"
            break
        fi
        echo -e "${R}  group tidak sah. Hanya huruf, angka, titik, strip, garis bawah.${N}"
        echo -e "${R}  Pisahkan dengan koma bila lebih dari satu, misalnya: linux-server,web${N}"
    done
else
    if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
        WAZUH_GROUP="$cleaned"
    else
        die "WAZUH_GROUP='$WAZUH_GROUP' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, dipisah koma. Contoh benar: linux-server,web"
    fi
fi

# --- nama agent
if [ -z "${AGENT_NAME:-}" ]; then
    DEFAULT_NAME="$(hostname 2>/dev/null || echo "wazuh-agent")"
    if [ "$NONINTERACTIVE" = "1" ]; then
        AGENT_NAME="$DEFAULT_NAME"
    else
        echo
        dim "Nama yang muncul di dashboard manager. Harus unik, tidak boleh"
        dim "sama dengan agent lain yang sudah terdaftar."
        dim "Contoh : srv-web-01"
        dim "Contoh : db-prod-02.corp.local"
        dim "Tekan Enter saja untuk memakai nama mesin ini: $DEFAULT_NAME"
        tries=0
        while true; do
            tries=$((tries + 1))
            [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk nama agent."
            ask "  Nama agent [$DEFAULT_NAME]: " AGENT_NAME
            AGENT_NAME="${AGENT_NAME:-$DEFAULT_NAME}"
            validate_agent_name "$AGENT_NAME" && break
            echo -e "${R}  '$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip,${N}"
            echo -e "${R}  garis bawah. Tanpa spasi. Panjang 2 sampai 128 karakter.${N}"
            AGENT_NAME=""
        done
    fi
fi
validate_agent_name "$AGENT_NAME" \
  || die "Nama agent '$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, 2 sampai 128 karakter. Contoh benar: srv-web-01"

echo
echo "  Ringkasan:"
echo "    manager       : $WAZUH_MANAGER"
echo "    Nama agent     : $AGENT_NAME"
echo "    group          : $WAZUH_GROUP"
echo "    Versi paket   : $WAZUH_VERSION"
# Baris di bawah hanya muncul bila memang menyimpang dari bawaan, supaya
# ringkasan tidak dipenuhi keterangan yang tidak memberi tahu apa apa.
# Bentuk if dipakai, bukan '[ ... ] && echo', karena bentuk kedua
# mengembalikan status 1 saat kondisi salah dan itu rapuh terhadap set -e.
if [ "$SKIP_AUDIT" = "1" ];      then echo "    Aturan audit  : DILEWATI"; fi
if [ "$SKIP_FIM" = "1" ];        then echo "    FIM tambahan  : DILEWATI"; fi
if [ "$SKIP_VERIFY" = "1" ];     then echo "    Verifikasi    : DILEWATI"; fi
echo "    Berkas log    : $LOGFILE"
echo

if [ "$NONINTERACTIVE" != "1" ]; then
    ask "  Lanjutkan pemasangan? (Y/n): " CONFIRM
    case "${CONFIRM:-Y}" in
        [Yy]*|"") : ;;
        *) echo "  Dibatalkan."; exit 0 ;;
    esac
fi

# =============================================================================
#  Langkah 2: pemeriksaan kesiapan
# =============================================================================
step "Memeriksa kesiapan mesin"

# port wajib terbuka. Gagal di sini jauh lebih baik daripada pemasangan
# yang dilaporkan berhasil lalu agent diam diam tidak pernah terdaftar.
for p in "$WAZUH_COMM_PORT" "$WAZUH_REG_PORT"; do
    label="pengiriman event"
    [ "$p" = "$WAZUH_REG_PORT" ] && label="pendaftaran"
    if timeout 5 bash -c "echo > /dev/tcp/$WAZUH_MANAGER/$p" 2>/dev/null; then
        ok "port $p ($label) terbuka ke $WAZUH_MANAGER"
    else
        die "port $p ($label) TERTUTUP ke $WAZUH_MANAGER. Periksa firewall dan rute lebih dulu."
    fi
done

# --- Perkakas yang dipakai skrip ini.
#
# python3 dipakai menyunting ossec.conf di Langkah 7. Pada citra minimal
# sering tidak terpasang, dan tanpa pemeriksaan di sini kegagalannya baru
# muncul SETELAH paket terpasang dan aturan audit aktif, meninggalkan
# mesin dalam keadaan setengah terkonfigurasi.
if ! command -v python3 >/dev/null 2>&1; then
    dim "python3 belum ada, dipasang lebih dulu ..."
    pkg_refresh
    pkg_install python3 >/dev/null 2>&1 || true
    command -v python3 >/dev/null 2>&1 \
      || die "python3 tidak bisa dipasang. Skrip memerlukannya untuk menyunting ossec.conf."
    ok "python3 terpasang"
else
    ok "python3 tersedia"
fi

# Jam yang meleset membuat korelasi di manager salah dan alert sulit
# diurutkan. Bukan penghalang, tapi perlu diketahui.
if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q '^yes$'; then
    ok "Jam tersinkron dengan NTP"
else
    warn "Jam TIDAK tersinkron NTP. Penanda waktu alert bisa meleset."
    case "$OS_FAMILY" in
        debian) dim "Perbaiki: apt-get install -y chrony" ;;
        rhel)   dim "Perbaiki: $PKG install -y chrony && systemctl enable --now chronyd" ;;
    esac
fi

# Ruang disk. agent menulis log dan basis data FIM, dan auditd bisa
# tumbuh cepat setelah aturan execve aktif.
AVAIL_MB="$(df -Pm /var 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$AVAIL_MB" ] && [ "$AVAIL_MB" -lt 2048 ]; then
    warn "Ruang bebas di /var hanya ${AVAIL_MB} MB. Disarankan minimal 2 GB."
else
    ok "Ruang bebas di /var: ${AVAIL_MB:-?} MB"
fi

# --- Paket yang tersangkut dari pemasangan atau pencabutan sebelumnya.
#
# Skrip prerm bawaan paket memakai 'set -e' lalu memanggil
#
#   /var/ossec/bin/wazuh-control stop
#
# tanpa memeriksa keberadaan berkas itu. Bila folder agent pernah dihapus
# manual sementara paket masih tercatat di dpkg, pemanggilan tersebut
# berakhir dengan kode 127 dan dpkg menolak memproses paket. Akibatnya
# paket tidak bisa dicabut maupun dipasang ulang.
#
# Keadaan itu terlihat dari status dpkg seperti 'pi' atau 'iF', dan
# dibereskan di sini sebelum pemasangan dimulai.
if [ "$OS_FAMILY" = "debian" ]; then
    DPKG_ST="$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)"

    # Medan Status berbentuk tiga kata: <keinginan> <galat> <keadaan>.
    # Kata pertama berubah menjadi 'hold' begitu paket dikunci, sehingga
    # paket terpasang yang dikunci berstatus 'hold ok installed', bukan
    # 'install ok installed'.
    #
    # Skrip ini memang mengunci paket di akhir pemasangan lewat pkg_hold,
    # jadi status itulah yang normal pada setiap pemasangan berikutnya.
    # Pencocokan harus mengenali keduanya. Versi sebelumnya hanya
    # mengenali 'install ok installed', sehingga paket terpasang yang
    # dikunci jatuh ke cabang 'tersangkut' dan ikut dipurge bersama
    # 'rm -rf /var/ossec' tanpa bertanya lebih dulu.
    #
    # Pencocokan dengan akhiran ' ok installed' dipakai, bukan daftar
    # nilai tetap, supaya keinginan lain seperti 'deinstall ok installed'
    # juga dikenali sebagai terpasang dan ditangani pemeriksaan berikutnya.
    case "$DPKG_ST" in
        ""|*"not-installed"*)
            : ;;
        *" ok installed")
            : ;;  # terpasang wajar, ditangani pemeriksaan PKG_PRESENT
        *)
            warn "Paket wazuh-agent tersangkut dengan status: $DPKG_ST"
            dim "Ini sisa pemasangan atau pencabutan yang berhenti di tengah."

            # Berkas bantu agar prerm paket dapat berjalan sampai selesai.
            if [ ! -x "$OSSEC_DIR/bin/wazuh-control" ]; then
                mkdir -p "$OSSEC_DIR/bin" 2>/dev/null || true
                printf '#!/bin/sh\nexit 0\n' > "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null || true
                chmod 0755 "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null || true
                dim "Berkas bantu wazuh-control dibuat agar prerm paket tidak gagal"
            fi

            dim "Membereskan catatan paket lebih dulu ..."
            apt-mark unhold wazuh-agent >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get purge -y wazuh-agent >/dev/null 2>&1 \
              || dpkg --purge --force-all wazuh-agent >/dev/null 2>&1 || true

            # Sisa folder dibuang agar pemasangan berikutnya tidak dianggap
            # peningkatan versi, yang membuat konfigurasi ditulis sebagai
            # ossec.conf.new dan ossec.conf tidak pernah terbentuk.
            rm -rf "$OSSEC_DIR" 2>/dev/null || true

            AFTER_ST="$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)"
            case "$AFTER_ST" in
                ""|"unknown ok not-installed"|"purge ok not-installed")
                    ok "Catatan paket lama dibersihkan, pemasangan dapat dilanjutkan" ;;
                *)
                    die "$(cat <<MSG
Paket lama tidak bisa dibereskan, status tersisa: $AFTER_ST

        Bersihkan manual lebih dulu:
          mkdir -p $OSSEC_DIR/bin
          printf '#!/bin/sh\\nexit 0\\n' > $OSSEC_DIR/bin/wazuh-control
          chmod +x $OSSEC_DIR/bin/wazuh-control
          dpkg --purge --force-all wazuh-agent
          rm -rf $OSSEC_DIR

        lalu jalankan skrip ini lagi.
MSG
)" ;;
            esac ;;
    esac
fi

# Keadaan setara pada keluarga RHEL: paket tercatat di basis data rpm
# tetapi folder agent sudah tidak ada.
if [ "$OS_FAMILY" = "rhel" ]; then
    if rpm -q wazuh-agent >/dev/null 2>&1 && [ ! -d "$OSSEC_DIR" ]; then
        warn "Paket wazuh-agent tercatat di rpm tetapi folder $OSSEC_DIR tidak ada."
        dim "Ini sisa pencabutan yang berhenti di tengah."

        if [ ! -x "$OSSEC_DIR/bin/wazuh-control" ]; then
            mkdir -p "$OSSEC_DIR/bin" 2>/dev/null || true
            printf '#!/bin/sh\nexit 0\n' > "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null || true
            chmod 0755 "$OSSEC_DIR/bin/wazuh-control" 2>/dev/null || true
        fi

        dim "Membereskan catatan paket lebih dulu ..."
        $PKG versionlock delete wazuh-agent >/dev/null 2>&1 || true
        $PKG remove -y wazuh-agent >/dev/null 2>&1 \
          || rpm -e --nodeps wazuh-agent >/dev/null 2>&1 \
          || rpm -e --nodeps --noscripts wazuh-agent >/dev/null 2>&1 || true
        rm -rf "$OSSEC_DIR" 2>/dev/null || true

        if rpm -q wazuh-agent >/dev/null 2>&1; then
            die "$(cat <<MSG
Paket lama tidak bisa dibereskan.

        Bersihkan manual lebih dulu:
          rpm -e --nodeps --noscripts wazuh-agent
          rm -rf $OSSEC_DIR

        lalu jalankan skrip ini lagi.
MSG
)"
        else
            ok "Catatan paket lama dibersihkan, pemasangan dapat dilanjutkan"
        fi
    fi
fi

# --- Paket yang sudah terpasang wajar.
#
# Memasang ulang di atas paket yang sudah ada TIDAK mendaftarkan ulang
# agent. Skrip postinst paket berisi:
#
#   if [ -z "$2" ] ; then
#       .../register_configure_agent.sh ${DIR}
#   fi
#
# Argumen kedua berisi versi lama pada peningkatan maupun pemasangan ulang,
# sehingga pendaftaran dilewati seluruhnya. Akibatnya alamat manager, group,
# dan nama agent yang baru diisi tidak pernah diterapkan, sementara skrip
# melaporkan pemasangan berhasil.
#
# Paket juga menulis konfigurasi ke ossec.conf.new pada jalur itu, bukan
# ossec.conf, jadi blok konfigurasi disisipkan ke berkas yang salah.
#
# Karena itu skrip berhenti di sini dengan instruksi pembersihan, bukan
# melanjutkan dan melaporkan hasil yang tidak benar.
PKG_PRESENT=0
case "$OS_FAMILY" in
    debian)
        # Akhiran ' ok installed' mencakup 'install ok installed' maupun
        # 'hold ok installed'. Paket yang dikunci skrip ini berstatus yang
        # kedua, dan tanpa pencocokan ini pesan di bawah tidak pernah
        # muncul di Debian atau Ubuntu.
        case "$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)" in
            *" ok installed") PKG_PRESENT=1 ;;
        esac ;;
    rhel)
        rpm -q wazuh-agent >/dev/null 2>&1 && PKG_PRESENT=1 ;;
esac

if [ "$PKG_PRESENT" -eq 1 ]; then
    OLD_ID=""
    OLD_ID_NUM=""
    if [ -s "$CLIENT_KEYS" ]; then
        OLD_ID="$(awk 'NR==1{print $1" "$2}' "$CLIENT_KEYS" 2>/dev/null || true)"
        OLD_ID_NUM="$(awk 'NR==1{print $1}' "$CLIENT_KEYS" 2>/dev/null || true)"
    fi

    # Perintah disusun lebih dulu, di luar heredoc. Substitusi perintah
    # yang memuat 'case' di dalam heredoc bersarang sulit dibaca dan
    # perilakunya tidak seragam di bash versi lama.
    case "$OS_FAMILY" in
        debian)
            PURGE_CMD="apt-get purge -y wazuh-agent"
            UNLOCK_CMD="apt-mark unhold wazuh-agent" ;;
        rhel)
            PURGE_CMD="$PKG remove -y wazuh-agent"
            UNLOCK_CMD="$PKG versionlock delete wazuh-agent" ;;
        *)
            PURGE_CMD="cabut paket wazuh-agent lewat manager paket distribusi ini"
            UNLOCK_CMD="lepas kunci versi paket bila ada" ;;
    esac

    IDENT_LINE=""
    [ -n "$OLD_ID" ] && IDENT_LINE="
        Terdaftar saat ini sebagai: $OLD_ID"

    MANAGER_NOTE=""
    [ -n "$OLD_ID" ] && MANAGER_NOTE="

        Setelah dicabut, hapus juga entri lama di manager. Jalankan ini
        DI SERVER MANAGER, bukan di mesin ini:
          /var/ossec/bin/manage_agents -r ${OLD_ID_NUM:-<id>}"

    echo
    die "$(cat <<MSG
wazuh-agent sudah terpasang di mesin ini.$IDENT_LINE

        Memasang ulang di atasnya TIDAK akan mendaftarkan agent kembali.
        Skrip pascapasang paket hanya mendaftarkan agent pada pemasangan
        baru, sehingga alamat manager, group, dan nama agent yang baru
        tidak akan diterapkan.

        Ada dua pilihan.

        1. Hanya mengubah pendaftaran, tanpa memasang ulang paket:
             $OSSEC_DIR/bin/agent-auth -m $WAZUH_MANAGER -p $WAZUH_REG_PORT -G '$WAZUH_GROUP' -A '$AGENT_NAME'
             systemctl restart wazuh-agent

        2. Memasang dari awal. Cabut lebih dulu dengan skrip pencabutan
           yang disertakan:
             bash uninstall_wazuh_linux.sh

           Atau manual, bila skrip itu tidak ada:
             systemctl stop wazuh-agent
             $UNLOCK_CMD
             $PURGE_CMD
             rm -rf $OSSEC_DIR

           lalu jalankan skrip ini lagi.$MANAGER_NOTE
MSG
)"
fi
ok "Belum ada wazuh-agent terpasang"

# SELinux dalam mode enforcing dapat menghalangi auditd dan agent.
if [ "$OS_FAMILY" = "rhel" ] && command -v getenforce >/dev/null 2>&1; then
    SEL="$(getenforce 2>/dev/null || echo Unknown)"
    case "$SEL" in
        Enforcing) warn "SELinux Enforcing. Bila agent gagal membaca log, periksa 'ausearch -m AVC -ts recent'." ;;
        *) ok "SELinux: $SEL" ;;
    esac
fi

# =============================================================================
#  Langkah 3: repositori
# =============================================================================
step "Menyiapkan repositori Wazuh"

case "$OS_FAMILY" in
  debian)
    pkg_refresh
    # curl dipasang hanya bila belum ada. Pada RHEL 9 dan Amazon Linux
    # 2023, paket curl bentrok dengan curl-minimal yang sudah terpasang,
    # dan memaksa pemasangannya membuat manager paket menolak transaksi.
    # Pemeriksaan yang sama dipakai di kedua keluarga agar perilakunya
    # seragam.
    command -v curl >/dev/null 2>&1 || pkg_install curl
    pkg_install gnupg apt-transport-https ca-certificates

    install -d -m 0755 /usr/share/keyrings
    # Opsi -f wajib. Tanpa itu, kegagalan HTTP menghasilkan berkas sampah
    # yang kemudian diimpor sebagai kunci GPG dan repositori tampak sah.
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor --batch --yes -o /usr/share/keyrings/wazuh.gpg \
      || die "Gagal mengunduh atau memproses kunci GPG Wazuh."
    chmod 0644 /usr/share/keyrings/wazuh.gpg

    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    pkg_refresh
    ;;
  rhel)
    # Lihat catatan di cabang debian: curl-minimal pada RHEL 9 dan
    # Amazon Linux 2023 bentrok dengan paket curl.
    command -v curl >/dev/null 2>&1 || pkg_install curl
    pkg_install ca-certificates

    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      || die "Gagal mengimpor kunci GPG Wazuh."

    cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
    chmod 0644 /etc/yum.repos.d/wazuh.repo
    pkg_refresh
    ;;
esac
ok "Repositori siap"

# =============================================================================
#  Langkah 4: pemasangan paket
# =============================================================================
step "Memasang wazuh-agent $WAZUH_VERSION"

# Variabel lingkungan di bawah dibaca oleh skrip pascapasang paket untuk
# mengisi konfigurasi awal dan mendaftarkan agent.
INSTALL_ENV=(
    "WAZUH_MANAGER=$WAZUH_MANAGER"
    "WAZUH_AGENT_GROUP=$WAZUH_GROUP"
    "WAZUH_AGENT_NAME=$AGENT_NAME"
)

# port diteruskan hanya bila menyimpang dari bawaan. Tanpa ini, port kustom
# lolos pemeriksaan sambungan di Langkah 2 tetapi agent tetap memakai 1514
# dan 1515, dan selisihnya baru ketahuan saat agent tidak pernah terdaftar.
#
# Nama variabelnya WAZUH_MANAGER_PORT dan WAZUH_REGISTRATION_PORT, dibaca
# oleh src/init/register_configure_agent.sh yang dipanggil postinst paket.
if [ "$WAZUH_COMM_PORT" != "1514" ]; then
    INSTALL_ENV+=("WAZUH_MANAGER_PORT=$WAZUH_COMM_PORT")
fi
if [ "$WAZUH_REG_PORT" != "1515" ]; then
    INSTALL_ENV+=("WAZUH_REGISTRATION_PORT=$WAZUH_REG_PORT")
fi

# Keluaran manager paket disimpan, bukan dibuang. Bila pemasangan gagal,
# pesan aslinya yang menjelaskan sebabnya, bukan kode keluar.
PKG_OUT="$(mktemp)"
PKG_RC=0

case "$PKG" in
    apt) env "${INSTALL_ENV[@]}" DEBIAN_FRONTEND=noninteractive \
             apt-get install -y "wazuh-agent=$WAZUH_VERSION" > "$PKG_OUT" 2>&1 || PKG_RC=$? ;;
    dnf) env "${INSTALL_ENV[@]}" dnf install -y "wazuh-agent-$WAZUH_VERSION" > "$PKG_OUT" 2>&1 || PKG_RC=$? ;;
    yum) env "${INSTALL_ENV[@]}" yum install -y "wazuh-agent-$WAZUH_VERSION" > "$PKG_OUT" 2>&1 || PKG_RC=$? ;;
esac

if [ "$PKG_RC" -ne 0 ]; then
    echo
    echo -e "${R}       Keluaran manager paket:${N}"
    tail -20 "$PKG_OUT" | while IFS= read -r l; do echo "         $l"; done
    echo

    # Versi yang diminta tidak ada di repositori adalah kegagalan paling
    # sering, dan daftar versi yang tersedia mempercepat penanganannya.
    if grep -qiE "has no installation candidate|Version .* not found|Unable to locate package|No match for argument" "$PKG_OUT"; then
        echo -e "${Y}       Versi $WAZUH_VERSION sepertinya tidak ada di repositori.${N}"
        echo "       Versi yang tersedia:"
        case "$PKG" in
            apt) apt-cache madison wazuh-agent 2>/dev/null | awk '{print "         "$3}' | head -8 ;;
            dnf|yum) $PKG --showduplicates list wazuh-agent 2>/dev/null | awk '/wazuh-agent/{print "         "$2}' | head -8 ;;
        esac
        echo
        echo "       Pasang versi lain dengan: WAZUH_VERSION=<versi> bash $0"
    fi
    rm -f "$PKG_OUT"
    die "Pemasangan paket gagal dengan kode $PKG_RC. Catatan lengkap di $LOGFILE"
fi
rm -f "$PKG_OUT"

# Berkas ossec.conf tidak diekstrak langsung dari paket, melainkan dibuat
# oleh skrip postinst. Skrip itu memeriksa apakah ini pemasangan baru atau
# peningkatan versi:
#
#   if [ -z "$2" ] || [ -f .../create_conf ]; then
#       gen_ossec.sh ... > /var/ossec/etc/ossec.conf
#   else
#       gen_ossec.sh ... > /var/ossec/etc/ossec.conf.new
#   fi
#
# Argumen kedua berisi versi lama saat peningkatan. Jadi bila paket pernah
# terpasang lalu dicabut tanpa purge, dpkg masih menyimpan catatannya dan
# memperlakukan pemasangan berikutnya sebagai peningkatan. Hasilnya berkas
# ditulis sebagai ossec.conf.new dan ossec.conf tidak pernah terbentuk.
#
# Keadaan itu dipulihkan di sini, bukan dilaporkan sebagai kegagalan.
if [ ! -f "$OSSEC_CONF" ] && [ -f "${OSSEC_CONF}.new" ]; then
    warn "Paket memperlakukan ini sebagai peningkatan, konfigurasi ditulis sebagai ossec.conf.new"
    dim "Ini terjadi bila agent pernah dipasang lalu dicabut tanpa purge."
    if mv "${OSSEC_CONF}.new" "$OSSEC_CONF"; then
        ok "ossec.conf.new dipakai sebagai ossec.conf"
    else
        die "Gagal memindahkan ${OSSEC_CONF}.new ke $OSSEC_CONF"
    fi
    chmod 0660 "$OSSEC_CONF" 2>/dev/null || true
    chown root:wazuh "$OSSEC_CONF" 2>/dev/null || true
fi

# Upaya terakhir: bangkitkan konfigurasi memakai skrip bawaan paket.
if [ ! -f "$OSSEC_CONF" ] && [ -x "$OSSEC_DIR/packages_files/agent_installation_scripts/gen_ossec.sh" ]; then
    dim "Mencoba membangkitkan ossec.conf dengan gen_ossec.sh bawaan paket"
    GEN="$OSSEC_DIR/packages_files/agent_installation_scripts/gen_ossec.sh"
    # shellcheck disable=SC1091
    OSNAME="$(. /etc/os-release 2>/dev/null && echo "${ID:-debian}")"
    # shellcheck disable=SC1091
    OSVER="$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}")"
    "$GEN" conf agent "$OSNAME" "$OSVER" "$OSSEC_DIR" > "$OSSEC_CONF" 2>/dev/null || true
    if [ -s "$OSSEC_CONF" ]; then
        ok "ossec.conf dibangkitkan ulang"
    fi
fi

if [ ! -f "$OSSEC_CONF" ]; then
    echo
    die "$(cat <<MSG
Paket terpasang tetapi $OSSEC_CONF tidak ada.

        Penyebab paling umum: agent pernah dipasang lalu dicabut tanpa purge,
        sehingga dpkg memperlakukan pemasangan ini sebagai peningkatan versi
        dan menulis konfigurasi ke ossec.conf.new.

        Pembersihan menyeluruh lalu pasang ulang:
          systemctl stop wazuh-agent
          apt-get purge -y wazuh-agent      atau   dnf remove -y wazuh-agent
          rm -rf $OSSEC_DIR
          lalu jalankan skrip ini lagi

        Periksa juga isi direktori saat ini:
          ls -la $OSSEC_DIR/etc/
MSG
)"
fi

ok "Paket wazuh-agent $WAZUH_VERSION terpasang"

# Berkas tanda tangan rootkit disalin keluar dari etc/shared sebelum agent
# berjalan. Direktori itu dikelola manager: begitu konfigurasi group
# dikirim, seluruh isinya diganti dan berkas bawaan paket terhapus.
# Akibatnya rootcheck mencatat 'No rootcheck_files file' pada setiap
# pemindaian dan pemeriksaan tanda tangan rootkit tidak pernah berjalan.
#
# Salinan disimpan di etc/ yang tidak disentuh manager, lalu konfigurasi
# diarahkan ke sana pada langkah penyisipan blok.
ROOTKIT_DB_OK=0
for rk in rootkit_files rootkit_trojans; do
    if [ -f "$OSSEC_DIR/etc/shared/$rk.txt" ]; then
        cp -a "$OSSEC_DIR/etc/shared/$rk.txt" "$OSSEC_DIR/etc/$rk.txt" 2>/dev/null || true
    fi
done
if [ -f "$OSSEC_DIR/etc/rootkit_files.txt" ] && [ -f "$OSSEC_DIR/etc/rootkit_trojans.txt" ]; then
    chown root:wazuh "$OSSEC_DIR/etc/rootkit_files.txt" "$OSSEC_DIR/etc/rootkit_trojans.txt" 2>/dev/null || true
    chmod 0640 "$OSSEC_DIR/etc/rootkit_files.txt" "$OSSEC_DIR/etc/rootkit_trojans.txt" 2>/dev/null || true
    ROOTKIT_DB_OK=1
    dim "Basis tanda tangan rootkit disalin ke etc/ agar tidak tertimpa manager"
else
    warn "Berkas tanda tangan rootkit tidak ditemukan di paket."
    dim "Pemeriksaan tanda tangan rootkit tidak akan berjalan."
fi
pkg_hold

# =============================================================================
#  Langkah 5: auditd dan aturan audit
# =============================================================================
step "Menyiapkan auditd dan aturan audit"

if [ "$SKIP_AUDIT" = "1" ]; then
    dim "Dilewati karena SKIP_AUDIT=1"
else
    case "$OS_FAMILY" in
        debian) pkg_install auditd audispd-plugins \
                  || die "Gagal memasang auditd. Periksa $LOGFILE" ;;
        rhel)   pkg_install audit audit-libs \
                  || die "Gagal memasang audit. Periksa $LOGFILE" ;;
    esac

    # Binari auditd wajib ada sebelum aturan dipasang. Tanpa pemeriksaan
    # ini, augenrules gagal di langkah berikutnya dengan pesan yang
    # membingungkan.
    command -v augenrules >/dev/null 2>&1 \
      || die "augenrules tidak ditemukan setelah pemasangan paket audit."
    command -v auditctl >/dev/null 2>&1 \
      || die "auditctl tidak ditemukan setelah pemasangan paket audit."

    systemctl enable --now auditd >/dev/null 2>&1 || \
      service auditd start >/dev/null 2>&1 || \
      warn "auditd tidak bisa dijalankan lewat systemctl maupun service."

    # Pada sebagian sistem, auditd menolak dikelola systemd dan harus
    # dijalankan lewat skrip init bawaannya. Bila layanan tetap mati,
    # aturan tidak akan menghasilkan event apa pun.
    if ! systemctl is-active --quiet auditd 2>/dev/null && ! pgrep -x auditd >/dev/null 2>&1; then
        warn "Layanan auditd tidak berjalan. Aturan audit tidak akan menghasilkan event."
        dim "Coba: systemctl status auditd, lalu journalctl -u auditd -n 30"
    fi

    # GID dihitung, tidak ditulis tetap. Nilai 994 yang sering dicontohkan
    # tidak dijamin sama di tiap host. Bila meleset, penyaring mengecualikan
    # group yang salah dan agent mencatat aktivitasnya sendiri tanpa henti.
    # Akhiran '|| true' wajib. Tanpa itu, getent yang gagal membuat pipa
    # mengembalikan status bukan nol, lalu 'set -o pipefail' bersama trap
    # ERR menghentikan skrip di baris ini. Pesan yang muncul hanya nomor
    # baris, dan die yang menjelaskan sebabnya tidak pernah dijalankan.
    GID_WAZUH="$(getent group wazuh | cut -d: -f3 || true)"
    [ -n "$GID_WAZUH" ] || die "group 'wazuh' tidak ada setelah pemasangan paket."
    dim "GID group wazuh: $GID_WAZUH"

    # Berkas ditulis penuh setiap kali, sehingga menjalankan skrip dua kali
    # tidak menghasilkan aturan ganda.
    #
    # Dua penyaring penting pada aturan syscall:
    #   auid>=1000              semua pengguna interaktif, bukan hanya uid 1000
    #   auid!=4294967295        kecualikan proses daemon yang tidak punya auid
    #   egid!=$GID_WAZUH        cegah agent mencatat dirinya sendiri
    cat > "$AUDIT_RULES" <<EOF
## Dikelola skrip pemasangan Wazuh. Jangan sunting manual.
## Perubahan akan ditimpa saat skrip dijalankan ulang.

## ---------- Eksekusi perintah ----------
## Dasar untuk melihat apa yang dijalankan pengguna. Tanpa ini, sebagian
## besar aturan Wazuh untuk Linux tidak punya data.
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-c

## ---------- Eskalasi hak akses ----------
## Perubahan identitas proses. Pola utama eskalasi hak.
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-privesc
-a always,exit -F arch=b64 -S setgid,setregid,setresgid -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-privesc

## Pemakaian sudo dan su
-w /usr/bin/sudo -p x -k audit-wazuh-privesc
-w /usr/bin/su   -p x -k audit-wazuh-privesc
-w /usr/bin/pkexec -p x -k audit-wazuh-privesc

## ---------- Injeksi proses ----------
## ptrace dipakai untuk menyuntik kode ke proses lain dan membaca memori
## proses lain. Volumenya rendah dan nilai deteksinya tinggi.
-a always,exit -F arch=b64 -S ptrace -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-inject
-a always,exit -F arch=b32 -S ptrace -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-inject

## ---------- Modul kernel ----------
## Jalur utama rootkit tingkat kernel. Volume sangat rendah.
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k audit-wazuh-kmod
-a always,exit -F arch=b32 -S init_module,delete_module -k audit-wazuh-kmod
-w /sbin/insmod   -p x -k audit-wazuh-kmod
-w /sbin/modprobe -p x -k audit-wazuh-kmod
-w /sbin/rmmod    -p x -k audit-wazuh-kmod
-w /etc/modprobe.d/ -p wa -k audit-wazuh-kmod

## ---------- Pustaka yang dimuat paksa ----------
## Berkas ini memaksa setiap proses memuat pustaka tertentu. Jalur rootkit
## tingkat pengguna yang klasik dan masih sering dipakai.
-w /etc/ld.so.preload -p wa -k audit-wazuh-rootkit
-w /etc/ld.so.conf    -p wa -k audit-wazuh-rootkit
-w /etc/ld.so.conf.d/ -p wa -k audit-wazuh-rootkit

## ---------- Kredensial dan akun ----------
-w /etc/passwd   -p wa -k audit-wazuh-w
-w /etc/shadow   -p wa -k audit-wazuh-w
-w /etc/group    -p wa -k audit-wazuh-w
-w /etc/gshadow  -p wa -k audit-wazuh-w
-w /etc/sudoers  -p wa -k audit-wazuh-w
-w /etc/sudoers.d/ -p wa -k audit-wazuh-w
-w /etc/security/ -p wa -k audit-wazuh-w
-w /etc/pam.d/    -p wa -k audit-wazuh-w

## ---------- Akses jarak jauh ----------
-w /etc/ssh/sshd_config -p wa -k audit-wazuh-w
-w /etc/ssh/sshd_config.d/ -p wa -k audit-wazuh-w
-w /root/.ssh/ -p wa -k audit-wazuh-w

## ---------- Persistence ----------
-w /etc/crontab    -p wa -k audit-wazuh-persist
-w /etc/cron.d/    -p wa -k audit-wazuh-persist
-w /etc/cron.daily/ -p wa -k audit-wazuh-persist
-w /etc/cron.hourly/ -p wa -k audit-wazuh-persist
-w /var/spool/cron/ -p wa -k audit-wazuh-persist
-w /etc/systemd/system/ -p wa -k audit-wazuh-persist
-w /etc/rc.local -p wa -k audit-wazuh-persist
-w /etc/profile.d/ -p wa -k audit-wazuh-persist
-w /etc/profile -p wa -k audit-wazuh-persist
-w /etc/bash.bashrc -p wa -k audit-wazuh-persist

## ---------- Jaringan ----------
-w /etc/hosts -p wa -k audit-wazuh-net
-w /etc/resolv.conf -p wa -k audit-wazuh-net
-w /etc/hosts.allow -p wa -k audit-wazuh-net
-w /etc/hosts.deny -p wa -k audit-wazuh-net

## ---------- Alat yang sering dipakai penyerang ----------
## Keberadaan eksekusi alat ini bukan berarti serangan, tetapi
## kombinasinya dengan konteks lain sangat berguna saat penyelidikan.
-w /usr/bin/nc -p x -k audit-wazuh-tool
-w /usr/bin/ncat -p x -k audit-wazuh-tool
-w /bin/nc.openbsd -p x -k audit-wazuh-tool
-w /bin/nc.traditional -p x -k audit-wazuh-tool
-w /usr/bin/socat -p x -k audit-wazuh-tool
-w /usr/bin/nmap -p x -k audit-wazuh-tool
-w /usr/bin/tcpdump -p x -k audit-wazuh-tool
-w /usr/sbin/tcpdump -p x -k audit-wazuh-tool
-w /usr/bin/wget -p x -k audit-wazuh-tool
-w /usr/bin/curl -p x -k audit-wazuh-tool
-w /usr/bin/base64 -p x -k audit-wazuh-tool
-w /usr/bin/xxd -p x -k audit-wazuh-tool

## ---------- Anti forensik ----------
## Penghapusan dan penggantian nama berkas log.
-w /var/log/audit/ -p wa -k audit-wazuh-antiforensik
-w /var/log/wtmp -p wa -k audit-wazuh-antiforensik
-w /var/log/btmp -p wa -k audit-wazuh-antiforensik
-w /var/log/lastlog -p wa -k audit-wazuh-antiforensik
-w /usr/bin/shred -p x -k audit-wazuh-antiforensik
-w /usr/bin/wipe -p x -k audit-wazuh-antiforensik

## ---------- Pengaturan audit sendiri ----------
## Upaya melumpuhkan audit adalah tanda kuat.
-w /etc/audit/ -p wa -k audit-wazuh-config
-w /etc/audisp/ -p wa -k audit-wazuh-config
-w /sbin/auditctl -p x -k audit-wazuh-config
-w /sbin/auditd -p x -k audit-wazuh-config

## ---------- Pemasangan berkas sistem ----------
## Dipakai untuk keluar dari kontainer dan menyembunyikan berkas.
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-mount
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-mount
EOF

    # Aturan koneksi keluar dipisah karena volumenya paling tinggi dan
    # paling mungkin perlu dimatikan sendiri di server dengan lalu lintas
    # padat seperti server web atau basis data.
    cat >> "$AUDIT_RULES" <<EOF

## ---------- Koneksi keluar ----------
## Berguna untuk mendeteksi komando kendali dan penyelundupan data.
## Volumenya paling tinggi di antara semua aturan di berkas ini. Bila
## beban terlalu besar di server tertentu, beri tanda pagar pada dua
## baris berikut lalu jalankan: augenrules --load
-a always,exit -F arch=b64 -S connect -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-netconn
-a always,exit -F arch=b32 -S connect -F auid>=1000 -F auid!=4294967295 -F egid!=$GID_WAZUH -k audit-wazuh-netconn
EOF

    chmod 0640 "$AUDIT_RULES"

    # Aturan -w pada jalur yang tidak ada membuat augenrules menolak
    # SELURUH berkas, bukan hanya baris itu. Karena jalur binari berbeda
    # antar distribusi, baris yang jalurnya tidak ada dibuang lebih dulu.
    #
    # Pengecualian penting: beberapa berkas memang normalnya TIDAK ada,
    # dan justru pembuatannya yang menandakan serangan. Contoh utama
    # /etc/ld.so.preload, yang kosong pada sistem sehat dan dibuat oleh
    # rootkit tingkat pengguna.
    #
    # Untuk berkas semacam itu dipakai aturan -a dengan penyaring nama
    # berkas, bukan -w pada direktori induk. Memantau seluruh /etc akan
    # menghasilkan ribuan event dari pembaruan paket biasa, sedangkan
    # penyaring nama hanya menangkap berkas yang dimaksud.
    declare -A WATCH_IF_ABSENT=(
        ["/etc/ld.so.preload"]="audit-wazuh-rootkit"
        ["/etc/rc.local"]="audit-wazuh-persist"
        ["/etc/hosts.allow"]="audit-wazuh-net"
        ["/etc/hosts.deny"]="audit-wazuh-net"
    )

    TMP_RULES="$(mktemp)"
    DROPPED=0
    SUBSTITUTED=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^-w[[:space:]]+([^[:space:]]+)(.*)$ ]]; then
            target="${BASH_REMATCH[1]}"
            rest="${BASH_REMATCH[2]}"
            if [ -e "${target%/}" ] || [ -d "$target" ]; then
                echo "$line" >> "$TMP_RULES"
            elif [ -n "${WATCH_IF_ABSENT[$target]:-}" ]; then
                # Berkas belum ada tetapi pembuatannya bernilai deteksi.
                # Penyaring -F path menangkap pembuatan dan penyuntingan
                # berkas itu tanpa memantau seluruh direktori induk.
                key="${WATCH_IF_ABSENT[$target]}"
                echo "## $target belum ada, dipantau lewat penyaring path:" >> "$TMP_RULES"
                echo "-a always,exit -F arch=b64 -F path=$target -F perm=wa -k $key" >> "$TMP_RULES"
                SUBSTITUTED=$((SUBSTITUTED + 1))
            else
                echo "## dilewati, jalur tidak ada di sistem ini: $target" >> "$TMP_RULES"
                DROPPED=$((DROPPED + 1))
            fi
        else
            echo "$line" >> "$TMP_RULES"
        fi
    done < "$AUDIT_RULES"

    # Buang aturan -w ganda yang muncul akibat penggantian ke induk yang
    # sama, karena auditd menolak aturan identik.
    awk '!/^-w / || !seen[$0]++' "$TMP_RULES" > "${TMP_RULES}.dedup"
    mv "${TMP_RULES}.dedup" "$AUDIT_RULES"
    rm -f "$TMP_RULES"
    chmod 0640 "$AUDIT_RULES"

    [ "$DROPPED" -gt 0 ] && dim "$DROPPED aturan dilewati karena jalurnya tidak ada di sistem ini"
    [ "$SUBSTITUTED" -gt 0 ] && dim "$SUBSTITUTED berkas belum ada, dipantau lewat penyaring path"

    RULE_COUNT="$(grep -cE '^-[aw]' "$AUDIT_RULES" 2>/dev/null || true)"
    [ -n "$RULE_COUNT" ] || RULE_COUNT=0
    dim "$RULE_COUNT aturan ditulis ke $AUDIT_RULES"

    augenrules --load >/dev/null 2>&1 || die "augenrules gagal memuat aturan. Periksa $AUDIT_RULES"

    if auditctl -s 2>/dev/null | grep -qE '^enabled[[:space:]]+2'; then
        warn "auditd dalam mode immutable (-e 2). Aturan baru baru berlaku setelah REBOOT."
    else
        LOADED="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
        if [ "$LOADED" -ge 10 ]; then
            ok "Aturan audit aktif ($LOADED aturan termuat)"
        elif [ "$LOADED" -gt 0 ]; then
            warn "Hanya $LOADED aturan audit termuat, diharapkan lebih banyak."
        else
            die "Tidak ada aturan audit yang termuat. Periksa 'auditctl -l' dan $AUDIT_RULES"
        fi
    fi

    # Ukuran dan rotasi log audit. Setelah aturan execve aktif, berkas ini
    # tumbuh jauh lebih cepat dan bawaan distribusi sering terlalu kecil,
    # sehingga event lama terhapus sebelum agent mengirimkannya.
    if [ -f /etc/audit/auditd.conf ]; then
        cp -a /etc/audit/auditd.conf "/etc/audit/auditd.conf.bak.$(date +%s)"
        set_auditd_conf() {
            local key="$1" val="$2"
            if grep -qE "^[[:space:]]*${key}[[:space:]]*=" /etc/audit/auditd.conf; then
                sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" /etc/audit/auditd.conf
            else
                echo "${key} = ${val}" >> /etc/audit/auditd.conf
            fi
        }
        set_auditd_conf "max_log_file" "50"
        set_auditd_conf "num_logs" "5"
        set_auditd_conf "max_log_file_action" "ROTATE"
        # Pilihan sadar: saat disk penuh, catat peringatan dan terus jalan,
        # bukan menghentikan sistem. Nilai bawaan beberapa distribusi
        # adalah SUSPEND yang membuat audit berhenti diam diam.
        set_auditd_conf "space_left_action" "SYSLOG"
        set_auditd_conf "admin_space_left_action" "SYSLOG"
        set_auditd_conf "disk_full_action" "SYSLOG"
        systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
        ok "Rotasi log audit diatur: 5 berkas, 50 MB per berkas"
    fi
fi

# =============================================================================
#  Langkah 6: local_internal_options.conf
# =============================================================================
step "Mengatur local_internal_options.conf"

# Hanya berkas lokal yang disentuh. Berkas internal_options.conf ditimpa
# setiap kali paket diperbarui, sehingga perubahan di sana akan hilang.
touch "$LOCAL_OPT"
add_opt(){
  local key="$1" val="$2"
  if grep -qE "^[[:space:]]*${key}=" "$LOCAL_OPT" 2>/dev/null; then
    sed -i "s|^[[:space:]]*${key}=.*|${key}=${val}|" "$LOCAL_OPT"
  else
    echo "${key}=${val}" >> "$LOCAL_OPT"
  fi
}

# Kedua opsi di bawah menentukan apakah agent mau menjalankan perintah
# yang DIKIRIM manager lewat agent.conf. Bawaannya 0 di
# internal_options.conf, dan tanpa diubah, konfigurasi group yang memuat
# <command> atau <full_command> diterima agent tetapi perintahnya
# diabaikan diam diam, tanpa pesan galat yang menjelaskannya.
add_opt "logcollector.remote_commands"  "1"
add_opt "wazuh_command.remote_commands" "1"

# Tidak ada opsi lain yang diubah di sini.
#
# syscheck.max_fd pernah diisi di versi sebelumnya, tetapi opsi itu tidak
# dikenali Wazuh di Linux. Yang ada hanya syscheck.max_fd_win_rt, dan itu
# khusus pemantauan realtime di Windows.
#
# logcollector.max_lines juga pernah diisi 10000, padahal bawaannya sudah
# 10000, jadi tidak mengubah apa pun.

chown root:wazuh "$LOCAL_OPT" 2>/dev/null || true
chmod 0640 "$LOCAL_OPT"
ok "local_internal_options.conf diperbarui, isi lama dipertahankan"

# =============================================================================
#  Langkah 7: blok konfigurasi ossec.conf
# =============================================================================
step "Menyisipkan blok konfigurasi ke ossec.conf"

cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"
dim "Cadangan: ${OSSEC_CONF}.bak.*"

# Konfigurasi bawaan di luar marker dibaca lebih dulu. Paket Wazuh sudah
# menyisipkan banyak sumber log sendiri lewat add_localfiles.sh, dan
# daftarnya cukup panjang:
#
#   syslog-logs.template   /var/log/syslog, auth.log, messages, secure,
#                          kern.log, dpkg.log, mail.log, dan lainnya
#   audit-logs.template    /var/log/audit/audit.log
#   apache-logs.template   nginx dan apache2 access serta error, format apache
#   pgsql-logs.template    log postgresql
#   WriteLogs              journald, bila journalctl ada
#   localfile-commands     'last -n 20' dan daftar port menyimak
#
# Menambahkan entri yang sama membuat berkas dibaca dua kali, dan setiap
# baris log menghasilkan dua event di manager.
#
# Hanya bagian di LUAR marker yang dibaca, supaya menjalankan skrip
# berulang kali tidak menganggap bloknya sendiri sebagai bawaan.
BASE_CONF="$(awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    index($0, b) { skip = 1 }
    !skip        { print }
    index($0, e) { skip = 0 }
' "$OSSEC_CONF" 2>/dev/null || true)"

# Sumber log berbeda antar distribusi dan antar pemasangan. Bagian ini
# menyusun daftar berkas log yang benar benar ada DAN belum terdaftar di
# konfigurasi bawaan.
LOGFILES_BLOCK=""
SKIPPED_DUP=0
add_logfile() {
    local path="$1" fmt="${2:-syslog}"
    [ -e "$path" ] || return 0

    # Pencocokan memakai elemen <location> yang lengkap, bukan substring
    # jalurnya, supaya /var/log/messages tidak dianggap cocok dengan
    # /var/log/messages.old dan sebaliknya.
    if grep -qF "<location>$path</location>" <<< "$BASE_CONF"; then
        dim "sudah ada di konfigurasi bawaan, dilewati: $path"
        SKIPPED_DUP=$((SKIPPED_DUP + 1))
        return 0
    fi

    LOGFILES_BLOCK+="  <localfile>
    <log_format>$fmt</log_format>
    <location>$path</location>
  </localfile>
"
    dim "sumber log ditambahkan: $path"
}

# Berkas di bawah dicoba semuanya. Yang sudah terdaftar di konfigurasi
# bawaan akan dilewati add_logfile, jadi daftar ini boleh memuat jalur
# yang tumpang tindih dengan bawaan tanpa menghasilkan entri ganda.
case "$OS_FAMILY" in
  debian)
    add_logfile /var/log/auth.log
    add_logfile /var/log/syslog
    add_logfile /var/log/kern.log
    add_logfile /var/log/dpkg.log
    # Tidak ada di template bawaan. Mencatat paket yang dipasang, dihapus,
    # dan siapa yang menjalankannya.
    add_logfile /var/log/apt/history.log
    ;;
  rhel)
    add_logfile /var/log/secure
    add_logfile /var/log/messages
    # Tidak ada di template bawaan.
    add_logfile /var/log/dnf.log
    add_logfile /var/log/yum.log
    ;;
esac

# audit.log ditambahkan satu kali untuk kedua keluarga. Berkas ini sudah
# ada di audit-logs.template bawaan, jadi biasanya dilewati. Baris ini
# tetap ada sebagai jaring pengaman bila template bawaan berubah.
add_logfile /var/log/audit/audit.log audit

# Log server web bila ada. Format 'apache' dipakai, bukan 'syslog', karena
# dekoder Wazuh untuk akses web mengharapkan bentuk log gabungan. Dengan
# format syslog, baris akses tidak terurai dan aturan serangan web tidak
# pernah cocok. Ini juga format yang dipakai apache-logs.template bawaan.
add_logfile /var/log/nginx/access.log apache
add_logfile /var/log/nginx/error.log apache
add_logfile /var/log/apache2/access.log apache
add_logfile /var/log/apache2/error.log apache
add_logfile /var/log/httpd/access_log apache
add_logfile /var/log/httpd/error_log apache

# Log basis data bila ada. mysql tidak ada di template bawaan.
add_logfile /var/log/mysql/error.log mysql_log
add_logfile /var/log/postgresql/postgresql-main.log postgresql_log

# rsyslog sering tidak terpasang pada citra awan dan pemasangan minimal.
# Akibatnya /var/log/auth.log tidak pernah terbentuk dan masuk SSH serta
# pemakaian sudo tidak terpantau, tanpa pesan kesalahan apa pun.
#
# Paket Wazuh sudah menambahkan sumber journald sendiri bila journalctl
# tersedia, lewat WriteLogs di inst-functions.sh. Jadi blok ini hanya
# ditambahkan bila bawaan belum memuatnya, supaya jurnal tidak terbaca
# dua kali.
JOURNALD_BLOCK=""
if grep -qF "<location>journald</location>" <<< "$BASE_CONF"; then
    ok "Sumber journald sudah ada di konfigurasi bawaan"
elif command -v journalctl >/dev/null 2>&1; then
    JOURNALD_BLOCK="  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
"
    dim "sumber log ditambahkan: journald"
fi

if systemctl is-active --quiet rsyslog 2>/dev/null; then
    ok "rsyslog aktif"
elif [ -n "$JOURNALD_BLOCK" ] || grep -qF "<location>journald</location>" <<< "$BASE_CONF"; then
    warn "rsyslog tidak aktif. Log masuk dibaca dari journald."
else
    warn "rsyslog tidak aktif dan journald tidak tersedia."
    dim "Masuk SSH dan pemakaian sudo mungkin tidak terpantau."
fi

# Blok FIM. Dipisah agar bisa dilewati lewat SKIP_FIM.
FIM_BLOCK=""
if [ "$SKIP_FIM" != "1" ]; then
FIM_BLOCK=$(cat <<'FIMEOF'
  <!-- Pemantauan keutuhan berkas.
       Mode realtime diperlukan karena tanpa itu perubahan pada berkas
       penting seperti /etc/shadow baru diketahui saat pemindaian
       berikutnya, yang bisa dua belas jam kemudian. -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <!-- Kredensial dan akun -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/group,/etc/gshadow</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/sudoers,/etc/sudoers.d</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/pam.d,/etc/security</directories>

    <!-- Akses jarak jauh -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/ssh</directories>
    <directories realtime="yes" check_all="yes">/root/.ssh,/home/*/.ssh</directories>

    <!-- Pustaka yang dimuat paksa. Jalur rootkit tingkat pengguna. -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/ld.so.preload,/etc/ld.so.conf</directories>
    <directories realtime="yes" check_all="yes">/etc/ld.so.conf.d</directories>

    <!-- Persistence lewat penjadwal dan layanan -->
    <directories realtime="yes" check_all="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/cron.monthly,/etc/cron.weekly</directories>
    <directories realtime="yes" check_all="yes">/etc/crontab,/var/spool/cron</directories>
    <!-- /lib adalah simlink ke /usr/lib pada sistem merged-usr, yang kini
         baku di Debian, Ubuntu, dan RHEL modern. Menulis keduanya membuat
         Wazuh memantau direktori yang sama dua kali dan mencatat
         peringatan duplikat di ossec.log. Jalur yang dipakai ditentukan
         saat skrip berjalan di bagian penyusunan blok. -->
    <directories realtime="yes" check_all="yes">/etc/systemd/system,SYSTEMD_UNIT_DIRS</directories>
    <directories realtime="yes" check_all="yes">/etc/init.d,/etc/rc.local</directories>

    <!-- Persistence lewat berkas profil shell -->
    <directories realtime="yes" check_all="yes">/etc/profile,/etc/profile.d,/etc/bash.bashrc</directories>

    <!-- Modul kernel -->
    <directories realtime="yes" check_all="yes">/etc/modprobe.d,/etc/modules-load.d</directories>

    <!-- Jaringan -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/hosts,/etc/resolv.conf</directories>

    <!-- Binari sistem. Tanpa realtime karena jumlah berkasnya besar. -->
    <directories check_all="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/usr/local/bin,/usr/local/sbin</directories>

    <!-- Lokasi yang sering dipakai untuk menaruh muatan.
         Memori bersama sering dipakai perangkat lunak berbahaya tanpa
         berkas karena isinya hilang saat mesin dimatikan. -->
    <directories realtime="yes" check_all="yes">/dev/shm</directories>
    <directories realtime="yes" check_all="yes">/tmp,/var/tmp</directories>

    <!-- Isi berkas di bawah TIDAK boleh dikirim ke manager.
         Dengan report_changes="yes", Wazuh melampirkan selisih baris
         sebelum dan sesudah ke dalam alert, dan selisih itu tersimpan di
         manager serta tampil di dashboard. Pada berkas ini artinya hash
         kata sandi seluruh pengguna dan kunci privat host SSH ikut
         terkirim, terbaca siapa pun yang punya akses dashboard.

         nodiff tetap memantau dan tetap memberi peringatan saat berkas
         berubah. Yang dibuang hanya lampiran isinya. Konfigurasi bawaan
         Wazuh memakai pola yang sama untuk /etc/ssl/private.key. -->
    <nodiff>/etc/shadow</nodiff>
    <nodiff>/etc/gshadow</nodiff>
    <nodiff type="sregex">^/etc/ssh/ssh_host_.*_key$</nodiff>
    <nodiff type="sregex">^/etc/ssl/private</nodiff>

    <!-- Berkas yang berubah terus menerus. Tanpa pengecualian ini,
         peringatan FIM membanjiri dashboard dan menutupi yang penting. -->
    <ignore type="sregex">\.log$|\.swp$|\.tmp$|\.lock$|\.pid$|\.sock$</ignore>
    <ignore>/tmp/systemd-private</ignore>
    <ignore>/var/tmp/systemd-private</ignore>
    <ignore type="sregex">^/tmp/\.X11-unix</ignore>
    <ignore type="sregex">^/tmp/\.ICE-unix</ignore>
    <ignore>/var/ossec</ignore>
  </syscheck>
FIMEOF
)

# Jalur unit systemd dihitung di sini, bukan ditulis tetap di blok.
#
# Pada sistem merged-usr, /lib adalah simlink ke /usr/lib, sehingga
# /lib/systemd/system dan /usr/lib/systemd/system menunjuk direktori yang
# sama. Memantau keduanya membuat Wazuh mencatat peringatan duplikat.
# Jalur nyatanya diselesaikan dengan readlink lalu disatukan.
SYSTEMD_DIRS=""
for d in /lib/systemd/system /usr/lib/systemd/system; do
    [ -d "$d" ] || continue
    real="$(readlink -f "$d" 2>/dev/null || echo "$d")"
    case ",$SYSTEMD_DIRS," in
        *",$real,"*) continue ;;
    esac
    SYSTEMD_DIRS="${SYSTEMD_DIRS:+$SYSTEMD_DIRS,}$real"
done

if [ -n "$SYSTEMD_DIRS" ]; then
    FIM_BLOCK="${FIM_BLOCK//SYSTEMD_UNIT_DIRS/$SYSTEMD_DIRS}"
    dim "direktori unit systemd dipantau: $SYSTEMD_DIRS"
else
    # Tidak ada jalur yang ada. Penanda dibuang bersama koma di depannya
    # supaya tidak menghasilkan daftar direktori yang cacat.
    FIM_BLOCK="${FIM_BLOCK//,SYSTEMD_UNIT_DIRS/}"
fi

# /dev/shm adalah tmpfs. Dengan skip_dev=yes, Wazuh melewati tmpfs yang
# TIDAK dipasang dengan opsi nodev, mengikuti logika di src/shared/fs_op.c:
#
#   case TMPFS: return set.dev && (stfs.f_flags & ST_NODEV) == 0;
#
# Pemasangan baku /dev/shm memakai nodev, jadi tetap dipantau. Tetapi bila
# host memasangnya tanpa nodev, direktori itu dilewati diam diam padahal
# terdaftar di konfigurasi. Keadaan itu diperiksa di sini karena hanya
# terlihat saat skrip berjalan.
if [ -d /dev/shm ] && command -v findmnt >/dev/null 2>&1; then
    SHM_OPTS="$(findmnt -no OPTIONS /dev/shm 2>/dev/null || true)"
    case ",$SHM_OPTS," in
        *nodev*) : ;;
        *)
            if [ -n "$SHM_OPTS" ]; then
                warn "/dev/shm dipasang tanpa opsi nodev, sehingga dilewati FIM."
                dim "Penyebabnya skip_dev=yes, yang melewati tmpfs tanpa nodev."
                dim "Perbaiki pemasangannya: mount -o remount,nodev /dev/shm"
            fi ;;
    esac
fi
fi

BLOCK=$(cat <<EOF
$MARK_BEGIN
  <!-- Penyangga kiriman TIDAK ditulis di sini.
       Konfigurasi bawaan agent sudah memuat blok <client_buffer> dengan
       queue_size 5000 dan events_per_second 500. Menambahkan blok kedua
       membuat Wazuh memakai nilai yang pertama dibaca dan mengabaikan
       sisanya, sehingga nilai baru tidak pernah berlaku. Nilai bawaan
       diubah di tempat setelah blok ini disisipkan. -->

$LOGFILES_BLOCK$JOURNALD_BLOCK
$FIM_BLOCK

  <!-- Modul berikut TIDAK ditulis ulang di sini, karena konfigurasi
       bawaan agent sudah memuat semuanya dalam keadaan aktif:

         <rootcheck>          pemeriksaan rootkit, seluruh uji aktif
         <sca>                nilainya persis sama dengan yang diinginkan
         <active-response>    sudah disabled=no dengan verifikasi CA
         <wodle name="syscollector">   inventaris sistem
         <client_buffer>      penyangga kiriman

       Wazuh memakai blok yang pertama dibaca dan mengabaikan blok kedua
       dengan nama sama, jadi menambahkannya tidak mengubah apa pun dan
       hanya membuat setiap pesan modul muncul dua kali di ossec.log.

       Dua nilai bawaan yang memang perlu diubah, yaitu ukuran penyangga
       dan pemindaian seluruh port, diubah di tempat setelah blok ini
       disisipkan. -->

  <!-- Perintah berkala untuk hal yang tidak tertangkap audit maupun FIM.
       Memerlukan logcollector.remote_commands yang sudah diaktifkan.
       Perintah 'last -n 20' dan daftar port menyimak tidak ditulis di
       sini karena sudah ada di localfile-commands.template bawaan. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>awk -F: '\$3 == 0 {print \$1}' /etc/passwd</command>
    <alias>uid-zero-accounts</alias>
    <frequency>3600</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>lsmod</command>
    <alias>kernel-modules</alias>
    <frequency>3600</frequency>
  </localfile>

  <!-- Berkas dengan bit setuid di luar jalur baku adalah pola eskalasi
       hak yang sering dipakai.
       Pencarian dibatasi pada direktori tempat berkas setuid yang sah
       berada, bukan seluruh sistem berkas. Menjelajah dari / bisa
       memakan waktu lama dan membebani cakram pada server dengan
       jutaan berkas, dan hasil di luar jalur ini sudah tertangkap FIM. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>find /usr /bin /sbin /opt /tmp /var/tmp /home /dev/shm -xdev -type f -perm -4000 2>/dev/null | sort</command>
    <alias>suid-files</alias>
    <frequency>86400</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>getent group sudo wheel 2>/dev/null</command>
    <alias>sudo-group-members</alias>
    <frequency>3600</frequency>
  </localfile>
$MARK_END
EOF
)

# Penyisipan idempoten. Blok lama dibuang lebih dulu bila ada, lalu blok
# baru disisipkan sebelum penutup </ossec_config> yang terakhir.
# Python dipakai agar aman terhadap indentasi dan baris panjang.
BLOCK="$BLOCK" python3 - "$OSSEC_CONF" "$MARK_BEGIN" "$MARK_END" <<'PYEOF'
import os, re, sys
path, mb, me = sys.argv[1], sys.argv[2], sys.argv[3]
block = os.environ["BLOCK"]
s = open(path, encoding="utf-8").read()
s = re.sub(re.escape(mb) + r".*?" + re.escape(me) + r"\n?", "", s, flags=re.S)
idx = s.rfind("</ossec_config>")
if idx == -1:
    sys.exit("</ossec_config> tidak ditemukan di " + path)
out = s[:idx] + block + "\n" + s[idx:]

# Pastikan hasil tetap XML yang sah sebelum ditulis. Berkas ossec.conf
# memuat beberapa blok <ossec_config> sejajar, jadi perlu dibungkus akar
# semu lebih dulu.
import xml.etree.ElementTree as ET
try:
    ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", out) + "</root>")
except ET.ParseError as e:
    sys.exit("Hasil penyuntingan bukan XML yang sah: %s" % e)

open(path, "w", encoding="utf-8").write(out)
PYEOF

chown root:wazuh "$OSSEC_CONF" 2>/dev/null || true
chmod 0660 "$OSSEC_CONF"
ok "Blok konfigurasi tersisip dan lolos pemeriksaan XML"

if [ "$SKIPPED_DUP" -gt 0 ]; then
    dim "$SKIPPED_DUP sumber log dilewati karena sudah ada di konfigurasi bawaan"
fi

# --- Nilai bawaan yang diubah di tempat.
#
# Blok di bawah sudah ada di konfigurasi bawaan, dan Wazuh mengabaikan
# blok kedua dengan nama sama. Jadi nilainya diubah pada blok yang ada,
# bukan ditambah sebagai blok baru.
#
# Penyuntingan dibatasi pada blok yang dimaksud, bukan seluruh berkas,
# supaya angka yang sama di tempat lain tidak ikut berubah. Python dipakai
# karena sed tidak bisa membatasi pola pada rentang antar baris dengan
# aman.
TUNE_OUT="$(BLOCK_UNUSED=1 python3 - "$OSSEC_CONF" <<'PYEOF' 2>&1 || true
import re, sys
path = sys.argv[1]
s = open(path, encoding="utf-8").read()
orig = s
changed = []

def tune_block(text, open_re, inner_pairs, label):
    """Ubah nilai di dalam blok pertama yang cocok open_re."""
    global changed
    m = re.search(open_re, text)
    if not m:
        return text
    start = m.start()
    # Cari penutup yang sepadan dengan nama elemen pembuka.
    tag = re.match(r"\s*<([A-Za-z_][\w-]*)", m.group(0)).group(1)
    close = "</%s>" % tag
    end = text.find(close, start)
    if end == -1:
        return text
    body = text[start:end]
    newbody = body
    for pat, repl, note in inner_pairs:
        newbody, n = re.subn(pat, repl, newbody, count=1)
        if n and newbody != body:
            changed.append(note)
    return text[:start] + newbody + text[end:]

# Penyangga kiriman. Bawaan 5000 antrean dengan 500 event per detik
# terlalu kecil begitu aturan execve auditd aktif: antrean penuh berarti
# event dibuang, dan satu satunya tandanya adalah sebaris di ossec.log.
s = tune_block(
    s, r"<client_buffer>",
    [(r"<queue_size>\s*\d+\s*</queue_size>",
      "<queue_size>100000</queue_size>", "queue_size 100000"),
     (r"<events_per_second>\s*\d+\s*</events_per_second>",
      "<events_per_second>1000</events_per_second>", "events_per_second 1000")],
    "client_buffer")

# Pemindaian port. Bawaan all="no" hanya melaporkan port yang menyimak,
# sedangkan all="yes" ikut melaporkan sambungan keluar yang sedang aktif.
# Yang kedua diperlukan untuk melihat sambungan ke alamat kendali.
s = tune_block(
    s, r"<wodle\s+name=\"syscollector\">",
    [(r"<ports\s+all=\"no\">", "<ports all=\"yes\">", "ports all=yes")],
    "syscollector")

if s == orig:
    print("TIDAK_ADA_PERUBAHAN")
    sys.exit(0)

import xml.etree.ElementTree as ET
try:
    ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", s) + "</root>")
except ET.ParseError as e:
    sys.exit("XML_TIDAK_SAH: %s" % e)

open(path, "w", encoding="utf-8").write(s)
print("DIUBAH: " + ", ".join(changed))
PYEOF
)"

case "$TUNE_OUT" in
    DIUBAH:*)            ok "Nilai bawaan disesuaikan (${TUNE_OUT#DIUBAH: })" ;;
    TIDAK_ADA_PERUBAHAN) dim "Nilai bawaan sudah sesuai, tidak ada yang diubah" ;;
    XML_TIDAK_SAH*)
        warn "Penyesuaian nilai bawaan menghasilkan XML tidak sah, dilewati."
        dim "$TUNE_OUT" ;;
    *)
        warn "Penyesuaian nilai bawaan tidak dapat dipastikan."
        [ -n "$TUNE_OUT" ] && dim "$TUNE_OUT" ;;
esac

# Blok <rootcheck> bawaan menunjuk ke etc/shared, direktori yang isinya
# diganti manager. Rujukannya dialihkan ke salinan di etc/ yang dibuat
# pada langkah pemasangan paket, sehingga pemeriksaan tanda tangan
# rootkit tetap berjalan setelah konfigurasi group diterima.
if [ "$ROOTKIT_DB_OK" = "1" ]; then
    if grep -q 'etc/shared/rootkit_files.txt' "$OSSEC_CONF" 2>/dev/null; then
        sed -i 's|<rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>|<rootkit_files>etc/rootkit_files.txt</rootkit_files>|g; s|<rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>|<rootkit_trojans>etc/rootkit_trojans.txt</rootkit_trojans>|g' "$OSSEC_CONF"

        # Pastikan hasil suntingan tetap XML yang sah.
        if python3 - "$OSSEC_CONF" <<'PYCHK' 2>/dev/null
import re, sys
import xml.etree.ElementTree as ET
s = open(sys.argv[1], encoding="utf-8").read()
ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", s) + "</root>")
PYCHK
        then
            ok "Rujukan basis tanda tangan rootkit dialihkan ke etc/"
        else
            warn "Penyuntingan rujukan rootkit menghasilkan XML tidak sah, dikembalikan."
            # Cadangan terbaru dicari lewat find, bukan ls, supaya nama
            # berkas yang tidak lazim tidak merusak pemilihan.
            LAST_BAK="$(find "$(dirname "$OSSEC_CONF")" -maxdepth 1 \
                          -name "$(basename "$OSSEC_CONF").bak.*" -printf '%T@ %p\n' 2>/dev/null \
                        | sort -rn | head -1 | cut -d' ' -f2- || true)"
            if [ -n "$LAST_BAK" ] && [ -f "$LAST_BAK" ]; then
                cp -a "$LAST_BAK" "$OSSEC_CONF" 2>/dev/null || true
                dim "dikembalikan dari $LAST_BAK"
            fi
        fi
    fi
fi

# =============================================================================
#  Langkah 8: menjalankan agent
# =============================================================================
step "Menjalankan wazuh-agent"

# Posisi akhir log dicatat SEBELUM agent dijalankan.
#
# Tanpa penanda ini, verifikasi sambungan di langkah berikutnya membaca
# seluruh ossec.log. Pada mesin yang pernah dipasangi agent, baris
# 'Connected to the server' dari sesi lama membuat pemeriksaan lolos
# walaupun agent sekarang tidak pernah tersambung. Sebaliknya, pesan
# 'Unable to connect' dari sesi lama membuat pemeriksaan gagal lebih awal
# padahal agent sehat.
LOG_START=0
if [ -f "$OSSEC_LOG" ]; then
    LOG_START="$(wc -l < "$OSSEC_LOG" 2>/dev/null || echo 0)"
fi

systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent || die "wazuh-agent gagal dijalankan. Periksa: journalctl -u wazuh-agent -n 50"

sleep 3
if systemctl is-active --quiet wazuh-agent; then
    ok "Layanan wazuh-agent berjalan"
else
    die "Layanan wazuh-agent tidak berjalan setelah restart. Periksa: journalctl -u wazuh-agent -n 50"
fi

# =============================================================================
#  Langkah 9: menunggu sambungan ke manager
# =============================================================================
step "Menunggu pendaftaran dan sambungan ke manager"

# Pemeriksaan ini yang menentukan. agent bisa berstatus aktif tetapi tidak
# pernah tersambung karena alamat salah, port diblokir, nama bentrok,
# atau group tidak ada di manager.
info "Batas waktu ${CONNECT_TIMEOUT} detik"

# Hanya baris yang muncul setelah restart yang dibaca, memakai penanda
# posisi dari langkah sebelumnya.
new_log() {
    [ -f "$OSSEC_LOG" ] || return 0
    tail -n "+$((LOG_START + 1))" "$OSSEC_LOG" 2>/dev/null || true
}

CONNECTED=0
FAIL_REASON=""
FAIL_PATTERN="Unable to connect|Invalid server address|Authentication error|Duplicate agent name|Unable to add agent"

for _ in $(seq 1 "$CONNECT_TIMEOUT"); do
    CHUNK="$(new_log)"

    if grep -q "Connected to the server" <<< "$CHUNK"; then
        CONNECTED=1
        FAIL_REASON=""
        break
    fi

    # Pesan gagal dicatat tetapi loop TIDAK dihentikan. Agent yang baru
    # start sering mencatat 'Unable to connect' sekali lalu berhasil
    # beberapa detik kemudian, dan berhenti di pesan pertama akan
    # melaporkan kegagalan pada pemasangan yang sebenarnya berhasil.
    # Pesan terakhir disimpan, dan baru dilaporkan bila batas waktu
    # terlampaui tanpa sambungan.
    LAST_ERR="$(grep -hoE "$FAIL_PATTERN.*" <<< "$CHUNK" 2>/dev/null | tail -1 || true)"
    [ -n "$LAST_ERR" ] && FAIL_REASON="$LAST_ERR"

    sleep 1
done

REGISTERED=0
AGENT_ID=""
if [ -s "$CLIENT_KEYS" ]; then
    REGISTERED=1
    AGENT_ID="$(awk 'NR==1{print $1" ("$2")"}' "$CLIENT_KEYS" 2>/dev/null || true)"
    ok "Terdaftar ke manager: ID $AGENT_ID"
else
    warn "client.keys masih kosong, agent belum terdaftar."
    dim "Penyebab umum: nama agent sudah dipakai agent lain di manager,"
    dim "atau manager menolak pendaftaran baru."
    dim "Periksa di manager: /var/ossec/logs/ossec.log"
fi

if [ "$CONNECTED" -eq 1 ]; then
    ok "agent tersambung ke manager $WAZUH_MANAGER"
elif [ -n "$FAIL_REASON" ]; then
    warn "Gagal tersambung: $FAIL_REASON"
else
    warn "Belum ada pesan sambungan dalam ${CONNECT_TIMEOUT} detik."
fi

# =============================================================================
#  Langkah 10: verifikasi pemantauan
# =============================================================================
step "Verifikasi pemantauan"

# agent merestart dirinya sendiri setelah menerima konfigurasi group dari
# manager, karena ossec.conf bawaan memuat <auto_restart>yes</auto_restart>.
# Verifikasi yang berjalan tepat pada saat itu akan melihat daemon sedang
# mati dan melaporkannya sebagai kegagalan, padahal agent sehat.
#
# Bagian ini menunggu sampai daftar daemon stabil: tidak ada lagi yang
# berstatus 'not running' selama beberapa pemeriksaan berturut turut.
if [ "$SKIP_VERIFY" != "1" ] && [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    info "Menunggu daemon agent stabil"
    STABLE=0
    for _ in $(seq 1 20); do
        CTRL_NOW="$("$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null || true)"
        if [ -n "$CTRL_NOW" ] && ! echo "$CTRL_NOW" | grep -q 'not running'; then
            STABLE=$((STABLE + 1))
            # Dua pemeriksaan berturut turut dengan jeda, supaya restart
            # yang sedang berlangsung tidak terlewat.
            [ "$STABLE" -ge 2 ] && break
        else
            STABLE=0
        fi
        sleep 2
    done
    if [ "$STABLE" -ge 2 ]; then
        ok "Daemon agent stabil"
    else
        dim "Daemon masih berubah status, verifikasi tetap dilanjutkan"
    fi
fi

V_PASS=0
V_FAIL=0

# Pembungkus 'grep -c' yang selalu menghasilkan angka.
#
# Tanpa ini, 'grep -c pola berkas-yang-tidak-ada || true' menghasilkan
# string KOSONG, bukan nol, karena grep tidak mencetak apa pun saat
# berkasnya tidak terbuka. Perbandingan berikutnya lalu gagal dengan
# '[: : integer expected' dan menghentikan verifikasi di tengah.
count_matches() {
    local pattern="$1" file="$2" n
    [ -f "$file" ] || { echo 0; return 0; }
    n="$(grep -cE "$pattern" "$file" 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) echo 0 ;;
        *)           echo "$n" ;;
    esac
}

# Seperti count_matches, tetapi komentar XML dibuang lebih dulu.
#
# Diperlukan karena blok yang disisipkan skrip ini memuat komentar
# penjelas yang menyebut nama modul, misalnya '<client_buffer>' di dalam
# keterangan. Tanpa membuang komentar, nama itu ikut terhitung dan satu
# blok nyata dilaporkan sebagai dua, sehingga verifikasi memberi
# peringatan tentang blok ganda yang sebenarnya tidak ada.
count_elements() {
    local pattern="$1" file="$2" n
    [ -f "$file" ] || { echo 0; return 0; }
    n="$(python3 -c '
import re, sys
pat, path = sys.argv[1], sys.argv[2]
try:
    s = open(path, encoding="utf-8", errors="replace").read()
except OSError:
    print(0); sys.exit(0)
print(len(re.findall(pat, re.sub(r"<!--.*?-->", "", s, flags=re.S))))
' "$pattern" "$file" 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) echo 0 ;;
        *)           echo "$n" ;;
    esac
}

vcheck() {
    local state="$1" label="$2" detail="${3:-}"
    case "$state" in
        pass) echo -e "  ${G}OK  ${N} $label ${GRY}$detail${N}"; V_PASS=$((V_PASS + 1)) ;;
        warn) echo -e "  ${Y}WARN${N} $label ${GRY}$detail${N}" ;;
        fail) echo -e "  ${R}BLM ${N} $label ${GRY}$detail${N}"; V_FAIL=$((V_FAIL + 1))
              WARN_LIST+=("Verifikasi: $label $detail"); WARN_COUNT=$((WARN_COUNT + 1)) ;;
    esac
}

if [ "$SKIP_VERIFY" = "1" ]; then
    dim "Dilewati karena SKIP_VERIFY=1"
else
    # --- remote_commands
    #
    # Keduanya diperiksa, bukan hanya yang pertama. logcollector mengurus
    # <localfile> dengan log_format command, sedangkan wazuh_command
    # mengurus modul command yang dikirim manager lewat agent.conf. Salah
    # satu mati berarti sebagian perintah diabaikan tanpa pesan galat.
    #
    # Titik dalam pola diloloskan supaya tidak cocok dengan sembarang
    # karakter di posisi itu.
    for opt in logcollector.remote_commands wazuh_command.remote_commands; do
        if grep -qE "^[[:space:]]*${opt//./\\.}=1[[:space:]]*$" "$LOCAL_OPT" 2>/dev/null; then
            vcheck pass "$opt aktif"
        else
            vcheck fail "$opt aktif" "perintah dari manager akan diabaikan"
        fi
    done

    # --- aturan audit benar termuat
    if [ "$SKIP_AUDIT" != "1" ]; then
        LOADED="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
        if [ "$LOADED" -ge 10 ]; then
            vcheck pass "Aturan audit termuat" "$LOADED aturan"
        elif [ "$LOADED" -gt 0 ]; then
            vcheck warn "Aturan audit termuat sebagian" "$LOADED aturan"
        else
            vcheck fail "Aturan audit termuat" "tidak ada"
        fi

        # Bukti audit benar menulis, bukan hanya aturan terdaftar.
        if [ -s /var/log/audit/audit.log ]; then
            AUDIT_LINES="$(wc -l < /var/log/audit/audit.log 2>/dev/null || echo 0)"
            vcheck pass "audit.log berisi data" "$AUDIT_LINES baris"
        else
            vcheck warn "audit.log masih kosong" "wajar di mesin yang baru dipasang"
        fi

        if systemctl is-active --quiet auditd 2>/dev/null; then
            vcheck pass "Layanan auditd berjalan"
        else
            vcheck fail "Layanan auditd berjalan" "audit tidak menghasilkan event"
        fi
    fi

    # --- modul di ossec.conf
    # Sebagian modul ditulis sebagai elemen bernama diri sendiri, misalnya
    # <syscheck>, dan sebagian lagi sebagai <wodle name="...">. Pencarian
    # harus mengenali keduanya, kalau tidak modul yang sebenarnya ada
    # dilaporkan hilang.
    # Pola harus diakhiri '[ >]' supaya nama elemen cocok seluruhnya.
    # Tanpa itu, '<sca' juga cocok dengan '<scan_on_start>' dan
    # pemeriksaan selalu lolos tanpa membuktikan apa pun.
    #
    # Blok <syscheck> dikecualikan dari pemeriksaan blok ganda, karena
    # Wazuh MENGGABUNGKAN beberapa blok syscheck menjadi satu daftar
    # direktori. Dua blok di situ wajar dan memang dimanfaatkan: bawaan
    # memantau /etc dan /usr/bin, blok skrip menambah sisanya.
    for mod in syscheck sca rootcheck active-response client_buffer; do
        # Kurung kurawal wajib. Tanpa itu, bash membaca "$mod[ >]" sebagai
        # rujukan elemen array bernama mod, bukan nama variabel yang
        # diikuti kelas karakter.
        COUNT_MOD="$(count_elements "<${mod}[ >]" "$OSSEC_CONF")"
        if [ "$COUNT_MOD" -eq 0 ]; then
            vcheck fail "Modul $mod terdaftar" "tidak ada di ossec.conf"
        elif [ "$COUNT_MOD" -eq 1 ] || [ "$mod" = "syscheck" ]; then
            if [ "$COUNT_MOD" -gt 1 ]; then
                vcheck pass "Modul $mod terdaftar" "$COUNT_MOD blok, digabung Wazuh"
            else
                vcheck pass "Modul $mod terdaftar"
            fi
        else
            # Untuk modul selain syscheck, blok kedua diabaikan Wazuh.
            # Nilainya tidak berlaku, dan itu menyesatkan saat menyetel.
            vcheck warn "Modul $mod terdaftar" "$COUNT_MOD blok, hanya yang pertama dipakai"
        fi
    done
    # syscollector ditulis sebagai <wodle name="..."> , bukan elemen
    # bernama diri sendiri, jadi pencariannya berbeda dari modul di atas.
    COUNT_SYSCOL="$(count_elements '<wodle[ \t]+name="syscollector"' "$OSSEC_CONF")"
    if [ "$COUNT_SYSCOL" -eq 1 ]; then
        vcheck pass "Modul syscollector terdaftar"
    elif [ "$COUNT_SYSCOL" -gt 1 ]; then
        vcheck warn "Modul syscollector terdaftar" "$COUNT_SYSCOL blok, hanya yang pertama dipakai"
    else
        vcheck fail "Modul syscollector terdaftar" "tidak ada di ossec.conf"
    fi

    # Pemindaian seluruh port benar berlaku, bukan hanya port menyimak.
    # Nilai ini disetel di tempat pada blok bawaan, jadi perlu dibuktikan.
    if grep -qE '<ports[[:space:]]+all="yes"' "$OSSEC_CONF" 2>/dev/null; then
        vcheck pass "syscollector memindai seluruh port"
    else
        vcheck warn "syscollector memindai seluruh port" "hanya port menyimak yang dilaporkan"
    fi

    # Ukuran penyangga kiriman. Nilai bawaan 5000 terlalu kecil begitu
    # aturan execve auditd aktif, dan antrean penuh berarti event dibuang
    # tanpa peringatan di dashboard.
    QSIZE="$(grep -oE '<queue_size>[0-9]+</queue_size>' "$OSSEC_CONF" 2>/dev/null \
             | head -1 | tr -cd '0-9' || true)"
    if [ -n "$QSIZE" ] && [ "$QSIZE" -ge 100000 ]; then
        vcheck pass "Penyangga kiriman diperbesar" "queue_size $QSIZE"
    elif [ -n "$QSIZE" ]; then
        vcheck warn "Penyangga kiriman" "queue_size $QSIZE, event bisa dibuang saat lonjakan"
    fi

    # --- basis tanda tangan rootkit benar terbaca
    #
    # Rootcheck tetap melaporkan diri aktif walau berkas tanda tangannya
    # hilang, dan kegagalannya hanya muncul sebagai galat berulang di
    # ossec.log. Pemeriksaan ini membuatnya terlihat.
    RK_REF="$(grep -oE '<rootkit_files>[^<]+</rootkit_files>' "$OSSEC_CONF" 2>/dev/null \
              | sed 's|</\?rootkit_files>||g' | head -1 || true)"
    if [ -n "$RK_REF" ]; then
        case "$RK_REF" in
            /*) RK_PATH="$RK_REF" ;;
            *)  RK_PATH="$OSSEC_DIR/$RK_REF" ;;
        esac
        if [ -f "$RK_PATH" ]; then
            vcheck pass "Basis tanda tangan rootkit" "$(basename "$RK_PATH")"
        else
            vcheck fail "Basis tanda tangan rootkit" "berkas $RK_PATH tidak ada"
            dim "Rootcheck akan mencatat galat pada setiap pemindaian dan"
            dim "pemeriksaan tanda tangan rootkit tidak berjalan."
        fi
    fi

    # --- sumber log benar ada
    SRC_COUNT="$(count_matches '<location>' "$OSSEC_CONF")"
    if [ "$SRC_COUNT" -ge 5 ]; then
        vcheck pass "Sumber log terdaftar" "$SRC_COUNT entri"
    else
        vcheck warn "Sumber log terdaftar" "hanya $SRC_COUNT entri"
    fi

    # --- kebijakan SCA benar berjalan, bukan hanya modulnya aktif
    #
    # Berkas kebijakan memuat uji versi sistem operasi di bagian
    # 'requirements'. Bila versi mesin tidak cocok, seluruh kebijakan
    # dilewati dan pemindaian selesai dalam nol detik tanpa satu pun
    # pemeriksaan dijalankan. Modul tetap melaporkan diri aktif, sehingga
    # keadaan ini mudah terlewat.
    if grep -q '<sca>' "$OSSEC_CONF" 2>/dev/null; then
        # Dihitung sebagai jumlah kebijakan yang berbeda, bukan jumlah
        # baris log, karena kebijakan yang sama dilewati berulang pada
        # setiap pemindaian.
        SCA_SKIP="$(grep -h 'sca: INFO: Skipping policy' "$OSSEC_LOG" 2>/dev/null \
                    | sed 's/^.*sca: INFO: //' | sort -u | wc -l || echo 0)"
        SCA_DONE="$(count_matches 'Security Configuration Assessment scan finished' "$OSSEC_LOG")"
        SCA_POLICIES="$(find "$OSSEC_DIR/ruleset/sca" -name '*.yml' 2>/dev/null | wc -l || echo 0)"

        if [ "$SCA_SKIP" -gt 0 ] && [ "$SCA_DONE" -gt 0 ]; then
            vcheck warn "Kebijakan SCA berjalan" "$SCA_SKIP kebijakan dilewati karena versi tidak cocok"
            # Kebijakan yang sama dilewati pada setiap pemindaian, jadi
            # baris berulang disatukan agar jumlahnya mencerminkan berapa
            # kebijakan yang terpengaruh, bukan berapa kali tercatat.
            grep -h 'sca: INFO: Skipping policy' "$OSSEC_LOG" 2>/dev/null \
              | sed 's/^.*sca: INFO: //' | sort -u | head -5 | while IFS= read -r l; do
                dim "$l"
            done
            dim "Wazuh membawa kebijakan CIS hanya untuk sebagian versi rilis."
            dim "Bila versi mesin ini belum didukung, SCA tidak memeriksa apa pun."
            dim "Periksa kebijakan yang tersedia di manager: /var/ossec/etc/shared/<group>/"
        elif [ "$SCA_POLICIES" -gt 0 ]; then
            vcheck pass "Kebijakan SCA tersedia" "$SCA_POLICIES berkas"
        else
            vcheck warn "Kebijakan SCA tersedia" "belum ada, biasanya dikirim manager lewat group"
        fi
    fi

    # --- proses agent yang seharusnya hidup
    #
    # Kernel memotong nama proses di /proc/PID/comm menjadi 15 karakter,
    # sedangkan 'pgrep -x' mencocokkan tepat terhadap nama itu. Akibatnya
    # wazuh-logcollector yang panjangnya 18 karakter tidak pernah cocok
    # walaupun prosesnya berjalan.
    #
    # Pencocokan dilakukan dua arah: terhadap nama terpotong, lalu
    # terhadap baris perintah penuh sebagai cadangan.
    for proc in wazuh-agentd wazuh-logcollector wazuh-syscheckd wazuh-modulesd; do
        short="${proc:0:15}"
        if pgrep -x "$short" >/dev/null 2>&1 \
           || pgrep -f "$OSSEC_DIR/bin/$proc" >/dev/null 2>&1; then
            vcheck pass "Proses $proc hidup"
        else
            # wazuh-modulesd menangani syscollector, SCA, dan rootcheck.
            # Bila mati, ketiganya ikut mati tanpa pesan terpisah.
            case "$proc" in
                wazuh-modulesd)
                    vcheck fail "Proses $proc hidup" "syscollector, SCA, dan rootcheck ikut tidak berjalan" ;;
                wazuh-logcollector)
                    vcheck fail "Proses $proc hidup" "pembacaan berkas log berhenti" ;;
                *)
                    vcheck fail "Proses $proc hidup" "modul terkait tidak berjalan" ;;
            esac
        fi
    done

    # Daftar status resmi dari wazuh-control memberi gambaran yang lebih
    # tepat daripada menebak dari nama proses.
    if [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
        CTRL_OUT="$("$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null || true)"
        if [ -n "$CTRL_OUT" ]; then
            NOT_RUN="$(echo "$CTRL_OUT" | grep -c 'not running' || true)"
            if [ "$NOT_RUN" -eq 0 ]; then
                vcheck pass "wazuh-control status" "semua daemon berjalan"
            else
                vcheck warn "wazuh-control status" "$NOT_RUN daemon tidak berjalan"
                echo "$CTRL_OUT" | grep 'not running' | while IFS= read -r l; do
                    dim "$l"
                done
            fi
        fi
    fi

    # --- galat di log agent
    #
    # Hanya baris sejak restart yang dihitung. Galat dari sesi lama tidak
    # memberi tahu apa pun tentang pemasangan ini, dan pada mesin yang
    # pernah bermasalah justru membuat pemasangan yang sehat terlihat
    # gagal.
    if [ -f "$OSSEC_LOG" ]; then
        NEW_LINES="$(new_log)"
        ERR_COUNT="$(grep -cE 'ERROR|CRITICAL' <<< "$NEW_LINES" 2>/dev/null || true)"
        [ -n "$ERR_COUNT" ] || ERR_COUNT=0
        if [ "$ERR_COUNT" -eq 0 ]; then
            vcheck pass "Tidak ada galat baru di ossec.log"
        else
            vcheck warn "Ada $ERR_COUNT galat sejak agent dijalankan"
            grep -E 'ERROR|CRITICAL' <<< "$NEW_LINES" | tail -4 | while IFS= read -r l; do
                dim "$l"
            done
        fi
    fi
fi

# =============================================================================
#  Penutup
# =============================================================================
echo
echo "=============================================================="
echo "   Selesai"
echo "=============================================================="
echo "   agent          : $AGENT_NAME"
echo "   manager       : $WAZUH_MANAGER"
echo "   group          : $WAZUH_GROUP"
echo "   Distribusi    : ${PRETTY_NAME:-$OS_FAMILY}"
if [ "$SKIP_AUDIT" != "1" ]; then
    LOADED_FINAL="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
    echo "   Aturan audit  : $LOADED_FINAL termuat"
fi
echo "   Sumber log    : $(grep -c '<location>' "$OSSEC_CONF" 2>/dev/null || echo '?') entri"
echo -n "   Layanan       : "
if systemctl is-active --quiet wazuh-agent; then echo -e "${G}berjalan${N}"; else echo -e "${R}tidak berjalan${N}"; fi
echo -n "   Terdaftar     : "
if [ "$REGISTERED" -eq 1 ]; then echo -e "${G}ya${N} ($AGENT_ID)"; else echo -e "${Y}belum${N}"; fi
echo -n "   Tersambung    : "
if [ "$CONNECTED" -eq 1 ]; then echo -e "${G}ya${N}"; else echo -e "${Y}belum${N}"; fi
if [ "$SKIP_VERIFY" != "1" ]; then
    echo -n "   Verifikasi    : "
    if [ "$V_FAIL" -eq 0 ]; then
        echo -e "${G}$V_PASS lolos${N}"
    else
        echo -e "${G}$V_PASS lolos${N}, ${R}$V_FAIL belum terbukti${N}"
    fi
fi
echo "   Berkas log    : $LOGFILE"

if [ "$WARN_COUNT" -gt 0 ]; then
    echo
    echo -e "   ${Y}$WARN_COUNT peringatan:${N}"
    for w in "${WARN_LIST[@]}"; do
        echo -e "     ${Y}-${N} $w"
    done
fi

echo
echo "   Langkah berikutnya:"
echo
echo "   Di mesin ini (agent):"
echo "     Status daemon      : $OSSEC_DIR/bin/wazuh-control status"
echo "     Konfigurasi aktif  : $OSSEC_DIR/bin/wazuh-control info"
echo "     Pantau log         : tail -f $OSSEC_LOG"
echo "     Aturan audit aktif : auditctl -l | grep -c audit-wazuh"
echo
echo "     Lihat pendaftaran  : cat $CLIENT_KEYS"
echo
echo "   Di server manager:"
echo "     Perkakas agent_control hanya terpasang di manager, tidak di"
echo "     mesin agent, jadi perintah berikut dijalankan di sana."
echo
echo "     Pastikan agent terdaftar :"
echo "       /var/ossec/bin/agent_control -l | grep -i '$AGENT_NAME'"
echo "     Lihat rincian agent :"
echo "       /var/ossec/bin/agent_control -i <id-agent>"

# Aturan auditd berlaku seketika lewat augenrules, jadi pemasangan tidak
# memerlukan mesin dinyalakan ulang. Satu satunya pengecualian adalah
# auditd yang dikunci dalam mode immutable.
if [ "$SKIP_AUDIT" != "1" ] && command -v auditctl >/dev/null 2>&1; then
    if auditctl -s 2>/dev/null | grep -qE '^enabled[[:space:]]+2'; then
        echo
        echo -e "   ${Y}auditd dikunci dalam mode immutable (-e 2).${N}"
        echo -e "   ${Y}Aturan audit yang baru ditulis belum aktif dan baru dimuat${N}"
        echo -e "   ${Y}setelah mesin dinyalakan ulang. Pemantauan lain sudah jalan.${N}"
    fi
fi

echo "=============================================================="

if [ "$CONNECTED" -ne 1 ]; then
    echo
    echo "agent belum tersambung. Periksa:"
    echo "  - group '$WAZUH_GROUP' sudah ada di manager?"
    echo "  - nama '$AGENT_NAME' bentrok dengan agent lain?"
    echo "  - port $WAZUH_REG_PORT dan $WAZUH_COMM_PORT terbuka dua arah?"
    echo
    echo "--- 25 baris terakhir $OSSEC_LOG ---"
    tail -25 "$OSSEC_LOG" 2>/dev/null || echo "(log tidak terbaca)"
    exit 2
fi

exit 0
