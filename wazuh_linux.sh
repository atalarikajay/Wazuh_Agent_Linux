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
#    WAZUH_MANAGER     IP atau hostname manajer (wajib bila tanpa interaksi)
#    WAZUH_GROUP       satu atau lebih grup, pisah koma (wajib bila tanpa interaksi)
#    AGENT_NAME        nama agen, bawaan hostname
#    WAZUH_PASSWORD    kata sandi pendaftaran, bila manajer memintanya
#    WAZUH_VERSION     versi paket, bawaan 4.9.2-1
#    WAZUH_REG_PORT    porta pendaftaran, bawaan 1515
#    WAZUH_COMM_PORT   porta pengiriman event, bawaan 1514
#    CONNECT_TIMEOUT   lama tunggu sambungan, bawaan 60 detik
#    SKIP_AUDIT        isi 1 untuk melewati pemasangan aturan auditd
#    SKIP_FIM          isi 1 untuk melewati aturan FIM tambahan
#    SKIP_VERIFY       isi 1 untuk melewati verifikasi akhir
#    RUN_TESTS         isi 1 untuk menjalankan uji deteksi jinak
#    ASSUME_YES        isi 1 untuk melewati semua konfirmasi
#
#  TIDAK PERLU REBOOT. Aturan auditd berlaku seketika lewat augenrules,
#  kecuali auditd dalam mode immutable (-e 2), dan script memberi tahu
#  bila itu terjadi.
# =============================================================================
set -euo pipefail

# ---------- parameter dasar ----------
WAZUH_VERSION="${WAZUH_VERSION:-4.9.2-1}"
WAZUH_REG_PORT="${WAZUH_REG_PORT:-1515}"
WAZUH_COMM_PORT="${WAZUH_COMM_PORT:-1514}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-60}"
SKIP_AUDIT="${SKIP_AUDIT:-0}"
SKIP_FIM="${SKIP_FIM:-0}"
SKIP_VERIFY="${SKIP_VERIFY:-0}"
RUN_TESTS="${RUN_TESTS:-0}"
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
STEP_TOTAL=11
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
# FQDN. Versi sebelumnya memaksa IP sehingga manajer di belakang DNS
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
        # Alamat ini tidak mungkin menjadi manajer.
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

# Nama agen Wazuh boleh memuat titik, strip, dan garis bawah. Versi
# sebelumnya membuang titik sehingga nama berbentuk FQDN menjadi rusak,
# misalnya srv-01.corp.local menjadi srv-01corplocal.
validate_agent_name() {
    local n="$1"
    [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$ ]] || return 1
    return 0
}

# Grup dipisah koma. Versi sebelumnya membuang koma lewat tr sehingga
# tiga grup menjadi satu nama grup yang tidak ada di manajer, dan
# pendaftaran gagal tanpa penjelasan.
clean_groups() {
    local raw="$1" out=() g
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
    local IFS2=','
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

    ok "Distribusi: ${PRETTY_NAME:-$id} (keluarga $OS_FAMILY, manajer paket $PKG)"
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
# Pembaruan agen sebaiknya direncanakan, bukan terjadi tanpa sengaja,
# karena versi agen perlu cocok dengan versi manajer.
pkg_hold() {
    case "$PKG" in
        apt)
            apt-mark hold wazuh-agent >/dev/null 2>&1 \
              && ok "Paket dikunci dengan apt-mark hold" \
              || warn "apt-mark hold gagal, paket bisa ikut terbarui tanpa sengaja."
            ;;
        dnf|yum)
            # Memakai versionlock, bukan exclude. Baris exclude di berkas
            # konfigurasi manajer paket membuat paket tidak bisa dipasang
            # ulang maupun diperbarui bahkan secara sengaja, dan itu
            # menyulitkan saat agen perlu dinaikkan versinya.
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
                dim "Agen bisa ikut terbarui saat '$PKG update'. Untuk mengunci:"
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

# --- alamat manajer
if [ -z "${WAZUH_MANAGER:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_MANAGER belum diisi dalam mode tanpa interaksi."
    echo
    dim "Alamat tujuan agen menyambung. Boleh IP maupun nama domain."
    dim "Contoh IP      : 10.184.0.7"
    dim "Contoh domain  : wazuh.corp.local"
    dim "Contoh domain  : soc-wazuh.perusahaan.co.id"
    dim "Jangan memakai awalan jaringan seperti 10.184.0.0/24,"
    dim "dan jangan menambahkan porta seperti 10.184.0.7:1514."
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk alamat manajer."
        ask "  IP atau domain Wazuh Manager: " WAZUH_MANAGER
        validate_host "$WAZUH_MANAGER" && break
        echo -e "${R}  '$WAZUH_MANAGER' bukan IP atau nama domain yang sah.${N}"
        case "$WAZUH_MANAGER" in
            */*) echo -e "${R}  Tanda garis miring tidak dipakai. Isi alamat saja, misalnya 10.184.0.7${N}" ;;
            *:*) echo -e "${R}  Porta tidak perlu ditulis. Isi alamat saja, misalnya 10.184.0.7${N}" ;;
        esac
    done
else
    validate_host "$WAZUH_MANAGER" \
      || die "WAZUH_MANAGER='$WAZUH_MANAGER' bukan IP atau nama domain yang sah. Contoh benar: 10.184.0.7 atau wazuh.corp.local"
fi

# --- grup
if [ -z "${WAZUH_GROUP:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_GROUP belum diisi dalam mode tanpa interaksi."
    echo
    dim "Grup menentukan berkas agent.conf mana yang diterima agen ini."
    dim "Grup harus SUDAH ADA di manajer, skrip ini tidak membuatnya."
    dim "Contoh satu grup   : default"
    dim "Contoh satu grup   : linux-server"
    dim "Contoh banyak grup : linux-server,web,produksi"
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk grup."
        ask "  Grup agen: " WAZUH_GROUP
        if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
            WAZUH_GROUP="$cleaned"
            break
        fi
        echo -e "${R}  Grup tidak sah. Hanya huruf, angka, titik, strip, garis bawah.${N}"
        echo -e "${R}  Pisahkan dengan koma bila lebih dari satu, misalnya: linux-server,web${N}"
    done
else
    if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
        WAZUH_GROUP="$cleaned"
    else
        die "WAZUH_GROUP='$WAZUH_GROUP' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, dipisah koma. Contoh benar: linux-server,web"
    fi
fi

# --- nama agen
if [ -z "${AGENT_NAME:-}" ]; then
    DEFAULT_NAME="$(hostname 2>/dev/null || echo "wazuh-agent")"
    if [ "$NONINTERACTIVE" = "1" ]; then
        AGENT_NAME="$DEFAULT_NAME"
    else
        echo
        dim "Nama yang muncul di dasbor manajer. Harus unik, tidak boleh"
        dim "sama dengan agen lain yang sudah terdaftar."
        dim "Contoh : srv-web-01"
        dim "Contoh : db-prod-02.corp.local"
        dim "Tekan Enter saja untuk memakai nama mesin ini: $DEFAULT_NAME"
        tries=0
        while true; do
            tries=$((tries + 1))
            [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk nama agen."
            ask "  Nama agen [$DEFAULT_NAME]: " AGENT_NAME
            AGENT_NAME="${AGENT_NAME:-$DEFAULT_NAME}"
            validate_agent_name "$AGENT_NAME" && break
            echo -e "${R}  '$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip,${N}"
            echo -e "${R}  garis bawah. Tanpa spasi. Panjang 2 sampai 128 karakter.${N}"
            AGENT_NAME=""
        done
    fi
fi
validate_agent_name "$AGENT_NAME" \
  || die "Nama agen '$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, 2 sampai 128 karakter. Contoh benar: srv-web-01"

echo
echo "  Ringkasan:"
echo "    Manajer       : $WAZUH_MANAGER"
echo "    Nama agen     : $AGENT_NAME"
echo "    Grup          : $WAZUH_GROUP"
echo "    Versi paket   : $WAZUH_VERSION"
# Baris di bawah hanya muncul bila memang menyimpang dari bawaan, supaya
# ringkasan tidak dipenuhi keterangan yang tidak memberi tahu apa apa.
# Bentuk if dipakai, bukan '[ ... ] && echo', karena bentuk kedua
# mengembalikan status 1 saat kondisi salah dan itu rapuh terhadap set -e.
if [ -n "${WAZUH_PASSWORD:-}" ]; then echo "    Kata sandi    : dipakai"; fi
if [ "$SKIP_AUDIT" = "1" ];      then echo "    Aturan audit  : DILEWATI"; fi
if [ "$SKIP_FIM" = "1" ];        then echo "    FIM tambahan  : DILEWATI"; fi
if [ "$SKIP_VERIFY" = "1" ];     then echo "    Verifikasi    : DILEWATI"; fi
if [ "$RUN_TESTS" = "1" ];       then echo "    Uji deteksi   : ya, artefak jinak dibuat lalu dihapus"; fi
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

# Porta wajib terbuka. Gagal di sini jauh lebih baik daripada pemasangan
# yang dilaporkan berhasil lalu agen diam diam tidak pernah terdaftar.
for p in "$WAZUH_COMM_PORT" "$WAZUH_REG_PORT"; do
    label="pengiriman event"
    [ "$p" = "$WAZUH_REG_PORT" ] && label="pendaftaran"
    if timeout 5 bash -c "echo > /dev/tcp/$WAZUH_MANAGER/$p" 2>/dev/null; then
        ok "Porta $p ($label) terbuka ke $WAZUH_MANAGER"
    else
        die "Porta $p ($label) TERTUTUP ke $WAZUH_MANAGER. Periksa firewall dan rute lebih dulu."
    fi
done

# Jam yang meleset membuat korelasi di manajer salah dan alert sulit
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

# Ruang disk. Agen menulis log dan basis data FIM, dan auditd bisa
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
# tanpa memeriksa keberadaan berkas itu. Bila folder agen pernah dihapus
# manual sementara paket masih tercatat di dpkg, pemanggilan tersebut
# berakhir dengan kode 127 dan dpkg menolak memproses paket. Akibatnya
# paket tidak bisa dicabut maupun dipasang ulang.
#
# Keadaan itu terlihat dari status dpkg seperti 'pi' atau 'iF', dan
# dibereskan di sini sebelum pemasangan dimulai.
if [ "$OS_FAMILY" = "debian" ]; then
    DPKG_ST="$(dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null || true)"
    case "$DPKG_ST" in
        ""|"unknown ok not-installed"|"purge ok not-installed")
            : ;;
        "install ok installed")
            : ;;  # terpasang wajar, ditangani blok berikutnya
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
# tetapi folder agen sudah tidak ada.
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

# Agen lama yang masih berjalan wajar. Pemasangan di atasnya menimpa
# konfigurasi dan kunci pendaftaran.
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    warn "wazuh-agent sudah berjalan. Konfigurasi akan dipasang ulang."
    if [ -s "$CLIENT_KEYS" ]; then
        OLD_ID="$(awk 'NR==1{print $1" "$2}' "$CLIENT_KEYS" 2>/dev/null || true)"
        [ -n "$OLD_ID" ] && dim "Terdaftar saat ini sebagai: $OLD_ID"
        dim "Pemasangan ulang membuat entri baru. Entri lama perlu dihapus dari dasbor."
    fi
    if [ "$NONINTERACTIVE" != "1" ]; then
        ask "  Tetap lanjutkan? (y/N): " GO
        case "${GO:-N}" in
            [Yy]*) : ;;
            *) echo "  Dibatalkan."; exit 0 ;;
        esac
    fi
else
    ok "Belum ada wazuh-agent yang berjalan"
fi

# SELinux dalam mode enforcing dapat menghalangi auditd dan agen.
if [ "$OS_FAMILY" = "rhel" ] && command -v getenforce >/dev/null 2>&1; then
    SEL="$(getenforce 2>/dev/null || echo Unknown)"
    case "$SEL" in
        Enforcing) warn "SELinux Enforcing. Bila agen gagal membaca log, periksa 'ausearch -m AVC -ts recent'." ;;
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
    pkg_install curl gnupg apt-transport-https ca-certificates

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
    pkg_install curl ca-certificates

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
# mengisi konfigurasi awal dan mendaftarkan agen.
INSTALL_ENV=(
    "WAZUH_MANAGER=$WAZUH_MANAGER"
    "WAZUH_AGENT_GROUP=$WAZUH_GROUP"
    "WAZUH_AGENT_NAME=$AGENT_NAME"
)
[ -n "${WAZUH_PASSWORD:-}" ] && INSTALL_ENV+=("WAZUH_REGISTRATION_PASSWORD=$WAZUH_PASSWORD")

# Keluaran manajer paket disimpan, bukan dibuang. Bila pemasangan gagal,
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
    echo -e "${R}       Keluaran manajer paket:${N}"
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
    dim "Ini terjadi bila agen pernah dipasang lalu dicabut tanpa purge."
    mv "${OSSEC_CONF}.new" "$OSSEC_CONF" \
      && ok "ossec.conf.new dipakai sebagai ossec.conf" \
      || die "Gagal memindahkan ${OSSEC_CONF}.new ke $OSSEC_CONF"
    chmod 0660 "$OSSEC_CONF" 2>/dev/null || true
    chown root:wazuh "$OSSEC_CONF" 2>/dev/null || true
fi

# Upaya terakhir: bangkitkan konfigurasi memakai skrip bawaan paket.
if [ ! -f "$OSSEC_CONF" ] && [ -x "$OSSEC_DIR/packages_files/agent_installation_scripts/gen_ossec.sh" ]; then
    dim "Mencoba membangkitkan ossec.conf dengan gen_ossec.sh bawaan paket"
    GEN="$OSSEC_DIR/packages_files/agent_installation_scripts/gen_ossec.sh"
    OSNAME="$(. /etc/os-release 2>/dev/null && echo "${ID:-debian}")"
    OSVER="$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}")"
    "$GEN" conf agent "$OSNAME" "$OSVER" "$OSSEC_DIR" > "$OSSEC_CONF" 2>/dev/null || true
    [ -s "$OSSEC_CONF" ] && ok "ossec.conf dibangkitkan ulang"
fi

if [ ! -f "$OSSEC_CONF" ]; then
    echo
    die "$(cat <<MSG
Paket terpasang tetapi $OSSEC_CONF tidak ada.

        Penyebab paling umum: agen pernah dipasang lalu dicabut tanpa purge,
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

# Berkas tanda tangan rootkit disalin keluar dari etc/shared sebelum agen
# berjalan. Direktori itu dikelola manajer: begitu konfigurasi grup
# dikirim, seluruh isinya diganti dan berkas bawaan paket terhapus.
# Akibatnya rootcheck mencatat 'No rootcheck_files file' pada setiap
# pemindaian dan pemeriksaan tanda tangan rootkit tidak pernah berjalan.
#
# Salinan disimpan di etc/ yang tidak disentuh manajer, lalu konfigurasi
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
    dim "Basis tanda tangan rootkit disalin ke etc/ agar tidak tertimpa manajer"
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
    # grup yang salah dan agen mencatat aktivitasnya sendiri tanpa henti.
    GID_WAZUH="$(getent group wazuh | cut -d: -f3)"
    [ -n "$GID_WAZUH" ] || die "Grup 'wazuh' tidak ada setelah pemasangan paket."
    dim "GID grup wazuh: $GID_WAZUH"

    # Berkas ditulis penuh setiap kali, sehingga menjalankan skrip dua kali
    # tidak menghasilkan aturan ganda.
    #
    # Dua penyaring penting pada aturan syscall:
    #   auid>=1000              semua pengguna interaktif, bukan hanya uid 1000
    #   auid!=4294967295        kecualikan proses daemon yang tidak punya auid
    #   egid!=$GID_WAZUH        cegah agen mencatat dirinya sendiri
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
    # padat seperti peladen web atau basis data.
    cat >> "$AUDIT_RULES" <<EOF

## ---------- Koneksi keluar ----------
## Berguna untuk mendeteksi komando kendali dan penyelundupan data.
## Volumenya paling tinggi di antara semua aturan di berkas ini. Bila
## beban terlalu besar di peladen tertentu, beri tanda pagar pada dua
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

    RULE_COUNT="$(grep -cE '^-[aw]' "$AUDIT_RULES" || true)"
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
    # sehingga event lama terhapus sebelum agen mengirimkannya.
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

# Diperlukan karena konfigurasi grup memakai <command> dan <full_command>.
add_opt "logcollector.remote_commands"  "1"
add_opt "wazuh_command.remote_commands" "1"
# Jumlah berkas yang boleh dipantau FIM secara serentak. Bawaan terlalu
# kecil begitu pohon direktori besar dipantau, dan kelebihannya dilewati
# tanpa pesan kesalahan.
add_opt "syscheck.max_fd" "512"
# Batas laju pembacaan log. Dinaikkan agar lonjakan audit tidak membuat
# agen tertinggal membaca audit.log.
add_opt "logcollector.max_lines" "10000"

chown root:wazuh "$LOCAL_OPT" 2>/dev/null || true
chmod 0640 "$LOCAL_OPT"
ok "local_internal_options.conf diperbarui, isi lama dipertahankan"

# =============================================================================
#  Langkah 7: blok konfigurasi ossec.conf
# =============================================================================
step "Menyisipkan blok konfigurasi ke ossec.conf"

cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"
dim "Cadangan: ${OSSEC_CONF}.bak.*"

# Sumber log berbeda antar distribusi dan antar pemasangan. Bagian ini
# menyusun daftar berkas log yang benar benar ada, sehingga tidak ada
# entri yang menunjuk berkas kosong.
LOGFILES_BLOCK=""
add_logfile() {
    local path="$1" fmt="${2:-syslog}"
    if [ -e "$path" ]; then
        LOGFILES_BLOCK+="  <localfile>
    <log_format>$fmt</log_format>
    <location>$path</location>
  </localfile>
"
        dim "sumber log: $path"
    fi
}

case "$OS_FAMILY" in
  debian)
    add_logfile /var/log/auth.log
    add_logfile /var/log/syslog
    add_logfile /var/log/kern.log
    add_logfile /var/log/dpkg.log
    add_logfile /var/log/apt/history.log
    ;;
  rhel)
    add_logfile /var/log/secure
    add_logfile /var/log/messages
    add_logfile /var/log/dnf.log
    add_logfile /var/log/yum.log
    add_logfile /var/log/audit/audit.log audit
    ;;
esac

# Audit log ditambahkan untuk keluarga debian secara terpisah agar tidak
# tertambah dua kali pada keluarga rhel.
if [ "$OS_FAMILY" = "debian" ]; then
    add_logfile /var/log/audit/audit.log audit
fi

# Log peladen web bila ada. Sumber utama deteksi eksploitasi aplikasi.
add_logfile /var/log/nginx/access.log
add_logfile /var/log/nginx/error.log
add_logfile /var/log/apache2/access.log
add_logfile /var/log/apache2/error.log
add_logfile /var/log/httpd/access_log
add_logfile /var/log/httpd/error_log

# Log basis data bila ada.
add_logfile /var/log/mysql/error.log
add_logfile /var/log/postgresql/postgresql-main.log

# rsyslog sering tidak terpasang pada citra awan dan pemasangan minimal.
# Akibatnya /var/log/auth.log tidak pernah terbentuk dan masuk SSH serta
# pemakaian sudo tidak terpantau, tanpa pesan kesalahan apa pun.
JOURNALD_BLOCK=""
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    ok "rsyslog aktif"
else
    warn "rsyslog tidak aktif. journald dipakai sebagai sumber log pengganti."
    JOURNALD_BLOCK="  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
"
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
    <directories realtime="yes" check_all="yes">/etc/systemd/system,/lib/systemd/system,/usr/lib/systemd/system</directories>
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

    <!-- Berkas yang berubah terus menerus. Tanpa pengecualian ini,
         peringatan FIM membanjiri dasbor dan menutupi yang penting. -->
    <ignore type="sregex">\.log$|\.swp$|\.tmp$|\.lock$|\.pid$|\.sock$</ignore>
    <ignore>/tmp/systemd-private</ignore>
    <ignore>/var/tmp/systemd-private</ignore>
    <ignore type="sregex">^/tmp/\.X11-unix</ignore>
    <ignore type="sregex">^/tmp/\.ICE-unix</ignore>
    <ignore>/var/ossec</ignore>
  </syscheck>
FIMEOF
)
fi

BLOCK=$(cat <<EOF
$MARK_BEGIN
  <!-- Penyangga kiriman. Bawaan 5000 dengan 500 event per detik terlalu
       kecil begitu aturan execve auditd aktif. Penyangga penuh berarti
       event dibuang tanpa peringatan, hanya satu baris di ossec.log. -->
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>100000</queue_size>
    <events_per_second>1000</events_per_second>
  </client_buffer>

$LOGFILES_BLOCK$JOURNALD_BLOCK
$FIM_BLOCK

  <!-- Inventaris sistem. Dasar bagi deteksi kerentanan di manajer.
       Tanpa syscollector, pencocokan CVE tidak punya data paket. -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- Penilaian konfigurasi keamanan. Menjalankan tolok ukur CIS yang
       sesuai dengan distribusi secara otomatis. -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- Pemeriksaan rootkit tidak ditulis ulang di sini.
       Konfigurasi bawaan paket sudah memuat blok <rootcheck> lengkap
       dengan seluruh pemeriksaan aktif. Menambahkan blok kedua membuat
       setiap pesan rootcheck muncul dua kali, termasuk pesan galat,
       sehingga sulit membedakan satu masalah dari dua masalah. -->

  <!-- Tanggapan aktif. Diperlukan agar manajer dapat menjalankan
       tindakan seperti memblokir alamat yang menyerang. -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>$OSSEC_DIR/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Perintah berkala untuk hal yang tidak tertangkap audit maupun FIM.
       Memerlukan logcollector.remote_commands yang sudah diaktifkan. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <alias>last-logins</alias>
    <frequency>600</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>awk -F: '\$3 == 0 {print \$1}' /etc/passwd</command>
    <alias>uid-zero-accounts</alias>
    <frequency>3600</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null</command>
    <alias>listening-ports</alias>
    <frequency>1800</frequency>
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
       memakan waktu lama dan membebani cakram pada peladen dengan
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

# Blok <rootcheck> bawaan menunjuk ke etc/shared, direktori yang isinya
# diganti manajer. Rujukannya dialihkan ke salinan di etc/ yang dibuat
# pada langkah pemasangan paket, sehingga pemeriksaan tanda tangan
# rootkit tetap berjalan setelah konfigurasi grup diterima.
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
            LAST_BAK="$(ls -1t "${OSSEC_CONF}".bak.* 2>/dev/null | head -1 || true)"
            [ -n "$LAST_BAK" ] && cp -a "$LAST_BAK" "$OSSEC_CONF" 2>/dev/null || true
        fi
    fi
fi

# =============================================================================
#  Langkah 8: menjalankan agen
# =============================================================================
step "Menjalankan wazuh-agent"

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
#  Langkah 9: menunggu sambungan ke manajer
# =============================================================================
step "Menunggu pendaftaran dan sambungan ke manajer"

# Pemeriksaan ini yang menentukan. Agen bisa berstatus aktif tetapi tidak
# pernah tersambung karena alamat salah, porta diblokir, nama bentrok,
# atau grup tidak ada di manajer.
info "Batas waktu ${CONNECT_TIMEOUT} detik"
CONNECTED=0
FAIL_REASON=""
for _ in $(seq 1 "$CONNECT_TIMEOUT"); do
    if grep -q "Connected to the server" "$OSSEC_LOG" 2>/dev/null; then
        CONNECTED=1
        break
    fi
    if grep -qE "Unable to connect|Invalid server address|Authentication error|Duplicate agent name|Unable to add agent" "$OSSEC_LOG" 2>/dev/null; then
        FAIL_REASON="$(grep -hoE "Unable to connect.*|Invalid server address.*|Authentication error.*|Duplicate agent name.*|Unable to add agent.*" "$OSSEC_LOG" 2>/dev/null | tail -1)"
        break
    fi
    sleep 1
done

REGISTERED=0
AGENT_ID=""
if [ -s "$CLIENT_KEYS" ]; then
    REGISTERED=1
    AGENT_ID="$(awk 'NR==1{print $1" ("$2")"}' "$CLIENT_KEYS" 2>/dev/null || true)"
    ok "Terdaftar ke manajer: ID $AGENT_ID"
else
    warn "client.keys masih kosong, agen belum terdaftar."
    dim "Penyebab umum: porta 1515 tertutup, kata sandi pendaftaran salah,"
    dim "atau nama agen sudah dipakai agen lain di manajer."
fi

if [ "$CONNECTED" -eq 1 ]; then
    ok "Agen tersambung ke manajer $WAZUH_MANAGER"
elif [ -n "$FAIL_REASON" ]; then
    warn "Gagal tersambung: $FAIL_REASON"
else
    warn "Belum ada pesan sambungan dalam ${CONNECT_TIMEOUT} detik."
fi

# =============================================================================
#  Langkah 10: verifikasi pemantauan
# =============================================================================
step "Verifikasi pemantauan"

# Agen merestart dirinya sendiri setelah menerima konfigurasi grup dari
# manajer, karena ossec.conf bawaan memuat <auto_restart>yes</auto_restart>.
# Verifikasi yang berjalan tepat pada saat itu akan melihat daemon sedang
# mati dan melaporkannya sebagai kegagalan, padahal agen sehat.
#
# Bagian ini menunggu sampai daftar daemon stabil: tidak ada lagi yang
# berstatus 'not running' selama beberapa pemeriksaan berturut turut.
if [ "$SKIP_VERIFY" != "1" ] && [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    info "Menunggu daemon agen stabil"
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
        ok "Daemon agen stabil"
    else
        dim "Daemon masih berubah status, verifikasi tetap dilanjutkan"
    fi
fi

V_PASS=0
V_FAIL=0
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
    if grep -qE "^logcollector.remote_commands=1" "$LOCAL_OPT" 2>/dev/null; then
        vcheck pass "remote_commands aktif"
    else
        vcheck fail "remote_commands aktif" "perintah berkala tidak akan jalan"
    fi

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
    for mod in syscheck sca rootcheck active-response client_buffer; do
        if grep -q "<$mod" "$OSSEC_CONF" 2>/dev/null; then
            vcheck pass "Modul $mod terdaftar"
        else
            vcheck fail "Modul $mod terdaftar" "tidak ada di ossec.conf"
        fi
    done
    for wodle in syscollector; do
        if grep -qE "<wodle[[:space:]]+name=\"$wodle\"" "$OSSEC_CONF" 2>/dev/null; then
            vcheck pass "Modul $wodle terdaftar"
        else
            vcheck fail "Modul $wodle terdaftar" "tidak ada di ossec.conf"
        fi
    done

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
    SRC_COUNT="$(grep -c '<location>' "$OSSEC_CONF" 2>/dev/null || true)"
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
                    | sed 's/^.*sca: INFO: //' | sort -u | wc -l || true)"
        SCA_DONE="$(grep -c 'Security Configuration Assessment scan finished' "$OSSEC_LOG" 2>/dev/null || true)"
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
            dim "Periksa kebijakan yang tersedia di manajer: /var/ossec/etc/shared/<grup>/"
        elif [ "$SCA_POLICIES" -gt 0 ]; then
            vcheck pass "Kebijakan SCA tersedia" "$SCA_POLICIES berkas"
        else
            vcheck warn "Kebijakan SCA tersedia" "belum ada, biasanya dikirim manajer lewat grup"
        fi
    fi

    # --- proses agen yang seharusnya hidup
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

    # --- galat di log agen
    if [ -f "$OSSEC_LOG" ]; then
        ERR_COUNT="$(tail -200 "$OSSEC_LOG" 2>/dev/null | grep -cE 'ERROR|CRITICAL' || true)"
        if [ "$ERR_COUNT" -eq 0 ]; then
            vcheck pass "Tidak ada galat di ossec.log"
        else
            vcheck warn "Ada $ERR_COUNT galat di 200 baris terakhir ossec.log"
            tail -200 "$OSSEC_LOG" | grep -E 'ERROR|CRITICAL' | tail -4 | while IFS= read -r l; do
                dim "$l"
            done
        fi
    fi
fi

# =============================================================================
#  Langkah 11: uji deteksi jinak
# =============================================================================
step "Uji deteksi"

if [ "$RUN_TESTS" != "1" ]; then
    dim "Dilewati. Isi RUN_TESTS=1 untuk menjalankan uji deteksi jinak."
    dim "Uji membuat lalu menghapus: satu berkas di /tmp, satu tugas cron,"
    dim "dan menjalankan satu perintah yang seharusnya tercatat audit."
else
    TEST_TAG="zz-verifytest-$(date +%s)"
    TEST_FILE="/tmp/${TEST_TAG}.sh"
    TEST_CRON="/etc/cron.d/${TEST_TAG}"
    TEST_START="$(date '+%m/%d/%Y %H:%M:%S')"
    declare -a MADE=()

    info "Penanda uji: $TEST_TAG"

    # Berkas di /tmp. Memicu FIM realtime.
    if echo '#!/bin/bash' > "$TEST_FILE" 2>/dev/null; then
        chmod +x "$TEST_FILE"
        MADE+=("file")
        dim "berkas uji dibuat: $TEST_FILE"
    fi

    # Tugas cron. Memicu FIM pada /etc/cron.d.
    # Dijadwalkan pada tanggal 31 Februari yang tidak pernah ada, jadi
    # tidak akan pernah benar benar dijalankan.
    if printf '# %s\n' "$TEST_TAG" > "$TEST_CRON" 2>/dev/null; then
        MADE+=("cron")
        dim "tugas cron uji dibuat: $TEST_CRON"
    fi

    # Perintah yang seharusnya tercatat aturan execve audit.
    /usr/bin/id > /dev/null 2>&1 || true
    dim "perintah uji dijalankan"

    info "Menunggu 15 detik supaya event tercatat"
    sleep 15
    echo

    # --- Periksa audit mencatat eksekusi
    if [ "$SKIP_AUDIT" != "1" ] && command -v ausearch >/dev/null 2>&1; then
        if ausearch -k audit-wazuh-c -ts recent 2>/dev/null | grep -q 'type=EXECVE'; then
            vcheck pass "Audit mencatat eksekusi perintah" "kunci audit-wazuh-c"
        else
            vcheck fail "Audit mencatat eksekusi perintah" "tidak ada event EXECVE terbaru"
        fi
    fi

    # --- Periksa FIM mencatat berkas baru
    if [ "$SKIP_FIM" != "1" ]; then
        if grep -q "$TEST_TAG" "$OSSEC_LOG" 2>/dev/null; then
            vcheck pass "Agen mencatat artefak uji" "penanda ditemukan di ossec.log"
        else
            vcheck warn "Agen mencatat artefak uji" "penanda belum muncul, FIM realtime bisa butuh waktu lebih"
        fi
    fi

    # --- Bersihkan
    echo
    info "Membersihkan artefak uji"
    for m in "${MADE[@]:-}"; do
        case "$m" in
            file) rm -f "$TEST_FILE" && dim "berkas uji dihapus" ;;
            cron) rm -f "$TEST_CRON" && dim "tugas cron uji dihapus" ;;
        esac
    done

    LEFT=()
    [ -e "$TEST_FILE" ] && LEFT+=("$TEST_FILE")
    [ -e "$TEST_CRON" ] && LEFT+=("$TEST_CRON")
    if [ "${#LEFT[@]}" -eq 0 ]; then
        vcheck pass "Pembersihan artefak uji" "semua bersih"
    else
        vcheck fail "Pembersihan artefak uji" "sisa: ${LEFT[*]}"
    fi
fi

# =============================================================================
#  Penutup
# =============================================================================
echo
echo "=============================================================="
echo "   Selesai"
echo "=============================================================="
echo "   Agen          : $AGENT_NAME"
echo "   Manajer       : $WAZUH_MANAGER"
echo "   Grup          : $WAZUH_GROUP"
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
echo "   Di mesin ini (agen):"
echo "     Status daemon      : $OSSEC_DIR/bin/wazuh-control status"
echo "     Konfigurasi aktif  : $OSSEC_DIR/bin/wazuh-control info"
echo "     Pantau log         : tail -f $OSSEC_LOG"
echo "     Aturan audit aktif : auditctl -l | grep -c audit-wazuh"
echo
echo "   Di peladen manajer, bukan di sini:"
echo "     Pastikan agen terdaftar :"
echo "       /var/ossec/bin/agent_control -l | grep -i '$AGENT_NAME'"
echo "     Lihat rincian agen :"
echo "       /var/ossec/bin/agent_control -i \$(/var/ossec/bin/agent_control -l | grep -i '$AGENT_NAME' | awk '{print \$2}' | tr -d ',')"
echo
echo "   Di dasbor:"
echo "     Pastikan alert dari '$AGENT_NAME' masuk ke indeks wazuh-alerts-*"
echo "     Tanpa ini, agen terlihat tersambung tetapi datanya tidak terpakai."
if [ "$RUN_TESTS" = "1" ]; then
    echo "     Cari penanda '$TEST_TAG' di dasbor sebagai bukti rantai penuh bekerja."
fi

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
    echo "Agen belum tersambung. Periksa:"
    echo "  - grup '$WAZUH_GROUP' sudah ada di manajer?"
    echo "  - nama '$AGENT_NAME' bentrok dengan agen lain?"
    echo "  - porta $WAZUH_REG_PORT dan $WAZUH_COMM_PORT terbuka dua arah?"
    echo
    echo "--- 25 baris terakhir $OSSEC_LOG ---"
    tail -25 "$OSSEC_LOG" 2>/dev/null || echo "(log tidak terbaca)"
    exit 2
fi

exit 0
