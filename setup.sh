#!/usr/bin/env bash
# =============================================================================
# OpenVPN + Cloudflare WARP (via WireGuard) Setup
# =============================================================================
#
# "Because sometimes you just want your packets to take the scenic route
#  through Cloudflare's global network before reaching their destination."
#
# Supported Distros:
#   Ubuntu 20.04+, Debian 10+, Fedora 38+, CentOS 8+, Rocky 8+,
#   AlmaLinux 8+, openSUSE Leap 15+, Arch Linux
#   (Yes, even Arch. We use btw.)
#
# The Grand Architecture:
#   Client ──► OpenVPN (TCP/443 or UDP/8443) ──► WireGuard (WARP) ──► Internet
#
#   It's like a VPN turducken: OpenVPN wrapped in WireGuard,
# 
#   Default route stays untouched → SSH lives another day
#
# Usage:
#   ./setup.sh [OPTIONS]
#
# Options:
#   --tcp-port PORT    OpenVPN TCP port (default: 443, the "hide in HTTPS" classic, More DPI resistanant)
#   --udp-port PORT    OpenVPN UDP port (default: 8443, for speed)
#   --ca-name NAME     Certificate Authority CN (default: random 32-char)
#   --no-warp          Skip WARP (for when you trust your ISP)
#   --help             Show this help and exit gracefully
#
# =============================================================================

set -euo pipefail

# ========================= DEFAULT CONFIGURATION ============================
# The sensible defaults. Override with CLI args if you're feeling adventurous.

SERVER_IP=""      # Auto-detected (we ask the internet who we are)
SERVER_IFACE=""   # Auto-detected (the one with the default route)

# Port Config — 443 blends with HTTPS, 8443 is for UDP
OVPN_TCP_PORT=443
OVPN_UDP_PORT=8443

# CA Name — random by default things like "OpenVPN-CA" screams "I'm a VPN! or better to say DPI will kill it" 
CA_NAME=""

# WARP toggle — set false if you enjoy seeing your real IP in logs
INSTALL_WARP=true

# OS Detection — filled in by detect_os()
OS_ID=""
OS_VERSION=""
OS_FAMILY=""
PKG_MANAGER=""
OVPN_GROUP=""   # 'nogroup' on Debian, 'nobody' elsewhere (fun inconsistency!)

TCP_SUBNET="10.8.0.0"
TCP_MASK="255.255.255.0"
UDP_SUBNET="10.9.0.0"
UDP_MASK="255.255.255.0"

OVPN_DIR="/etc/openvpn"
SERVER_DIR="${OVPN_DIR}/server"
EASYRSA_DIR="${OVPN_DIR}/easy-rsa"
LOG_DIR="/var/log/openvpn"
CLIENT_DIR="${OVPN_DIR}/client-configs"
CREDS_FILE="${SERVER_DIR}/credentials"

WARP_DIR="/etc/wireguard"
WARP_IFACE="wg-warp"
WARP_TABLE=42

# ========================= LOGGING ==========================================
# We are not monochrome.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }  
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }   
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }  
err()     { echo -e "${RED}[ERR ]${NC}  $*"; }   
die()     { err "$*"; exit 1; }                    
section() { echo -e "\n${CYAN}${BOLD}━━━ $* ━━━${NC}\n"; }

# ========================= USAGE ============================================
show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

OpenVPN + Cloudflare WARP (via WireGuard) Setup

Options:
  --tcp-port PORT    OpenVPN TCP port (default: 443)
  --udp-port PORT    OpenVPN UDP port (default: 8443)
  --ca-name NAME     Certificate Authority CN (default: random 32-char + "-CA")
  --no-warp          Skip Cloudflare WARP installation (direct routing)
  --help             Show this help and exit

Supported Distributions:
  Ubuntu 20.04+, Debian 10+, Fedora 38+, CentOS 8+, Rocky 8+,
  AlmaLinux 8+, openSUSE Leap 15+, Arch Linux

Examples:
  $0                                  # Default: TCP/443, UDP/8443, with WARP
  $0 --tcp-port 1194 --udp-port 1195  # Custom ports
  $0 --ca-name "MyCompany-CA"         # Custom CA name
  $0 --no-warp                        # Without Cloudflare WARP
  $0 --tcp-port 443 --ca-name "Corp-CA" --no-warp

EOF
    exit 0
}

# ========================= ARGUMENT PARSING =================================

# ─────────────────────────────────────────────────────────────────────────────
# parse_arguments()
# Processes CLI arguments with the enthusiasm of a bouncer checking IDs.
# Validates ports (1-65535), CA names (alphanum + some symbols), and ensures
# you're not trying to use the same port for TCP and UDP (we've all tried).
# Sets global vars: OVPN_TCP_PORT, OVPN_UDP_PORT, CA_NAME, INSTALL_WARP
# ─────────────────────────────────────────────────────────────────────────────
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tcp-port)
                if [[ -z "${2:-}" || "$2" =~ ^-- ]]; then
                    die "--tcp-port requires a port number"
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]] || [[ "$2" -lt 1 || "$2" -gt 65535 ]]; then
                    die "Invalid TCP port: $2 (must be 1-65535)"
                fi
                OVPN_TCP_PORT="$2"
                shift 2
                ;;
            --udp-port)
                if [[ -z "${2:-}" || "$2" =~ ^-- ]]; then
                    die "--udp-port requires a port number"
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]] || [[ "$2" -lt 1 || "$2" -gt 65535 ]]; then
                    die "Invalid UDP port: $2 (must be 1-65535)"
                fi
                OVPN_UDP_PORT="$2"
                shift 2
                ;;
            --ca-name)
                if [[ -z "${2:-}" || "$2" =~ ^-- ]]; then
                    die "--ca-name requires a name"
                fi
                # Validate CA name (alphanumeric, dash, underscore, max 64 chars)
                if ! [[ "$2" =~ ^[a-zA-Z0-9._-]{1,64}$ ]]; then
                    die "Invalid CA name: $2 (use a-z, 0-9, '.', '_', '-', max 64 chars)"
                fi
                CA_NAME="$2"
                shift 2
                ;;
            --no-warp)
                INSTALL_WARP=false
                shift
                ;;
            --help|-h)
                show_usage
                ;;
            *)
                die "Unknown option: $1 (use --help for usage)"
                ;;
        esac
    done

    # Validate ports are different
    if [[ "$OVPN_TCP_PORT" -eq "$OVPN_UDP_PORT" ]]; then
        die "TCP and UDP ports must be different"
    fi

    # Generate random CA name if not specified
    if [[ -z "$CA_NAME" ]]; then
        CA_NAME="$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32)-CA"
    fi
}

# ========================= OS DETECTION =====================================

# ─────────────────────────────────────────────────────────────────────────────
# detect_os()
# Figures out what flavor of Linux you are using
# /etc/os-release. Sets OS_ID, OS_VERSION, OS_FAMILY, PKG_MANAGER, OVPN_GROUP.
# life's too short for distro wars, yet I will always use Fedora with <3.
# (Except Gentoo. You're on your own, compile it.)
# ─────────────────────────────────────────────────────────────────────────────
detect_os() {
    section "Detecting Operating System"

    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS: /etc/os-release not found"
    fi

    source /etc/os-release

    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"

    case "$OS_ID" in
        ubuntu)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            OVPN_GROUP="nogroup"
            if [[ "${OS_VERSION%%.*}" -lt 20 ]]; then
                die "Ubuntu $OS_VERSION not supported. Requires 20.04+"
            fi
            ;;
        debian)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            OVPN_GROUP="nogroup"
            if [[ "${OS_VERSION%%.*}" -lt 10 ]]; then
                die "Debian $OS_VERSION not supported. Requires 10+"
            fi
            ;;
        fedora)
            OS_FAMILY="rhel"
            PKG_MANAGER="dnf"
            OVPN_GROUP="nobody"
            if [[ "${OS_VERSION%%.*}" -lt 38 ]]; then
                die "Fedora $OS_VERSION not supported. Requires 38+"
            fi
            ;;
        centos|rhel)
            OS_FAMILY="rhel"
            PKG_MANAGER="dnf"
            OVPN_GROUP="nobody"
            if [[ "${OS_VERSION%%.*}" -lt 8 ]]; then
                die "CentOS/RHEL $OS_VERSION not supported. Requires 8+"
            fi
            ;;
        rocky|almalinux)
            OS_FAMILY="rhel"
            PKG_MANAGER="dnf"
            OVPN_GROUP="nobody"
            if [[ "${OS_VERSION%%.*}" -lt 8 ]]; then
                die "$OS_ID $OS_VERSION not supported. Requires 8+"
            fi
            ;;
        opensuse-leap|opensuse-tumbleweed|sles)
            OS_FAMILY="suse"
            PKG_MANAGER="zypper"
            OVPN_GROUP="nobody"
            ;;
        arch|manjaro)
            OS_FAMILY="arch"
            PKG_MANAGER="pacman"
            OVPN_GROUP="nobody"
            ;;
        *)
            die "Unsupported distribution: $OS_ID. Supported: Ubuntu, Debian, Fedora, CentOS, Rocky, AlmaLinux, openSUSE, Arch"
            ;;
    esac

    ok "Detected: $OS_ID $OS_VERSION (family: $OS_FAMILY, pkg: $PKG_MANAGER)"
}

# ========================= PREREQUISITES ====================================

# ─────────────────────────────────────────────────────────────────────────────
# check_prerequisites()
# Ensures we're running as root,
# detects the server's public IP (by asking three different services because
# trust issues), finds the network interface, and saves the original gateway
# so we don't accidentally lock ourselves out and blow the SSH up. That would be embarrassing. 
# ─────────────────────────────────────────────────────────────────────────────
check_prerequisites() {
    section "Checking Prerequisites"

    [[ $EUID -ne 0 ]] && die "Run as root: sudo $0"
    ok "Running as root"

    # Detect public IP
    if [[ -z "$SERVER_IP" ]]; then
        info "Detecting public IP..."
        SERVER_IP=$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null) ||
        SERVER_IP=$(curl -4 -s --max-time 10 icanhazip.com 2>/dev/null) ||
        SERVER_IP=$(curl -4 -s --max-time 10 api.ipify.org 2>/dev/null) ||
        die "Failed to detect public IP."
        ok "Public IP: $SERVER_IP"
    fi

    # Detect interface
    if [[ -z "$SERVER_IFACE" ]]; then
        SERVER_IFACE=$(ip -4 route show default | head -1 | awk '{print $5}')
        [[ -z "$SERVER_IFACE" ]] && die "Cannot detect network interface."
        ok "Network interface: $SERVER_IFACE"
    fi

    # Save original gateway
    local orig_gw orig_dev
    orig_gw=$(ip -4 route show default | head -1 | awk '{print $3}')
    orig_dev=$(ip -4 route show default | head -1 | awk '{print $5}')
    [[ -z "$orig_gw" ]] && die "Cannot determine default gateway."

    mkdir -p "$SERVER_DIR"
    cat > "${SERVER_DIR}/orig-route.env" <<EOF
ORIG_GW=${orig_gw}
ORIG_DEV=${orig_dev}
SERVER_IP=${SERVER_IP}
EOF
    ok "Original gateway: $orig_gw via $orig_dev"
}

# ========================= SAVE CONFIGURATION ===============================

# ─────────────────────────────────────────────────────────────────────────────
# save_setup_config()
# Persists our configuration to setup.env so manage-users.sh and future-you
# know what ports, CA name, and WARP status we used. Because memory is
# ─────────────────────────────────────────────────────────────────────────────
save_setup_config() {
    section "Saving Setup Configuration"

    cat > "${SERVER_DIR}/setup.env" <<EOF
# OpenVPN + WARP Setup Configuration
# Generated: $(date -Iseconds)
# OS: ${OS_ID} ${OS_VERSION}

# Server
SERVER_IP="${SERVER_IP}"
SERVER_IFACE="${SERVER_IFACE}"

# OpenVPN Ports
OVPN_TCP_PORT=${OVPN_TCP_PORT}
OVPN_UDP_PORT=${OVPN_UDP_PORT}

# VPN Subnets
TCP_SUBNET="${TCP_SUBNET}"
UDP_SUBNET="${UDP_SUBNET}"

# Certificate Authority
CA_NAME="${CA_NAME}"

# WARP Status
INSTALL_WARP=${INSTALL_WARP}

# OS Detection
OS_ID="${OS_ID}"
OS_FAMILY="${OS_FAMILY}"
PKG_MANAGER="${PKG_MANAGER}"
OVPN_GROUP="${OVPN_GROUP}"
EOF

    chmod 600 "${SERVER_DIR}/setup.env"
    ok "Configuration saved to ${SERVER_DIR}/setup.env"
}

# ========================= INSTALL PACKAGES =================================

# ─────────────────────────────────────────────────────────────────────────────
# install_packages()
# The dispatcher that calls the right package installer for your distro.
# Each sub-function handles the quirks of apt/dnf/zypper/pacman because
# apparently the Linux community couldn't agree on ONE package manager.
# ─────────────────────────────────────────────────────────────────────────────
install_packages() {
    section "Installing Packages"

    case "$PKG_MANAGER" in
        apt)    install_packages_apt    ;;
        dnf)    install_packages_dnf    ;;
        zypper) install_packages_zypper ;;
        pacman) install_packages_pacman ;;
        *)      die "Unknown package manager: $PKG_MANAGER" ;;
    esac

    local ovpn_ver
    ovpn_ver=$(openvpn --version | head -1 | awk '{print $2}')
    info "OpenVPN: $ovpn_ver"
    info "WireGuard: $(wg --version 2>/dev/null || echo 'kernel module')"
}

# Debian/Ubuntu
install_packages_apt() {
    export DEBIAN_FRONTEND=noninteractive  # Shush, dpkg. No questions.

    info "Updating packages (apt)..."
    apt-get update -qq

    info "Installing the good stuff..."
    apt-get install -y -qq \
        openvpn easy-rsa wireguard wireguard-tools \
        iptables iptables-persistent \
        curl gnupg lsb-release net-tools jq dnsutils \
        > /dev/null

    ok "All packages installed (apt)"
}

# RHEL family: Fedora, CentOS, Rocky, Alma — the enterprise crowd (with love <3)
install_packages_dnf() {
    info "Updating packages (dnf)..."
    dnf check-update -q || true  # Returns 100 if updates available, not an error

    if [[ "$OS_ID" =~ ^(centos|rhel|rocky|almalinux)$ ]]; then
        info "Installing EPEL (Extra Packages for Enterprise Linux, not a sword)..."
        dnf install -y -q epel-release || true
    fi

    info "Installing the good stuff..."
    dnf install -y -q \
        openvpn easy-rsa wireguard-tools \
        iptables iptables-services \
        curl gnupg2 net-tools jq bind-utils

    ok "All packages installed (dnf)"
}

# openSUSE
install_packages_zypper() {
    info "Refreshing repositories (zypper)..."
    zypper --non-interactive refresh

    info "Installing the good stuff..."
    zypper --non-interactive install -y \
        openvpn easy-rsa wireguard-tools \
        iptables curl net-tools jq bind-utils

    ok "All packages installed (zypper)"
}

# Arch
install_packages_pacman() {
    info "Syncing packages (pacman)..."
    pacman -Sy --noconfirm

    info "Installing the good stuff..."
    pacman -S --noconfirm --needed \
        openvpn easy-rsa wireguard-tools \
        iptables curl net-tools jq bind

    ok "All packages installed (pacman)"
}

# ========================= PKI ==============================================

# ─────────────────────────────────────────────────────────────────────────────
# setup_pki()
# Creates the Public Key Infrastructure using EasyRSA. This is where we become
# our own Certificate Authority — basically a trust factory. Uses ECDSA P-384
# because RSA is so 2010s, and generates the server cert + tls-crypt-v2 key
# that makes our OpenVPN connections invisible to DPI (Deep Packet Inspectors,
# aka the packet police which is not fun anymore).
# ─────────────────────────────────────────────────────────────────────────────
setup_pki() {
    section "Setting Up PKI (Certificate Authority)"

    [[ -d "$EASYRSA_DIR" ]] && mv "$EASYRSA_DIR" "${EASYRSA_DIR}.bak.$(date +%s)"

    # Setup EasyRSA directory based on OS family
    setup_easyrsa_dir

    cd "$EASYRSA_DIR"

    cat > vars <<EOF
set_var EASYRSA_ALGO       ec
set_var EASYRSA_CURVE      secp384r1
set_var EASYRSA_DIGEST     sha512
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    1825
set_var EASYRSA_DN            "cn_only"
set_var EASYRSA_REQ_CN        "${CA_NAME}"
set_var EASYRSA_BATCH          "yes"
EOF

    export EASYRSA_BATCH=1
    export EASYRSA_REQ_CN="$CA_NAME"

    info "Initializing PKI..."
    printf 'yes\n' | ./easyrsa --batch init-pki 2>&1 | grep -v "^$" || true
    ok "PKI initialized"


    info "Building Certificate Authority (CN: ${CA_NAME})..."
    ./easyrsa --batch build-ca nopass > /dev/null 2>&1
    ok "CA created"

    info "Generating server certificate request..."
    ./easyrsa --batch gen-req server nopass > /dev/null 2>&1
    ok "Server certificate request generated"

    info "Signing server certificate..."
    ./easyrsa --batch sign-req server server > /dev/null 2>&1
    ok "Server certificate signed"

    info "Generating TLS-Crypt-v2 server key..."
    openvpn --genkey tls-crypt-v2-server "${SERVER_DIR}/tls-crypt-v2.key"
    ok "TLS-Crypt-v2 server key generated"

    # Verify
    for f in pki/ca.crt pki/issued/server.crt pki/private/server.key; do
        [[ ! -f "${EASYRSA_DIR}/$f" ]] && die "Missing: $f"
    done

    cp "${EASYRSA_DIR}/pki/ca.crt"            "${SERVER_DIR}/ca.crt"
    cp "${EASYRSA_DIR}/pki/issued/server.crt"  "${SERVER_DIR}/server.crt"
    cp "${EASYRSA_DIR}/pki/private/server.key" "${SERVER_DIR}/server.key"
    chmod 600 "${SERVER_DIR}/server.key" "${SERVER_DIR}/tls-crypt-v2.key"

    ok "PKI complete (CA: ${CA_NAME})"
}

# EasyRSA lives in different places on different distros.
setup_easyrsa_dir() {
    case "$OS_FAMILY" in
        debian)
            make-cadir "$EASYRSA_DIR" 
            ;;
        rhel|suse)
            local easyrsa_src="/usr/share/easy-rsa"
            [[ -d "$easyrsa_src/3" ]] && easyrsa_src="/usr/share/easy-rsa/3"
            [[ -d "$easyrsa_src/3.0" ]] && easyrsa_src="/usr/share/easy-rsa/3.0"
            mkdir -p "$EASYRSA_DIR"
            cp -r "${easyrsa_src}"/* "$EASYRSA_DIR/" 2>/dev/null || true
            [[ ! -x "${EASYRSA_DIR}/easyrsa" && -f "${easyrsa_src}/easyrsa" ]] && \
                cp "${easyrsa_src}/easyrsa" "${EASYRSA_DIR}/"
            ;;
        arch)
            mkdir -p "$EASYRSA_DIR"
            cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR/" 2>/dev/null || true
            ;;
        *)
            die "Unknown OS family for EasyRSA setup: $OS_FAMILY"
            ;;
    esac
    chmod +x "${EASYRSA_DIR}/easyrsa" 2>/dev/null || true
}

# ========================= AUTH ==============================================

# ─────────────────────────────────────────────────────────────────────────────
# setup_auth()
# Sets up username/password authentication with SHA-512 hashed passwords.
# Creates the auth-verify.sh script that OpenVPN calls to check credentials.
# Passwords are stored as salted hashes
# ─────────────────────────────────────────────────────────────────────────────
setup_auth() {
    section "Setting Up Authentication"

    touch "$CREDS_FILE"
    chmod 644 "$CREDS_FILE"

    cat > "${SERVER_DIR}/auth-verify.sh" <<'AUTHEOF'
#!/usr/bin/env bash
set -euo pipefail

CREDS_FILE="/etc/openvpn/server/credentials"
LOG_FILE="/var/log/openvpn/auth.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') AUTH: $*" >> "$LOG_FILE"; }

[[ ! -f "$1" ]] && { log "FAIL - no temp file"; exit 1; }

USERNAME=$(sed -n '1p' "$1")
PASSWORD=$(sed -n '2p' "$1")

[[ -z "$USERNAME" || -z "$PASSWORD" ]] && { log "FAIL - empty creds"; exit 1; }
[[ ! "$USERNAME" =~ ^[a-zA-Z0-9._-]+$ ]] && { log "FAIL - bad username: $USERNAME"; exit 1; }

STORED_HASH=""
while IFS=: read -r stored_user stored_hash_val; do
    [[ -z "$stored_user" || "$stored_user" =~ ^# ]] && continue
    if [[ "$stored_user" == "$USERNAME" ]]; then
        STORED_HASH="$stored_hash_val"
        break
    fi
done < "$CREDS_FILE"

[[ -z "$STORED_HASH" ]] && { log "FAIL - user not found: $USERNAME"; exit 1; }

SALT=$(echo "$STORED_HASH" | grep -oP '^\$6\$[^$]*\$' | sed 's/\$$//')
[[ -z "$SALT" ]] && { log "FAIL - bad salt: $USERNAME"; exit 1; }

COMPUTED_HASH=$(openssl passwd -6 -salt "${SALT#\$6\$}" <<< "$PASSWORD" 2>/dev/null)

if [[ "$COMPUTED_HASH" == "$STORED_HASH" ]]; then
    log "OK   - $USERNAME authenticated"
    exit 0
else
    log "FAIL - wrong password: $USERNAME"
    exit 1
fi
AUTHEOF

    chmod 755 "${SERVER_DIR}/auth-verify.sh"
    mkdir -p "$LOG_DIR"
    touch "${LOG_DIR}/auth.log"
    chown nobody:"${OVPN_GROUP}" "${LOG_DIR}/auth.log"
    chmod 660 "${LOG_DIR}/auth.log"
    ok "Authentication system ready"
}

# ========================= OPENVPN CONFIGS ==================================

# ─────────────────────────────────────────────────────────────────────────────
# create_server_configs()
# Generates the OpenVPN server configs for TCP and UDP. The security.conf
# shared config contains our DPI-hardening settings: single cipher (no
# negotiation fingerprint), TLS 1.3 only, disabled renegotiation, and
# per-client tls-crypt-v2 keys. It's like wearing a trench coat made of
# encryption through a fingerprint scanner.
# ─────────────────────────────────────────────────────────────────────────────
create_server_configs() {
    section "Creating OpenVPN Server Configurations"

    mkdir -p "$LOG_DIR"

    cat > "${SERVER_DIR}/security.conf" <<EOF
dh none
ecdh-curve secp384r1

; Single cipher only - no negotiation fingerprint
cipher AES-256-GCM
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
ncp-ciphers AES-256-GCM
auth SHA512

tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384

; tls-crypt-v2: per-client keys, silent drop of unknown connections (Tolerate DPI better! based on my tests of course)
tls-crypt-v2 /etc/openvpn/server/tls-crypt-v2.key

; Disable TLS renegotiation (fingerprintable)
reneg-sec 0

auth-user-pass-verify /etc/openvpn/server/auth-verify.sh via-file
script-security 2
verify-client-cert none
username-as-common-name

; Security hardening
user nobody
group ${OVPN_GROUP}
persist-key
persist-tun

verify-x509-name ${CA_NAME} name
keepalive 25 180

; MTU settings for double-encapsulation (OpenVPN inside WireGuard)
; Must match on server and client
tun-mtu 1300
mssfix 1250

push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "redirect-gateway def1 bypass-dhcp"
verb 3
mute 20
duplicate-cn
EOF

    cat > "${SERVER_DIR}/tcp.conf" <<EOF
port ${OVPN_TCP_PORT}
proto tcp
dev tun0
server ${TCP_SUBNET} ${TCP_MASK}
topology subnet
ca   ${SERVER_DIR}/ca.crt
cert ${SERVER_DIR}/server.crt
key  ${SERVER_DIR}/server.key
config ${SERVER_DIR}/security.conf
tcp-nodelay
tcp-queue-limit 256
sndbuf 524288
rcvbuf 524288
status ${LOG_DIR}/tcp-status.log 30
log-append ${LOG_DIR}/tcp.log
management 127.0.0.1 7505
EOF

    cat > "${SERVER_DIR}/udp.conf" <<EOF
port ${OVPN_UDP_PORT}
proto udp
dev tun1
server ${UDP_SUBNET} ${UDP_MASK}
topology subnet
ca   ${SERVER_DIR}/ca.crt
cert ${SERVER_DIR}/server.crt
key  ${SERVER_DIR}/server.key
config ${SERVER_DIR}/security.conf
fast-io
sndbuf 524288
rcvbuf 524288
; UDP-only fragmentation (application-layer)
fragment 1280
explicit-exit-notify 1
status ${LOG_DIR}/udp-status.log 30
log-append ${LOG_DIR}/udp.log
management 127.0.0.1 7506
EOF

    ok "OpenVPN configs created (TCP/$OVPN_TCP_PORT, UDP/$OVPN_UDP_PORT)"
}

# =============================================================================
# CLOUDFLARE WARP VIA WIREGUARD
# =============================================================================
# The elegant solution to "I want Cloudflare's network without warp-cli"
#   1. Use 'wgcf' to register with WARP and get WireGuard creds
#   2. Create our own WireGuard interface
#   3. Add a route ONLY in table 42 — because 42 is the answer to everything
#   4. Policy rules send VPN traffic to table 42 → wg-warp → WARP → freedom
#   5. Default route? I won't touch it btw. SSH lives.
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# install_wgcf()
# Downloads the wgcf tool from GitHub 
# WireGuard credentials from Cloudflare WARP. Supports x86_64 and aarch64
# ─────────────────────────────────────────────────────────────────────────────
install_wgcf() {
    section "Installing wgcf (WARP WireGuard Credential Generator)"

    local wgcf_bin="/usr/local/bin/wgcf"

    if [[ -f "$wgcf_bin" ]]; then
        ok "wgcf already installed"
        return
    fi

    info "Downloading wgcf..."
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       die "Unsupported architecture: $arch" ;;
    esac

    local wgcf_url
    # Get latest release URL from GitHub API
    wgcf_url=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | jq -r ".assets[] | select(.name | test(\"linux_${arch}\")) | .browser_download_url" \
        | head -1)

    if [[ -z "$wgcf_url" || "$wgcf_url" == "null" ]]; then
        # Fallback: try known version
        wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_${arch}"
    fi

    info "Downloading from: $wgcf_url"
    curl -L -o "$wgcf_bin" "$wgcf_url"
    sync  # Ensure file is fully written to disk before execution
    chmod +x "$wgcf_bin"

    if ! "$wgcf_bin" --version 2>/dev/null; then
        die "wgcf binary is not working"
    fi

    ok "wgcf installed: $($wgcf_bin --version 2>&1 | head -1)"
}

# ─────────────────────────────────────────────────────────────────────────────
# generate_warp_wireguard_config()
# Registers with WARP (accepts TOS so you don't have to read them) and
# generates WireGuard credentials. Parses the profile to extract private key,
# endpoint, and IP addresses. Stores everything in warp-env.sh for later use.
# ─────────────────────────────────────────────────────────────────────────────
generate_warp_wireguard_config() {
    section "Generating WARP WireGuard Credentials"

    mkdir -p "$WARP_DIR"
    chmod 700 "$WARP_DIR"

    local wgcf_dir="/etc/wireguard/wgcf"
    mkdir -p "$wgcf_dir"
    cd "$wgcf_dir"

    # Register with WARP (creates wgcf-account.toml)
    if [[ ! -f "${wgcf_dir}/wgcf-account.toml" ]]; then
        info "Registering with Cloudflare WARP..."
        wgcf register --accept-tos
        ok "WARP registration complete"
    else
        ok "WARP account already exists"
    fi

    # Generate WireGuard profile (creates wgcf-profile.conf)
    info "Generating WireGuard profile..."
    wgcf generate
    ok "WireGuard profile generated"

    # Parse the generated config
    local private_key peer_public_key peer_endpoint warp_addr4 warp_addr6
    private_key=$(grep "^PrivateKey" wgcf-profile.conf | awk '{print $3}')
    peer_public_key=$(grep "^PublicKey" wgcf-profile.conf | awk '{print $3}')
    peer_endpoint=$(grep "^Endpoint" wgcf-profile.conf | awk '{print $3}')
    warp_addr4=$(grep "^Address" wgcf-profile.conf | awk '{print $3}' | tr ',' '\n' | grep '\.' | tr -d ' ')
    warp_addr6=$(grep "^Address" wgcf-profile.conf | awk '{print $3}' | tr ',' '\n' | grep ':' | tr -d ' ' || echo "")

    if [[ -z "$private_key" || -z "$peer_public_key" ]]; then
        die "Failed to parse WireGuard credentials from wgcf"
    fi

    info "WARP IPv4: $warp_addr4"
    info "Endpoint:  $peer_endpoint"

    # Create our own WireGuard config (NOT using wg-quick to avoid route hijacking)
    cat > "${WARP_DIR}/${WARP_IFACE}.conf" <<WGEOF
[Interface]
PrivateKey = ${private_key}
# Address is set manually via ip addr (not by wg-quick)
# No DNS, PostUp, PostDown — we handle routing ourselves

[Peer]
PublicKey = ${peer_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${peer_endpoint}
PersistentKeepalive = 25
WGEOF

    chmod 600 "${WARP_DIR}/${WARP_IFACE}.conf"

    # Save parsed values for the routing script
    # Store hostname, not IP - the warp-wg.sh script resolves dynamically at startup
    # This prevents Cloudflare from rate-limiting due to single IP usage
    local endpoint_host endpoint_port
    endpoint_host=$(echo "${peer_endpoint}" | cut -d: -f1)
    endpoint_port=$(echo "${peer_endpoint}" | cut -d: -f2)

    cat > "${WARP_DIR}/warp-env.sh" <<ENVEOF
WARP_IFACE="${WARP_IFACE}"
WARP_ADDR4="${warp_addr4}"
WARP_ADDR6="${warp_addr6}"
WARP_ENDPOINT="${peer_endpoint}"
WARP_ENDPOINT_HOST="${endpoint_host}"
WARP_ENDPOINT_PORT=${endpoint_port}
ENVEOF

    chmod 600 "${WARP_DIR}/warp-env.sh"

    ok "WARP WireGuard config saved to ${WARP_DIR}/${WARP_IFACE}.conf"
}

# ========================= WARP INTERFACE + ROUTING =========================

# ─────────────────────────────────────────────────────────────────────────────
# setup_warp_interface()
# Creates the wg-warp interface, sets up
# policy routing rules in table 42 (the answer!), and generates the systemd
# service. The embedded warp-wg.sh script handles start/stop/restart and
# dynamically resolves Cloudflare endpoints
# ─────────────────────────────────────────────────────────────────────────────
setup_warp_interface() {
    section "Setting Up WARP WireGuard Interface & Policy Routing"

    source "${WARP_DIR}/warp-env.sh"
    source "${SERVER_DIR}/orig-route.env"

    # ── Register routing table ──
    if ! grep -q "^${WARP_TABLE}" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "${WARP_TABLE} warp" >> /etc/iproute2/rt_tables
    fi
    ok "Routing table 'warp' (${WARP_TABLE}) registered"

    # ── Create the warp-wg.sh management script ──
    cat > "${SERVER_DIR}/warp-wg.sh" <<'WGSCRIPT'
#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# WARP WireGuard Interface & Policy Routing Manager
# ─────────────────────────────────────────────────────────────────
# This script does the heavy lifting:
#   1. Creates the wg-warp WireGuard interface (not wg-quick, we're in control)
#   2. Routes ONLY VPN subnets (10.8.0.0/24, 10.9.0.0/24) via table 42
#   3. NEVER touches default route → SSH survives, you keep your job
#   4. Dynamically resolves engage.cloudflareclient.com because static IPs
#      are for people who enjoy getting rate-limited by Cloudflare
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

ACTION="${1:-start}"

WARP_DIR="/etc/wireguard"
SERVER_DIR="/etc/openvpn/server"
WARP_TABLE=42
TCP_SUBNET="10.8.0.0/24"
UDP_SUBNET="10.9.0.0/24"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') WARP-WG: $*"; }

# Resolve WARP endpoint hostname to current IP(s)
# Cloudflare rotates IPs, so we resolve fresh each time
resolve_warp_endpoints() {
    local host="${WARP_ENDPOINT_HOST:-engage.cloudflareclient.com}"
    local resolved_ips

    # Get all IPs for the hostname (Cloudflare may return multiple)
    resolved_ips=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.' | head -5)

    if [[ -z "$resolved_ips" ]]; then
        # Fallback to getent if dig fails
        resolved_ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+\.' | sort -u | head -5)
    fi

    if [[ -z "$resolved_ips" ]]; then
        log "WARNING: Could not resolve $host, using Cloudflare anycast range"
        # Cloudflare WARP uses 162.159.192.0/24 and 162.159.193.0/24
        resolved_ips="162.159.192.0/24"
    fi

    echo "$resolved_ips"
}

start_warp() {
    log "Starting WARP WireGuard interface..."

    # Load config
    source "${WARP_DIR}/warp-env.sh"
    source "${SERVER_DIR}/orig-route.env"

    # ── Tear down if exists ──
    ip link del "$WARP_IFACE" 2>/dev/null || true

    # ── Create WireGuard interface ──
    ip link add "$WARP_IFACE" type wireguard
    wg setconf "$WARP_IFACE" "${WARP_DIR}/${WARP_IFACE}.conf"

    # Set IP address (from WARP registration)
    ip addr add "$WARP_ADDR4" dev "$WARP_IFACE"

    # Set MTU (1420 is standard for WireGuard)
    ip link set "$WARP_IFACE" mtu 1420

    # Bring up
    ip link set "$WARP_IFACE" up
    log "Interface $WARP_IFACE is up with address $WARP_ADDR4"

    # ── Ensure WARP endpoints are reachable via original gateway ──
    # Dynamically resolve the hostname to get current Cloudflare IPs
    # This is critical: WireGuard packets to Cloudflare must go via the
    # real internet, not loop back through the tunnel.
    local endpoint_ips
    endpoint_ips=$(resolve_warp_endpoints)

    for ip in $endpoint_ips; do
        ip route replace "${ip}" via "${ORIG_GW}" dev "${ORIG_DEV}" 2>/dev/null || true
        log "Endpoint route: ${ip} via ${ORIG_GW}"
    done

    # Also add routes for Cloudflare WARP anycast ranges (belt and suspenders)
    ip route replace 162.159.192.0/24 via "${ORIG_GW}" dev "${ORIG_DEV}" 2>/dev/null || true
    ip route replace 162.159.193.0/24 via "${ORIG_GW}" dev "${ORIG_DEV}" 2>/dev/null || true
    log "Added Cloudflare WARP anycast routes"

    # ── Policy routing: VPN subnets → table 42 → wg-warp ──
    # Only these subnets go through WARP. Everything else is untouched.

    # Set default route in warp table (goes through our WireGuard interface)
    ip route replace default dev "$WARP_IFACE" table "$WARP_TABLE"
    log "Table $WARP_TABLE: default dev $WARP_IFACE"

    # Add policy rules for VPN subnets
    ip rule del from "$TCP_SUBNET" table "$WARP_TABLE" 2>/dev/null || true
    ip rule del from "$UDP_SUBNET" table "$WARP_TABLE" 2>/dev/null || true
    ip rule add from "$TCP_SUBNET" table "$WARP_TABLE" priority 10
    ip rule add from "$UDP_SUBNET" table "$WARP_TABLE" priority 10
    log "Policy rules: $TCP_SUBNET, $UDP_SUBNET → table $WARP_TABLE (prio 10)"

    ip route flush cache 2>/dev/null || true

    # ── Verify ──
    if wg show "$WARP_IFACE" 2>/dev/null | grep -q "endpoint"; then
        log "WireGuard handshake endpoint configured"
    fi

    # Trigger a handshake by pinging through the tunnel
    ping -I "$WARP_IFACE" -c 2 -W 5 1.1.1.1 > /dev/null 2>&1 && \
        log "WARP tunnel is WORKING (ping via $WARP_IFACE successful)" || \
        log "WARNING: ping via $WARP_IFACE failed — tunnel may need a moment"

    log "WARP WireGuard routing active"
}

stop_warp() {
    log "Stopping WARP WireGuard..."

    source "${WARP_DIR}/warp-env.sh" 2>/dev/null || WARP_IFACE="wg-warp"
    source "${SERVER_DIR}/orig-route.env" 2>/dev/null || true

    ip rule del from "10.8.0.0/24" table "$WARP_TABLE" 2>/dev/null || true
    ip rule del from "10.9.0.0/24" table "$WARP_TABLE" 2>/dev/null || true
    ip route flush table "$WARP_TABLE" 2>/dev/null || true

    # Clean up endpoint routes (resolve current IPs)
    local endpoint_ips
    endpoint_ips=$(resolve_warp_endpoints 2>/dev/null || echo "")
    for ip in $endpoint_ips; do
        ip route del "${ip}" 2>/dev/null || true
    done
    ip route del 162.159.192.0/24 2>/dev/null || true
    ip route del 162.159.193.0/24 2>/dev/null || true

    ip link del "$WARP_IFACE" 2>/dev/null || true

    log "WARP WireGuard stopped"
}

status_warp() {
    source "${WARP_DIR}/warp-env.sh" 2>/dev/null || true

    echo "=== WireGuard Interface ==="
    wg show "${WARP_IFACE:-wg-warp}" 2>/dev/null || echo "(not running)"
    echo ""
    echo "=== Current WARP Endpoint IPs ==="
    resolve_warp_endpoints 2>/dev/null | sed 's/^/  /'
    echo ""
    echo "=== ip rule list ==="
    ip rule list
    echo ""
    echo "=== Routing table ${WARP_TABLE} (warp) ==="
    ip route show table "$WARP_TABLE" 2>/dev/null || echo "(empty)"
    echo ""
    echo "=== Main table default route ==="
    ip route show default
    echo ""
    echo "=== Tunnel test ==="
    if ping -I "${WARP_IFACE:-wg-warp}" -c 1 -W 3 1.1.1.1 > /dev/null 2>&1; then
        echo "✓ Tunnel is working"
    else
        echo "✗ Tunnel ping failed"
    fi
}

case "$ACTION" in
    start)   start_warp ;;
    stop)    stop_warp ;;
    restart) stop_warp; sleep 1; start_warp ;;
    status)  status_warp ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
WGSCRIPT

    chmod 755 "${SERVER_DIR}/warp-wg.sh"
    ok "warp-wg.sh management script created"

    # ── Systemd service ──
    cat > /etc/systemd/system/warp-wg.service <<EOF
[Unit]
Description=WARP via WireGuard (policy routing for OpenVPN)
After=network-online.target
Wants=network-online.target
Before=openvpn-server@tcp.service openvpn-server@udp.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SERVER_DIR}/warp-wg.sh start
ExecStop=${SERVER_DIR}/warp-wg.sh stop
ExecReload=${SERVER_DIR}/warp-wg.sh restart
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable warp-wg
    ok "warp-wg.service created and enabled"

    # ── Start it now ──
    info "Bringing up WARP WireGuard interface..."
    "${SERVER_DIR}/warp-wg.sh" start

    # Verify default route is untouched
    local current_gw
    current_gw=$(ip -4 route show default | head -1 | awk '{print $3}')
    if [[ "$current_gw" == "$ORIG_GW" ]]; then
        ok "Default route UNTOUCHED: via $ORIG_GW (SSH is safe)"
    else
        warn "Default route changed to $current_gw — but this shouldn't affect SSH"
    fi

    # Show status
    echo ""
    info "WARP WireGuard status:"
    wg show "$WARP_IFACE" 2>/dev/null | head -10 | sed 's/^/  /'
}

# ========================= IP FORWARDING + SYSCTL ===========================

# ─────────────────────────────────────────────────────────────────────────────
# setup_sysctl()
# Tunes the kernel for VPN workloads. Enables IP forwarding,
# disables reverse path filtering for WARP (because asymmetric routing is
# a feature, not a bug), and modify the buffer sizes
# Also disables IPv6 because dual-stack VPNs are a headache we don't need today.
# ─────────────────────────────────────────────────────────────────────────────
setup_sysctl() {
    section "Configuring System Settings"

    local rp_filter_comment
    if [[ "$INSTALL_WARP" == true ]]; then
        rp_filter_comment="# Disable reverse path filtering (required for WARP policy routing)"
    else
        rp_filter_comment="# Keep default reverse path filtering"
    fi

    cat > /etc/sysctl.d/99-openvpn.conf <<EOF
# IP forwarding
net.ipv4.ip_forward = 1

# Disable IPv6 (optional - reduces attack surface)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

${rp_filter_comment}
net.ipv4.conf.all.rp_filter = $( [[ "$INSTALL_WARP" == true ]] && echo 0 || echo 2 )
net.ipv4.conf.default.rp_filter = $( [[ "$INSTALL_WARP" == true ]] && echo 0 || echo 2 )

# ─── PERFORMANCE TUNING ───
# Increase socket buffer limits (for OpenVPN sndbuf/rcvbuf 393216)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# TCP buffer auto-tuning (min, default, max)
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# Increase backlog for high-throughput
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192

# TCP optimizations
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384

# Reduce TIME_WAIT sockets
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Increase conntrack for VPN
net.netfilter.nf_conntrack_max = 262144
EOF
    sysctl --system > /dev/null 2>&1
    ok "IP forwarding enabled, buffers optimized"
}

# ========================= FIREWALL ========================================

# ─────────────────────────────────────────────────────────────────────────────
# setup_firewall()
# Detects whether UFW is running and delegates to the appropriate function.
# UFW users get their rules injected into before.rules (the proper way).
# Everyone else gets raw iptables rules (the universal way). Sets up NAT,
# forwarding, and MSS clamping to prevent fragmentation issues.
# ─────────────────────────────────────────────────────────────────────────────
setup_firewall() {
    section "Configuring Firewall"

    local use_ufw=false
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        use_ufw=true
        info "UFW detected and active — using UFW rules"
    else
        info "Using iptables directly — old school, but reliable"
    fi

    if [[ "$use_ufw" == true ]]; then
        setup_firewall_ufw
    else
        setup_firewall_iptables
    fi
}

# UFW mode: Inject rules into /etc/ufw/before.rules
setup_firewall_ufw() {
    ufw allow "${OVPN_TCP_PORT}/tcp" comment "OpenVPN TCP" >/dev/null
    ufw allow "${OVPN_UDP_PORT}/udp" comment "OpenVPN UDP" >/dev/null
    ok "OpenVPN ports allowed (UFW)"
    ok "WireGuard outbound allowed (UFW default permits egress)"

    local before_rules="/etc/ufw/before.rules"
    local marker="# OPENVPN-WARP-NAT"

    if ! grep -q "$marker" "$before_rules" 2>/dev/null; then
        info "Adding NAT rules to $before_rules..."

        # Create NAT rules block
        local nat_block
        if [[ "$INSTALL_WARP" == true ]]; then
            nat_block="$marker - START
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${TCP_SUBNET}/24 -o ${WARP_IFACE} -j MASQUERADE
-A POSTROUTING -s ${UDP_SUBNET}/24 -o ${WARP_IFACE} -j MASQUERADE
-A POSTROUTING -s ${TCP_SUBNET}/24 -o ${SERVER_IFACE} -j MASQUERADE
-A POSTROUTING -s ${UDP_SUBNET}/24 -o ${SERVER_IFACE} -j MASQUERADE
COMMIT
$marker - END"
        else
            nat_block="$marker - START
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${TCP_SUBNET}/24 -o ${SERVER_IFACE} -j MASQUERADE
-A POSTROUTING -s ${UDP_SUBNET}/24 -o ${SERVER_IFACE} -j MASQUERADE
COMMIT
$marker - END"
        fi

        # Insert before the *filter section
        local tmp_rules
        tmp_rules=$(mktemp)
        echo "$nat_block" > "$tmp_rules"
        echo "" >> "$tmp_rules"
        cat "$before_rules" >> "$tmp_rules"
        mv "$tmp_rules" "$before_rules"
        ok "NAT rules added to before.rules"
    else
        ok "NAT rules already present in before.rules"
    fi

    # Enable IP forwarding in UFW
    if ! grep -q "^DEFAULT_FORWARD_POLICY=\"ACCEPT\"" /etc/default/ufw 2>/dev/null; then
        sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
        ok "UFW forwarding policy set to ACCEPT"
    fi

    # Add forwarding rules to before.rules if needed
    local fwd_marker="# OPENVPN-WARP-FORWARD"
    if ! grep -q "$fwd_marker" "$before_rules" 2>/dev/null; then
        local fwd_block
        if [[ "$INSTALL_WARP" == true ]]; then
            fwd_block="$fwd_marker - START
-A ufw-before-forward -i tun0 -o ${WARP_IFACE} -j ACCEPT
-A ufw-before-forward -i tun1 -o ${WARP_IFACE} -j ACCEPT
-A ufw-before-forward -i ${WARP_IFACE} -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -i ${WARP_IFACE} -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -i tun0 -o ${SERVER_IFACE} -j ACCEPT
-A ufw-before-forward -i tun1 -o ${SERVER_IFACE} -j ACCEPT
-A ufw-before-forward -i ${SERVER_IFACE} -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -i ${SERVER_IFACE} -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$fwd_marker - END"
        else
            fwd_block="$fwd_marker - START
-A ufw-before-forward -i tun0 -o ${SERVER_IFACE} -j ACCEPT
-A ufw-before-forward -i tun1 -o ${SERVER_IFACE} -j ACCEPT
-A ufw-before-forward -i ${SERVER_IFACE} -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -i ${SERVER_IFACE} -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$fwd_marker - END"
        fi

        # Insert forwarding rules before COMMIT in *filter section
        sed -i "/^COMMIT/i $fwd_block" "$before_rules"
        ok "Forwarding rules added to before.rules"
    fi

    # Add MSS clamping to mangle table in before.rules
    local mss_marker="# OPENVPN-WARP-MSS"
    if ! grep -q "$mss_marker" "$before_rules" 2>/dev/null; then
        local mss_block
        if [[ "$INSTALL_WARP" == true ]]; then
            mss_block="$mss_marker - START
*mangle
:POSTROUTING ACCEPT [0:0]
-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
-A FORWARD -o ${WARP_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1260
COMMIT
$mss_marker - END"
        else
            mss_block="$mss_marker - START
*mangle
:POSTROUTING ACCEPT [0:0]
-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
$mss_marker - END"
        fi

        # Insert mangle rules before NAT block
        local tmp_rules
        tmp_rules=$(mktemp)
        echo "$mss_block" > "$tmp_rules"
        echo "" >> "$tmp_rules"
        cat "$before_rules" >> "$tmp_rules"
        mv "$tmp_rules" "$before_rules"
        ok "MSS clamping rules added to before.rules"
    fi

    # Reload UFW
    ufw --force reload >/dev/null 2>&1 || ufw --force enable >/dev/null 2>&1
    ok "UFW reloaded"
}

# iptables mode: Raw rules for maximum compatibility and control
setup_firewall_iptables() {
    iptables -C INPUT -p tcp --dport "$OVPN_TCP_PORT" -j ACCEPT 2>/dev/null ||
        iptables -A INPUT -p tcp --dport "$OVPN_TCP_PORT" -j ACCEPT
    iptables -C INPUT -p udp --dport "$OVPN_UDP_PORT" -j ACCEPT 2>/dev/null ||
        iptables -A INPUT -p udp --dport "$OVPN_UDP_PORT" -j ACCEPT
    ok "OpenVPN ports punched through firewall"

    if [[ "$INSTALL_WARP" == true ]]; then
        # WireGuard to Cloudflare uses UDP/2408
        iptables -C OUTPUT -p udp --dport 2408 -j ACCEPT 2>/dev/null ||
            iptables -A OUTPUT -p udp --dport 2408 -j ACCEPT
        ok "WireGuard outbound to Cloudflare allowed"

        # Forwarding: VPN tunnels → WARP interface
        for tun in tun0 tun1; do
            iptables -C FORWARD -i "$tun" -o "$WARP_IFACE" -j ACCEPT 2>/dev/null ||
                iptables -A FORWARD -i "$tun" -o "$WARP_IFACE" -j ACCEPT
            iptables -C FORWARD -i "$WARP_IFACE" -o "$tun" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
                iptables -A FORWARD -i "$WARP_IFACE" -o "$tun" -m state --state RELATED,ESTABLISHED -j ACCEPT
        done
        ok "Forwarding: VPN → WARP (the scenic route)"

        # NAT through WARP
        iptables -t nat -C POSTROUTING -s "${TCP_SUBNET}/24" -o "$WARP_IFACE" -j MASQUERADE 2>/dev/null ||
            iptables -t nat -A POSTROUTING -s "${TCP_SUBNET}/24" -o "$WARP_IFACE" -j MASQUERADE
        iptables -t nat -C POSTROUTING -s "${UDP_SUBNET}/24" -o "$WARP_IFACE" -j MASQUERADE 2>/dev/null ||
            iptables -t nat -A POSTROUTING -s "${UDP_SUBNET}/24" -o "$WARP_IFACE" -j MASQUERADE
        ok "NAT: VPN traffic exits via Cloudflare"

        # MSS clamping for WARP (double encapsulation needs smaller MSS)
        iptables -t mangle -C FORWARD -o "$WARP_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1260 2>/dev/null ||
            iptables -t mangle -A FORWARD -o "$WARP_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1260
    fi

    # Forwarding: VPN → physical interface (fallback or primary if no WARP)
    for tun in tun0 tun1; do
        iptables -C FORWARD -i "$tun" -o "$SERVER_IFACE" -j ACCEPT 2>/dev/null ||
            iptables -A FORWARD -i "$tun" -o "$SERVER_IFACE" -j ACCEPT
        iptables -C FORWARD -i "$SERVER_IFACE" -o "$tun" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
            iptables -A FORWARD -i "$SERVER_IFACE" -o "$tun" -m state --state RELATED,ESTABLISHED -j ACCEPT
    done
    ok "Forwarding: VPN → ${SERVER_IFACE}"

    # NAT through physical interface
    iptables -t nat -C POSTROUTING -s "${TCP_SUBNET}/24" -o "$SERVER_IFACE" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -s "${TCP_SUBNET}/24" -o "$SERVER_IFACE" -j MASQUERADE
    iptables -t nat -C POSTROUTING -s "${UDP_SUBNET}/24" -o "$SERVER_IFACE" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -s "${UDP_SUBNET}/24" -o "$SERVER_IFACE" -j MASQUERADE
    ok "NAT: VPN → physical"

    # MSS clamping (prevents fragmentation headaches)
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null ||
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ok "MSS clamping active (goodbye, fragmentation)"

    save_iptables_rules
}

# Persist iptables rules across reboots (each distro does it differently)
save_iptables_rules() {
    case "$OS_FAMILY" in
        debian) netfilter-persistent save > /dev/null 2>&1 || true ;;
        rhel)   iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                systemctl enable iptables 2>/dev/null || true ;;
        suse)   iptables-save > /etc/sysconfig/iptables 2>/dev/null || true ;;
        arch)   iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true
                systemctl enable iptables 2>/dev/null || true ;;
    esac
    ok "Firewall rules persisted for reboots"
}

# ========================= CLIENT CONFIG ====================================

# ─────────────────────────────────────────────────────────────────────────────
# generate_client_config()
# Creates .ovpn template files for TCP, UDP, and combined (TCP+UDP fallback).
# These are TEMPLATES with a placeholder for tls-crypt-v2 keys. The actual
# per-user .ovpn files are generated by manage-users.sh with unique keys.
# This is the DPI-hardening secret sauce: each client has a unique key that
# must match for the server to even acknowledge the connection exists.
# ─────────────────────────────────────────────────────────────────────────────
generate_client_config() {
    section "Generating Client Configuration Templates"

    mkdir -p "$CLIENT_DIR"

    local ca_cert
    ca_cert=$(cat "${SERVER_DIR}/ca.crt")

    # Note: These are TEMPLATES without tls-crypt-v2 key.
    # Per-user .ovpn files with embedded tls-crypt-v2 keys are generated by manage.sh

    # Combined (TCP first, UDP fallback) - TEMPLATE
    cat > "${CLIENT_DIR}/client.ovpn.template" <<EOF
client
dev tun
pull
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name ${CA_NAME} name

cipher AES-256-GCM
data-ciphers AES-256-GCM
ncp-ciphers AES-256-GCM
auth SHA512

tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384

auth-user-pass
auth-nocache

; Disable TLS renegotiation (fingerprintable)
reneg-sec 0

; MTU for double-encapsulation (must match server)
tun-mtu 1300
mssfix 1250
sndbuf 524288
rcvbuf 524288

; Connection resilience
connect-retry 3
connect-retry-max 5
connect-timeout 10

verb 3
mute 10

<connection>
remote ${SERVER_IP} ${OVPN_TCP_PORT} tcp
</connection>

<connection>
remote ${SERVER_IP} ${OVPN_UDP_PORT} udp
</connection>

<ca>
${ca_cert}
</ca>

; __TLS_CRYPT_V2_PLACEHOLDER__ (replaced by manage.sh with per-user key)
EOF

    # TCP-only - TEMPLATE
    cat > "${CLIENT_DIR}/client-tcp.ovpn.template" <<EOF
client
dev tun
proto tcp
pull
remote ${SERVER_IP} ${OVPN_TCP_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name ${CA_NAME} name

cipher AES-256-GCM
data-ciphers AES-256-GCM
ncp-ciphers AES-256-GCM
auth SHA512

tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384

auth-user-pass
auth-nocache

; Disable TLS renegotiation (fingerprintable)
reneg-sec 0

; MTU for double-encapsulation (must match server)
tun-mtu 1300
mssfix 1250
sndbuf 524288
rcvbuf 524288

; Connection resilience
connect-retry 3
connect-retry-max 5

verb 3

<ca>
${ca_cert}
</ca>

; __TLS_CRYPT_V2_PLACEHOLDER__ (replaced by manage.sh with per-user key)
EOF

    # UDP-only - TEMPLATE
    cat > "${CLIENT_DIR}/client-udp.ovpn.template" <<EOF
client
dev tun
proto udp
pull
remote ${SERVER_IP} ${OVPN_UDP_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name ${CA_NAME} name

cipher AES-256-GCM
data-ciphers AES-256-GCM
ncp-ciphers AES-256-GCM
auth SHA512

tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384

auth-user-pass
auth-nocache

; Disable TLS renegotiation (fingerprintable)
reneg-sec 0

; MTU for double-encapsulation (must match server)
tun-mtu 1300
mssfix 1250
fragment 1280
sndbuf 524288
rcvbuf 524288
fast-io
explicit-exit-notify 2

; Connection resilience
connect-retry 3
connect-retry-max 5

verb 3

<ca>
${ca_cert}
</ca>

; __TLS_CRYPT_V2_PLACEHOLDER__ (replaced by manage.sh with per-user key)
EOF

    chmod 644 "${CLIENT_DIR}"/*.template
    ok "Client templates: client.ovpn.template, client-tcp.ovpn.template, client-udp.ovpn.template"
    info "Per-user .ovpn files are generated by manage.sh with embedded tls-crypt-v2 keys"
}

# ========================= START SERVICES ===================================

# ─────────────────────────────────────────────────────────────────────────────
# start_services()
# Enables and starts OpenVPN (TCP and UDP instances)
# and WARP if configured. Uses systemd and Checks each service and reports status
# ─────────────────────────────────────────────────────────────────────────────
start_services() {
    section "Starting OpenVPN Services"

    systemctl daemon-reload

    if [[ "$INSTALL_WARP" == true ]]; then
        # WARP WireGuard should already be running from setup_warp_interface
        if ! systemctl is-active --quiet warp-wg; then
            systemctl start warp-wg
        fi
        ok "WARP WireGuard active"
    else
        info "WARP disabled — direct routing mode"
    fi

    # OpenVPN TCP
    systemctl enable openvpn-server@tcp --now
    sleep 2
    if systemctl is-active --quiet openvpn-server@tcp; then
        ok "OpenVPN TCP (port $OVPN_TCP_PORT) — running"
    else
        warn "OpenVPN TCP failed. Check: journalctl -u openvpn-server@tcp"
    fi

    # OpenVPN UDP
    systemctl enable openvpn-server@udp --now
    sleep 2
    if systemctl is-active --quiet openvpn-server@udp; then
        ok "OpenVPN UDP (port $OVPN_UDP_PORT) — running"
    else
        warn "OpenVPN UDP failed. Check: journalctl -u openvpn-server@udp"
    fi
}

# ========================= REMOVE WARP-SVC (cleanup) ========================

# ─────────────────────────────────────────────────────────────────────────────
# cleanup_old_warp()
# Exorcises the warp-svc daemon if it was installed from previous attempts.
# That thing hijacks the routing table like it owns the place. We mask it
# so it can never start again, even accidentally. Also removes old helper
# services that are no longer needed.
# ─────────────────────────────────────────────────────────────────────────────
cleanup_old_warp() {
    # Remove warp-svc if installed (from previous attempts)
    if systemctl is-active --quiet warp-svc 2>/dev/null; then
        info "Cleaning up old warp-svc..."
        warp-cli --accept-tos disconnect 2>/dev/null || true
        systemctl stop warp-svc 2>/dev/null || true
        systemctl disable warp-svc 2>/dev/null || true
        systemctl mask warp-svc 2>/dev/null || true
        ok "warp-svc stopped and masked (will never start again)"
    fi

    # Remove old route-protect and warp-routing services
    for svc in route-protect warp-routing; do
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
}

# ========================= SUMMARY ==========================================

# ─────────────────────────────────────────────────────────────────────────────
# print_summary()
# Prints a summary of what we built, including
# the routing architecture (VPN turducken diagram), service status, and
# helpful commands. Reminds you to add a user because an empty VPN is like
# a party with no guests — technically functional but deeply sad.
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    section "Setup Complete!"

    echo -e "${GREEN}${BOLD}"
    if [[ "$INSTALL_WARP" == true ]]; then
        cat <<'BANNER'
    ╔══════════════════════════════════════════════════════════╗
    ║       OpenVPN + WARP (WireGuard) — Ready!               ║
    ╚══════════════════════════════════════════════════════════╝
BANNER
    else
        cat <<'BANNER'
    ╔══════════════════════════════════════════════════════════╗
    ║       OpenVPN (Direct Routing) — Ready!                 ║
    ╚══════════════════════════════════════════════════════════╝
BANNER
    fi
    echo -e "${NC}"

    echo -e "${BOLD}How It Works:${NC}"
    if [[ "$INSTALL_WARP" == true ]]; then
        echo "  VPN Client  → OpenVPN (tun0/tun1)"
        echo "              → policy route (table 42)"
        echo "              → WireGuard (wg-warp)"
        echo "              → Cloudflare WARP → Internet"
        echo ""
        echo "  Server SSH  → default route (UNTOUCHED) → Internet"
    else
        echo "  VPN Client  → OpenVPN (tun0/tun1)"
        echo "              → NAT (masquerade)"
        echo "              → Server IP → Internet"
        echo ""
        echo "  (No WARP — traffic exits with server's public IP)"
    fi
    echo ""

    echo -e "${BOLD}Server:${NC}"
    echo "  IP: ${SERVER_IP}  |  TCP: ${OVPN_TCP_PORT}  |  UDP: ${OVPN_UDP_PORT}"
    echo "  CA: ${CA_NAME}"
    echo ""

    echo -e "${BOLD}Security:${NC}"
    echo "  AES-256-GCM | SHA-512 | TLS 1.3 | ECDSA P-384 | tls-crypt-v2"
    echo ""

    if [[ "$INSTALL_WARP" == true ]]; then
        echo -e "${BOLD}Routing Verification:${NC}"
        echo "  Default route:"
        ip route show default | head -1 | sed 's/^/    /'
        echo "  WARP table (42):"
        ip route show table 42 2>/dev/null | head -1 | sed 's/^/    /'
        echo "  Policy rules:"
        ip rule list | grep "table 42\|table warp" | sed 's/^/    /' || echo "    (none yet — will activate when VPN clients connect)"
        echo ""
    fi

    echo -e "${BOLD}Services:${NC}"
    local services
    if [[ "$INSTALL_WARP" == true ]]; then
        services="warp-wg openvpn-server@tcp openvpn-server@udp"
    else
        services="openvpn-server@tcp openvpn-server@udp"
    fi
    for svc in $services; do
        local status
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            status="${GREEN}running${NC}"
        else
            status="${RED}stopped${NC}"
        fi
        echo -e "  $svc: $status"
    done
    echo ""

    echo -e "${BOLD}User Management:${NC}"
    echo "  ./manage-users.sh add <username>"
    echo "  ./manage-users.sh remove <username>"
    echo "  ./manage-users.sh list"
    echo "  ./manage-users.sh show <username>     (display .ovpn config)"
    echo ""

    echo -e "${BOLD}Client Configs:${NC}"
    echo "  Templates: ${CLIENT_DIR}/*.template"
    echo "  Per-user:  ${CLIENT_DIR}/users/<username>-*.ovpn"
    echo ""

    echo -e "${BOLD}Troubleshooting:${NC}"
    if [[ "$INSTALL_WARP" == true ]]; then
        echo "  WARP status:   ${SERVER_DIR}/warp-wg.sh status"
        echo "  WARP restart:  systemctl restart warp-wg"
    fi
    echo "  OpenVPN logs:  journalctl -u openvpn-server@tcp -f"
    echo "  VPN auth log:  tail -f /var/log/openvpn/auth.log"
    echo ""

    echo -e "${YELLOW}⚠  Add a user first:  ./manage-users.sh add <username>${NC}"
    echo ""
}

# ========================= MAIN =============================================
main() {
    parse_arguments "$@"

    echo -e "${CYAN}${BOLD}"
    if [[ "$INSTALL_WARP" == true ]]; then
        cat <<'BANNER'
    ╔══════════════════════════════════════════════════════════╗
    ║      OpenVPN + Cloudflare WARP (WireGuard) Setup        ║
    ║      Multi-Distro | AES-256-GCM | TLS 1.3              ║
    ╚══════════════════════════════════════════════════════════╝
BANNER
    else
        cat <<'BANNER'
    ╔══════════════════════════════════════════════════════════╗
    ║         OpenVPN Setup (Direct Routing Mode)             ║
    ║      Multi-Distro | AES-256-GCM | TLS 1.3              ║
    ╚══════════════════════════════════════════════════════════╝
BANNER
    fi
    echo -e "${NC}"

    # Show configuration
    info "Configuration:"
    echo "  TCP Port:    ${OVPN_TCP_PORT}"
    echo "  UDP Port:    ${OVPN_UDP_PORT}"
    echo "  CA Name:     ${CA_NAME}"
    echo "  WARP:        ${INSTALL_WARP}"
    echo ""

    detect_os
    check_prerequisites
    save_setup_config
    install_packages
    setup_sysctl

    if [[ "$INSTALL_WARP" == true ]]; then
        cleanup_old_warp
    fi

    setup_pki
    setup_auth
    create_server_configs

    if [[ "$INSTALL_WARP" == true ]]; then
        install_wgcf
        generate_warp_wireguard_config
        setup_warp_interface          # Creates wg-warp, policy routes — NO default route change
    fi

    setup_firewall
    generate_client_config
    start_services
    print_summary
}

main "$@"
