#!/usr/bin/env bash
# =============================================================================
# OpenVPN User Management Script (tls-crypt-v2 per-user keys)
# =============================================================================

set -euo pipefail

# ========================= CONFIGURATION ====================================

CREDS_FILE="/etc/openvpn/server/credentials"
CLIENT_DIR="/etc/openvpn/client-configs"
SERVER_DIR="/etc/openvpn/server"
TLS_V2_SERVER_KEY="${SERVER_DIR}/tls-crypt-v2.key"
USER_KEYS_DIR="${CLIENT_DIR}/user-keys"
USER_OVPN_DIR="${CLIENT_DIR}/users"
SETUP_ENV="${SERVER_DIR}/setup.env"

# Default values (overridden by setup.env if present)
SERVER_IP=""
OVPN_TCP_PORT=443
OVPN_UDP_PORT=8443
CA_NAME="OpenVPN-CA"
INSTALL_WARP=true

# Load configuration from setup.env if exists
if [[ -f "$SETUP_ENV" ]]; then
    source "$SETUP_ENV"
fi

# ========================= LOGGING ==========================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*"; }
info() { echo -e "${BLUE}ℹ${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
die()  { err "$*"; exit 1; }

# ========================= HELPERS ==========================================

check_root() { if [[ $EUID -ne 0 ]]; then die "Run as root: sudo $0 $*"; fi; }

validate_username() {
    if [[ -z "${1:-}" ]]; then die "Username cannot be empty."; fi
    if [[ ! "$1" =~ ^[a-zA-Z0-9._-]{1,64}$ ]]; then die "Invalid username. Use: a-z, 0-9, '.', '_', '-' (max 64)."; fi
}

user_exists() { grep -q "^${1}:" "$CREDS_FILE" 2>/dev/null; }

generate_password() {
    # 16 chars: mix of upper, lower, digits, symbols — strong but typeable
    local pass=""
    # Ensure at least one of each category
    local upper lower digit symbol
    upper=$(tr -dc 'A-Z' < /dev/urandom | head -c1)
    lower=$(tr -dc 'a-z' < /dev/urandom | head -c1)
    digit=$(tr -dc '0-9' < /dev/urandom | head -c1)
    symbol=$(tr -dc '@#%^&*!?' < /dev/urandom | head -c1)
    local rest
    rest=$(tr -dc 'A-Za-z0-9@#%^&*!?' < /dev/urandom | head -c12)
    # Combine and shuffle
    pass=$(echo "${upper}${lower}${digit}${symbol}${rest}" | fold -w1 | shuf | tr -d '\n')
    echo "$pass"
}

hash_password() { openssl passwd -6 -stdin <<< "$1" 2>/dev/null; }

# Generate tls-crypt-v2 client key for a user
generate_user_v2key() {
    local username="$1"
    local keyfile="${USER_KEYS_DIR}/${username}.v2key"

    mkdir -p "$USER_KEYS_DIR"

    if [[ ! -f "$TLS_V2_SERVER_KEY" ]]; then
        die "TLS-Crypt-v2 server key not found: $TLS_V2_SERVER_KEY"
    fi

    openvpn --genkey tls-crypt-v2-client "$keyfile" --tls-crypt-v2 "$TLS_V2_SERVER_KEY"
    chmod 600 "$keyfile"

    echo "$keyfile"
}

# Generate per-user .ovpn files with embedded tls-crypt-v2 key
generate_user_ovpn() {
    local username="$1"
    local keyfile="${USER_KEYS_DIR}/${username}.v2key"

    mkdir -p "$USER_OVPN_DIR"

    if [[ ! -f "$keyfile" ]]; then
        die "User key not found: $keyfile (run 'add' first)"
    fi

    # Generate all three variants
    for template in client.ovpn.template client-tcp.ovpn.template client-udp.ovpn.template; do
        local tpl_path="${CLIENT_DIR}/${template}"
        if [[ ! -f "$tpl_path" ]]; then
            warn "Template not found: $tpl_path (skipping)"
            continue
        fi

        local out_name="${template%.template}"
        local out_path="${USER_OVPN_DIR}/${username}-${out_name}"

        # Copy template (excluding placeholder line) and append tls-crypt-v2 block
        grep -v "__TLS_CRYPT_V2_PLACEHOLDER__" "$tpl_path" > "$out_path"

        # Append the tls-crypt-v2 block
        echo "" >> "$out_path"
        echo "<tls-crypt-v2>" >> "$out_path"
        cat "$keyfile" >> "$out_path"
        echo "</tls-crypt-v2>" >> "$out_path"

        chmod 644 "$out_path"
    done

    ok "Generated .ovpn files for '${username}' in ${USER_OVPN_DIR}/"
}

cmd_add() {
    local username="${1:-}"
    if [[ -z "$username" ]]; then
        echo "Usage: $0 add <username>"
        exit 1
    fi

    validate_username "$username"
    if user_exists "$username"; then die "User '${username}' already exists."; fi

    local password
    password=$(generate_password)
    local hashed
    hashed=$(hash_password "$password")

    echo "${username}:${hashed}" >> "$CREDS_FILE"
    chmod 644 "$CREDS_FILE"

    # Generate per-user tls-crypt-v2 client key
    info "Generating tls-crypt-v2 client key..."
    generate_user_v2key "$username"
    ok "TLS-Crypt-v2 client key generated"

    # Generate per-user .ovpn files
    info "Generating per-user .ovpn files..."
    generate_user_ovpn "$username"

    echo ""
    ok "User '${username}' created with unique TLS-Crypt-v2 key"
    echo ""
    echo -e "  ${BOLD}Username:${NC}  ${username}"
    echo -e "  ${BOLD}Password:${NC}  ${password}"
    echo ""
    echo -e "  ${BOLD}Client configs (UNIQUE per user):${NC}"
    echo "    ${USER_OVPN_DIR}/${username}-client.ovpn       (TCP+UDP auto-fallback)"
    echo "    ${USER_OVPN_DIR}/${username}-client-tcp.ovpn   (TCP/443 only)"
    echo "    ${USER_OVPN_DIR}/${username}-client-udp.ovpn   (UDP/8443 only)"
    echo ""
    echo -e "  ${YELLOW}⚠  Save the password now — it cannot be recovered.${NC}"
    echo -e "  ${YELLOW}⚠  Each user's .ovpn contains a UNIQUE key — do not share between users.${NC}"
    echo ""
}

cmd_remove() {
    local username="${1:-}"
    if [[ -z "$username" ]]; then echo "Usage: $0 remove <username>"; exit 1; fi
    if ! user_exists "$username"; then die "User '${username}' not found."; fi

    local tmp; tmp=$(mktemp)
    grep -v "^${username}:" "$CREDS_FILE" > "$tmp"
    mv "$tmp" "$CREDS_FILE"
    chmod 644 "$CREDS_FILE"

    # Remove user's tls-crypt-v2 key
    local keyfile="${USER_KEYS_DIR}/${username}.v2key"
    if [[ -f "$keyfile" ]]; then
        rm -f "$keyfile"
        ok "Removed TLS-Crypt-v2 key: $keyfile"
    fi

    # Remove user's .ovpn files
    for f in "${USER_OVPN_DIR}/${username}-"*.ovpn; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
        fi
    done
    ok "User '${username}' removed (credentials, key, and configs deleted)."
}

cmd_reset() {
    local username="${1:-}"
    if [[ -z "$username" ]]; then echo "Usage: $0 reset <username>"; exit 1; fi
    if ! user_exists "$username"; then die "User '${username}' not found."; fi

    local password
    password=$(generate_password)
    local hashed
    hashed=$(hash_password "$password")

    local tmp; tmp=$(mktemp)
    while IFS= read -r line; do
        if [[ "$line" =~ ^${username}: ]]; then
            echo "${username}:${hashed}"
        else
            echo "$line"
        fi
    done < "$CREDS_FILE" > "$tmp"
    mv "$tmp" "$CREDS_FILE"
    chmod 644 "$CREDS_FILE"

    echo ""
    ok "Password reset for '${username}'"
    echo ""
    echo -e "  ${BOLD}Username:${NC}  ${username}"
    echo -e "  ${BOLD}Password:${NC}  ${password}"
    echo ""
    echo -e "  ${YELLOW}⚠  Save the password now — it cannot be recovered.${NC}"
    echo -e "  ${YELLOW}Note:${NC} TLS-Crypt-v2 key unchanged. Use 'regenerate <user>' to rotate key."
    echo ""
}

# Regenerate tls-crypt-v2 key and .ovpn files for a single user
cmd_regenerate() {
    local username="${1:-}"
    if [[ -z "$username" ]]; then echo "Usage: $0 regenerate <username>"; exit 1; fi
    if ! user_exists "$username"; then die "User '${username}' not found."; fi

    info "Regenerating TLS-Crypt-v2 key for '${username}'..."
    generate_user_v2key "$username"
    ok "New TLS-Crypt-v2 client key generated"

    info "Regenerating .ovpn files..."
    generate_user_ovpn "$username"

    echo ""
    ok "Key and configs regenerated for '${username}'"
    echo -e "  ${YELLOW}⚠  User must download new .ovpn file — old one will not work.${NC}"
    echo ""
}

# Regenerate all users' keys and configs
cmd_regenerate_all() {
    if [[ ! -s "$CREDS_FILE" ]]; then
        warn "No users to regenerate."
        return
    fi

    echo ""
    info "Regenerating TLS-Crypt-v2 keys and .ovpn files for ALL users..."
    echo ""

    local count=0
    while IFS=: read -r user _; do
        if [[ -z "$user" || "$user" =~ ^# ]]; then continue; fi

        info "Processing: ${user}"
        generate_user_v2key "$user"
        generate_user_ovpn "$user"
        count=$((count + 1))
    done < "$CREDS_FILE"

    echo ""
    ok "Regenerated keys and configs for ${count} user(s)"
    echo -e "  ${YELLOW}⚠  ALL users must download new .ovpn files — old ones will not work.${NC}"
    echo ""
}

cmd_list() {
    if [[ ! -s "$CREDS_FILE" ]]; then warn "No users configured."; return; fi

    echo ""
    echo -e "${BOLD}VPN Users:${NC}"
    echo "──────────────────────────"
    local count=0
    while IFS=: read -r user _; do
        if [[ -z "$user" || "$user" =~ ^# ]]; then continue; fi
        count=$((count + 1))
        local has_key="✗"
        if [[ -f "${USER_KEYS_DIR}/${user}.v2key" ]]; then has_key="✓"; fi
        echo "  ${count}. ${user}  [key: ${has_key}]"
    done < "$CREDS_FILE"
    echo "──────────────────────────"
    echo "Total: ${count} user(s)"
    echo ""
    echo -e "${BOLD}User configs:${NC} ${USER_OVPN_DIR}/<username>-client.ovpn"
    echo ""
}

cmd_status() {
    echo -e "\n${BOLD}Server Configuration:${NC}"
    if [[ -f "$SETUP_ENV" ]]; then
        echo "  Server IP:  ${SERVER_IP:-unknown}"
        echo "  TCP Port:   ${OVPN_TCP_PORT}"
        echo "  UDP Port:   ${OVPN_UDP_PORT}"
        echo "  CA Name:    ${CA_NAME}"
        echo "  WARP:       ${INSTALL_WARP}"
    else
        warn "  setup.env not found — run setup.sh first"
    fi
    echo ""

    echo -e "${BOLD}Services:${NC}"
    local services
    if [[ "$INSTALL_WARP" == true ]]; then
        services="warp-wg openvpn-server@tcp openvpn-server@udp"
    else
        services="openvpn-server@tcp openvpn-server@udp"
    fi
    for svc in $services; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  $svc: ${GREEN}running${NC}"
        else
            echo -e "  $svc: ${RED}stopped${NC}"
        fi
    done
    echo ""

    if [[ "$INSTALL_WARP" == true ]] && [[ -x /etc/openvpn/server/warp-wg.sh ]]; then
        /etc/openvpn/server/warp-wg.sh status 2>/dev/null || true
    fi
}

cmd_show() {
    local username="${1:-}"
    local proto="${2:-}"

    if [[ -z "$username" ]]; then
        echo "Usage: $0 show <username> [tcp|udp|combined]"
        echo ""
        echo "Options:"
        echo "  tcp       Show TCP-only config"
        echo "  udp       Show UDP-only config"
        echo "  combined  Show combined TCP+UDP config (default)"
        exit 1
    fi

    validate_username "$username"
    if ! user_exists "$username"; then die "User '${username}' not found."; fi

    # Determine which file to show
    local ovpn_file
    case "${proto,,}" in
        tcp)
            ovpn_file="${USER_OVPN_DIR}/${username}-client-tcp.ovpn"
            ;;
        udp)
            ovpn_file="${USER_OVPN_DIR}/${username}-client-udp.ovpn"
            ;;
        combined|"")
            ovpn_file="${USER_OVPN_DIR}/${username}-client.ovpn"
            ;;
        *)
            die "Unknown protocol: ${proto}. Use: tcp, udp, or combined"
            ;;
    esac

    if [[ ! -f "$ovpn_file" ]]; then
        die "Config file not found: $ovpn_file\nRun: $0 regenerate $username"
    fi

    # Output the config content
    echo "# =========================================="
    echo "# OpenVPN Config for: ${username}"
    echo "# File: ${ovpn_file}"
    echo "# Server: ${SERVER_IP:-unknown}  TCP:${OVPN_TCP_PORT}  UDP:${OVPN_UDP_PORT}"
    echo "# =========================================="
    echo ""
    cat "$ovpn_file"
}

usage() {
    cat <<EOF

${BOLD}OpenVPN User Management (tls-crypt-v2)${NC}

Usage:
  $0 add          <username>           Create user + unique tls-crypt-v2 key + .ovpn
  $0 remove       <username>           Remove user, key, and configs
  $0 reset        <username>           Reset password only (keeps same key)
  $0 regenerate   <username>           Rotate user's tls-crypt-v2 key + .ovpn
  $0 regenerate-all                    Rotate ALL users' keys + .ovpn files
  $0 list                              List all users
  $0 show         <username> [proto]   Display .ovpn config (proto: tcp/udp/combined)
  $0 status                            Show services and WARP status

Security Notes:
  • Each user gets a UNIQUE tls-crypt-v2 key (DPI-resistant)
  • Per-user .ovpn files in: ${USER_OVPN_DIR}/
  • User keys stored in:     ${USER_KEYS_DIR}/

Examples:
  $0 add alice                  # Create user with auto-generated password
  $0 show alice                 # Display combined TCP+UDP config
  $0 show alice tcp             # Display TCP-only config
  $0 reset alice                # Reset password
  $0 regenerate alice           # Rotate encryption key
  $0 regenerate-all             # Rotate ALL users' keys
  $0 remove bob                 # Delete user
EOF
}

main() {
    check_root
    if [[ ! -f "$CREDS_FILE" ]]; then
        mkdir -p "$(dirname "$CREDS_FILE")"
        touch "$CREDS_FILE"
        chmod 644 "$CREDS_FILE"
    fi

    mkdir -p "$USER_KEYS_DIR" "$USER_OVPN_DIR"
    chmod 700 "$USER_KEYS_DIR"
    chmod 755 "$USER_OVPN_DIR"

    local command="${1:-help}"; shift || true
    case "$command" in
        add)                      cmd_add "$@" ;;
        remove|rm|del)            cmd_remove "$@" ;;
        reset|passwd|pw)          cmd_reset "$@" ;;
        regenerate|regen)         cmd_regenerate "$@" ;;
        regenerate-all|regen-all) cmd_regenerate_all ;;
        list|ls)                  cmd_list ;;
        show|cat|get)             cmd_show "$@" ;;
        status|stat)              cmd_status ;;
        *)                        usage ;;
    esac
}

main "$@"
