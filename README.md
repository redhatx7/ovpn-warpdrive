# ovpn-warpdrive

> *Your traffic wrapped in OpenVPN, stuffed inside WireGuard, launched through Cloudflare's global network. It's a VPN turducken and it actually works somehow.*

## What's This?

A script that sets up OpenVPN and routes all client traffic through Cloudflare WARP. Your users connect to your server, but their traffic exits through Cloudflare's anycast network. DPI sees encrypted noise on port 443, and the destination sees a Cloudflare IP — not yours.

No certificates to manually generate. No routing tables to debug. Just run it.

---

## Why?

Let's be honest. If you live somewhere with normal internet, you wouldn't take a plane to visit the city downtown. You'd just drive. Or walk. Same logic applies here.

**WARP itself is blocked in restricted countries.** The Great Firewall and friends don't let you connect to Cloudflare WARP directly or use popular VPN service providers. So running WARP on your laptop is useless — it just times out while you stare at the screen questioning your life choices.

This script is **not** about WARP. It's about running an **OpenVPN server** that gives you access to the internet. WARP is just a cloak — it hides your server's real IP so when someone traces the traffic, they see Cloudflare, not your precious VPS that you'd rather not get blocked.

**TL;DR:**
- OpenVPN = the actual tunnel to freedom
- WARP = disguise so your server doesn't get blacklisted

If your country has normal internet, just use WARP directly. Close this tab. Go touch grass.

---

## Features

- **Hide Main Server IP** — Route OpenVPN through WARP and does not expose Server IP address
- **DPI-resistant** — TLS 1.3 only, tls-crypt-v2, TCP/443
- **Supports** — Ubuntu, Debian, Fedora, CentOS, Rocky, Alma, Arch, openSUSE
- **Simple user management** — One command to add/remove users

---

## Quick Start

```bash
# Clone and run
git clone https://github.com/redhatx7/ovpn-warpdrive.git
cd ovpn-warpdrive
chmod +x setup.sh manage-users.sh

# Install with defaults (TCP/443, UDP/8443, with WARP)
sudo ./setup.sh

# Add a user
sudo ./manage-users.sh add <username>

# Show their config (copy-paste to client)
sudo ./manage-users.sh show alice
```

That's it. Alice can now connect.

---

## Installation Options

| Option | Description | Default |
|--------|-------------|---------|
| `--tcp-port PORT` | OpenVPN TCP port | 443 |
| `--udp-port PORT` | OpenVPN UDP port | 8443 |
| `--ca-name NAME` | Certificate Authority name | Random 32-char |
| `--no-warp` | Direct routing (no Cloudflare) | WARP enabled |

### Examples

```bash
# All defaults — maximum stealth
./setup.sh

# Custom ports
./setup.sh --tcp-port 1194 --udp-port 1195

# Corporate setup with custom CA
./setup.sh --ca-name "My-Test-CA"

# Simple VPN without WARP (traffic exits from server IP)
./setup.sh --no-warp

# Full custom
./setup.sh --tcp-port 443 --udp-port 8443 --ca-name "MyVPN-CA"
```

---

## Traffic Flow

### With WARP (Default)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRAFFIC FLOW (WARP MODE)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   VPN Client                                                                │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────┐                          │
│   │  OpenVPN Server                             │                          │
│   │  ├── TCP/443 (tun0) → 10.8.0.0/24          │                           │
│   │  └── UDP/8443 (tun1) → 10.9.0.0/24         │                           │
│   └─────────────────────────────────────────────┘                          │
│       │                                                                    │
│       ▼                                                                    │
│   ┌─────────────────────────────────────────────┐                          │
│   │  Policy Routing (table 42)                  │  ← "42"                  │
│   │  VPN subnets → wg-warp interface            │                          │
│   └─────────────────────────────────────────────┘                          │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────┐                          │
│   │  WireGuard → Cloudflare WARP                │                          │
│   │  Endpoint: engage.cloudflareclient.com      │                          │
│   └─────────────────────────────────────────────┘                          │
│       │                                                                     │
│       ▼                                                                     │
│   Internet (client sees Cloudflare IP, not your server)                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Without WARP (`--no-warp`)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       TRAFFIC FLOW (DIRECT MODE)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   VPN Client                                                                │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────┐                          │
│   │  OpenVPN Server                             │                          │
│   │  ├── TCP/443 (tun0) → 10.8.0.0/24          │                          │
│   │  └── UDP/8443 (tun1) → 10.9.0.0/24         │                          │
│   └─────────────────────────────────────────────┘                          │
│       │                                                                     │
│       ▼                                                                     │
│   ┌─────────────────────────────────────────────┐                          │
│   │  NAT (Masquerade) → Server's Public IP      │                          │
│   └─────────────────────────────────────────────┘                          │
│       │                                                                     │
│       ▼                                                                     │
│   Internet (client sees your server's IP)                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## User Management

```bash
# Add user (prompts for password)
./manage-users.sh add alice

# Remove user
./manage-users.sh remove alice

# List all users
./manage-users.sh list

# Show config (for copy-paste to client)
./manage-users.sh show alice           # Combined (TCP + UDP fallback)
./manage-users.sh show alice tcp       # TCP only
./manage-users.sh show alice udp       # UDP only

# Server status
./manage-users.sh status

# Regenerate all configs (after changes)
./manage-users.sh regenerate-all
```

---

## Technical Details

### Security Stack

| Layer | Technology |
|-------|------------|
| Encryption | AES-256-GCM (OpenVPN) + ChaCha20 (WireGuard) |
| TLS | 1.3 only, no negotiation |
| Auth | tls-crypt-v2 (per-user keys) |
| PKI | ECDSA secp384r1, SHA-512 |
| Passwords | SHA-512 crypt hashes |

### MTU Configuration

Double encapsulation needs careful tuning:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| tun-mtu | 1300 | OpenVPN tunnel MTU |
| mssfix | 1250 | TCP MSS clamping |
| fragment | 1280 | UDP fragmentation |
| WireGuard MTU | 1420 | Standard WG MTU |

### Key Files

| File | Purpose |
|------|---------|
| `/etc/openvpn/server/setup.env` | Installation config |
| `/etc/openvpn/server/credentials` | User passwords (hashed) |
| `/etc/wireguard/wg-warp.conf` | WireGuard config |
| `/etc/openvpn/client-configs/users/` | User .ovpn files |

---

## Troubleshooting

### Check Services

```bash
systemctl status warp-wg openvpn-server@tcp openvpn-server@udp
```

### Verify WARP is Working

```bash
# On your server
curl -s --interface wg-warp https://1.1.1.1/cdn-cgi/trace | grep warp=
# Should show: warp=on

# From a connected client
curl https://1.1.1.1/cdn-cgi/trace
# Should show Cloudflare IP, not your server
```

### Common Fixes

| Problem | Solution |
|---------|----------|
| Can't connect | `systemctl restart openvpn-server@tcp openvpn-server@udp` |
| Traffic shows server IP | `systemctl restart warp-wg` |
| Slow speeds | Check MTU settings, try UDP instead of TCP |
| WARP=off | `wg show wg-warp` — check handshake |

### Logs

```bash
journalctl -u openvpn-server@tcp -f    # TCP logs
journalctl -u openvpn-server@udp -f    # UDP logs
journalctl -u warp-wg -f               # WARP logs
```

---

## Supported Distros

Ubuntu 20.04+, Debian 10+, Fedora 38+, CentOS/Rocky/Alma 8+, openSUSE Leap 15+, Arch Linux

---

## Why Not warp-cli?

Cloudflare's official WARP client (`warp-svc`) hijacks your default route. Great for desktops, but here we use `wgcf` to get WireGuard credentials and manage the interface ourselves — clean and predictable. Better for future customization


---

## راهنمای فارسی

### چیکار میکنه؟

یه اسکریپت که OpenVPN رو نصب می‌کنه و ترافیکش رو از Cloudflare WARP رد می‌کنه. یعنی کسی که به VPN شما وصل میشه، IP کلودفلر رو می‌بینه نه IP سرور اصلی رو.

### نصب 

```bash
git clone https://github.com/redhatx7/ovpn-warpdrive.git
cd ovpn-warpdrive

# نصب با تنظیمات پیش‌فرض
sudo ./setup.sh

# اضافه کردن کاربر
sudo ./manage-users.sh add kiye

# نمایش کانفیگ کاربر (کپی کنین تو کلاینت)
sudo ./manage-users.sh show kiye
```

### گزینه‌های نصب

```bash
# بدون WARP (ترافیک از IP سرور خارج میشه)
./setup.sh --no-warp

# پورت‌های سفارشی
./setup.sh --tcp-port 1194 --udp-port 1195

# اسم CA سفارشی
./setup.sh --ca-name "MyVPN"
```

### مدیریت کاربرها

```bash
./manage-users.sh add kiye        # اضافه کردن
./manage-users.sh remove kiye     # حذف کردن
./manage-users.sh list           # لیست همه
./manage-users.sh show kiye       # نمایش کانفیگ
./manage-users.sh status         # وضعیت سرور
```

### دیباگ کردن

```bash
# چک کردن سرویس‌ها
systemctl status warp-wg openvpn-server@tcp openvpn-server@udp

# ریستارت
systemctl restart warp-wg
systemctl restart openvpn-server@tcp
systemctl restart openvpn-server@udp

# تست WARP
curl https://1.1.1.1/cdn-cgi/trace
# باید warp=on نشون بده
```
---

## Dependencies

- [wgcf](https://github.com/ViRb3/wgcf) — Generates WireGuard credentials for Cloudflare WARP

---

## License

### MIT.
