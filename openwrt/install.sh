#!/bin/sh
# FoxyVPN OpenRouter - One-line Installer for OpenWrt
set -e

REPO="hermanescode/foxyvpn-openrouter"
INSTALL_DIR="/usr/bin"
CONF_DIR="/etc/foxyvpn"
INIT_DIR="/etc/init.d"

echo "=== Installing FoxyVPN OpenRouter on OpenWrt ==="

# 1. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    armv7*|armv7l)
        TARGET="linux-armv7"
        ;;
    aarch64*|arm64)
        TARGET="linux-arm64"
        ;;
    x86_64)
        TARGET="linux-amd64"
        ;;
    mips)
        TARGET="linux-mips"
        ;;
    mipsel|mipsle)
        TARGET="linux-mipsle"
        ;;
    *)
        echo "Unknown architecture: $ARCH, defaulting to linux-armv7 (Google Wifi AC1304)"
        TARGET="linux-armv7"
        ;;
esac

echo "Detected architecture: $ARCH -> using binary: $TARGET"

# 2. Download Binary
mkdir -p "$INSTALL_DIR" "$CONF_DIR"

# Stop existing running instance so binary file is not locked (avoids ETXTBSY / curl 23 error)
killall foxyvpn 2>/dev/null || true
rm -f "$INSTALL_DIR/foxyvpn"

LATEST_URL="https://github.com/$REPO/releases/latest/download/foxyvpn-$TARGET"
echo "Downloading binary from $LATEST_URL..."

TMP_BIN="/tmp/foxyvpn_download"
rm -f "$TMP_BIN"

if command -v curl >/dev/null 2>&1; then
    curl -sSL "$LATEST_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_BIN" "$LATEST_URL"
elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$TMP_BIN" "$LATEST_URL"
else
    echo "Error: Neither curl, wget nor uclient-fetch found."
    exit 1
fi

mv "$TMP_BIN" "$INSTALL_DIR/foxyvpn"
chmod +x "$INSTALL_DIR/foxyvpn"

# 3. Setup Default Config if missing
if [ ! -f "$CONF_DIR/config.json" ]; then
    cat << 'EOF' > "$CONF_DIR/config.json"
{
  "web_listen": ":8080",
  "web_password": "",
  "socks_listen": "0.0.0.0:1080",
  "auto_connect": true,
  "mode": "auto",
  "guardian_endpoint": "https://vpn.mozilla.org",
  "use_h3": false
}
EOF
fi

# 4. Setup Procd Service
cat << 'EOF' > "$INIT_DIR/foxyvpn"
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

PROG=/usr/bin/foxyvpn
CONF=/etc/foxyvpn/config.json

start_service() {
    [ -x "$PROG" ] || return 1
    mkdir -p /etc/foxyvpn

    procd_open_instance
    procd_set_param command "$PROG" -config "$CONF"
    procd_set_param env GOMEMLIMIT="32MiB" GOGC="30"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    killall foxyvpn 2>/dev/null
}

reload_service() {
    stop
    start
}
EOF

chmod +x "$INIT_DIR/foxyvpn"

# 5. Enable and start service
"$INIT_DIR/foxyvpn" enable
"$INIT_DIR/foxyvpn" restart

echo "===================================================="
echo "✅ FoxyVPN OpenRouter installed and running!"
echo "Web Dashboard: http://<router-ip>:8080"
echo "SOCKS5 Proxy : socks5://<router-ip>:1080"
echo "===================================================="
