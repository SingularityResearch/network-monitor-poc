#!/usr/bin/env bash
# ==============================================================================
# Network Monitor & Cloudflare Gateway Unified Startup Script
# - Enforces CAP_NET_RAW / CAP_NET_ADMIN for continuous raw packet sniffing
# - Preserves & binds to: https://enlarge-disciplines-executive-watches.trycloudflare.com/
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

PORT="${1:-8080}"
export CLOUDFLARE_TUNNEL_URL="${CLOUDFLARE_TUNNEL_URL:-https://enlarge-disciplines-executive-watches.trycloudflare.com/}"

echo "======================================================================"
echo " Starting Network Monitor NOC & Cloudflare Gateway"
echo " Target Port:            $PORT"
echo " Cloudflare Gateway URL: $CLOUDFLARE_TUNNEL_URL"
echo "======================================================================"

# 1. Enforce CAP_NET_RAW capability for raw packet sniffing
PY_BIN=$(readlink -f "$(which python3)")
if ! python3 -c "import socket; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()" 2>/dev/null; then
    echo "[start.sh] CAP_NET_RAW missing on $PY_BIN. Applying capability..."
    if command -v setcap >/dev/null 2>&1; then
        sudo setcap cap_net_raw,cap_net_admin=eip "$PY_BIN" || true
    fi
fi

if python3 -c "import socket; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()" 2>/dev/null; then
    echo "[start.sh] CAP_NET_RAW & CAP_NET_ADMIN confirmed: Raw packet sniffer ALWAYS active."
else
    echo "[start.sh] WARNING: CAP_NET_RAW not granted. To enable: sudo setcap cap_net_raw,cap_net_admin=eip $PY_BIN"
fi

# 2. Verify / Launch Cloudflare Tunnel
CF_PID=$(pgrep -f "cloudflared tunnel" | head -n 1 || true)
if [ -n "$CF_PID" ]; then
    echo "[start.sh] Active Cloudflare tunnel found (PID: $CF_PID). Preserving session."
else
    echo "[start.sh] No running cloudflared detected. Launching Cloudflare tunnel daemon..."
    nohup cloudflared tunnel --url "http://localhost:$PORT" > /tmp/cloudflared_network_monitor.log 2>&1 &
    CF_PID=$!
    echo "[start.sh] Cloudflare tunnel launched (PID: $CF_PID)."
fi

# 3. Launch Python Backend Server
echo "[start.sh] Starting Python backend server on port $PORT..."
exec python3 serve.py "$PORT"
