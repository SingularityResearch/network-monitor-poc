#!/usr/bin/env bash
# ==============================================================================
# Network Monitor & Cloudflare Gateway Unified Startup Script
# Always preserves & binds to: https://enlarge-disciplines-executive-watches.trycloudflare.com/
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

# 1. Verify / Launch Cloudflare Tunnel
CF_PID=$(pgrep -f "cloudflared tunnel" | head -n 1 || true)
if [ -n "$CF_PID" ]; then
    echo "[start.sh] Active Cloudflare tunnel found (PID: $CF_PID). Preserving session."
else
    echo "[start.sh] No running cloudflared detected. Launching Cloudflare tunnel daemon..."
    nohup cloudflared tunnel --url "http://localhost:$PORT" > /tmp/cloudflared_network_monitor.log 2>&1 &
    CF_PID=$!
    echo "[start.sh] Cloudflare tunnel launched (PID: $CF_PID)."
fi

# 2. Launch Python Backend Server
echo "[start.sh] Starting Python backend server on port $PORT..."
exec python3 serve.py "$PORT"
