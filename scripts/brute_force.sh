#!/usr/bin/env bash
# SentinelShield - Brute Force / Rate Limit Simulation
# Sends rapid requests to trigger the token-bucket rate limiter.
#
# Usage:
#   ./brute_force.sh                     # self-contained demo (recommended)
#   ./brute_force.sh http://host:8080 30 0.05   # target an existing proxy
#
# NOTE: 127.0.0.1 is allowlisted by default and therefore bypasses rate
# limiting. To get a meaningful demo, this script starts a dedicated proxy
# instance with rate limiting enabled and an EMPTY allowlist, runs the
# brute-force loop against it, then cleans up.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COUNT="${2:-30}"
DELAY="${3:-0.05}"
TARGET="${1:-}"

if command -v sentinel-shield >/dev/null 2>&1; then
    SHIELD="$(command -v sentinel-shield)"
elif [ -x "$SCRIPT_DIR/../venv/bin/sentinel-shield" ]; then
    SHIELD="$SCRIPT_DIR/../venv/bin/sentinel-shield"
else
    echo "sentinel-shield not found. Install with: pip install -e ." >&2
    exit 1
fi

if [ -z "$TARGET" ]; then
    DEMO_PORT="${RATE_LIMIT_DEMO_PORT:-8099}"
    TARGET="http://127.0.0.1:$DEMO_PORT"
    DEMO_CFG="$(mktemp /tmp/sentinel-rate-demo.XXXXXX.yml)"
    cat > "$DEMO_CFG" <<EOF
server:
  host: "127.0.0.1"
  port: $DEMO_PORT
  upstream: "http://localhost:3000"
detection:
  mode: "block"
rate_limiter:
  enabled: true
  requests_per_minute: 60
  burst_size: 10
ip_reputation:
  enabled: true
  blocklist: []
  allowlist: []
logging:
  level: "INFO"
  format: "json"
  output: "stdout"
  file: "sentinel-shield-rate-demo.log"
traffic_analyzer:
  enabled: true
  window_seconds: 300
EOF

    echo "Starting dedicated rate-limit demo proxy on port $DEMO_PORT"
    echo "(allowlist cleared so rate limiting applies to this client)"
    echo ""
    "$SHIELD" proxy -c "$DEMO_CFG" >/tmp/sentinel-rate-demo.log 2>&1 &
    PROXY_PID=$!
    trap 'kill "$PROXY_PID" 2>/dev/null; rm -f "$DEMO_CFG"' EXIT
    sleep 3
fi

echo "Simulating brute-force attack ($COUNT requests to $TARGET)..."
echo ""

BLOCKED=0
ALLOWED=0

for i in $(seq 1 "$COUNT"); do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${TARGET}/login?user=admin&pass=attempt${i}" 2>/dev/null)

    if [ "$status" = "403" ] || [ "$status" = "429" ]; then
        echo "[$i] BLOCKED (HTTP $status)"
        BLOCKED=$((BLOCKED + 1))
    else
        echo "[$i] ALLOWED (HTTP $status)"
        ALLOWED=$((ALLOWED + 1))
    fi

    sleep "$DELAY"
done

echo ""
echo "Results:"
echo "  Allowed: $ALLOWED"
echo "  Blocked: $BLOCKED"

if [ "$BLOCKED" -gt 0 ]; then
    echo ""
    echo "Rate limiter triggered after $ALLOWED requests."
    echo "Check the log for RateLimitExceeded events:"
    if [ -n "${DEMO_CFG:-}" ]; then
        echo "  grep -c 'RateLimitExceeded' sentinel-shield-rate-demo.log"
    else
        echo "  grep -c 'RateLimitExceeded' sentinel-shield.log"
    fi
else
    echo ""
    echo "Rate limiter was NOT triggered. Check configuration."
fi
