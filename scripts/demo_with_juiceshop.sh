#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "  SentinelShield + OWASP Juice Shop Demo"
echo "============================================"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required but not installed."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: docker-compose is required but not installed."
    exit 1
fi

echo "[1/4] Building SentinelShield image..."
cd "$PROJECT_DIR"
docker-compose build sentinel-shield

echo ""
echo "[2/4] Starting Juice Shop and SentinelShield..."
docker-compose up -d

echo ""
echo "[3/4] Waiting for services to start..."
sleep 5

echo ""
echo "[4/4] Demo is ready!"
echo ""
echo "  Access the demo:"
echo "  -----------------"
echo "  Juice Shop (direct):   http://localhost:3000"
echo "  Juice Shop (shielded): http://localhost:8080"
echo ""
echo "  Test attacks:"
echo "  -------------"
echo "  curl -v 'http://localhost:8080/?id=1%27+OR+1=1--'"
echo "  curl -v 'http://localhost:8080/?q=<script>alert(1)</script>'"
echo "  curl -v 'http://localhost:8080/?file=../../../etc/passwd'"
echo ""
echo "  View SentinelShield logs:"
echo "  -------------------------"
echo "  docker-compose logs -f sentinel-shield"
echo ""
echo "  Stop demo:"
echo "  ----------"
echo "  docker-compose down"
echo ""
