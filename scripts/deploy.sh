#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "  SentinelShield Deployment Script"
echo "============================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3.10+ is required."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

# Create virtual environment
VENV_DIR="$PROJECT_DIR/venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip -q
pip install -r "$PROJECT_DIR/requirements.txt" -q
pip install -e "$PROJECT_DIR" -q

echo ""
echo "SentinelShield installed successfully!"
echo ""
echo "Available commands:"
echo "  sentinel-shield --help"
echo ""
echo "To start the proxy server:"
echo "  sentinel-shield proxy --upstream http://localhost:3000"
echo ""
echo "To start the admin API:"
echo "  sentinel-shield admin --port 9090"
echo ""
echo "To check status:"
echo "  sentinel-shield status"
echo ""
echo "To list detection rules:"
echo "  sentinel-shield rules"
echo ""
echo "Docker deployment:"
echo "  docker-compose up -d"
echo ""
