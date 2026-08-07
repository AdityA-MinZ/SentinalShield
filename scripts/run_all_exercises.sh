#!/usr/bin/env bash
# SentinelShield - Complete Student Exercise Runner
# Orchestrates all practical exercises in sequence
# Usage: ./run_all_exercises.sh [target_url]

set -euo pipefail

TARGET="${1:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="$SCRIPT_DIR/../exercise_output_$TIMESTAMP"
mkdir -p "$LOG_DIR"

echo "============================================"
echo "  SentinelShield - Practical Exercises"
echo "  Target: $TARGET"
echo "  Output: $LOG_DIR"
echo "============================================"

echo ""
echo "=== Exercise 1: Normal Traffic Baseline ==="
"$SCRIPT_DIR/normal_traffic.sh" "$TARGET" 15 | tee "$LOG_DIR/normal_traffic.log"
echo ""

echo "=== Exercise 2: Attack Simulation ==="
# Do not abort if some simulated tests fail (e.g. missing upstream routes).
"$SCRIPT_DIR/test_attacks.sh" "$TARGET" 2>&1 | tee "$LOG_DIR/test_attacks.log" || true
echo ""

echo "=== Exercise 3: Brute Force / Rate Limiting ==="
echo "(uses a dedicated proxy with rate limiting enabled and an empty allowlist)"
"$SCRIPT_DIR/brute_force.sh" "" 40 2>&1 | tee "$LOG_DIR/brute_force.log"
echo ""

echo "=== Exercise 4: Check Logs ==="
if [ -f "$SCRIPT_DIR/../sentinel-shield.log" ]; then
    LOG_FILE="$SCRIPT_DIR/../sentinel-shield.log"
    echo "Log file: $LOG_FILE"
    wc -l "$LOG_FILE"
    echo ""
    echo "Last 20 log entries:"
    tail -20 "$LOG_FILE" | python3 -m json.tool --no-ensure-ascii 2>/dev/null || tail -20 "$LOG_FILE"
    cp "$LOG_FILE" "$LOG_DIR/"
else
    echo "No sentinel-shield.log found. Check the --log-file path."
fi
echo ""

echo "=== Exercise 5: Generate Report ==="
if command -v sentinel-shield >/dev/null 2>&1; then
    SHIELD="$(command -v sentinel-shield)"
elif [ -x "$SCRIPT_DIR/../venv/bin/sentinel-shield" ]; then
    SHIELD="$SCRIPT_DIR/../venv/bin/sentinel-shield"
else
    SHIELD=""
fi
if [ -n "$SHIELD" ]; then
    "$SHIELD" report --log-file "$LOG_DIR/sentinel-shield.log" 2>/dev/null | tee "$LOG_DIR/report.txt" || \
    "$SHIELD" report 2>/dev/null | tee "$LOG_DIR/report.txt" || \
    echo "Report generation failed. Check the log file."
else
    echo "sentinel-shield CLI not found. Install with: pip install -e ."
fi
echo ""

echo "============================================"
echo "  Practical Exercises Complete!"
echo "  All outputs saved to: $LOG_DIR"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Review the exercise outputs in $LOG_DIR"
echo "  2. Open the dashboard at http://localhost:9091"
echo "  3. Complete your practical worksheet (docs/student_worksheet.md)"
echo "  4. Write your final report"
