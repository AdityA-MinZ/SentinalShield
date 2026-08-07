#!/usr/bin/env bash
# SentinelShield - Normal Traffic Simulation
# Simulates legitimate user browsing to establish baseline traffic
# Usage: ./normal_traffic.sh [target_url] [requests]

TARGET="${1:-http://localhost:8080}"
COUNT="${2:-20}"
SLEEP_MIN="${3:-0.5}"
SLEEP_MAX="${4:-2.0}"

echo "Simulating $COUNT normal requests to $TARGET..."

PATHS=(
    "/"
    "/about"
    "/contact"
    "/products"
    "/search?q=laptop"
    "/search?q=phone"
    "/login"
    "/cart"
    "/checkout"
    "/api/products"
    "/api/categories"
    "/assets/style.css"
    "/assets/script.js"
    "/images/logo.png"
    "/favicon.ico"
    "/robots.txt"
    "/sitemap.xml"
    "/terms"
    "/privacy"
    "/support"
)

for i in $(seq 1 "$COUNT"); do
    path="${PATHS[$((RANDOM % ${#PATHS[@]}))]}"
    sleep_time=$(awk "BEGIN { printf \"%.2f\", $SLEEP_MIN + rand() * ($SLEEP_MAX - $SLEEP_MIN) }")
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}" 2>/dev/null)
    echo "[$i/$COUNT] GET $path -> $status (sleep ${sleep_time}s)"
    sleep "$sleep_time"
done

echo "Normal traffic simulation complete."
