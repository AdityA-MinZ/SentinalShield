#!/usr/bin/env python3
import argparse
import json
from datetime import datetime

# reads a sentinel-shield log file and prints a summary + per request info
# usage: python scripts/analyze_log.py --log-file sentinel-shield.log --format table


def read_lines(filepath):
    out = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                # skip broken lines, the log can get cut off if it was
                # copied while still being written
                continue
    return out


def _time_diff(det_time, acc_time):
    # returns how many seconds the detection was before the access line,
    # or None if it doesnt fit. the detection is always logged right
    # before the block so it should be just a tiny bit earlier.
    if not det_time or not acc_time:
        return None
    try:
        d = datetime.fromisoformat(det_time)
        a = datetime.fromisoformat(acc_time)
    except Exception:
        return None
    diff = (a - d).total_seconds()
    if 0 <= diff < 2:
        return diff
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-file", required=True)
    ap.add_argument("--format", default="table",
                    choices=["table", "json", "markdown"])
    args = ap.parse_args()

    logs = read_lines(args.log_file)

    # split the log lines by event type
    access = []
    blocks = []
    detect = []

    for l in logs:
        ev = l.get("event")
        if ev == "access":
            access.append(l)
        elif ev == "block":
            blocks.append(l)
        elif ev == "detection":
            detect.append(l)

    # ev_types was for a different idea, keeping it around just in case
    ev_types = {"access": 0, "block": 0, "detection": 0}

    # each access event = one http request, build a row for it
    rows = []
    for a in access:
        ip = a.get("client_ip", "?")
        path = a.get("path", "?")
        method = a.get("method", "?")
        status = a.get("status", "?")
        ts = a.get("timestamp", "")

        result = "ALLOWED"
        attack = ""
        rule = ""

        if status == 200:
            result = "ALLOWED"
        elif status == 429:
            result = "RATE LIMITED"
            attack = "rate_limit"
            rule = "RateLimitExceeded"
        elif status == 403:
            result = "BLOCKED"
            # the block event stores the main rule that caught the request,
            # so use that instead of guessing from the detection lines
            best = None
            best_diff = None
            for b in blocks:
                if b.get("client_ip") == ip and b.get("path") == path:
                    diff = _time_diff(b.get("timestamp"), ts)
                    if diff is not None and (best_diff is None or diff < best_diff):
                        best = b
                        best_diff = diff
            if best and best.get("reason_type") == "AttackDetected":
                # reason looks like "sqli: SQLI-001"
                parts = str(best.get("reason", "")).split(":", 1)
                attack = parts[0].strip()
                rule = parts[1].strip() if len(parts) > 1 else ""
            else:
                attack = "blocked_ip"
                rule = "IPBlocked"

        # debug print, used this to check the status values were right
        # print(ip, path, status, attack, rule)

        rows.append({
            "time": ts[11:19],
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
            "result": result,
            "attack": attack,
            "rule": rule,
        })

    # summary counts
    total = len(access)
    allowed = 0
    blocked = 0
    rate_limited = 0
    for r in rows:
        if r["result"] == "ALLOWED":
            allowed += 1
        elif r["result"] == "RATE LIMITED":
            rate_limited += 1
        else:
            blocked += 1

    # attacks by category (count per request, from the rows above)
    cats = {}
    for r in rows:
        if r["result"] != "ALLOWED" and r["attack"] not in ("", "rate_limit", "blocked_ip"):
            cat = r["attack"]
            if cat in cats:
                cats[cat] = cats[cat] + 1
            else:
                cats[cat] = 1

    # requests per ip (only count the access events)
    ip_hits = {}
    for a in access:
        ip = a.get("client_ip", "?")
        if ip in ip_hits:
            ip_hits[ip] = ip_hits[ip] + 1
        else:
            ip_hits[ip] = 1

    top_ips = sorted(ip_hits.items(), key=lambda x: x[1], reverse=True)

    if args.format == "json":
        print(json.dumps({
            "total_requests": total,
            "allowed": allowed,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "by_category": cats,
            "top_ips": dict(top_ips),
        }, indent=2))
        return

    if args.format == "markdown":
        print("# Log Analysis Report\n")
        print("| Time | IP | Method | Path | Status | Result | Attack | Rule |")
        print("|------|----|--------|------|--------|--------|--------|------|")
        for r in rows:
            print(f"| {r['time']} | {r['ip']} | {r['method']} | {r['path']} | "
                  f"{r['status']} | {r['result']} | {r['attack']} | {r['rule']} |")
        print()
        print("## Summary\n")
        print(f"- **Total requests:** {total}")
        print(f"- **Allowed:** {allowed}")
        print(f"- **Blocked:** {blocked}")
        print(f"- **Rate limited:** {rate_limited}\n")
        print("## Attacks by Category\n")
        print("| Category | Count |")
        print("|----------|-------|")
        for c in sorted(cats.items()):
            print(f"| {c[0]} | {c[1]} |")
        print("\n## Top IPs\n")
        print("| IP | Requests |")
        print("|----|----------|")
        for ip, n in top_ips:
            print(f"| {ip} | {n} |")
        return

    # default table format
    print(f"{'TIME':<9} {'IP':<16} {'METHOD':<7} {'PATH':<50} {'STATUS':<8} "
          f"{'RESULT':<13} {'ATTACK':<16} RULE")
    print("-" * 140)
    for r in rows:
        print(f"{r['time']:<9} {r['ip']:<16} {r['method']:<7} {r['path']:<50} "
              f"{str(r['status']):<8} {r['result']:<13} {r['attack']:<16} {r['rule']}")
    print()
    print(f"total requests: {total}")
    print(f"allowed: {allowed}")
    print(f"blocked: {blocked}")
    print(f"rate limited: {rate_limited}")
    print()
    print("attacks by category:")
    for c in sorted(cats.items()):
        print(f"  {c[0]}: {c[1]}")
    print()
    print("top ips:")
    for ip, n in top_ips:
        print(f"  {ip}: {n}")


if __name__ == "__main__":
    main()
