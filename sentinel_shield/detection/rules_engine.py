"""
Loads detection rules from YAML files and checks each incoming request
against every rule.

A rule file (in sentinel_shield/detection/rules/*.yml) looks like:

    attack_type: sqli
    rules:
      - id: SQLI-001
        name: "SQL injection - union based"
        severity: critical
        locations: [query, body]
        patterns: ["UNION\\s+SELECT", ...]

"locations" says which parts of the request to scan: query, body, headers,
cookies, path, uri, or "all". The request itself is a plain dict built by
the WSGI engine or the proxy.
"""

import re
from pathlib import Path
from urllib.parse import unquote_plus

import yaml


class RulesEngine:
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """Read every .yml file in the rules directory into self.rules."""
        self.rules = []
        if not self.rules_dir.exists():
            return

        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            with open(rule_file) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                continue

            # Rules in the same file can share an attack_type, so the file
            # may set it once and individual rules may leave it out.
            file_attack_type = data.get("attack_type", "unknown")
            for rule in data["rules"]:
                rule.setdefault("attack_type", file_attack_type)
                rule["_file"] = rule_file.name
                # Compile the regexes once up front so matching is fast.
                rule["_compiled"] = [
                    re.compile(pattern, re.IGNORECASE)
                    for pattern in rule.get("patterns", [])
                ]
                self.rules.append(rule)

    def evaluate(self, request):
        """Return a list of every rule that matched the request."""
        matches = []
        for rule in self.rules:
            match = self._match_rule(rule, request)
            if match:
                matches.append(match)
        return matches

    def _match_rule(self, rule, request):
        """Return match details if the rule matched, otherwise None."""
        locations = rule.get("locations", ["query", "body"])
        base_confidence = rule.get("confidence", 0.8)

        for location in locations:
            payload = self._get_payload(request, location)
            if not payload:
                continue

            for pattern, compiled in zip(rule.get("patterns", []), rule["_compiled"]):
                found = compiled.search(payload)
                if found:
                    return {
                        "rule_id": rule["id"],
                        "attack_type": rule.get("attack_type", "unknown"),
                        "name": rule.get("name", ""),
                        "location": location,
                        "confidence": rule.get("severity_weight", 1.0) * base_confidence,
                        "payload": found.group()[:200],
                        "matched": found.group(),
                    }
        return None

    def _get_payload(self, request, location):
        """Return the part of the request the rule wants to scan."""
        if location == "query":
            return unquote_plus(request.get("query", ""))
        if location == "body":
            return unquote_plus(request.get("body", ""))
        if location == "headers":
            return str(request.get("headers", {}))
        if location == "cookies":
            return unquote_plus(request.get("cookies", ""))
        if location == "path":
            return unquote_plus(request.get("path", ""))
        if location == "uri":
            return unquote_plus(request.get("uri", ""))
        if location == "all":
            parts = []
            for key in ("query", "body", "headers", "cookies", "path", "uri"):
                value = request.get(key, "")
                if key == "headers":
                    parts.append(str(value))
                else:
                    parts.append(unquote_plus(value))
            return " ".join(part for part in parts if part)
        return ""

    def reload(self):
        """Re-read the rule files (e.g. after editing a rule)."""
        self._load_rules()
