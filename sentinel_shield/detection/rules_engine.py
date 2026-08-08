import re
from pathlib import Path
from urllib.parse import unquote_plus

import yaml


class RulesEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules = []
        self._load()

    def _load(self):
        self.rules.clear()
        if not self.rules_dir.exists():
            return
        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            with open(rule_file) as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    file_type = data.get("attack_type", "unknown")
                    for rule in data["rules"]:
                        rule["_file"] = rule_file.name
                        rule.setdefault("attack_type", file_type)
                        compiled = []
                        for p in rule.get("patterns", []):
                            compiled.append(re.compile(p, re.IGNORECASE))
                        rule["_compiled"] = compiled
                        self.rules.append(rule)

    def evaluate(self, request: dict) -> list:
        found = []
        for rule in self.rules:
            res = self._match(rule, request)
            if res:
                found.append(res)
        return found

    def _match(self, rule: dict, request: dict) -> dict:
        locations = rule.get("locations", ["query", "body"])
        base = rule.get("confidence", 0.8)

        for loc in locations:
            payload = self._payload(request, loc)
            if not payload:
                continue

            for i, p in enumerate(rule.get("patterns", [])):
                compiled = rule["_compiled"][i]
                m = compiled.search(payload)
                if m:
                    return {
                        "rule_id": rule["id"],
                        "attack_type": rule.get("attack_type", "unknown"),
                        "name": rule.get("name", ""),
                        "location": loc,
                        "confidence": rule.get("severity_weight", 1.0) * base,
                        "payload": m.group()[:200],
                        "matched": m.group(),
                    }
        return {}

    def _payload(self, request: dict, loc: str) -> str:
        if loc == "query":
            return unquote_plus(request.get("query", ""))
        if loc == "body":
            return unquote_plus(request.get("body", ""))
        if loc == "headers":
            return str(request.get("headers", {}))
        if loc == "cookies":
            return unquote_plus(request.get("cookies", ""))
        if loc == "path":
            return unquote_plus(request.get("path", ""))
        if loc == "uri":
            return unquote_plus(request.get("uri", ""))
        if loc == "all":
            parts = []
            for key in ("query", "body", "headers", "cookies", "path", "uri"):
                val = request.get(key, "")
                if key == "headers":
                    parts.append(str(val))
                else:
                    parts.append(unquote_plus(val))
            out = []
            for p in parts:
                if p:
                    out.append(p)
            return " ".join(out)
        return ""

    def reload(self):
        self._load()
