import re
from pathlib import Path
from typing import List
from urllib.parse import unquote_plus

import yaml


class RulesEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        self.rules.clear()
        if not self.rules_dir.exists():
            return
        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            with open(rule_file) as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    file_attack_type = data.get("attack_type", "unknown")
                    for rule in data["rules"]:
                        rule["_file"] = rule_file.name
                        rule.setdefault("attack_type", file_attack_type)
                        rule["_compiled"] = [
                            re.compile(p, re.IGNORECASE)
                            for p in rule.get("patterns", [])
                        ]
                        self.rules.append(rule)

    def evaluate(self, request: dict) -> List[dict]:
        matches = []
        for rule in self.rules:
            result = self._match_rule(rule, request)
            if result:
                matches.append(result)
        return matches

    def _match_rule(self, rule: dict, request: dict) -> dict:
        locations = rule.get("locations", ["query", "body"])
        base_confidence = rule.get("confidence", 0.8)

        for location in locations:
            payload = self._extract_payload(request, location)
            if not payload:
                continue

            for i, pattern_str in enumerate(rule.get("patterns", [])):
                compiled = rule["_compiled"][i]
                match = compiled.search(payload)
                if match:
                    return {
                        "rule_id": rule["id"],
                        "attack_type": rule.get("attack_type", "unknown"),
                        "name": rule.get("name", ""),
                        "location": location,
                        "confidence": rule.get("severity_weight", 1.0) * base_confidence,
                        "payload": match.group()[:200],
                        "matched": match.group(),
                    }
        return {}

    def _extract_payload(self, request: dict, location: str) -> str:
        if location == "query":
            return unquote_plus(request.get("query", ""))
        elif location == "body":
            return unquote_plus(request.get("body", ""))
        elif location == "headers":
            return str(request.get("headers", {}))
        elif location == "cookies":
            return unquote_plus(request.get("cookies", ""))
        elif location == "path":
            return unquote_plus(request.get("path", ""))
        elif location == "uri":
            return unquote_plus(request.get("uri", ""))
        elif location == "all":
            parts = [
                unquote_plus(request.get("query", "")),
                unquote_plus(request.get("body", "")),
                str(request.get("headers", {})),
                unquote_plus(request.get("cookies", "")),
                unquote_plus(request.get("path", "")),
                unquote_plus(request.get("uri", "")),
            ]
            return " ".join(p for p in parts if p)
        return ""

    def reload(self):
        self._load_rules()
