"""
Loads the sentinel-shield.yml settings file and gives typed access to each
section. Sections are returned as plain dicts, e.g.:

    config.rate_limiter.get("requests_per_minute")
"""

from pathlib import Path

import yaml

from .exceptions import ConfigError

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "sentinel-shield.yml"


class Config:
    def __init__(self, path=None):
        self._config_path = path or DEFAULT_CONFIG_PATH
        self._data = self._read(self._config_path)

    @classmethod
    def from_dict(cls, data):
        """Build a Config straight from a dict instead of a file."""
        instance = cls.__new__(cls)
        instance._config_path = None
        instance._data = data
        return instance

    def _read(self, path):
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def set(self, section, key, value):
        """Change one setting, e.g. Config.set("server", "port", 8080)."""
        self._data.setdefault(section, {})[key] = value

    def reload(self):
        """Re-read the config file from disk."""
        self._data = self._read(self._config_path)

    def to_dict(self):
        return self._data

    @property
    def server(self):
        return self._data.get("server", {})

    @property
    def admin_api(self):
        return self._data.get("admin_api", {"enabled": False})

    @property
    def detection(self):
        return self._data.get("detection", {"mode": "log"})

    @property
    def rate_limiter(self):
        return self._data.get("rate_limiter", {"enabled": False})

    @property
    def ip_reputation(self):
        return self._data.get("ip_reputation", {"enabled": False})

    @property
    def logging(self):
        return self._data.get("logging", {})

    @property
    def traffic_analyzer(self):
        return self._data.get("traffic_analyzer", {"enabled": False})

    @property
    def rules_dir(self):
        """Directory containing the .yml rule files."""
        rules_dir = self.detection.get("rules_dir", "rules")
        path = Path(rules_dir)
        if not path.is_absolute():
            path = Path(__file__).parent.parent / "detection" / rules_dir
        return path


config = Config()
