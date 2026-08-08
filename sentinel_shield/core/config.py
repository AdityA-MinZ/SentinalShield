from pathlib import Path

import yaml

from .exceptions import ConfigError

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "sentinel-shield.yml"


class Config:
    def __init__(self, path: Path = None):
        self._config_path = path or DEFAULT_CONFIG_PATH
        self._data = self._read(self._config_path)

    def _read(self, path: Path) -> dict:
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        with open(path) as f:
            return yaml.safe_load(f) or {}

    @property
    def server(self) -> dict:
        return self._data.get("server", {})

    @property
    def admin_api(self) -> dict:
        return self._data.get("admin_api", {"enabled": False})

    @property
    def detection(self) -> dict:
        return self._data.get("detection", {"mode": "log"})

    @property
    def rate_limiter(self) -> dict:
        return self._data.get("rate_limiter", {"enabled": False})

    @property
    def ip_reputation(self) -> dict:
        return self._data.get("ip_reputation", {"enabled": False})

    @property
    def logging(self) -> dict:
        return self._data.get("logging", {})

    @property
    def traffic_analyzer(self) -> dict:
        return self._data.get("traffic_analyzer", {"enabled": False})

    @property
    def rules_dir(self) -> Path:
        rd = self.detection.get("rules_dir", "rules")
        p = Path(rd)
        if not p.is_absolute():
            p = Path(__file__).parent.parent / "detection" / rd
        return p

    def reload(self):
        self._data = self._read(self._config_path)

    def to_dict(self) -> dict:
        return self._data


config = Config()
