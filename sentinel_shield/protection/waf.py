from typing import Optional, Callable, Union
from pathlib import Path

from ..core.config import Config, config as default_config
from ..core.engine import SentinelShield


class WAFMiddleware:
    def __init__(
        self,
        app: Callable,
        config: Optional[Union[Config, Path, str, dict]] = None,
    ):
        if config is None:
            config = default_config
        elif isinstance(config, Config):
            pass
        elif isinstance(config, (Path, str)):
            config = Config(Path(config))
        elif isinstance(config, dict):
            cfg = Config()
            cfg._data = config
            config = cfg
        self.shield = SentinelShield(app, config)

    def __call__(self, environ, start_response):
        return self.shield(environ, start_response)
