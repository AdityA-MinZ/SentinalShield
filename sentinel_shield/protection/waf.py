"""
A small helper that makes it easy to add SentinelShield to an existing WSGI
application:

    from sentinel_shield.protection.waf import WAFMiddleware
    app.wsgi_app = WAFMiddleware(app.wsgi_app)
"""

from pathlib import Path

from ..core.config import Config, config as default_config
from ..core.engine import SentinelShield


class WAFMiddleware:
    """Wraps a WSGI app so every request passes through SentinelShield."""

    def __init__(self, app, config=None):
        if config is None:
            config = default_config
        elif isinstance(config, Config):
            pass  # already a Config object
        elif isinstance(config, (Path, str)):
            config = Config(Path(config))
        elif isinstance(config, dict):
            config = Config.from_dict(config)
        self.shield = SentinelShield(app, config)

    def __call__(self, environ, start_response):
        return self.shield(environ, start_response)
