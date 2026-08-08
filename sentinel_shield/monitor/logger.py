"""
Logging helpers. Every event is written as one JSON line so the log can be
parsed and analysed later (see the "sentinel-shield report" command and
scripts/analyze_log.py).
"""

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Formats a log record as a single JSON object."""

    # Attributes that logging adds to every record automatically. We do not
    # want to copy these into the JSON line, only our custom fields (the ones
    # passed to logger.info(..., extra={...})).
    _STD_ATTRS = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    }

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._STD_ATTRS and not key.startswith("_"):
                log_entry[key] = value
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class Logger:
    """The wrapper used everywhere else in the code to write log events."""

    def __init__(self, config):
        self.logger = logging.getLogger("sentinel_shield")
        self.logger.setLevel(config.get("level", "INFO").upper())
        self.logger.handlers.clear()

        fmt = config.get("format", "json")
        output = config.get("output", "stdout")
        file_path = config.get("file")

        if fmt == "json":
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        if file_path:
            handler = logging.FileHandler(file_path)
        elif output == "stdout":
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _log(self, level, message, extra=None):
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        if extra:
            log_method(message, extra=extra)
        else:
            log_method(message)

    def log_access(self, client_ip, method, path, status, elapsed):
        """Write one JSON line for every completed request."""
        self._log("INFO", "Request processed", {
            "event": "access",
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status": status,
            "elapsed_ms": round(elapsed * 1000, 2),
        })

    def log_block(self, client_ip, path, reason_type, reason):
        """Write one JSON line when a request is blocked."""
        self._log("WARNING", "Request blocked", {
            "event": "block",
            "client_ip": client_ip,
            "path": path,
            "reason_type": reason_type,
            "reason": reason,
        })

    def log_warning(self, client_ip, path, attack_type, rule_id):
        """Write one JSON line when a rule matches (before blocking)."""
        self._log("WARNING", "Attack detected", {
            "event": "detection",
            "client_ip": client_ip,
            "path": path,
            "attack_type": attack_type,
            "rule_id": rule_id,
        })

    def log_error(self, client_ip, path, error):
        """Write one JSON line when something goes wrong internally."""
        self._log("ERROR", "Internal error", {
            "event": "error",
            "client_ip": client_ip,
            "path": path,
            "error": error,
        })

    def log_info(self, message, extra=None):
        self._log("INFO", message, extra)
