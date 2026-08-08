import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    _STD_ATTRS = set(
        logging.LogRecord(
            "sentinel_shield", logging.INFO, "", 0, "", (), None
        ).__dict__
    ) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
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
    def __init__(self, config: dict):
        self.logger = logging.getLogger("sentinel_shield")
        self.logger.setLevel(config.get("level", "INFO").upper())
        self.logger.handlers.clear()

        fmt = config.get("format", "json")
        output = config.get("output", "stdout")
        file_path = config.get("file")

        if fmt == "json":
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s"
            )

        if file_path:
            handler = logging.FileHandler(file_path)
        elif output == "stdout":
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _log(self, level: str, message: str, extra: dict = None):
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        if extra:
            log_method(message, extra=extra)
        else:
            log_method(message)

    def log_access(self, client_ip: str, method: str, path: str,
                   status: int, elapsed: float):
        self._log("INFO", "Request processed", {
            "event": "access",
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status": status,
            "elapsed_ms": round(elapsed * 1000, 2),
        })

    def log_block(self, client_ip: str, path: str,
                  reason_type: str, reason: str):
        self._log("WARNING", "Request blocked", {
            "event": "block",
            "client_ip": client_ip,
            "path": path,
            "reason_type": reason_type,
            "reason": reason,
        })

    def log_warning(self, client_ip: str, path: str,
                    attack_type: str, rule_id: str):
        self._log("WARNING", "Attack detected", {
            "event": "detection",
            "client_ip": client_ip,
            "path": path,
            "attack_type": attack_type,
            "rule_id": rule_id,
        })

    def log_error(self, client_ip: str, path: str, error: str):
        self._log("ERROR", "Internal error", {
            "event": "error",
            "client_ip": client_ip,
            "path": path,
            "error": error,
        })

    def log_info(self, message: str, extra: dict = None):
        self._log("INFO", message, extra)
