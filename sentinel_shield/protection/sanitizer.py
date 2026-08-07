import html
import re
from typing import Optional


class Sanitizer:
    @staticmethod
    def sanitize_html(value: str) -> str:
        return html.escape(value, quote=True)

    @staticmethod
    def sanitize_sql(value: str) -> str:
        return value.replace("'", "''").replace("\\", "\\\\")

    @staticmethod
    def sanitize_shell(value: str) -> str:
        unsafe = r"[;&|`$(){}[\]!#~<>*?\\\n\r]"
        return re.sub(unsafe, "", value)

    @staticmethod
    def sanitize_path(value: str) -> str:
        return re.sub(r"\.\./|\.\.\\|%2e%2e", "", value, flags=re.IGNORECASE)

    @staticmethod
    def sanitize_url(value: str) -> str:
        return re.sub(
            r"[\x00-\x1f\x7f<>\"{}|\\^`'#]",
            "",
            value
        )

    @staticmethod
    def strip_control_chars(value: str) -> str:
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    def sanitize(self, value: str, context: Optional[str] = None) -> str:
        value = self.strip_control_chars(value)
        if context == "html":
            return self.sanitize_html(value)
        elif context == "sql":
            return self.sanitize_sql(value)
        elif context == "shell":
            return self.sanitize_shell(value)
        elif context == "path":
            return self.sanitize_path(value)
        elif context == "url":
            return self.sanitize_url(value)
        return value
