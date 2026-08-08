"""
Helpers that remove or escape dangerous characters from untrusted input.
This is defense in depth: it is a second line of defence behind the rules
engine, for when data must be stored or echoed back to the user.
"""

import html
import re


class Sanitizer:
    @staticmethod
    def sanitize_html(value):
        """Escape HTML so the browser shows it as text, not markup."""
        return html.escape(value, quote=True)

    @staticmethod
    def sanitize_sql(value):
        """Escape quotes so the value cannot break out of a SQL string."""
        return value.replace("'", "''").replace("\\", "\\\\")

    @staticmethod
    def sanitize_shell(value):
        """Remove characters that could chain commands or redirect output."""
        return re.sub(r"[;&|`$(){}[\]!#~<>*?\\\n\r]", "", value)

    @staticmethod
    def sanitize_path(value):
        """Remove path traversal sequences like ../ or %2e%2e."""
        return re.sub(r"\.\./|\.\.\\|%2e%2e", "", value, flags=re.IGNORECASE)

    @staticmethod
    def sanitize_url(value):
        """Remove characters that are not allowed in a URL."""
        return re.sub(r"[\x00-\x1f\x7f<>\"{}|\\^`'#]", "", value)

    @staticmethod
    def strip_control_chars(value):
        """Remove invisible control characters (null bytes, etc.)."""
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    def sanitize(self, value, context=None):
        """Clean a value based on where it will be used.

        context can be "html", "sql", "shell", "path" or "url".
        Without a context, only control characters are removed.
        """
        value = self.strip_control_chars(value)
        cleaners = {
            "html": self.sanitize_html,
            "sql": self.sanitize_sql,
            "shell": self.sanitize_shell,
            "path": self.sanitize_path,
            "url": self.sanitize_url,
        }
        cleaner = cleaners.get(context)
        if cleaner:
            return cleaner(value)
        return value
