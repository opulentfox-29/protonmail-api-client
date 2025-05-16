"""Logger."""

from .constants import colors


class Logger:
    """
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    """
    def __init__(self, level, func):
        self.level = level
        self.func = func
        self.do_color = func is print

    def debug(self, status: str) -> None:
        """Debug."""
        if self.level < 1:
            return
        self.func(status)

    def info(self, status: str, color: str = 'reset') -> None:
        """Info."""
        if self.level < 2:
            return
        if self.do_color:
            status = f"{colors[color]}{status}{colors['reset']}"
        self.func(status)

    def warning(self, status: str, color: str = 'yellow') -> None:
        """Warning."""
        if self.level < 3:
            return
        if self.do_color:
            status = f"{colors[color]}{status}{colors['reset']}"
        self.func(status)

    def error(self, status: str, color: str = 'red') -> None:
        """Error."""
        if self.level < 4:
            return
        if self.do_color:
            status = f"{colors[color]}{status}{colors['reset']}"
        self.func(status)
