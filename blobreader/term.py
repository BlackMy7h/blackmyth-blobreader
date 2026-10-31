"""Tiny ANSI colour helpers (no dependencies)."""
from __future__ import annotations

import os
import sys

if os.name == "nt":  # enable VT sequences on Windows 10+
    os.system("")


def supports_color() -> bool:
    return (
        sys.stdout.isatty()
        and not os.environ.get("NO_COLOR")
        and os.environ.get("TERM") != "dumb"
    )


_CODES = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "grey": "90", "bold": "1", "dim": "2",
}


def c(text: str, *styles: str) -> str:
    if not supports_color():
        return text
    seq = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\033[{seq}m{text}\033[0m" if seq else text


def c256(text: str, n: int) -> str:
    if not supports_color():
        return text
    return f"\033[38;5;{n}m{text}\033[0m"
