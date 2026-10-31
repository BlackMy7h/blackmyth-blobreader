"""Banner + signature."""
from __future__ import annotations

from . import __version__
from .term import c, c256

AUTHOR = "BlackMy7h"

ART = [
    '    ____  __           __   __  ___     _______  ',
    '   / __ )/ /___ ______/ /__/  |/  /_  _/__  / /_ ',
    '  / __  / / __ `/ ___/ //_/ /|_/ / / / / / / __ \\',
    ' / /_/ / / /_/ / /__/ ,< / /  / / /_/ / / / / / /',
    '/_____/_/\\__,_/\\___/_/|_/_/  /_/\\__, / /_/_/ /_/ ',
    '                               /____/            ',
]

# purple -> cyan gradient (256-colour palette)
_GRADIENT = [93, 99, 105, 69, 75, 81]


def show_banner() -> None:
    print()
    for i, line in enumerate(ART):
        print(c256(line, _GRADIENT[i % len(_GRADIENT)]))
    print(c("  ┌─ BlobReader v" + __version__ + " · blob deserialization & inspection toolkit", "grey"))
    print(c("  └─ crafted by ", "grey") + c(AUTHOR, "bold", "magenta") + c("  ·  decode only, never execute", "grey"))
    print()
