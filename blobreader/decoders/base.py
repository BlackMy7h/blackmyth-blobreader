from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class DecodeError(Exception):
    """Raised when a blob cannot be decoded by a given decoder."""


@dataclass
class Result:
    output: str
    inner: Optional[bytes] = None      # bytes to feed to the next layer (auto mode)
    warnings: List[str] = field(default_factory=list)


class Decoder:
    key = ""
    name = ""
    category = ""
    description = ""

    def detect(self, data: bytes) -> float:
        """Confidence 0.0 - 1.0 that `data` is in this format."""
        return 0.0

    def decode(self, data: bytes, opts: dict) -> Result:
        raise NotImplementedError
