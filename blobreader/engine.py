"""Auto-detection and recursive 'peeling' of encoded layers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .decoders import BY_KEY, REGISTRY, Decoder, Result

THRESHOLD = 0.3


@dataclass
class Layer:
    decoder: Decoder
    result: Result
    score: float


def rank(data: bytes, threshold: float = THRESHOLD) -> List[Tuple[float, Decoder]]:
    scored = []
    for d in REGISTRY:
        try:
            s = d.detect(data)
        except Exception:
            s = 0.0
        if s >= threshold:
            scored.append((s, d))
    scored.sort(key=lambda x: -x[0])
    return scored


def auto_decode(data: bytes, opts: dict | None = None, max_depth: int = 8) -> List[Layer]:
    """Detect the format, decode, and keep peeling while a layer yields more bytes."""
    opts = opts or {}
    layers: List[Layer] = []
    for _ in range(max_depth):
        advanced = False
        for score, dec in rank(data):
            try:
                res = dec.decode(data, opts)
            except Exception:
                continue
            layers.append(Layer(dec, res, score))
            if res.inner is None or not res.inner or res.inner == data:
                return layers
            data, advanced = res.inner, True
            break
        if not advanced:
            fb = BY_KEY["raw"]
            layers.append(Layer(fb, fb.decode(data, opts), 0.0))
            return layers
    return layers


def decode_with(key: str, data: bytes, opts: dict | None = None) -> Layer:
    dec = BY_KEY[key]
    return Layer(dec, dec.decode(data, opts or {}), 1.0)
