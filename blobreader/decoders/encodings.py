"""Plain text encodings: base64, hex, URL-encoding, query strings."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote_to_bytes

from ..utils import (as_text, b64_decode_loose, identify_magic, pretty,
                     preview, printable_ratio)
from .base import DecodeError, Decoder, Result

_B64 = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


class Base64(Decoder):
    key = "base64"
    name = "Base64 / Base64URL"
    category = "Encoding"
    description = "Standard or URL-safe base64, padding optional"

    def _raw(self, data):
        t = as_text(data)
        if not t:
            return None, None
        c = re.sub(r"\s+", "", t)
        if not _B64.match(c):
            return None, None
        try:
            return c, b64_decode_loose(c)
        except ValueError:
            return None, None

    def detect(self, data):
        c, raw = self._raw(data)
        if raw is None:
            return 0.0
        if identify_magic(raw):
            return 0.85
        if len(c) >= 8 and printable_ratio(raw) > 0.95:
            return 0.65
        if len(c) < 16:
            return 0.0
        if _HEX.match(c) and len(c) % 2 == 0:
            return 0.15
        if c.isalpha() and (c.islower() or c.istitle()):
            return 0.0  # looks like an English word
        return 0.35

    def decode(self, data, opts):
        c, raw = self._raw(data)
        if raw is None:
            raise DecodeError("not valid base64")
        warn = []
        if "-" in c or "_" in c:
            warn.append("URL-safe alphabet detected")
        return Result(f"Decoded {len(raw)} bytes\n{preview(raw)}", inner=raw, warnings=warn)


class Hex(Decoder):
    key = "hex"
    name = "Hex string"
    category = "Encoding"
    description = "Hex digits (supports 0x prefix, spaces, colons)"

    def _raw(self, data):
        t = as_text(data)
        if not t:
            return None, None
        h = re.sub(r"[\s:]", "", t)
        if h.lower().startswith("0x"):
            h = h[2:]
        if len(h) < 2 or len(h) % 2 or not _HEX.match(h):
            return None, None
        return h, bytes.fromhex(h)

    def detect(self, data):
        h, raw = self._raw(data)
        if raw is None or len(h) < 8:
            return 0.0
        if identify_magic(raw):
            return 0.85
        if printable_ratio(raw) > 0.95:
            return 0.75
        if h.isdigit() or len(h) in (32, 40, 56, 64, 96, 128):
            return 0.2  # number or probably a hash
        return 0.45

    def decode(self, data, opts):
        h, raw = self._raw(data)
        if raw is None:
            raise DecodeError("not a hex string")
        warn = []
        if len(h) in (32, 40, 56, 64, 96, 128):
            warn.append(f"{len(h)} hex chars - might be a hash/digest rather than data")
        return Result(f"Decoded {len(raw)} bytes\n{preview(raw)}", inner=raw, warnings=warn)


class UrlEncoded(Decoder):
    key = "url"
    name = "URL / percent-encoding"
    category = "Encoding"
    description = "%XX escapes"

    def detect(self, data):
        t = as_text(data)
        if t and re.search(r"%[0-9A-Fa-f]{2}", t) and " " not in t:
            return 0.7
        return 0.0

    def decode(self, data, opts):
        t = as_text(data)
        if not t:
            raise DecodeError("not text")
        raw = unquote_to_bytes(t)
        return Result(f"Decoded {len(raw)} bytes\n{preview(raw)}", inner=raw)


class QueryString(Decoder):
    key = "query"
    name = "Query string / form data"
    category = "Encoding"
    description = "a=1&b=2 (application/x-www-form-urlencoded)"

    _RE = re.compile(r"^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$")

    def detect(self, data):
        t = as_text(data)
        if t and self._RE.match(t) and t.count("&") >= 1:
            return 0.5
        return 0.0

    def decode(self, data, opts):
        t = as_text(data)
        if not t:
            raise DecodeError("not text")
        pairs = parse_qsl(t, keep_blank_values=True)
        if not pairs:
            raise DecodeError("no key=value pairs")
        return Result(pretty([{"key": k, "value": v} for k, v in pairs]))
