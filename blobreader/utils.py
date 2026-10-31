"""Shared helpers."""
from __future__ import annotations

import base64
import datetime as _dt
import json
import math
import re
import string
from collections import Counter
from typing import Any, Optional

_PRINTABLE = frozenset(string.printable.encode())

# (signature, description) - checked with startswith on raw bytes
MAGIC = [
    (b"\xac\xed\x00\x05", "Java serialized object stream"),
    (b"\x80\x02", "Python pickle (protocol 2)"),
    (b"\x80\x03", "Python pickle (protocol 3)"),
    (b"\x80\x04", "Python pickle (protocol 4)"),
    (b"\x80\x05", "Python pickle (protocol 5)"),
    (b"\x04\x08", "Ruby Marshal 4.8"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz / lzma"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF executable"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"bplist00", "Apple binary plist"),
    (b"\xff\x01", "ASP.NET ViewState (LosFormatter)"),
    (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff", ".NET BinaryFormatter stream"),
    (b"\xca\xfe\xba\xbe", "Java class file / Mach-O fat binary"),
    (b"\x93NUMPY", "NumPy .npy"),
    (b"PAR1", "Apache Parquet"),
    (b"Salted__", "OpenSSL salted ciphertext (encrypted)"),
    (b"-----BEGIN", "PEM block"),
]


def identify_magic(data: bytes) -> Optional[str]:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    return None


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def as_text(data: bytes) -> Optional[str]:
    """Return stripped UTF-8 text, or None if the data looks binary."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in s:
        return None
    s = s.strip()
    return s or None


def b64_decode_loose(text: str) -> bytes:
    """Base64 / Base64URL with optional missing padding."""
    t = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/").rstrip("=")
    if len(t) % 4 == 1:
        raise ValueError("invalid base64 length")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t, validate=True)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def hexdump(data: bytes, width: int = 16, limit: int = 512) -> str:
    rows = []
    for off in range(0, min(len(data), limit), width):
        chunk = data[off:off + width]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:08x}  {hx}  |{asc}|")
    if len(data) > limit:
        rows.append(f"... ({len(data) - limit} more bytes)")
    return "\n".join(rows)


def extract_strings(data: bytes, min_len: int = 4, limit: int = 40) -> list:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    return [s.decode() for s in found[:limit]]


def preview(raw: bytes, limit: int = 512) -> str:
    txt = as_text(raw)
    if txt is not None and printable_ratio(raw) > 0.9:
        return txt if len(txt) <= limit else txt[:limit] + f"... (+{len(txt) - limit} chars)"
    return hexdump(raw, limit=min(limit, 256))


def human_time(ts: Any) -> str:
    try:
        return _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError, TypeError):
        return "?"


def to_jsonable(obj: Any, _depth: int = 0) -> Any:
    if _depth > 200:
        return "<max depth>"
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        if b and printable_ratio(b) > 0.95:
            try:
                return b.decode("utf-8")
            except UnicodeDecodeError:
                pass
        return {"__bytes_hex__": b.hex()}
    if isinstance(obj, dict):
        return {(k if isinstance(k, str) else str(to_jsonable(k, _depth + 1))): to_jsonable(v, _depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v, _depth + 1) for v in obj]
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return str(obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return repr(obj)


def pretty(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), indent=2, ensure_ascii=False)
