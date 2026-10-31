"""Structured data formats: JSON, XML, plist, YAML, MessagePack, BSON."""
from __future__ import annotations

import datetime as dt
import json
import plistlib
import struct
from xml.dom import minidom

from ..utils import as_text, pretty, printable_ratio
from .base import DecodeError, Decoder, Result


class Json(Decoder):
    key = "json"
    name = "JSON"
    category = "Structured"
    description = "JSON objects / arrays"

    def detect(self, data):
        t = as_text(data)
        if t and t[0] in "{[" and t[-1] in "}]":
            try:
                json.loads(t)
                return 0.92
            except ValueError:
                return 0.0
        return 0.0

    def decode(self, data, opts):
        t = as_text(data)
        if not t:
            raise DecodeError("not text")
        try:
            return Result(pretty(json.loads(t)))
        except ValueError as e:
            raise DecodeError(str(e))


class Xml(Decoder):
    key = "xml"
    name = "XML"
    category = "Structured"
    description = "XML documents (DTD/entities refused for safety)"

    def detect(self, data):
        t = as_text(data)
        if t and t.startswith("<") and t.endswith(">") and not t.startswith("<plist") and "<plist" not in t[:300]:
            return 0.6
        return 0.0

    def decode(self, data, opts):
        t = as_text(data)
        if not t:
            raise DecodeError("not text")
        if "<!DOCTYPE" in t.upper() or "<!ENTITY" in t.upper():
            return Result(t, warnings=["DOCTYPE/ENTITY present - not parsed (XXE / entity-expansion risk); showing raw text"])
        try:
            return Result(minidom.parseString(t.encode()).toprettyxml(indent="  "))
        except Exception as e:  # expat errors
            raise DecodeError(str(e))


class Plist(Decoder):
    key = "plist"
    name = "Apple plist (XML / binary)"
    category = "Structured"
    description = "bplist00 and XML property lists"

    def detect(self, data):
        if data.startswith(b"bplist00"):
            return 0.95
        t = as_text(data)
        if t and "<plist" in t[:400]:
            return 0.9
        return 0.0

    def decode(self, data, opts):
        try:
            return Result(pretty(plistlib.loads(data)))
        except Exception as e:
            raise DecodeError(str(e))


class Yaml(Decoder):
    key = "yaml"
    name = "YAML (safe_load)"
    category = "Structured"
    description = "Requires PyYAML; never builds arbitrary objects"

    def detect(self, data):
        return 0.0  # too ambiguous for auto-detect; manual only

    def decode(self, data, opts):
        try:
            import yaml
        except ImportError:
            raise DecodeError("PyYAML not installed (pip install pyyaml)")
        t = as_text(data)
        if not t:
            raise DecodeError("not text")
        try:
            return Result(pretty(yaml.safe_load(t)))
        except yaml.YAMLError as e:
            raise DecodeError(str(e))


# ----------------------------- MessagePack -----------------------------
class _MP:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise DecodeError("truncated msgpack")
        s = self.b[self.i:self.i + n]
        self.i += n
        return s

    def num(self, n: int, signed=False) -> int:
        return int.from_bytes(self.take(n), "big", signed=signed)

    def seq(self, n: int, depth: int):
        if n > len(self.b) - self.i:
            raise DecodeError("bad length")
        return [self.parse(depth + 1) for _ in range(n)]

    def mapping(self, n: int, depth: int):
        if n * 2 > len(self.b) - self.i:
            raise DecodeError("bad length")
        out = {}
        for _ in range(n):
            k = self.parse(depth + 1)
            out[k if isinstance(k, (str, int)) else repr(k)] = self.parse(depth + 1)
        return out

    def string(self, n: int) -> str:
        try:
            return self.take(n).decode("utf-8")
        except UnicodeDecodeError:
            raise DecodeError("bad utf-8")

    def parse(self, depth=0):
        if depth > 64:
            raise DecodeError("too deep")
        t = self.take(1)[0]
        if t <= 0x7F:
            return t
        if t >= 0xE0:
            return t - 256
        if 0x80 <= t <= 0x8F:
            return self.mapping(t & 0x0F, depth)
        if 0x90 <= t <= 0x9F:
            return self.seq(t & 0x0F, depth)
        if 0xA0 <= t <= 0xBF:
            return self.string(t & 0x1F)
        simple = {0xC0: None, 0xC2: False, 0xC3: True}
        if t in simple:
            return simple[t]
        if t in (0xC4, 0xC5, 0xC6):
            return self.take(self.num({0xC4: 1, 0xC5: 2, 0xC6: 4}[t]))
        if t in (0xC7, 0xC8, 0xC9):
            n = self.num({0xC7: 1, 0xC8: 2, 0xC9: 4}[t])
            return {"__ext__": self.num(1, True), "data": self.take(n)}
        if t == 0xCA:
            return struct.unpack(">f", self.take(4))[0]
        if t == 0xCB:
            return struct.unpack(">d", self.take(8))[0]
        if 0xCC <= t <= 0xCF:
            return self.num(1 << (t - 0xCC))
        if 0xD0 <= t <= 0xD3:
            return self.num(1 << (t - 0xD0), signed=True)
        if 0xD4 <= t <= 0xD8:
            return {"__ext__": self.num(1, True), "data": self.take(1 << (t - 0xD4))}
        if t in (0xD9, 0xDA, 0xDB):
            return self.string(self.num({0xD9: 1, 0xDA: 2, 0xDB: 4}[t]))
        if t in (0xDC, 0xDD):
            return self.seq(self.num(2 if t == 0xDC else 4), depth)
        if t in (0xDE, 0xDF):
            return self.mapping(self.num(2 if t == 0xDE else 4), depth)
        raise DecodeError("invalid msgpack byte 0xc1")


class MessagePack(Decoder):
    key = "msgpack"
    name = "MessagePack"
    category = "Structured"
    description = "Binary JSON-like format (built-in parser)"

    def _parse(self, data):
        p = _MP(data)
        obj = p.parse()
        if p.i != len(data):
            raise DecodeError("trailing bytes")
        return obj

    def detect(self, data):
        if not data or printable_ratio(data) > 0.95:
            return 0.0
        try:
            obj = self._parse(data)
        except (DecodeError, struct.error):
            return 0.0
        return 0.4 if isinstance(obj, (dict, list)) else 0.0

    def decode(self, data, opts):
        try:
            return Result(pretty(self._parse(data)))
        except struct.error as e:
            raise DecodeError(str(e))


# --------------------------------- BSON ---------------------------------
def _bson_doc(b: bytes, i: int, depth: int, array: bool = False):
    if depth > 64:
        raise DecodeError("too deep")
    if i + 5 > len(b):
        raise DecodeError("truncated bson")
    size = int.from_bytes(b[i:i + 4], "little")
    end = i + size
    if size < 5 or end > len(b) or b[end - 1] != 0:
        raise DecodeError("bad bson document")
    i += 4
    out = {}
    while i < end - 1:
        t = b[i]
        i += 1
        j = b.find(b"\x00", i, end)
        if j < 0:
            raise DecodeError("bad cstring")
        name = b[i:j].decode("utf-8", "replace")
        i = j + 1
        val, i = _bson_val(t, b, i, depth)
        out[name] = val
    if i != end - 1:
        raise DecodeError("bad bson length")
    return (list(out.values()) if array else out), end


def _bson_val(t: int, b: bytes, i: int, depth: int):
    def need(n):
        if i + n > len(b):
            raise DecodeError("truncated bson")
    if t == 0x01:
        need(8)
        return struct.unpack("<d", b[i:i + 8])[0], i + 8
    if t in (0x02, 0x0D, 0x0E):
        need(4)
        n = int.from_bytes(b[i:i + 4], "little")
        need(4 + n)
        return b[i + 4:i + 3 + n].decode("utf-8", "replace"), i + 4 + n
    if t == 0x03:
        return _bson_doc(b, i, depth + 1)
    if t == 0x04:
        return _bson_doc(b, i, depth + 1, array=True)
    if t == 0x05:
        need(5)
        n = int.from_bytes(b[i:i + 4], "little")
        need(5 + n)
        return {"__binary__": b[i + 5:i + 5 + n], "subtype": b[i + 4]}, i + 5 + n
    if t == 0x07:
        need(12)
        return {"$oid": b[i:i + 12].hex()}, i + 12
    if t == 0x08:
        need(1)
        return bool(b[i]), i + 1
    if t == 0x09:
        need(8)
        ms = int.from_bytes(b[i:i + 8], "little", signed=True)
        try:
            v = dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            v = ms
        return {"$date": v}, i + 8
    if t == 0x0A:
        return None, i
    if t == 0x10:
        need(4)
        return int.from_bytes(b[i:i + 4], "little", signed=True), i + 4
    if t in (0x11, 0x12):
        need(8)
        return int.from_bytes(b[i:i + 8], "little", signed=(t == 0x12)), i + 8
    raise DecodeError(f"unsupported bson type 0x{t:02x}")


class Bson(Decoder):
    key = "bson"
    name = "BSON"
    category = "Structured"
    description = "MongoDB binary JSON"

    def detect(self, data):
        if len(data) >= 5 and int.from_bytes(data[:4], "little") == len(data) and data[-1] == 0:
            try:
                _bson_doc(data, 0, 0)
                return 0.75
            except DecodeError:
                return 0.0
        return 0.0

    def decode(self, data, opts):
        doc, _ = _bson_doc(data, 0, 0)
        return Result(pretty(doc))
