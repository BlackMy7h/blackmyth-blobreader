"""Schema-less Protocol Buffers wire-format reader."""
from __future__ import annotations

import struct

from ..utils import as_text, printable_ratio
from .base import DecodeError, Decoder, Result


def _varint(b: bytes, i: int):
    shift = v = 0
    while True:
        if i >= len(b) or shift > 63:
            raise DecodeError("bad varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7


def _parse(b: bytes):
    i, fields = 0, []
    while i < len(b):
        tag, i = _varint(b, i)
        fn, wt = tag >> 3, tag & 7
        if fn == 0:
            raise DecodeError("field 0")
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 1:
            v, i = b[i:i + 8], i + 8
            if len(v) != 8:
                raise DecodeError("truncated")
        elif wt == 2:
            n, i = _varint(b, i)
            v, i = b[i:i + n], i + n
            if len(v) != n:
                raise DecodeError("truncated")
        elif wt == 5:
            v, i = b[i:i + 4], i + 4
            if len(v) != 4:
                raise DecodeError("truncated")
        else:
            raise DecodeError(f"unsupported wire type {wt}")
        fields.append((fn, wt, v))
    return fields


def _render(fields, depth=0):
    pad, lines = "  " * depth, []
    for fn, wt, v in fields:
        if wt == 0:
            zz = (v >> 1) ^ -(v & 1)
            lines.append(f"{pad}{fn}: {v}" + (f"   (zigzag: {zz})" if zz != v else ""))
        elif wt == 1:
            lines.append(f"{pad}{fn}: fixed64 {int.from_bytes(v, 'little')} / double {struct.unpack('<d', v)[0]:.6g}")
        elif wt == 5:
            lines.append(f"{pad}{fn}: fixed32 {int.from_bytes(v, 'little')} / float {struct.unpack('<f', v)[0]:.6g}")
        else:
            txt = as_text(v)
            if txt is not None and printable_ratio(v) > 0.95:
                lines.append(f'{pad}{fn}: "{txt}"')
                continue
            nested = None
            if v and depth < 6:
                try:
                    nested = _parse(v)
                except DecodeError:
                    nested = None
            if nested:
                lines.append(f"{pad}{fn}: {{")
                lines += _render(nested, depth + 1)
                lines.append(f"{pad}}}")
            else:
                lines.append(f"{pad}{fn}: bytes[{len(v)}] {v.hex()}")
    return lines


class Protobuf(Decoder):
    key = "protobuf"
    name = "Protocol Buffers (raw, no schema)"
    category = "Serialization"
    description = "Guesses types from wire format; field names unknown"

    def detect(self, data):
        if not data or data[0] == 0 or printable_ratio(data) > 0.9:
            return 0.0
        try:
            fields = _parse(data)
        except DecodeError:
            return 0.0
        return 0.35 if fields and fields[0][0] <= 100 else 0.0

    def decode(self, data, opts):
        fields = _parse(data)
        if not fields:
            raise DecodeError("empty message")
        return Result("\n".join(_render(fields)),
                      warnings=["schema-less decode: types are guesses (varint may be int/bool/enum/zigzag)"])
