"""Compression containers (size-capped to avoid decompression bombs)."""
from __future__ import annotations

import bz2
import io
import lzma
import zipfile
import zlib

from ..utils import preview
from .base import DecodeError, Decoder, Result

MAX_OUT = 50 * 1024 * 1024  # 50 MiB


def _result(label: str, raw: bytes, truncated: bool) -> Result:
    warn = [f"output capped at {MAX_OUT // (1024 * 1024)} MiB (possible decompression bomb)"] if truncated else []
    return Result(f"{label}: decompressed to {len(raw)} bytes\n{preview(raw)}", inner=raw, warnings=warn)


class Gzip(Decoder):
    key = "gzip"
    name = "gzip"
    category = "Compression"
    description = "RFC 1952 gzip stream"

    def detect(self, data):
        return 0.95 if data[:2] == b"\x1f\x8b" else 0.0

    def decode(self, data, opts):
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(data, MAX_OUT)
        except zlib.error as e:
            raise DecodeError(str(e))
        return _result("gzip", raw, bool(d.unconsumed_tail))


class Zlib(Decoder):
    key = "zlib"
    name = "zlib / deflate"
    category = "Compression"
    description = "zlib stream (78 9c / 78 da / 78 01 ...)"

    def detect(self, data):
        if len(data) > 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA) \
                and (data[0] * 256 + data[1]) % 31 == 0:
            return 0.8
        return 0.0

    def decode(self, data, opts):
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):  # zlib, then raw deflate
            try:
                d = zlib.decompressobj(wbits)
                raw = d.decompress(data, MAX_OUT)
                return _result("zlib", raw, bool(d.unconsumed_tail))
            except zlib.error:
                continue
        raise DecodeError("not a zlib/deflate stream")


class Bzip2(Decoder):
    key = "bzip2"
    name = "bzip2"
    category = "Compression"
    description = "bzip2 stream"

    def detect(self, data):
        return 0.9 if data[:3] == b"BZh" else 0.0

    def decode(self, data, opts):
        try:
            raw = bz2.BZ2Decompressor().decompress(data, max_length=MAX_OUT)
        except (OSError, ValueError) as e:
            raise DecodeError(str(e))
        return _result("bzip2", raw, len(raw) >= MAX_OUT)


class Lzma(Decoder):
    key = "xz"
    name = "xz / lzma"
    category = "Compression"
    description = "xz container"

    def detect(self, data):
        return 0.95 if data[:6] == b"\xfd7zXZ\x00" else 0.0

    def decode(self, data, opts):
        try:
            raw = lzma.LZMADecompressor().decompress(data, max_length=MAX_OUT)
        except lzma.LZMAError as e:
            raise DecodeError(str(e))
        return _result("xz", raw, len(raw) >= MAX_OUT)


class Zip(Decoder):
    key = "zip"
    name = "ZIP archive (listing)"
    category = "Compression"
    description = "Lists entries, never extracts"

    def detect(self, data):
        return 0.9 if data[:4] == b"PK\x03\x04" else 0.0

    def decode(self, data, opts):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise DecodeError(str(e))
        rows = [f"{i.file_size:>10}  {i.compress_size:>10}  {i.filename}" for i in zf.infolist()[:200]]
        return Result("   size  compressed  name\n" + "\n".join(rows))
