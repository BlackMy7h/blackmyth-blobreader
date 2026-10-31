"""Language-native serialization formats.

SAFETY: nothing here ever instantiates objects or executes code.
 - pickle is only *disassembled* (pickletools), never unpickled
 - Java streams are scanned for class names / strings, never deserialized
 - PHP serialize() is parsed by a small data-only parser
"""
from __future__ import annotations

import io
import pickletools
import re

from ..utils import as_text, extract_strings, pretty
from .base import DecodeError, Decoder, Result

_DANGEROUS_ROOTS = {"os", "posix", "nt", "subprocess", "builtins", "__builtin__", "sys", "socket",
                    "shutil", "commands", "pty", "importlib", "runpy", "ctypes", "webbrowser"}


class Pickle(Decoder):
    key = "pickle"
    name = "Python pickle (disassemble only)"
    category = "Serialization"
    description = "Shows opcodes & referenced callables - NEVER unpickles"

    def detect(self, data):
        return 0.85 if len(data) > 3 and data[0] == 0x80 and 2 <= data[1] <= 5 else 0.0

    def decode(self, data, opts):
        buf = io.StringIO()
        try:
            pickletools.dis(data, out=buf)
        except Exception as e:
            raise DecodeError(f"cannot disassemble: {e}")
        strings, refs, ops = [], [], set()
        try:
            for op, arg, _pos in pickletools.genops(data):
                n = op.name
                if n in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                         "STRING", "BINSTRING", "SHORT_BINSTRING") and isinstance(arg, str):
                    strings.append(arg)
                elif n == "GLOBAL" and isinstance(arg, str):
                    refs.append(arg.replace(" ", "."))
                elif n == "STACK_GLOBAL" and len(strings) >= 2:
                    refs.append(f"{strings[-2]}.{strings[-1]}")
                elif n in ("REDUCE", "OBJ", "INST", "NEWOBJ", "NEWOBJ_EX", "BUILD"):
                    ops.add(n)
        except Exception:
            pass
        warn = []
        if refs:
            warn.append("references callables: " + ", ".join(sorted(set(refs))))
            bad = sorted({r for r in refs if r.split(".")[0] in _DANGEROUS_ROOTS})
            if bad and ops & {"REDUCE", "OBJ", "INST", "NEWOBJ", "NEWOBJ_EX"}:
                warn.append("DANGEROUS: would call " + ", ".join(bad) + " when unpickled -> arbitrary code execution")
        warn.append("never pickle.loads() data from an untrusted source")
        lines = buf.getvalue().splitlines()
        text = "\n".join(lines[:300]) + (f"\n... ({len(lines) - 300} more lines)" if len(lines) > 300 else "")
        return Result(text, warnings=warn)


class JavaSerialized(Decoder):
    key = "java"
    name = "Java serialized object (static scan)"
    category = "Serialization"
    description = "Lists class names & strings - NEVER deserializes"

    _GADGET_HINTS = ("org.apache.commons.collections", "org.apache.commons.beanutils", "org.springframework",
                     "com.sun.org.apache.xalan", "org.codehaus.groovy", "com.mchange.v2.c3p0",
                     "org.apache.xbean", "javassist", "bsh.", "org.hibernate", "org.jboss")

    def detect(self, data):
        return 0.95 if data.startswith(b"\xac\xed\x00\x05") else 0.0

    def decode(self, data, opts):
        if not data.startswith(b"\xac\xed\x00\x05"):
            raise DecodeError("missing AC ED 00 05 stream header")
        classes, strs = [], []
        name_re = re.compile(rb"[A-Za-z_\[][\w.$;/\[]*")
        for m in re.finditer(rb"\x72([\x00-\x01][\x00-\xff])", data):  # TC_CLASSDESC
            ln = int.from_bytes(m.group(1), "big")
            nm = data[m.end():m.end() + ln]
            if 1 <= ln <= 300 and len(nm) == ln and name_re.fullmatch(nm):
                classes.append(nm.decode())
        for m in re.finditer(rb"\x74([\x00-\x01][\x00-\xff])", data):  # TC_STRING
            ln = int.from_bytes(m.group(1), "big")
            s = data[m.end():m.end() + ln]
            if 1 <= ln <= 500 and len(s) == ln and all(32 <= b < 127 for b in s):
                strs.append(s.decode())
        out = ["Java Object Serialization stream, version 5",
               "(heuristic scan - field values are not reconstructed)", "", "== CLASSES =="]
        out += [f"  {c}" for c in dict.fromkeys(classes)] or ["  (none found)"]
        out += ["", "== STRING CONSTANTS =="] + ([f"  {s}" for s in strs[:60]] or ["  (none found)"])
        warn = []
        hits = sorted({h for h in self._GADGET_HINTS for c in classes if h in c})
        if hits:
            warn.append("contains classes associated with known gadget chains: " + ", ".join(hits))
        warn.append("never ObjectInputStream.readObject() untrusted data")
        return Result("\n".join(out), warnings=warn)


class _PHP:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def until(self, ch: bytes) -> bytes:
        j = self.b.find(ch, self.i)
        if j < 0:
            raise DecodeError("malformed php serialize")
        s = self.b[self.i:j]
        self.i = j + 1
        return s

    def expect(self, s: bytes):
        if self.b[self.i:self.i + len(s)] != s:
            raise DecodeError(f"expected {s!r} at {self.i}")
        self.i += len(s)

    def string(self):
        n = int(self.until(b":"))
        self.expect(b'"')
        raw = self.b[self.i:self.i + n]
        if len(raw) != n:
            raise DecodeError("string length mismatch")
        self.i += n
        self.expect(b'"')
        return raw.decode("utf-8", "replace").replace("\x00", "\\0")

    def parse(self, depth=0):
        if depth > 100:
            raise DecodeError("too deep")
        t = self.b[self.i:self.i + 1]
        if t == b"N":
            self.expect(b"N;")
            return None
        if t not in (b"i", b"d", b"b", b"s", b"a", b"O"):
            raise DecodeError(f"unsupported type {t!r}")
        self.i += 1
        self.expect(b":")
        try:
            if t == b"i":
                return int(self.until(b";"))
            if t == b"d":
                return float(self.until(b";"))
            if t == b"b":
                return bool(int(self.until(b";")))
            if t == b"s":
                s = self.string()
                self.expect(b";")
                return s
            if t == b"a":
                n = int(self.until(b":"))
                self.expect(b"{")
                if n > len(self.b):
                    raise DecodeError("bad count")
                out = {}
                for _ in range(n):
                    k = self.parse(depth + 1)
                    out[str(k)] = self.parse(depth + 1)
                self.expect(b"}")
                return out
            name = self.string()  # O:
            self.expect(b":")
            n = int(self.until(b":"))
            self.expect(b"{")
            if n > len(self.b):
                raise DecodeError("bad count")
            out = {"__class__": name}
            for _ in range(n):
                k = self.parse(depth + 1)
                out[str(k)] = self.parse(depth + 1)
            self.expect(b"}")
            return out
        except ValueError as e:
            raise DecodeError(str(e))


class PhpSerialized(Decoder):
    key = "php"
    name = "PHP serialize()"
    category = "Serialization"
    description = "Data-only parser, never unserializes"

    def _parse(self, data):
        raw = data.strip()
        if not re.match(rb"^(?:[aOsidb]:[-\d]|N;)", raw) or len(raw) < 4:
            return None
        p = _PHP(raw)
        obj = p.parse()
        if p.i != len(raw):
            raise DecodeError("trailing data")
        return obj

    def detect(self, data):
        try:
            return 0.9 if self._parse(data) is not None or data.strip().startswith(b"N;") else 0.0
        except DecodeError:
            return 0.0

    def decode(self, data, opts):
        obj = self._parse(data)
        warn = []
        if data.strip().startswith(b"O:") or b'O:' in data:
            warn.append("contains objects - unserialize() on untrusted input enables PHP object injection")
        return Result(pretty(obj), warnings=warn)
