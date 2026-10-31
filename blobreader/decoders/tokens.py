"""Signed tokens / cookies: JWT, Flask session, Django signed values."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import zlib

from ..utils import as_text, b64_decode_loose, human_time, pretty
from .base import DecodeError, Decoder, Result

_B64URL = re.compile(r"^[A-Za-z0-9_\-]*$")
_MAX_INFLATE = 5 * 1024 * 1024


def _inflate(raw: bytes) -> bytes:
    d = zlib.decompressobj()
    out = d.decompress(raw, _MAX_INFLATE)
    if d.unconsumed_tail:
        raise DecodeError("compressed payload too large")
    return out


class Jwt(Decoder):
    key = "jwt"
    name = "JWT / JWS / JWE"
    category = "Token"
    description = "JSON Web Tokens (decode only, signature NOT verified)"

    def _parse(self, data):
        t = as_text(data)
        if not t or " " in t:
            return None
        if t.lower().startswith("bearer "):
            t = t[7:]
        parts = t.split(".")
        if len(parts) not in (3, 5) or not all(_B64URL.match(p) for p in parts) or not parts[0]:
            return None
        try:
            header = json.loads(b64_decode_loose(parts[0]))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(header, dict) or "alg" not in header:
            return None
        return header, parts

    def detect(self, data):
        return 0.97 if self._parse(data) else 0.0

    def decode(self, data, opts):
        parsed = self._parse(data)
        if not parsed:
            raise DecodeError("not a JWT")
        header, parts = parsed
        warn, out = [], ["== HEADER ==", pretty(header)]
        if len(parts) == 5:
            out.append("\n== JWE == payload is encrypted; only the header is readable")
            return Result("\n".join(out), warnings=warn)
        try:
            payload = json.loads(b64_decode_loose(parts[1]))
            out += ["\n== PAYLOAD ==", pretty(payload)]
            if isinstance(payload, dict):
                times = [f"  {k}: {human_time(payload[k])}" for k in ("iat", "nbf", "exp") if k in payload]
                if times:
                    out += ["\n== TIMES =="] + times
                exp = payload.get("exp")
                if isinstance(exp, (int, float)) and exp < time.time():
                    warn.append("token is EXPIRED")
        except (ValueError, UnicodeDecodeError):
            out += ["\n== PAYLOAD (raw) ==", b64_decode_loose(parts[1]).hex()]
        sig = b64_decode_loose(parts[2]) if parts[2] else b""
        out += ["\n== SIGNATURE ==", f"{len(sig)} bytes  {sig.hex()}" if sig else "(empty)"]
        if str(header.get("alg", "")).lower() == "none":
            warn.append('alg is "none" - token is unsigned')
        warn.append("signature was not verified")
        return Result("\n".join(out), warnings=warn)


class FlaskSession(Decoder):
    key = "flask"
    name = "Flask session cookie"
    category = "Token"
    description = "itsdangerous-signed cookie; optional --flask-secret signature check"

    def _parse(self, data):
        t = as_text(data)
        if not t or " " in t:
            return None
        compressed = t.startswith(".")
        parts = (t[1:] if compressed else t).split(".")
        if len(parts) != 3:
            return None
        payload, ts, sig = parts
        if not (1 <= len(ts) <= 8 and len(sig) == 27 and all(_B64URL.match(p) for p in parts)):
            return None
        try:
            raw = b64_decode_loose(payload)
            if compressed:
                raw = _inflate(raw)
            obj = json.loads(raw)
            ts_int = int.from_bytes(b64_decode_loose(ts), "big")
        except (ValueError, UnicodeDecodeError, zlib.error, DecodeError):
            return None
        return {"obj": obj, "ts": ts_int, "sig": sig, "compressed": compressed,
                "signed": f"{payload}.{ts}".encode()}

    def detect(self, data):
        return 0.95 if self._parse(data) else 0.0

    @staticmethod
    def sign(secret: str, value: bytes) -> str:
        key = hmac.new(secret.encode(), b"cookie-session", hashlib.sha1).digest()
        digest = hmac.new(key, value, hashlib.sha1).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def decode(self, data, opts):
        p = self._parse(data)
        if not p:
            raise DecodeError("not a Flask session cookie")
        warn = []
        out = ["== SESSION DATA ==", pretty(p["obj"]),
               "\n== META ==",
               f"signed at : {human_time(p['ts'])}",
               f"compressed: {p['compressed']}",
               f"signature : {p['sig']}  (HMAC-SHA1)"]
        secret = opts.get("flask_secret")
        if secret:
            ok = hmac.compare_digest(self.sign(secret, p["signed"]), p["sig"])
            out.append(f"verified  : {'YES - secret key matches' if ok else 'NO - secret key does not match'}")
        else:
            warn.append("signature not verified (pass --flask-secret KEY to check)")
        warn.append("Flask cookies are signed, not encrypted - never store secrets in them")
        return Result("\n".join(out), warnings=warn)


_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class DjangoSigned(Decoder):
    key = "django"
    name = "Django signed value"
    category = "Token"
    description = "django.core.signing dumps(): payload:timestamp:signature"

    _RE = re.compile(r"^(\.?)([A-Za-z0-9_\-]+):([0-9A-Za-z]+):([A-Za-z0-9_\-]+)$")

    def _parse(self, data):
        t = as_text(data)
        m = self._RE.match(t) if t else None
        if not m:
            return None
        comp, payload, ts, sig = m.groups()
        try:
            raw = b64_decode_loose(payload)
            if comp:
                raw = _inflate(raw)
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError, zlib.error, DecodeError):
            return None
        n = 0
        for ch in ts:
            n = n * 62 + _B62.index(ch)
        return obj, n, sig, bool(comp)

    def detect(self, data):
        return 0.9 if self._parse(data) else 0.0

    def decode(self, data, opts):
        p = self._parse(data)
        if not p:
            raise DecodeError("not a Django signed value")
        obj, ts, sig, comp = p
        out = ["== DATA ==", pretty(obj), "\n== META ==",
               f"signed at : {human_time(ts)}", f"compressed: {comp}", f"signature : {sig}"]
        return Result("\n".join(out), warnings=["signature not verified"])
