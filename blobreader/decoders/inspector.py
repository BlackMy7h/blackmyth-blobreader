from __future__ import annotations

from ..utils import (as_text, entropy, extract_strings, hexdump,
                     identify_magic, printable_ratio)
from .base import Decoder, Result


class Inspector(Decoder):
    key = "raw"
    name = "Raw inspector (magic / entropy / hexdump / strings)"
    category = "Fallback"
    description = "Always works - used when nothing else matches"

    def detect(self, data):
        return 0.05  # never picked by auto-detect ranking; used as the final fallback

    def decode(self, data, opts):
        e = entropy(data)
        hint = ("likely encrypted or compressed" if e > 7.5
                else "structured binary" if e > 5 else "low entropy / text-like")
        out = [f"Size   : {len(data)} bytes", f"Entropy: {e:.2f} bits/byte ({hint})"]
        magic = identify_magic(data)
        if magic:
            out.append(f"Magic  : {magic}")
        txt = as_text(data)
        if txt is not None and printable_ratio(data) > 0.9:
            out += ["", "== PLAIN TEXT ==", txt[:4000] + ("..." if len(txt) > 4000 else "")]
        else:
            out += ["", "== HEXDUMP ==", hexdump(data)]
            strs = extract_strings(data)
            if strs:
                out += ["", "== STRINGS =="] + [f"  {s}" for s in strs]
        warn = []
        if e > 7.5 and not magic:
            warn.append("high entropy with no known header: probably ciphertext, a hash, or compressed data")
        return Result("\n".join(out), warnings=warn)
