"""Command-line + interactive menu."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .banner import AUTHOR, show_banner
from .decoders import BY_KEY, REGISTRY, DecodeError
from .engine import Layer, auto_decode, decode_with, rank
from .term import c

LINE = "─" * 64


# ------------------------------ rendering ------------------------------
def render_layer(idx: int, layer: Layer) -> None:
    d = layer.decoder
    conf = f"  confidence {layer.score:.0%}" if layer.score and layer.score < 1 else ""
    print(c(f"┌─ Layer {idx}: ", "cyan") + c(d.name, "bold", "cyan") + c(conf, "grey"))
    print(c(LINE, "grey"))
    print(layer.result.output)
    for w in layer.result.warnings:
        print(c(f"  ⚠  {w}", "yellow"))
    print(c(LINE, "grey"))


def render_chain(layers: List[Layer]) -> None:
    if len(layers) > 1:
        path = " → ".join(l.decoder.key for l in layers)
        print(c(f"\n  detected chain: {path}\n", "green"))
    for i, layer in enumerate(layers, 1):
        render_layer(i, layer)


def next_input(layers: List[Layer]) -> Optional[bytes]:
    if not layers:
        return None
    last = layers[-1].result
    return last.inner if last.inner is not None else last.output.encode()


# ------------------------------- input ---------------------------------
def read_multiline(prompt: str) -> bytes:
    print(c(prompt + " (finish with an empty line):", "grey"))
    lines = []
    while True:
        try:
            line = input("» ")
        except EOFError:
            break
        if not line.strip() and lines:
            break
        if line.strip():
            lines.append(line)
    return "\n".join(lines).encode()


def read_file(path: str) -> bytes:
    with open(path.strip().strip("'\""), "rb") as f:
        return f.read()


# ---------------------------- interactive UI ---------------------------
def print_decoder_menu() -> None:
    print(c("\n  [0] ", "magenta") + c("AUTO-DETECT (recursive)", "bold", "green"))
    cat = None
    for n, d in enumerate(REGISTRY, 1):
        if d.category != cat:
            cat = d.category
            print(c(f"\n  {cat}", "yellow"))
        print(c(f"  [{n:>2}] ", "magenta") + f"{d.name:<46}" + c(d.description, "grey"))
    print(c("\n  [d] detection report   [c] chain: use last output as input   [i] new input", "grey"))
    print(c("  [s] settings            [q] quit", "grey"))


def settings_menu(opts: dict) -> None:
    print(c("\nSettings", "bold"))
    print(f"  1) Flask secret key : {'(set)' if opts.get('flask_secret') else '(none)'}")
    print(f"  2) Auto max depth   : {opts.get('max_depth', 8)}")
    print("  0) back")
    ch = input("» ").strip()
    if ch == "1":
        opts["flask_secret"] = input("Flask SECRET_KEY (empty to clear): ").strip() or None
    elif ch == "2":
        v = input("Max layers (1-20): ").strip()
        if v.isdigit():
            opts["max_depth"] = max(1, min(20, int(v)))


def detection_report(data: bytes) -> None:
    ranked = rank(data, threshold=0.1)
    print(c("\nDetection report", "bold"))
    if not ranked:
        print("  no decoder recognised this input -> raw inspector will be used")
    for s, d in ranked:
        bar = "█" * int(s * 20)
        print(f"  {s:>4.0%} {c(bar, 'green'):<20} {d.name}")


def acquire_input() -> Optional[bytes]:
    print(c("\nInput source", "bold"))
    print("  [1] Paste text / blob")
    print("  [2] Load file")
    print("  [q] Quit")
    ch = input("» ").strip().lower()
    if ch == "1":
        data = read_multiline("Paste your blob")
        return data or None
    if ch == "2":
        try:
            return read_file(input("File path: "))
        except OSError as e:
            print(c(f"  cannot read file: {e}", "red"))
            return None
    if ch in ("q", "quit", "exit"):
        raise SystemExit(0)
    return None


def interactive(opts: dict) -> int:
    show_banner()
    data: Optional[bytes] = None
    last: List[Layer] = []
    try:
        while True:
            if data is None:
                data = acquire_input()
                if data is None:
                    continue
                last = []
                print(c(f"  loaded {len(data)} bytes", "green"))
            print_decoder_menu()
            ch = input("\nchoose » ").strip().lower()
            if ch in ("q", "quit", "exit"):
                break
            if ch == "i":
                data = None
                continue
            if ch == "s":
                settings_menu(opts)
                continue
            if ch == "d":
                detection_report(data)
                continue
            if ch == "c":
                nxt = next_input(last)
                if nxt is None:
                    print(c("  nothing to chain yet - decode something first", "yellow"))
                else:
                    data = nxt
                    print(c(f"  input replaced with last output ({len(data)} bytes)", "green"))
                continue
            if ch == "0":
                last = auto_decode(data, opts, opts.get("max_depth", 8))
                render_chain(last)
                continue
            if ch.isdigit() and 1 <= int(ch) <= len(REGISTRY):
                dec = REGISTRY[int(ch) - 1]
                try:
                    layer = decode_with(dec.key, data, opts)
                    last = [layer]
                    render_layer(1, layer)
                except DecodeError as e:
                    print(c(f"  ✗ {dec.name} cannot decode this input: {e}", "red"))
                except Exception as e:
                    print(c(f"  ✗ {dec.name} failed: {type(e).__name__}: {e}", "red"))
                continue
            print(c("  invalid choice", "red"))
    except (KeyboardInterrupt, EOFError):
        print()
    print(c(f"\n  stay curious · {AUTHOR}\n", "magenta"))
    return 0


# --------------------------------- CLI ---------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blobreader",
        description="Decode & inspect blobs: tokens, serialized objects, encodings, compression. "
                    "Run without arguments for the interactive menu.",
        epilog=f"by {AUTHOR}",
    )
    p.add_argument("blob", nargs="?", help="blob text, or '-' to read stdin")
    p.add_argument("-f", "--file", help="read the blob from a file (binary safe)")
    p.add_argument("-t", "--type", default="auto",
                   help="decoder key (see --list) or 'auto' (default)")
    p.add_argument("-l", "--list", action="store_true", help="list available decoders")
    p.add_argument("--flask-secret", help="verify Flask cookie signatures with this SECRET_KEY")
    p.add_argument("--max-depth", type=int, default=8, help="max layers in auto mode (default 8)")
    p.add_argument("--no-banner", action="store_true", help="hide the banner")
    p.add_argument("-V", "--version", action="version", version=f"blobreader {__version__} by {AUTHOR}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    opts = {"flask_secret": args.flask_secret, "max_depth": max(1, min(20, args.max_depth))}

    if args.list:
        if not args.no_banner:
            show_banner()
        for d in REGISTRY:
            print(f"{d.key:<10} {d.category:<14} {d.name}")
        return 0

    if args.blob is None and not args.file:
        return interactive(opts)

    if args.file:
        try:
            data = read_file(args.file)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    elif args.blob == "-":
        data = sys.stdin.buffer.read()
    else:
        data = args.blob.encode()

    if not args.no_banner:
        show_banner()

    if args.type == "auto":
        render_chain(auto_decode(data, opts, opts["max_depth"]))
        return 0
    if args.type not in BY_KEY:
        print(f"error: unknown type '{args.type}' (use --list)", file=sys.stderr)
        return 2
    try:
        render_layer(1, decode_with(args.type, data, opts))
    except DecodeError as e:
        print(f"error: cannot decode as {args.type}: {e}", file=sys.stderr)
        return 1
    return 0
