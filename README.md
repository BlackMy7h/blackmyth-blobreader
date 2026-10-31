```
    ____  __           __   __  ___     _______
   / __ )/ /___ ______/ /__/  |/  /_  _/__  / /_
  / __  / / __ `/ ___/ //_/ /|_/ / / / / / / __ \
 / /_/ / / /_/ / /__/ ,< / /  / / /_/ / / / / / /
/_____/_/\__,_/\___/_/|_/_/  /_/\__, / /_/_/ /_/
                               /____/
```

# BlobReader

**Decode and inspect almost any blob from one tool.** Paste a cookie, token, serialized object or random encoded string, pick a format from the menu, or let auto-detect peel the layers for you.

Crafted by **BlackMy7h**. Pure Python standard library, with no required dependencies.

> **Decode only, never execute.** Pickle is disassembled (never unpickled), Java streams are statically scanned (never deserialized), PHP `serialize()` is parsed by a data-only parser, XML with DTD/entities is refused, and decompression is size-capped.

## Supported formats

| Category | Formats |
|---|---|
| Tokens / cookies | JWT/JWS/JWE, **Flask session** (with optional signature check), Django signed values |
| Serialization | Python pickle, Java serialized objects, PHP `serialize()`, Protocol Buffers (schema-less) |
| Structured | JSON, XML, Apple plist (XML + binary), YAML (`safe_load`), MessagePack, BSON |
| Compression | gzip, zlib/deflate, bzip2, xz/lzma, ZIP (listing only) |
| Encodings | Base64/Base64URL, hex, URL-encoding, query strings |
| Fallback | Magic-byte ID, entropy, hexdump, strings |

## Install

```bash
git clone https://github.com/BlackMy7h/blobreader.git
cd blobreader
pip install .            # or: pip install -e .
# optional: pip install ".[yaml]"
```

Or run it without installing: `python -m blobreader`

## Usage

### Interactive menu

```bash
blobreader
```

1. Paste a blob (finish with an empty line) or load a file.
2. Choose `[0]` for **auto-detect**, or a number for a specific decoder.
3. `d` shows a detection report, `c` chains the last output in as the new input, `s` opens settings, and `i` loads a new input.

### One-shot CLI

```bash
blobreader "<blob>"                       # auto-detect, recursive
blobreader -t flask "<cookie>"            # force a decoder
blobreader -f dump.bin                    # read from a file
cat blob.txt | blobreader -               # read from stdin
blobreader --flask-secret 'key' "<cookie>"  # check a Flask signature
blobreader --list                         # list decoder keys
```

### Auto-detect example

```
$ blobreader "H4sIAAAAAAAA..."        # hex(gzip(json)) or base64(gzip(json)) etc.
  detected chain: base64 → gzip → json
```

## How auto-detect works

Every decoder scores how likely the input is to be its format (0 to 1). The best match decodes the blob. If it produces inner bytes (base64, hex, gzip, URL-encoding...), the result is fed back in, up to `--max-depth` layers. When nothing matches, the raw inspector shows the entropy, magic bytes, hexdump and strings.

## Adding a decoder

Subclass `Decoder` in `blobreader/decoders/`, implement `detect()` and `decode()`, then add it to `REGISTRY` in `blobreader/decoders/__init__.py`.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Responsible use

Use this tool on data you own or are authorized to assess. Decoding is not authorization to tamper with other people's systems.

---
<sub>© 2026 BlackMy7h, MIT licensed.</sub>
