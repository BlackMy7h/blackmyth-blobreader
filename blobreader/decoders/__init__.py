from .base import DecodeError, Decoder, Result
from .compression import Bzip2, Gzip, Lzma, Zip, Zlib
from .encodings import Base64, Hex, QueryString, UrlEncoded
from .inspector import Inspector
from .protobuf import Protobuf
from .serialization import JavaSerialized, PhpSerialized, Pickle
from .structured import Bson, Json, MessagePack, Plist, Xml, Yaml
from .tokens import DjangoSigned, FlaskSession, Jwt

REGISTRY = [
    # tokens first (most specific)
    Jwt(), FlaskSession(), DjangoSigned(),
    # serialization
    Pickle(), JavaSerialized(), PhpSerialized(), Protobuf(),
    # structured
    Json(), Plist(), Xml(), MessagePack(), Bson(), Yaml(),
    # compression
    Gzip(), Zlib(), Bzip2(), Lzma(), Zip(),
    # encodings
    Base64(), Hex(), UrlEncoded(), QueryString(),
    # fallback
    Inspector(),
]
BY_KEY = {d.key: d for d in REGISTRY}

__all__ = ["REGISTRY", "BY_KEY", "Decoder", "Result", "DecodeError"]
