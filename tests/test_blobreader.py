import base64, bz2, gzip, json, pickle, struct, unittest, zlib

from blobreader.engine import auto_decode, decode_with
from blobreader.decoders.tokens import FlaskSession

FLASK = (".eJyrVkpOLCpRsqpWcvZz0_XyidQ1NjBQsjLUAfN9_UJ0DUF8Ix2lYLcQXbeoKF1TqDyIH-wNVG-M4If5hOiaQHh-3rrOQX5gdrhjCJAdrGvog8INhvA8_XSDXDx0zU0N4PxgnzAov1YH7L74zBQlK6Xk-LSUNHNjUwsLCxOlWgCKXC3v."
         "auXl3w.YbEa-4yZE42Ngi0tKByapNbsUUk")


def keys(blob, **kw):
    return [l.decoder.key for l in auto_decode(blob if isinstance(blob, bytes) else blob.encode(), kw)]


class Tests(unittest.TestCase):
    def test_flask_cookie(self):
        layers = auto_decode(FLASK.encode())
        self.assertEqual(layers[0].decoder.key, "flask")
        self.assertIn("c_fdf7358884", layers[0].result.output)

    def test_flask_secret_verification(self):
        value = b"payload.ts"
        sig = FlaskSession.sign("k3y", value)
        self.assertEqual(len(sig), 27)
        self.assertNotEqual(sig, FlaskSession.sign("other", value))

    def test_jwt(self):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        tok = f"{b({'alg': 'none'})}.{b({'sub': 'bob', 'exp': 1})}."
        layer = auto_decode(tok.encode())[0]
        self.assertEqual(layer.decoder.key, "jwt")
        self.assertTrue(any("EXPIRED" in w for w in layer.result.warnings))

    def test_base64_json_chain(self):
        blob = base64.b64encode(json.dumps({"a": [1, 2, 3], "name": "test"}).encode())
        self.assertEqual(keys(blob), ["base64", "json"])

    def test_hex_gzip_json_chain(self):
        blob = gzip.compress(b'{"hello": "world"}').hex()
        self.assertEqual(keys(blob), ["hex", "gzip", "json"])

    def test_zlib_bz2(self):
        self.assertEqual(keys(zlib.compress(b'{"x": 1}'))[:2], ["zlib", "json"])
        self.assertEqual(keys(bz2.compress(b'{"x": 1}'))[:2], ["bzip2", "json"])

    def test_pickle_is_not_executed(self):
        class Evil:
            def __reduce__(self):
                import os
                return (os.system, ("echo pwned",))
        layer = auto_decode(pickle.dumps(Evil(), protocol=4))[0]
        self.assertEqual(layer.decoder.key, "pickle")
        self.assertTrue(any("DANGEROUS" in w for w in layer.result.warnings))

    def test_php(self):
        layer = auto_decode(b'a:2:{s:4:"name";s:3:"bob";s:3:"age";i:30;}')[0]
        self.assertEqual(layer.decoder.key, "php")
        self.assertIn('"age": 30', layer.result.output)

    def test_java_magic(self):
        blob = b"\xac\xed\x00\x05\x73\x72\x00\x0bcom.x.Thing\x00" + b"\x00" * 8
        self.assertEqual(auto_decode(blob)[0].decoder.key, "java")

    def test_msgpack(self):
        blob = bytes([0x82, 0xA1]) + b"a" + bytes([0x01, 0xA1]) + b"b" + bytes([0x93, 1, 2, 3])
        layer = decode_with("msgpack", blob)
        self.assertEqual(json.loads(layer.result.output), {"a": 1, "b": [1, 2, 3]})

    def test_bson(self):
        doc = b"\x10n\x00" + struct.pack("<i", 7)
        blob = struct.pack("<i", len(doc) + 5) + doc + b"\x00"
        self.assertEqual(json.loads(decode_with("bson", blob).result.output), {"n": 7})

    def test_protobuf(self):
        layer = decode_with("protobuf", bytes([0x08, 0x96, 0x01, 0x12, 0x03]) + b"abc")
        self.assertIn("150", layer.result.output)

    def test_url_and_query(self):
        self.assertEqual(keys("a%3D1%26b%3D2")[0], "url")
        self.assertEqual(keys("a=1&b=2")[0], "query")

    def test_fallback_raw(self):
        self.assertEqual(keys(bytes(range(1, 40)))[-1], "raw")

    def test_xml_dtd_refused(self):
        r = decode_with("xml", b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>').result
        self.assertTrue(r.warnings)


if __name__ == "__main__":
    unittest.main()
