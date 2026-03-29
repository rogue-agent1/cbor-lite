#!/usr/bin/env python3
"""Minimal CBOR encoder/decoder (RFC 7049)."""
import struct, math

def _encode_head(major, value):
    major <<= 5
    if value <= 23: return bytes([major | value])
    if value <= 0xff: return bytes([major | 24, value])
    if value <= 0xffff: return bytes([major | 25]) + struct.pack(">H", value)
    if value <= 0xffffffff: return bytes([major | 26]) + struct.pack(">I", value)
    return bytes([major | 27]) + struct.pack(">Q", value)

def encode(obj) -> bytes:
    if obj is None: return b"\xf6"
    if obj is True: return b"\xf5"
    if obj is False: return b"\xf4"
    if isinstance(obj, int):
        if obj >= 0: return _encode_head(0, obj)
        return _encode_head(1, -1 - obj)
    if isinstance(obj, float):
        return b"\xfb" + struct.pack(">d", obj)
    if isinstance(obj, str):
        b = obj.encode()
        return _encode_head(3, len(b)) + b
    if isinstance(obj, bytes):
        return _encode_head(2, len(obj)) + obj
    if isinstance(obj, (list, tuple)):
        return _encode_head(4, len(obj)) + b"".join(encode(i) for i in obj)
    if isinstance(obj, dict):
        return _encode_head(5, len(obj)) + b"".join(encode(k) + encode(v) for k, v in obj.items())
    raise TypeError(f"Cannot CBOR encode {type(obj)}")

def decode(data: bytes):
    val, _ = _decode(data, 0)
    return val

def _decode(data, pos):
    b = data[pos]; major = b >> 5; info = b & 0x1f; pos += 1
    # Major 7 special values
    if major == 7:
        if info == 20: return False, pos
        if info == 21: return True, pos
        if info == 22: return None, pos
        if info == 27:  # float64
            return struct.unpack(">d", data[pos:pos+8])[0], pos + 8
        if info == 26:  # float32
            return struct.unpack(">f", data[pos:pos+4])[0], pos + 4
        raise ValueError(f"Unsupported CBOR simple value {info}")
    # Read additional info as unsigned integer
    if info <= 23: value = info
    elif info == 24: value = data[pos]; pos += 1
    elif info == 25: value = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
    elif info == 26: value = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
    elif info == 27: value = struct.unpack(">Q", data[pos:pos+8])[0]; pos += 8
    else: raise ValueError(f"Unknown additional info {info}")
    if major == 0: return value, pos
    if major == 1: return -1 - value, pos
    if major == 2: return data[pos:pos+value], pos + value
    if major == 3: return data[pos:pos+value].decode(), pos + value
    if major == 4:
        items = []
        for _ in range(value): v, pos = _decode(data, pos); items.append(v)
        return items, pos
    if major == 5:
        d = {}
        for _ in range(value): k, pos = _decode(data, pos); v, pos = _decode(data, pos); d[k] = v
        return d, pos
    raise ValueError(f"Unsupported CBOR major={major}")
    raise ValueError(f"Unsupported CBOR major={major} value={value}")

if __name__ == "__main__":
    obj = {"name": "test", "values": [1, -2, 3.14, True, None]}
    enc = encode(obj)
    print(f"Encoded ({len(enc)} bytes): {enc.hex()}")
    print(f"Decoded: {decode(enc)}")

def test():
    for obj in [0, 1, 23, 24, 255, 256, 65535, -1, -100, True, False, None,
                3.14, "", "hello", b"bytes", [], [1,2,3], {}, {"a": 1}]:
        result = decode(encode(obj))
        if isinstance(obj, float):
            assert abs(result - obj) < 1e-10
        else:
            assert result == obj, f"Failed for {obj!r}: got {result!r}"
    # Nested
    nested = {"list": [1, "two", {"three": 3}]}
    assert decode(encode(nested)) == nested
    print("  cbor_lite: ALL TESTS PASSED")
