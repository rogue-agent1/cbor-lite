#!/usr/bin/env python3
"""cbor_lite: Minimal CBOR (RFC 7049) encoder/decoder."""
import struct, sys

def _encode_head(major, val):
    major <<= 5
    if val <= 23: return bytes([major | val])
    if val <= 0xFF: return bytes([major | 24, val])
    if val <= 0xFFFF: return bytes([major | 25]) + struct.pack(">H", val)
    if val <= 0xFFFFFFFF: return bytes([major | 26]) + struct.pack(">I", val)
    return bytes([major | 27]) + struct.pack(">Q", val)

def encode(obj):
    if obj is None: return b"\xf6"
    if obj is True: return b"\xf5"
    if obj is False: return b"\xf4"
    if isinstance(obj, int):
        if obj >= 0: return _encode_head(0, obj)
        return _encode_head(1, -1 - obj)
    if isinstance(obj, float):
        return b"\xfb" + struct.pack(">d", obj)
    if isinstance(obj, bytes):
        return _encode_head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return _encode_head(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _encode_head(4, len(obj)) + b"".join(encode(i) for i in obj)
    if isinstance(obj, dict):
        return _encode_head(5, len(obj)) + b"".join(encode(k) + encode(v) for k, v in obj.items())
    raise TypeError(f"Cannot encode {type(obj)}")

def _decode_head(data, offset):
    b = data[offset]; major = b >> 5; info = b & 0x1f
    if info <= 23: return major, info, offset+1
    if info == 24: return major, data[offset+1], offset+2
    if info == 25: return major, struct.unpack(">H", data[offset+1:offset+3])[0], offset+3
    if info == 26: return major, struct.unpack(">I", data[offset+1:offset+5])[0], offset+5
    if info == 27: return major, struct.unpack(">Q", data[offset+1:offset+9])[0], offset+9
    raise ValueError(f"Unknown additional info {info}")

def decode(data, offset=0):
    b = data[offset]
    if b == 0xf6: return None, offset+1
    if b == 0xf5: return True, offset+1
    if b == 0xf4: return False, offset+1
    if b == 0xfb: return struct.unpack(">d", data[offset+1:offset+9])[0], offset+9
    major, val, offset = _decode_head(data, offset)
    if major == 0: return val, offset
    if major == 1: return -1 - val, offset
    if major == 2: return data[offset:offset+val], offset+val
    if major == 3: return data[offset:offset+val].decode(), offset+val
    if major == 4:
        result = []
        for _ in range(val):
            item, offset = decode(data, offset)
            result.append(item)
        return result, offset
    if major == 5:
        result = {}
        for _ in range(val):
            k, offset = decode(data, offset)
            v, offset = decode(data, offset)
            result[k] = v
        return result, offset
    raise ValueError(f"Unknown major type {major}")

def test():
    for val in [0, 1, 23, 24, 255, 256, 65535, 65536, -1, -100]:
        assert decode(encode(val))[0] == val
    assert decode(encode(None))[0] is None
    assert decode(encode(True))[0] is True
    assert decode(encode(False))[0] is False
    assert abs(decode(encode(3.14))[0] - 3.14) < 1e-9
    assert decode(encode("hello"))[0] == "hello"
    assert decode(encode(b"\x01\x02"))[0] == b"\x01\x02"
    assert decode(encode([1, "two", 3]))[0] == [1, "two", 3]
    assert decode(encode({"a": 1, "b": [2, 3]}))[0] == {"a": 1, "b": [2, 3]}
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test": test()
    else: print("Usage: cbor_lite.py test")
