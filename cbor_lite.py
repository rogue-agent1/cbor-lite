#!/usr/bin/env python3
"""cbor_lite - Minimal CBOR (RFC 7049) encoder and decoder."""
import sys, struct

def encode(val):
    if val is None: return b"\xf6"
    if val is True: return b"\xf5"
    if val is False: return b"\xf4"
    if isinstance(val, int):
        if val >= 0: return _encode_uint(0, val)
        return _encode_uint(1, -1 - val)
    if isinstance(val, bytes): return _encode_uint(2, len(val)) + val
    if isinstance(val, str):
        b = val.encode("utf-8")
        return _encode_uint(3, len(b)) + b
    if isinstance(val, list):
        return _encode_uint(4, len(val)) + b"".join(encode(v) for v in val)
    if isinstance(val, dict):
        return _encode_uint(5, len(val)) + b"".join(encode(k) + encode(v) for k, v in val.items())
    raise TypeError(f"Cannot encode {type(val)}")

def _encode_uint(major, n):
    major <<= 5
    if n < 24: return bytes([major | n])
    if n < 256: return bytes([major | 24, n])
    if n < 65536: return bytes([major | 25]) + struct.pack(">H", n)
    if n < 2**32: return bytes([major | 26]) + struct.pack(">I", n)
    return bytes([major | 27]) + struct.pack(">Q", n)

def decode(data):
    val, _ = _decode(data, 0)
    return val

def _decode(data, i):
    b = data[i]; major = b >> 5; info = b & 0x1f
    if b == 0xf4: return False, i+1
    if b == 0xf5: return True, i+1
    if b == 0xf6: return None, i+1
    n, i = _decode_uint(data, i)
    if major == 0: return n, i
    if major == 1: return -1 - n, i
    if major == 2: return data[i:i+n], i+n
    if major == 3: return data[i:i+n].decode("utf-8"), i+n
    if major == 4:
        lst = []
        for _ in range(n): v, i = _decode(data, i); lst.append(v)
        return lst, i
    if major == 5:
        d = {}
        for _ in range(n): k, i = _decode(data, i); v, i = _decode(data, i); d[k] = v
        return d, i
    raise ValueError(f"Unknown major {major}")

def _decode_uint(data, i):
    info = data[i] & 0x1f; i += 1
    if info < 24: return info, i
    if info == 24: return data[i], i+1
    if info == 25: return struct.unpack(">H", data[i:i+2])[0], i+2
    if info == 26: return struct.unpack(">I", data[i:i+4])[0], i+4
    if info == 27: return struct.unpack(">Q", data[i:i+8])[0], i+8
    return 0, i

def test():
    for val in [0, 1, 23, 24, 255, 1000, -1, -100, True, False, None,
                "hello", b"\x01\x02", [1, 2, 3], {"a": 1}]:
        assert decode(encode(val)) == val, f"Failed for {val!r}"
    nested = {"nums": [1, 2], "flag": True, "name": "test"}
    assert decode(encode(nested)) == nested
    print("cbor_lite: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: cbor_lite.py --test")
