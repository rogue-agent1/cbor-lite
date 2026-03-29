#!/usr/bin/env python3
"""CBOR encoder/decoder (subset). Zero dependencies."""
import struct, sys

def encode(obj):
    if obj is None: return b"\xf6"
    if isinstance(obj, bool): return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        if obj >= 0: return _encode_uint(0, obj)
        return _encode_uint(1, -1-obj)
    if isinstance(obj, float): return b"\xfb" + struct.pack(">d", obj)
    if isinstance(obj, bytes): return _encode_uint(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode(); return _encode_uint(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _encode_uint(4, len(obj)) + b"".join(encode(i) for i in obj)
    if isinstance(obj, dict):
        return _encode_uint(5, len(obj)) + b"".join(encode(k)+encode(v) for k,v in obj.items())
    raise TypeError(f"Cannot CBOR encode {type(obj)}")

def _encode_uint(major, value):
    major <<= 5
    if value <= 23: return bytes([major | value])
    if value <= 0xFF: return bytes([major | 24]) + struct.pack("B", value)
    if value <= 0xFFFF: return bytes([major | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF: return bytes([major | 26]) + struct.pack(">I", value)
    return bytes([major | 27]) + struct.pack(">Q", value)

def decode(data, offset=0):
    b = data[offset]; major = b >> 5; info = b & 0x1f; offset += 1
    if info <= 23: value = info
    elif info == 24: value = data[offset]; offset += 1
    elif info == 25: value = struct.unpack_from(">H", data, offset)[0]; offset += 2
    elif info == 26: value = struct.unpack_from(">I", data, offset)[0]; offset += 4
    elif info == 27: value = struct.unpack_from(">Q", data, offset)[0]; offset += 8
    else: value = 0
    if major == 0: return value, offset
    if major == 1: return -1-value, offset
    if major == 2: return data[offset:offset+value], offset+value
    if major == 3: return data[offset:offset+value].decode(), offset+value
    if major == 4:
        items = []
        for _ in range(value): v, offset = decode(data, offset); items.append(v)
        return items, offset
    if major == 5:
        d = {}
        for _ in range(value): k, offset = decode(data, offset); v, offset = decode(data, offset); d[k] = v
        return d, offset
    if major == 7:
        if info == 20: return False, offset
        if info == 21: return True, offset
        if info == 22: return None, offset
        if info == 27: return struct.unpack_from(">d", data, offset-8)[0], offset
    return None, offset

def loads(data): return decode(data, 0)[0]
def dumps(obj): return encode(obj)

if __name__ == "__main__":
    obj = {"key": "value", "num": 42, "list": [1, 2, 3]}
    enc = dumps(obj)
    print(f"CBOR: {enc.hex()} ({len(enc)} bytes)")
    dec = loads(enc)
    print(f"Decoded: {dec}")
