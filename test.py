from cbor_lite import dumps, loads
for obj in [None, True, False, 0, 42, -1, "hello", b"\x01", [1,2,3], {"a": 1}]:
    r = loads(dumps(obj))
    assert r == obj, f"Failed for {obj}: got {r}"
print("CBOR tests passed")