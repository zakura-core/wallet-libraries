#!/usr/bin/env python3
"""Print draft v1 rivk vectors using Python HMAC and integer reduction.

The parent rivk is the first public Orchard key-component test vector shipped
in zakura-orchard 1.2.0, src/test_vectors/keys.rs. No wallet secrets are used.
Run from the crate directory: python3 tests/vectors/generate.py
"""

import hashlib
import hmac
import struct

KEY = bytes.fromhex("021ccf89604f5f7cc6e034b32d338908b819fbe325fee6458b56b4ca71a7e43d")
PALLAS_SCALAR_ORDER = int(
    "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16
)

print("purpose,index,attempt,rivk")
for purpose in ("refund", "receive"):
    label = f"swap-{purpose}-v1".encode("ascii")
    for index, attempt in ((0, 0), (1, 0), (2**64 - 1, 0), (0, 1)):
        data = bytes([len(label)]) + label + struct.pack("<QI", index, attempt)
        digest = hmac.new(KEY, data, hashlib.sha512).digest()
        scalar = int.from_bytes(digest, "little") % PALLAS_SCALAR_ORDER
        print(f"{purpose},{index},{attempt},{scalar.to_bytes(32, 'little').hex()}")
