#!/usr/bin/env python3
"""Print v1 dynamic key rivk vectors using Python BLAKE2b and integer reduction.

The account is the first public Orchard key-component test vector shipped in
zakura-orchard, src/test_vectors/keys.rs. No wallet secrets are used.
Run from the crate directory: python3 tests/vectors/generate.py
"""

import hashlib
import struct

AK = bytes.fromhex("740bbe5d0580b2cad430180d02cc128b9a140d5e07c151721dc16d25d4e20f15")
NK = bytes.fromhex("9f2f826738945ad01f47f70db0c367c246c20c61ff5583948c39dea968fefd1b")
RIVK = bytes.fromhex("021ccf89604f5f7cc6e034b32d338908b819fbe325fee6458b56b4ca71a7e43d")
INTERNAL_RIVK = "901a30b99ae1570cb80bb616aeef3bb916c640c4cc620f9b4b4499c74332eb2a"
SWAP_RIVK_DOMAIN = 0x85
PALLAS_SCALAR_ORDER = int(
    "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16
)


def expand_rivk(domain, suffix):
    """ToScalar(PRF^expand_rivk([domain] || ak || nk || suffix)), as ZIP 32."""
    digest = hashlib.blake2b(
        RIVK + bytes([domain]) + AK + NK + suffix,
        digest_size=64,
        person=b"Zcash_ExpandSeed",
    ).digest()
    scalar = int.from_bytes(digest, "little") % PALLAS_SCALAR_ORDER
    return scalar.to_bytes(32, "little").hex()


# The same construction with ZIP 32's internal byte must give the vector's internal rivk.
assert expand_rivk(0x83, b"") == INTERNAL_RIVK

print("purpose,index,rivk")
for purpose, code in (("refund", 0), ("receive", 1)):
    for index in (0, 1, 2**64 - 1):
        print(f"{purpose},{index},{expand_rivk(SWAP_RIVK_DOMAIN, struct.pack('<BQ', code, index))}")
