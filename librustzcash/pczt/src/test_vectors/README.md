The two `serde_arrays_*.bin` fixtures record the existing Postcard encoding of
the fixed byte arrays used by PCZT. They were checked against `serde_with`
before replacing its adapters. These are serialization fixtures, not valid
transaction proofs or signatures.

The populated fixture (697 bytes) contains, in order:

- A 64-byte tuple whose byte at index `i` is `(17 * i + 1) % 256`.
- Present optional tuples of lengths 32, 43, 64, 96 and 192, using the same
  pattern with offsets 2, 3, 4, 5 and 6 respectively.
- A two-entry map sorted by its 33-byte keys. The first key repeats byte 1
  and its 129-byte vector value is `(3 * i) % 256`. The second key repeats
  byte 254 and its value is `[128, 255]`.

The absent fixture (70 bytes) contains the same initial tuple, five absent
options and an empty map. Tuples have no length prefix, each option has its
usual one-byte discriminant, and map/vector lengths use Postcard varints.
