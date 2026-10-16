# Frozen Enhance record oracle

Source: the public transaction in `ironwood-fee-expiry.hex`; its original retrieval
provenance is recorded in `ironwood-fee-expiry.md`. The transaction contains two
Ironwood actions and no transparent, Sapling or Orchard activity.

`ironwood-record-oracle.json` binds the raw transaction SHA-256 and transaction ID
to two 737-byte record fixtures. Each record concatenates ephemeral key (32),
encrypted note (580), value commitment (32), outgoing ciphertext (80), flags (1),
expiry height (4), and fee (8). Flag 4 means fee present. Expiry bytes are at raw
offset 16; the Ironwood-only value balance/fee is at offset 1667. All integers
retain the transaction's little-endian encoding.

Action field offsets were initially located using the pinned Zakura parser and
matched uniquely in the raw transaction. The frozen records themselves were
assembled by direct byte slicing, without the Enhance record serializer. The
integration test independently reconstructs those slices and checks the pinned
hashes, parser-produced fields, metadata and PIR-returned bytes.

This is a fixed transaction-byte oracle, not a second transaction parser or a
proof of canonical-chain inclusion. The HTTP fixture assigns synthetic positions
32 and 33 and uses synthetic journal block hashes. No private viewing keys are
available for these public notes; authenticated note recovery is tested separately
with constructed test notes. Do not describe this fixture as a full wallet
conformance certificate.
