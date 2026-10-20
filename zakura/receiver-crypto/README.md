# Receiver directory validation

A receiver directory serves, over PIR, the payments that were sent to each Ironwood
receiver with the public all-zero outgoing viewing key, and for each payment table a
companion witness table of lower Merkle paths proving those payments' note
commitments. Serving packages consume this library-owned format. The raw codec and
cryptographic acceptance checks remain distinct:

- `Receiver` accepts only bytes that decode to an Ironwood address.
- `wire::RawRecord` reads and writes the fixed 289-byte record, checking structure only.
  Its `ordinal` selects the payment's slot in the companion witness table of the payment
  table that carried it, and means nothing under any other table.
- `wire::{decode_payload, encode_payload, supplied, is_final}` define the 512-byte
  witness payload: a payment's sixteen siblings inside its Ironwood shard, supplied only
  where complete at the table's construction tree size, every other slot zero.
- `Record` uses the same codec and refuses noncanonical note commitments and
  nullifiers and invalid ephemeral keys. Only an entirely zero slot is empty.
- `recovery::Action` recovers the receiver of a zero-OVK Action, authenticating
  the note plaintext.
- `witness::ShardPaths` builds payloads from one Ironwood shard's commitments and
  extends incrementally as the shard fills; `witness::payloads` rebuilds them from a
  commitment prefix. A payload is never trusted on its own: the wallet reconstructs the
  rest of the path from its own tree and checks it against its own root.
- `witness::{combine, empty_root}` provides checked byte-array hashing for
  external tree layouts: combine levels are 0 through 31, empty-root heights
  are 0 through 32, and malformed node encodings are refused.

A payload whose shard is still filling is provisional: it is usable only with the
wallet's tree at exactly the construction block. Once the shard is full the payload is
final on that chain and usable at any later accepted anchor.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test -p zakura-receiver-crypto
```

The default `crypto` feature enables address, record and proof validation. A PIR
protocol consumer that only transports records can use `default-features = false`
and `wire::{RawRecord, Payment, RECORD_BYTES, PAYLOAD_BYTES}` without any cryptography or node
dependencies. The raw codec never grants a payment cryptographic validity.

```sh
python3 scripts/dev.py test --config receiver-wire
```
