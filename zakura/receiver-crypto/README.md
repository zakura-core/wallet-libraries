# Receiver directory validation

A receiver directory serves, over PIR, the payments that were sent to each Ironwood
receiver with the public all-zero outgoing viewing key, and one common file of
Merkle siblings proving those payments' note commitments. Serving packages consume
this library-owned format. The raw codec and cryptographic acceptance checks
remain distinct:

- `Receiver` accepts only bytes that decode to an Ironwood address.
- `wire::RawRecord` reads and writes the fixed row format, checking structure only.
- `Record` uses the same codec and refuses noncanonical note commitments and
  nullifiers and invalid ephemeral keys. Only an entirely zero slot is empty.
- `recovery::Action` recovers the receiver of a zero-OVK Action, authenticating
  the note plaintext.
- `witness` builds the common `IWPROOF1` proof file from a commitment history, and
  checks a downloaded one against a publication. A proof root is never trusted on
  its own: callers compare it with their own chain.

`witness::Publication` carries the manifest fields a proof binds to. Callers
validate the manifest and compute its revision with the receiver protocol package
before building one.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test -p zakura-receiver-crypto
```

The default `crypto` feature enables address, record and proof validation. A PIR
protocol consumer that only transports records can use `default-features = false`
and `wire::{RawRecord, Payment, RECORD_BYTES}` without any cryptography or node
dependencies. The raw codec never grants a payment cryptographic validity.

```sh
python3 scripts/dev.py test --config receiver-wire
```
