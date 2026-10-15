# Receiver directory validation

A receiver directory serves, over PIR, the payments that were sent to each Ironwood
receiver with the public all-zero outgoing viewing key, and one common file of
Merkle siblings proving those payments' note commitments. The wallet-pir packages
that serve them move bytes without interpreting them. This crate decides what is
trusted:

- `Receiver` accepts only bytes that decode to an Ironwood address.
- `Record` reads and writes one row slot through `receiver-wire`, the sole record
  codec, and refuses noncanonical note commitments and nullifiers and invalid
  ephemeral keys. Only an entirely zero slot is empty.
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
