# Transparent PQ wallet spends

`transparent-pq-wallet` turns keys from [`transparent-pq-keys`](../transparent-pq-keys/README.md)
into P2SH addresses and builds signed transactions that spend them, with fresh change
from [`transparent-pq-pool`](../transparent-pq-pool/README.md). It uses Common's PQ
P2SH rules (Common PR #650, pinned by this workspace while Common 5 is unpublished), so
the transactions it builds are the ones a node with those rules accepts. It is
unpublished.

## Addresses

Each key gets its own single-signer script:

```text
body   = <public key> OP_CHECKSIG          # direct push: 0x20 for 128f, 0x30 for 192s
redeem = 50 02 'P' 'Q' 01 <version> body   # Common's PQ header; version 1 = 128f, 2 = 192s
output = OP_HASH160 HASH160(redeem) OP_EQUAL
```

The sender sees an ordinary P2SH address. The body's exact bytes are part of the wallet's
recovery contract: the address commits to them through HASH160, so restoring a key only
finds its funds if the same template is rebuilt. This crate fixes the template above;
changing it would change every address.

## Spending

`build_spend` spends caller-chosen PQ outputs to the requested payments:

1. **Fee.** ZIP 317 from exact sizes. Each PQ input is its outpoint, its sequence, and a
   scriptSig of `PUSHDATA2(signature ‖ 0x01)` followed by `PUSHDATA2(redeem)`, whose
   size is fixed by the parameter set. Common's fee code cannot size these inputs
   itself, so the builder passes the sizes in.
2. **Change.** What remains after payments and fee goes to the next change key from the
   pool, so a later spend of that change uses a key that has not signed before. Change
   below the node's dust threshold (54 zatoshis for a P2SH output) is left to the fee
   instead. If the pool has no fresh change key, the last one is reused and the result
   says so.
3. **Signing.** One call to a `PqSigner` carries the unsigned transaction, which key
   spends each input, which outputs are the wallet's own change, and the key ranges the
   pool wants refilled. The signer returns one signature per input and the refilled
   public keys; the builder adds those to the pool.
4. **Checks.** Each finished input is verified with Common's PQ P2SH verifier before the
   transaction is returned, and the fee is recomputed from the serialized inputs.

Transactions are version 5 and every input signs with `SIGHASH_ALL`. Inputs may mix
parameter sets and accounts.

## The signer and hardware

A signer receives the transaction, not digests, and computes each signature hash
itself, which is what a hardware device has to do before it signs. It also checks that
every input and every change output belongs to one of its keys. Signing, change
rotation, and refilling the pool happen in the same call, matching the design's single
hardware interaction during a spend.

`SeedSigner` is the software signer: it derives each key from the wallet seed, checks
ownership, signs with Common's PQ signing context, and derives the refill keys. A
hardware signer would implement the same trait over a device transport; that and a
transport encoding of the request are not part of this crate.

## Not built here

Choosing which outputs to spend, tracking outputs in the wallet database, broadcasting,
PCZT, a hardware signer, multisig, signing modes other than `SIGHASH_ALL`, and network
activation checks.

## Validation

From the repository root:

```sh
python3 scripts/dev.py test --config transparent-pq-wallet
python3 scripts/dev.py lint --config transparent-pq-wallet
```
