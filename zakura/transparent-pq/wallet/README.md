# Transparent PQ wallet spends

`transparent-pq-wallet` turns keys from [`transparent-pq-keys`](../keys/README.md)
into post-quantum transparent destinations, publishes them in a Unified Address, and builds
signed transactions that spend them, with fresh change from
[`transparent-pq-pool`](../pool/README.md). It uses Common's PQ output rules
(Common PR #724, pinned by this crate while Common 5 is unpublished), so the transactions it
builds are the ones a node with those rules accepts. It is unpublished.

## Destinations

Each key gets its own output, which commits to the script that key will spend with:

```text
body   = <public key> OP_CHECKSIG          # direct push: 0x20 for 128f, 0x30 for 192s
output = 00 5s 20 <SHA-256(body)>          # format 0, scheme 1 = 128f, 2 = 192s
```

The output carries the format, the scheme and thirty-two bytes, and nothing else; the body
stays with the wallet until the money is spent. The body's exact bytes are part of the
recovery contract — restoring a key finds its funds only if the same body is rebuilt — so
this crate commits to Common's canonical single-key body and nothing else. `PqDestination`
builds one; `Recipient` is either such a commitment or a legacy transparent address.

## Addresses

A key is published as a PQ receiver inside a Unified Address the wallet already hands out:
`with_pq_receiver` attaches the scheme the key's derivation fixed and the bare commitment.
Senders that do not know the typecode keep paying the address's shielded or legacy
transparent receiver, so nothing is reissued and no sender has to upgrade first. A PQ
receiver is transparent, so it may not stand alone in a Revision 0 address; the standalone
`tpq` form is specified upstream but not built, here or in Common.

`pq_recipient` is the sender's side: it reads the receiver an address publishes and turns it
into something `build_spend` pays. It reads the receiver directly rather than walking the
address's understood receivers, which omit PQ by design and would silently skip it. An
address with no PQ receiver is an error rather than a quiet fall back to its weaker one.

The typecodes `0x04` and `0x05` are provisional until the ZIP process assigns them, so an
address issued today is not durable.

## Spending

`build_spend` spends caller-chosen PQ outputs to the requested payments:

1. **Activation.** PQ outputs are only protected from the height the rules start applying
   at, which the node reads as `network.params.pq_activation_height`; below it such an
   output is claimable by an empty scriptSig. `build_spend` takes that height and refuses
   rather than create one early.
2. **Fee.** ZIP 317 from exact sizes. Each PQ input is its outpoint, its sequence, and a
   scriptSig of `PUSHDATA2(signature ‖ 0x01)` followed by a direct push of the body, whose
   size is fixed by the parameter set. Common's fee code cannot size these inputs itself, so
   the builder passes the sizes in.
3. **Change.** What remains after payments and fee goes to the next change key from the
   pool, so a later spend of that change uses a key that has not signed before. Change below
   the node's dust threshold (57 zatoshis for a 35-byte PQ output) is left to the fee
   instead. Change never goes to a key that was handed out before. If every derived change
   key has been handed out, the signer first derives the next ones in a separate call
   (`PqSigner::public_keys`). Every signing call also refills the next change key, so that
   separate call is only needed while the change branch is empty, for example on a hardware
   wallet's first spend. When unconfirmed change has used up the window, change steps past
   it; the pool README explains what that means for restore.
4. **Signing.** One call to a `PqSigner` carries the unsigned transaction, which key spends
   each input, which outputs are the wallet's own change, and the key ranges the pool wants
   refilled. The signer returns one signature per input and the refilled public keys; the
   builder adds those to the pool.
5. **Checks.** Each finished input is verified with Common's PQ verifier before the
   transaction is returned, and the fee is recomputed from the serialized inputs.

Transactions are version 5 and every input signs with `SIGHASH_ALL`. Inputs may mix
parameter sets and accounts.

`quote_spend` works out the same fee and change from the input values alone, before any key
is used, so a wallet can show the fee on its review screen; `build_spend` with the same
inputs and payments pays exactly that. `max_payment` is the largest single payment the
inputs can make with nothing left for change.

## The signer and hardware

A signer receives the transaction, not digests, and computes each signature hash itself,
which is what a hardware device has to do before it signs. The script code it signs over is
the body, which is the whole of what a PQ spend executes, and the signing context names the
network, the output format and the scheme, so a signature cannot be replayed on another
network or under another pair. The signer also checks that every input and every change
output belongs to one of its keys. Signing, change rotation, and refilling the pool happen
in the same call, matching the design's single hardware interaction during a spend. The one
exception is a pool with no derived change key left, where the builder first asks the signer
for public keys alone; on hardware that is a separate interaction.

`SeedSigner` is the software signer: it derives each key from the wallet seed, checks
ownership, signs with Common's PQ signing context, and derives the refill keys. A hardware
signer would implement the same trait over a device transport; that and a transport encoding
of the request are not part of this crate.

## Not built here

The standalone `tpq` address, choosing which outputs to spend, tracking outputs in the
wallet database, broadcasting, PCZT, a hardware signer, multisig and other custom bodies,
signing modes other than `SIGHASH_ALL`, and reading the activation height from anywhere.

## Validation

From the repository root:

```sh
python3 scripts/dev.py test --config transparent-pq-wallet
python3 scripts/dev.py lint --config transparent-pq-wallet
```

The end-to-end test against a node needs a `zakurad` from zakura #2186 built with the `pq`
feature; `tests/regtest.rs` says how to run it.
