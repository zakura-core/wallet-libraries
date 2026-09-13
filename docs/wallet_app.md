# Zakura wallet app

A Dart/Flutter application layer over the wallet core, in five composable
layers: simple sync, send, a single wallet, balance and history — built so each
layer can be swapped or overridden, and so demos can depend on whichever layers
they want.

This document describes what is built on top of `zakura/wallet-*`. It does not
propose changing the core's design, only closing the specific gaps a user
interface exposes.

It is written against `wallet_core_rewrite.md` for the design and
`wallet_core_hardening.md` for what a review of the built code found. The second
matters here more than it looks: several of its findings are not internal
correctness details but constraints on what the first version of a wallet can
honestly offer. Where that is the case it is called out below rather than
discovered on a device.

## The split

`zakura/wallet-*` is the library. `zakura/wallet-app/*` is the application built
on it. The core knows nothing about the app; the app is the only thing that
knows about FFI, Dart, or a screen.

```
zakura/wallet-app/
  facade/     Rust: the one UI-facing API, assembling the core crates
  bridge/     Rust: cdylib and the flutter_rust_bridge `api` module
  bindings/   Dart: generated bridge glue and the native build
  client/     Dart: plain models and `ZakuraWallet` (no Flutter)
  state/      Dart: riverpod providers
  ui/         Dart: overridable widgets and theme tokens
  example/    Flutter: the minimal reference wallet
```

One rule keeps it pluggable: **`ui/` never imports `bindings/`.** Widgets take
plain Dart models, so they render in a catalog and in tests with no native
library present. A wallet whose widgets are typed against generated FFI structs
cannot be tested without a compiled Rust toolchain, and every bridge
regeneration becomes a UI-wide breaking change.

## Why a facade crate

`zakura-wallet-facade` exists for three reasons, and none of them is taste.

**The FFI boundary should be narrow and typed in plain data.** Every public
signature takes and returns u64 zatoshis, `String` addresses and `[u8; 32]`
txids. No `orchard::` or `zcash_*` type crosses it. That keeps codegen trivial
and means a change to a core type is not automatically a change to the app.

**The orchestration is real logic and deserves Rust tests.** Sending is seven
ordered steps across three crates, with two parameters the caller must derive
and one that must not be exposed as a choice at all. Written in Dart it would be
untestable without a device; written once in Rust it is a unit test.

**Errors need to survive the crossing.** The core has six per-crate error enums
and a `Build(String)` catch-all. A UI needs stable, machine-readable codes it
can branch on and translate.

## What the core already provides

| Need | API |
| --- | --- |
| Open a wallet | `WalletDb::open` |
| Create an account from a seed | `WalletDb::create_account` |
| Receive address | `WalletDb::next_address` |
| Balance | `WalletDb::balance`, `WalletDb::total_balance` |
| History | `WalletDb::history` |
| Sync | `SyncEngine::{new, update_tip, step, run}` |
| Progress | `SyncEngine::status`, a `watch` channel |
| Build a payment | `zakura_wallet_tx::payment` |
| Serialise | `transaction::to_bytes` |
| Broadcast | `LightwalletdSource::send` |

The send path is complete through signing. `transaction::assemble` builds each
bundle unproven, assembles them, takes the transaction's signature hash, then
proves and signs against it — the order the protocol forces, since a v6
signature hash does not commit to the proofs but the signatures commit to the
hash. None of this needs rebuilding.

Two figures the app must respect rather than flatten. A balance is three
numbers — spendable, pending, and spent-but-unconfirmed — which are the same
funds at different stages of becoming usable; a wallet showing only a total will
offer funds and then refuse to send them. And progress is note-commitment
coverage, not blocks scanned, because the empty stretches of the chain scan
orders of magnitude faster than the busy ones.

## What the app layer has to close

Seven gaps sit between the core and a wallet somebody can use. All of them are
the facade's responsibility.

**A proving key that a release build can reach.** The keys live in
`wallet-tx`'s `testing` module, behind `test-dependencies`, so a production
build has no way to obtain one — yet every send needs it, and building it costs
seconds of CPU and a lot of memory. It moves to an always-available module and
is built once, off the interface thread, at startup.

**Address parsing.** `SpendRequest::recipient` is an `orchard::Address` and
nothing in the core decodes a string. A wallet where somebody pastes an address
has nothing to call.

**Mnemonics.** The core takes a raw seed. Generation, validation and wordlist
handling stay in Rust so the app never handles entropy.

**A birthday, and the asymmetry around it.** A birthday is the height below
which an account has no history, and it is the one number a restore can get
catastrophically wrong: too high and the wallet skips the blocks the money
arrived in, then shows a balance that is simply short, with nothing on screen to
suggest anything is missing. Too low only costs scanning time.

That asymmetry is built into the API rather than left to whoever calls it. A new
wallet is given the chain tip, because an account that did not exist a moment
ago cannot have been paid earlier. A restore is given the height it is told, and
the earliest height its pools could hold anything when it is told nothing — an
unknown birthday stays unknown rather than becoming a guess. Importing a wallet
the store already holds is refused: two accounts sharing an incoming viewing key
would see the same notes and count every balance twice.

**A seed to spending keys, and the test that seam has never had.** The store
derives an account from a seed and drops it, keeping only the viewing key.
`wallet-tx` needs a `SpendingKey`. Nothing bridges the two, and because every
existing spend test constructs a key directly, *no test has ever shown that an
account created from a seed can spend the notes it finds*. The facade derives
through ZIP 32 using the stored account index and checks the derived viewing key
against the stored one. This is the highest-value correctness work here.

**A consensus branch and an expiry.** Both are caller parameters, and both must
come from the chain tip rather than from the anchor. The anchor is the most
recent block both commitment trees hold a checkpoint for, which during recovery
can sit a long way below the tip; an expiry measured from it names a height the
chain passed an hour ago, and a branch identifier taken from it can name the
rules of an upgrade the chain has already left. A crossing additionally needs
the canonical expiry, because an ordinary one would single the transaction out
from the crossings it is meant to be indistinguishable from.

**The output pool, which is not a choice, and the crossing guard that is
missing underneath it.** From NU6.3 the Orchard pool prohibits cross-address
transfers, so a payment to somebody else is necessarily a crossing into
Ironwood. Offering the user a pool would be offering an option consensus
refuses.

But simply setting the output pool to Ironwood is the wrong conclusion, and
`wallet_core_hardening.md` names why. `build::bundles` raises `CrossingRequired`
only when the Orchard bundle is the one making the payment. A proposal with
Orchard inputs and an Ironwood output pool never reaches that branch: the
Orchard side becomes spend-only with a positive value balance, the Ironwood side
carries the output, and the result is a pool crossing assembled ad hoc, with
selection's action counts and fee instead of the canonical ones. Nothing refuses
it. A facade that picked Ironwood and passed whatever notes selection returned
would therefore build a transaction that is a crossing in substance and
non-canonical in shape — which is exactly the privacy property the design exists
to protect.

So the facade constrains the inputs, not just the output. Until the guard lands
in `select` and `build::bundles`, it selects from Ironwood notes only and
refuses an Orchard-funded payment with a distinct error rather than routing it
through a path that silently produces the wrong shape.

## Limits the interface is designed around

These are properties of the core as it stands, and the app should state them
rather than discover them.

**Payments out of the Orchard pool must be canonical.** From NU6.3 the Orchard
pool prohibits cross-address transfers, so value leaves it only as a ZIP 318
crossing — and every crossing carries one of a fixed set of denominations, at a
fixed fee, against an anchor on a shared grid, precisely so that they cannot be
told apart. The wallet routes an Orchard-funded payment through a crossing when
the amount is one of those denominations and refuses when it is not. Refusing is
the correct answer rather than a shortcoming: adjusting to the nearest canonical
amount would send somebody a different sum than they asked for, and a crossing
that is nearly the right shape stands out from the ones that are. Paying an
arbitrary amount out of Orchard is therefore two steps — cross a denomination
into Ironwood, then pay from there, which is an ordinary payment.

**Transparent value is held but not spent directly.** Addresses are derived and
watched, receipts are detected and attributed, and the balance reports them. But
spending them means shielding first, and this build does not drive that, so the
balance names them as needing a step rather than folding them into what can be
sent.

**Receive addresses carry only an Orchard receiver.** Issuance asks for one, so
a payer with only a transparent or Sapling implementation cannot use the address
the wallet hands out, even though the wallet would see a payment to a
transparent address it derived.

**A crossing whose preparation is needed cannot be built.** The planner can say
what consolidation an Orchard balance would need, and can verify the shape would
conform, but there is no builder for it. An Orchard-funded payment where no
single note covers the denomination and the fee is a dead end, and it has to
surface as a clear message rather than a spinner.

**Selection does not constrain inputs to one account.** Nothing at that boundary
stops a transaction linking two of the wallet's accounts on chain. The first
version is single-account, which sidesteps it; a multi-account version must not
ship before the guard does.

**One wallet at a time, then.** Because the store holds one account, changing
wallets is forgetting this one and restoring another: the facade deletes both
database files and reopens them empty, and the application returns to
onboarding. The same path re-runs a recovery whose birthday turned out to be
too high, since a forgotten wallet is not "already here" when its phrase is
restored again.

**An idle sync is not necessarily a finished one.** An empty fetch reports idle
too, so a transient failure to reach the server looks exactly like having caught
up. The wallet records why a sync stopped and reports it separately, and the
interface checks that before it says "up to date".

**Spendability is measured against the last batch, not the chain**, and
`subtree_end_height` is read as shard completeness when it is not. Both mean a
balance can report notes as spendable that selection then withholds. The send
flow treats "selected less than the balance implied" as an expected outcome with
a real message.


**There are no memos.** The field is omitted rather than accepted and dropped.

**Proving takes seconds.** Sending is a visible state machine, not a spinner.

## Two structural constraints

The sync engine takes ownership of the wallet database, so the interface cannot
read a balance through the same handle while a sync is running. The store
enables WAL for exactly this reason, and the facade opens a second, read-only
connection for queries.

Detection uses rayon and the apply stage is synchronous inside the engine's
async step, with no `spawn_blocking`. The engine therefore runs on its own
dedicated thread with a current-thread runtime, never on a shared worker where
it would stall unrelated tasks.

## The Dart layers

**`client/`** holds plain models — a typed `Zatoshi` rather than a raw integer,
`Balance`, `HistoryEntry`, `Account`, `SyncProgress` — and one `ZakuraWallet`
class. It imports no Flutter, so it runs under plain `dart test`. Mapping from
generated bridge structs into these models happens here and nowhere else: that
single choke point is what stops FFI types leaking into widgets.

**`state/`** is riverpod, with progress, balance, history and accounts as
*separate* providers with independent invalidation. The wallet this replaces
fused all of them into one 2,956-line notifier, so a balance refresh rebuilt
every progress consumer. Display progress is its own provider with its own
interpolation timer, exposing the smooth value to a bar and whole percentages to
labels, so unrelated widgets do not rebuild sixty times a second.

**`ui/`** depends on the models only. Theme tokens are semantic and by role, and
form factor is a runtime scope rather than a compile-time define — a binary that
cannot render both makes the phone and desktop layouts two codebases that drift.
Components take callbacks, never providers, and an overrides object lets a demo
replace one component without forking the package.

## Verification

The facade carries an end-to-end test over the in-memory chain: create an
account from a seed, sync, read balance and history, then build and sign a
payment with keys derived from that same seed. That last step is the seam
nothing currently covers.

Above that, a pure-Dart command-line client syncs mainnet and prints balance and
history, which proves the whole native stack before any interface exists. The
models are tested against a fake bindings implementation with no native library.
The widgets are tested against plain models and rendered in a catalog in both
themes. The example application is checked against regtest, where a payment can
be mined on demand, and the balance must move the moment the transaction is
broadcast rather than when it is mined.
