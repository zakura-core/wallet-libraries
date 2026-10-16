# Independent cross-check against btcsuite/btcd

`expected.json` holds BIP 158 filters produced by a **different** implementation
from the one under test, so a test comparing against it is not this crate's
encoder validating itself.

Generator: `main.go`, using `github.com/btcsuite/btcd/btcutil/gcs/builder`.

Pinned dependencies (see `go.mod`/`go.sum`):

- `github.com/btcsuite/btcd v0.24.2`
- `github.com/btcsuite/btcd/btcutil v1.1.5`
- `github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0`

Go toolchain used to generate the committed file: go1.26.1 darwin/arm64.

## Regenerating

`cases.json` is generated deterministically (fixed SHA-256-derived hashes and
scripts, no randomness), so regeneration is reproducible:

```sh
cd transparent/crates/transparent-filter/tests/crosscheck
go run . < cases.json > expected.json
```

`builder.WithKeyHash` takes the block hash in **display** order and derives the
SipHash keys itself, which is why `cases.json` carries `block_hash_display`.
That the two implementations agree is therefore also a check on this crate's
display-to-internal byte-order conversion.

Note that `gcs` will not build a filter with zero entries in every version, and
that `NBytes` includes the CompactSize element count; both are accounted for in
`main.go`.

Go is **not** required to run the Rust test suite. `expected.json` is committed
and the test reads it directly; the generator exists so the values can be
audited and regenerated.
