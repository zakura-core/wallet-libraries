# Vendored BIP 158 basic filter test vectors

`testnet-19.json` is copied verbatim from the BIP repository.

- Upstream: https://github.com/bitcoin/bips/blob/master/bip-0158/testnet-19.json
- Raw URL: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0158/testnet-19.json
- Upstream revision (last commit touching this path): dd3948b4742eaad13872a85691347dc77cce09f0
- Retrieved: 2026-09-04
- SHA-256: d9049756f744e561b882a8eff507582fb7cd74ed9cf5542bdac58257449ee2a2
- License: BIP 158 is released under the BSD 2-clause license (see the
  "Copyright" section of bip-0158.mediawiki).

These are **Bitcoin testnet** vectors. They are used here only to check that
this crate's generic Golomb-Rice encoding, SipHash keying and CompactSize
framing agree with the reference implementation. Bitcoin block parsing appears
in that test alone; Zcash source data is never parsed as a Bitcoin block.

Column order, from the file's own header row:

    Block Height, Block Hash, Block, [Prev Output Scripts for Block],
    Previous Basic Header, Basic Filter, Basic Header, Notes
