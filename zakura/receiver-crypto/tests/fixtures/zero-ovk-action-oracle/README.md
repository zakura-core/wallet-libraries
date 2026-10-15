# Independent receiver for `zero-ovk-action.json`

The receiver tests pin the Orchard receiver that the fixture Action pays, instead of deriving it with the recovery code under test.

- `near-explorer-record.json` keeps the public fields of NEAR Intents' explorer record for the fixture transaction `2060cf68…`: a refunded ZEC deposit whose `refundTo` unified address received this refund.
- `ua.py` is a standalone ZIP 316 unified-address decoder (Bech32m, F4Jumble and BLAKE2b from the Python standard library). It shares no code with this repository.

Reproduce the pinned 43 bytes, `RECEIVER_HEX` in `../../common/mod.rs`, from this directory with Python 3.9 or later:

```sh
python3 -c "import json, ua; r = json.load(open('near-explorer-record.json')); print(dict(ua.receivers(r['refundTo']))[3].hex())"
```

Typecode 3 is the Orchard receiver. The output must equal the record's `refundTo_orchard_receiver_hex`, and the `receiver` field of `../zero-ovk-action.json`, which carries the pin for the receiver probe. Recovery must reproduce the pin; nothing derives the pin from recovery.
