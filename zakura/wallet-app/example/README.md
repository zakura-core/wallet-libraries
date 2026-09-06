# zakura_example

The minimal reference wallet: onboarding, balance, sync, history, receive, send.

```
fvm flutter run -d macos
```

Cargokit builds and bundles the Rust library as part of the Flutter build, so
there is nothing to do first.

Add `--dart-define=ZAKURA_DEMO=true` to run against `lib/demo_bindings.dart`, an
in-memory wallet — useful for working on the interface without waiting for a
chain. The app says on screen when it is the demo.

Only `macos/` is scaffolded. The other platforms need
`flutter create --platforms=...`; `bindings/rust_builder/` already carries the
Cargokit wiring for all of them.

## What it is not

Thin on purpose. Every figure comes from a provider and every component from
`zakura_ui`, so there is little here to get wrong — if a screen needs real
logic, that logic belongs a layer down where it is tested.

Two things a real wallet must do that this does not:

- **Keep the seed properly.** `send` here passes a freshly generated phrase,
  which is a placeholder. The wallet stores only viewing keys by design, so
  spending needs the seed supplied again, and it belongs in the platform
  keychain.
- **Ask for a birthday when restoring.** Onboarding hardcodes one. Guessing too
  high silently loses transactions.
