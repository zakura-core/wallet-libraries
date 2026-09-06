# Zakura wallet app

The application layer over the wallet core. `zakura/wallet-*` is the library;
this is what is built on it. See `docs/wallet_app.md` for the design, and
`docs/wallet_core_hardening.md` for the constraints that shape it.

| Package | What it is | State |
| --- | --- | --- |
| `facade/` | Rust. The one wallet-facing API, and what a foreign-function layer binds to. | Built, 26 tests |
| `client/` | Dart. Plain models and `ZakuraWallet`, over a `ZakuraBindings` interface. No Flutter. | Built, 30 tests |
| `state/` | Dart. Riverpod providers, one concern each. | Built, 13 tests |
| `ui/` | Dart. Overridable widgets and theme tokens. | Built, 20 tests |
| `bridge/` | Rust. cdylib/staticlib and the `flutter_rust_bridge` API module. | Built |
| `bindings/` | Dart. Generated glue, the native build, and `NativeBindings`. | Built, 10 native tests |
| `example/` | Flutter. The minimal reference wallet. | Built, runs on the real wallet |

## Running the example

```
cd example && fvm flutter run -d macos
```

Cargokit builds the Rust crate as part of the Flutter build and bundles it, so
there is nothing to do first.

Add `--dart-define=ZAKURA_DEMO=true` to run against `lib/demo_bindings.dart`, an
in-memory wallet, which is useful for working on the interface without waiting
for a chain. That is not a hack: `client` talks to the `ZakuraBindings`
*interface* rather than to generated code, so the demo binding and the generated
one are equally valid implementations, and choosing between them is one
expression in `main.dart`. The app says on screen when it is the demo.

The same property is why 65 of the Dart tests run with no Rust toolchain
present.

## Testing

```
# Everything that needs no native library.
melos run test

# The bridge, against the real Rust wallet. Build it first.
cargo build -p zakura_wallet_bridge --release
cd bindings && fvm flutter test --tags native
```

The native tests are tagged so an ordinary run skips them. They are the only
check that the generated glue, the facade and the core agree; everything else
runs against a fake by design.

## The rules that keep it composable

**`ui/` never imports the bindings.** Widgets take plain models and callbacks,
so they render in tests and a catalog with nothing native present. Typing
widgets against generated FFI structs is the mistake that makes a UI
untestable and turns every bridge regeneration into a breaking change.

**One concern per provider.** Progress changes many times a second; balance
changes when a batch lands. Fusing them means every progress tick rebuilds the
balance card.

**Form factor is a runtime scope, not a compile-time define.** A binary that
cannot render both layouts makes phone and desktop two codebases that drift.

**Components take callbacks, never providers.** `ZakuraUiOverrides` replaces any
component with a builder, so a demo changes one widget without forking.

## What this build cannot do

Stated here because the interface has to say so rather than fail late. The
reasons are in `docs/wallet_app.md`.

- **Payments out of Orchard must be a canonical denomination.** Value leaves
  Orchard only as a ZIP 318 crossing, and every crossing carries one of a fixed
  set of amounts at a fixed fee so they cannot be told apart. The wallet routes
  an Orchard-funded payment through a crossing when the amount qualifies and
  refuses when it does not — refusing is correct, since a crossing that is
  nearly the right shape stands out from the ones that are. Arbitrary amounts
  are two steps: cross into Ironwood, then pay from there.
- **Transparent value is held but not spent directly.** Addresses are derived
  and watched and the balance reports them, but spending needs shielding first
  and this build does not drive that.
- **No memos.**
- **Sending needs the seed**, because the wallet stores only viewing keys. It
  belongs in the platform keystore; the example does not do this.

## Next

- Platform scaffolding beyond macOS. `example/` has only `macos/`; the other
  platforms need `flutter create --platforms=...` and the Cargokit wiring in
  `bindings/rust_builder/` already covers them.
- A real key store. The example passes a freshly generated phrase to `send`,
  which is a placeholder: the seed belongs in the platform keychain, because
  the wallet deliberately stores only viewing keys.
- The hardening work in `docs/wallet_core_hardening.md`, which is what would
  lift the Orchard-funded and transparent restrictions above.
