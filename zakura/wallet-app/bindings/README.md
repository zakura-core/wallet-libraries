# zakura_bindings

The generated bridge between `zakura_client` and the Rust facade, plus the
native build that produces the library it calls.

## Regenerating

After changing `zakura/wallet-app/bridge/src/api/`:

```
cd zakura/wallet-app/bindings
flutter_rust_bridge_codegen generate
```

Both halves — `lib/src/rust/` here and `bridge/src/frb_generated.rs` there — are
written by that one command and must be regenerated together. They are two
halves of one artefact, and a skew between them fails at runtime rather than at
compile time, which is why both `flutter_rust_bridge` versions are pinned
exactly.

## The native build

`rust_builder/` is Cargokit, taken from Vizor. It builds
`zakura_wallet_bridge` for whichever platform Flutter is targeting: a static
library force-loaded on Apple platforms, a shared library in `jniLibs` on
Android, and a CMake target on the desktops.

The workspace root sets `[profile.dev.package."*"] opt-level = 3`. Flutter's
debug builds use Cargo's dev profile, and the proving stack is unusable at
`opt-level = 0` — a single proof takes minutes rather than seconds. It has to
live at the root: Cargo ignores a profile declared by a workspace member, with
only a warning. Dependencies only, so iterating on the wallet crates themselves
stays fast.

## What this package adds

`NativeBindings` implements `zakura_client`'s `ZakuraBindings`, mapping the
generated types onto the plain models and the generated errors onto
`ZakuraException`. That mapping lives here, and only here, so that regenerating
the bridge cannot ripple past this package.
