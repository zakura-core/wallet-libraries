/// The generated bridge between `zakura_client` and the Rust wallet facade.
///
/// An application depends on this package once, at the point where it builds
/// its [ZakuraWallet], and nowhere else:
///
/// ```dart
/// final bindings = await NativeBindings.load();
/// final wallet = ZakuraWallet(bindings);
/// ```
///
/// Everything above that line is written against `ZakuraBindings`, so it can
/// equally be handed a fake — which is what lets the models, the providers and
/// the widgets be tested with no native library present.
library;

export 'src/native_bindings.dart';
