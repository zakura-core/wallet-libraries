/// Plain Dart models and a wallet handle over the Zakura wallet core.
///
/// Nothing here imports Flutter, so it runs under `dart test` with no native
/// library present. That is the point: the bindings are an interface, and the
/// fake in this package's tests is as valid an implementation as the generated
/// one.
library;

export 'src/bindings.dart';
export 'src/exception.dart';
export 'src/models.dart';
export 'src/wallet.dart';
export 'src/zatoshi.dart';
