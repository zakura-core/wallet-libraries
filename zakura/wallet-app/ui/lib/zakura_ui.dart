/// Overridable widgets and theme tokens for a Zakura wallet.
///
/// Depends on `zakura_client` for its models and on nothing else. In
/// particular it does not import the native bindings or a state-management
/// package, so every widget here renders in a test, or a catalog, with no Rust
/// toolchain present — and an application is free to drive them with whatever
/// it already uses.
///
/// Components take plain models and callbacks. Where one needs replacing,
/// [ZakuraUiOverrides] takes a builder rather than requiring a fork.
library;

export 'src/overrides.dart';
export 'src/theme/theme.dart';
export 'src/theme/tokens.dart';
export 'src/widgets/balance_card.dart';
export 'src/widgets/coverage_details.dart';
export 'src/widgets/history_list.dart';
export 'src/widgets/import_form.dart';
export 'src/widgets/primitives.dart';
export 'src/widgets/receive_card.dart';
export 'src/widgets/seed_phrase_view.dart';
export 'src/widgets/send_form.dart';
export 'src/widgets/sync_indicator.dart';
