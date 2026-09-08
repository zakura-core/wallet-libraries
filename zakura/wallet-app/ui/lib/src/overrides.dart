import 'package:flutter/widgets.dart';

/// Replacements for the components this package draws.
///
/// The point of the package is that a demo can take the parts it wants. Without
/// this, wanting a different balance card means forking; with it, it means
/// passing one builder and keeping everything else.
///
/// Every field is optional and null means "use the default". Each builder
/// receives the same model the default component would have drawn.
@immutable
class ZakuraUiOverrides {
  /// Replaces the balance card.
  final Widget Function(BuildContext, BalanceCardModel)? balanceCard;

  /// Replaces the synchronisation indicator.
  final Widget Function(BuildContext, SyncIndicatorModel)? syncIndicator;

  /// Replaces one row of the history list.
  final Widget Function(BuildContext, HistoryTileModel)? historyTile;

  /// Replaces the empty state of the history list.
  final Widget Function(BuildContext)? historyEmpty;

  /// Creates a set of overrides.
  const ZakuraUiOverrides({
    this.balanceCard,
    this.syncIndicator,
    this.historyTile,
    this.historyEmpty,
  });

  /// No overrides.
  static const none = ZakuraUiOverrides();
}

/// Provides [ZakuraUiOverrides] to the widgets below it.
class ZakuraUiOverridesScope extends InheritedWidget {
  /// The overrides in force.
  final ZakuraUiOverrides overrides;

  /// Creates an overrides scope.
  const ZakuraUiOverridesScope({
    required this.overrides,
    required super.child,
    super.key,
  });

  /// The overrides in force at [context], or none.
  ///
  /// Unlike the theme this has a default, because having no overrides is the
  /// ordinary case rather than a mistake.
  static ZakuraUiOverrides of(BuildContext context) =>
      context
          .dependOnInheritedWidgetOfExactType<ZakuraUiOverridesScope>()
          ?.overrides ??
      ZakuraUiOverrides.none;

  @override
  bool updateShouldNotify(ZakuraUiOverridesScope oldWidget) =>
      overrides != oldWidget.overrides;
}

/// What a balance card is given.
@immutable
class BalanceCardModel {
  /// The spendable figure, formatted.
  final String spendable;

  /// The pending figure, formatted, or null when there is none.
  final String? pending;

  /// Whether the figures should be hidden.
  final bool obscured;

  final String? transparentStatus;

  /// Creates the model.
  const BalanceCardModel({
    required this.spendable,
    required this.pending,
    required this.obscured,
    this.transparentStatus,
  });
}

/// What a synchronisation indicator is given.
@immutable
class SyncIndicatorModel {
  /// Progress between 0 and 1, or null when it is not yet known.
  final double? fraction;

  /// A sentence describing what is happening.
  final String label;

  /// Whether work is going on right now.
  final bool running;

  /// Creates the model.
  const SyncIndicatorModel({
    required this.fraction,
    required this.label,
    required this.running,
  });
}

/// What a history row is given.
@immutable
class HistoryTileModel {
  /// The amount, formatted and signed.
  final String amount;

  /// What the transaction was.
  final String title;

  /// When it happened, or that it has not yet.
  final String subtitle;

  /// Whether value arrived.
  final bool incoming;

  /// Whether the chain has recorded it yet.
  final bool pending;

  /// Where the value moved: which pools, or that it was transparent.
  final String pools;

  /// Whether any part of it was public.
  final bool touchedTransparent;

  /// Creates the model.
  const HistoryTileModel({
    required this.amount,
    required this.title,
    required this.subtitle,
    required this.incoming,
    required this.pending,
    this.pools = '',
    this.touchedTransparent = false,
  });
}
