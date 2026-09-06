import 'package:flutter/widgets.dart';

/// How much room the interface has.
///
/// A runtime value, not a compile-time constant. Choosing form factor at build
/// time tree-shakes the unused tokens, which is a real saving, but it means one
/// binary can never render both — so the phone and desktop layouts become two
/// codebases that drift, tests need a separate lane, and forgetting the flag
/// ships the wrong tokens silently. None of that is worth the kilobytes.
enum FormFactor {
  /// A phone.
  compact,

  /// A tablet, or a desktop window.
  expanded;

  /// Picks a form factor from the space available.
  static FormFactor fromWidth(double width) =>
      width < 600 ? FormFactor.compact : FormFactor.expanded;
}

/// Colours, named for what they are for rather than what they look like.
///
/// A token called `surface` survives a redesign; one called `grey100` does not,
/// and every widget that named it has to be found and changed.
@immutable
class ZakuraColors {
  /// Behind everything.
  final Color background;

  /// Cards and raised areas.
  final Color surface;

  /// A surface that needs to stand out from its neighbours.
  final Color surfaceRaised;

  /// Hairlines and dividers.
  final Color border;

  /// Ordinary text.
  final Color text;

  /// Text that supports rather than leads.
  final Color textMuted;

  /// Text on top of [accent].
  final Color textOnAccent;

  /// The one colour that means "this is the thing to press".
  final Color accent;

  /// Value arriving.
  final Color positive;

  /// Value leaving.
  final Color negative;

  /// Something is wrong.
  final Color danger;

  /// Something is unfinished: pending balance, an unmined transaction.
  final Color pending;

  const ZakuraColors({
    required this.background,
    required this.surface,
    required this.surfaceRaised,
    required this.border,
    required this.text,
    required this.textMuted,
    required this.textOnAccent,
    required this.accent,
    required this.positive,
    required this.negative,
    required this.danger,
    required this.pending,
  });

  /// The light palette.
  static const light = ZakuraColors(
    background: Color(0xFFF7F7F5),
    surface: Color(0xFFFFFFFF),
    surfaceRaised: Color(0xFFFFFFFF),
    border: Color(0xFFE3E3DF),
    text: Color(0xFF16160F),
    textMuted: Color(0xFF6B6B63),
    textOnAccent: Color(0xFFFFFFFF),
    accent: Color(0xFF3B5BDB),
    positive: Color(0xFF2B7A4B),
    negative: Color(0xFF8B2F2F),
    danger: Color(0xFFB4321F),
    pending: Color(0xFF8A6A17),
  );

  /// The dark palette.
  static const dark = ZakuraColors(
    background: Color(0xFF121210),
    surface: Color(0xFF1C1C19),
    surfaceRaised: Color(0xFF242420),
    border: Color(0xFF32322D),
    text: Color(0xFFF2F2ED),
    textMuted: Color(0xFF9A9A90),
    textOnAccent: Color(0xFFFFFFFF),
    accent: Color(0xFF748FFC),
    positive: Color(0xFF6BCB8B),
    negative: Color(0xFFE08A8A),
    danger: Color(0xFFE86B52),
    pending: Color(0xFFD9B44A),
  );
}

/// Text styles, by the job they do.
@immutable
class ZakuraTypography {
  /// The balance, and nothing else.
  final TextStyle display;

  /// Section headings.
  final TextStyle title;

  /// Ordinary text.
  final TextStyle body;

  /// Supporting text.
  final TextStyle caption;

  /// Addresses, identifiers, seed phrases: anything that must be compared
  /// character by character.
  final TextStyle mono;

  const ZakuraTypography({
    required this.display,
    required this.title,
    required this.body,
    required this.caption,
    required this.mono,
  });

  /// The scale for a given amount of room.
  ///
  /// Only sizes change between form factors. Making weights or families differ
  /// as well produces two designs rather than one design at two sizes.
  factory ZakuraTypography.forFactor(FormFactor factor) {
    final compact = factor == FormFactor.compact;
    return ZakuraTypography(
      display: TextStyle(
        fontSize: compact ? 34 : 42,
        fontWeight: FontWeight.w600,
        height: 1.1,
        letterSpacing: -0.5,
      ),
      title: TextStyle(
        fontSize: compact ? 17 : 19,
        fontWeight: FontWeight.w600,
        height: 1.3,
      ),
      body: TextStyle(fontSize: compact ? 15 : 15, height: 1.45),
      caption: TextStyle(fontSize: compact ? 13 : 13, height: 1.35),
      mono: TextStyle(
        fontSize: compact ? 13 : 13,
        height: 1.5,
        fontFamily: 'monospace',
        fontFamilyFallback: const ['Menlo', 'Consolas', 'Courier New'],
      ),
    );
  }
}

/// Spacing, on a four-point scale.
@immutable
class ZakuraSpacing {
  /// 4.
  final double xs;

  /// 8.
  final double sm;

  /// 12.
  final double md;

  /// 16, and the default gutter.
  final double lg;

  /// 24.
  final double xl;

  /// 32.
  final double xxl;

  const ZakuraSpacing({
    required this.xs,
    required this.sm,
    required this.md,
    required this.lg,
    required this.xl,
    required this.xxl,
  });

  /// The scale for a given amount of room.
  factory ZakuraSpacing.forFactor(FormFactor factor) {
    final compact = factor == FormFactor.compact;
    return ZakuraSpacing(
      xs: 4,
      sm: 8,
      md: 12,
      lg: compact ? 16 : 20,
      xl: compact ? 24 : 32,
      xxl: compact ? 32 : 48,
    );
  }
}

/// Corner radii.
@immutable
class ZakuraRadii {
  /// Chips and small controls.
  final BorderRadius small;

  /// Buttons and fields.
  final BorderRadius medium;

  /// Cards.
  final BorderRadius large;

  const ZakuraRadii({
    required this.small,
    required this.medium,
    required this.large,
  });

  /// The default set.
  static const standard = ZakuraRadii(
    small: BorderRadius.all(Radius.circular(6)),
    medium: BorderRadius.all(Radius.circular(10)),
    large: BorderRadius.all(Radius.circular(16)),
  );
}
