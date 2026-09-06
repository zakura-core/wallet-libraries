import 'package:flutter/widgets.dart';

import 'tokens.dart';

/// Everything a widget in this package needs to know about how it should look.
@immutable
class ZakuraThemeData {
  /// Colours by role.
  final ZakuraColors colors;

  /// Text styles by job.
  final ZakuraTypography typography;

  /// The spacing scale.
  final ZakuraSpacing spacing;

  /// Corner radii.
  final ZakuraRadii radii;

  /// How much room there is.
  final FormFactor formFactor;

  const ZakuraThemeData({
    required this.colors,
    required this.typography,
    required this.spacing,
    required this.radii,
    required this.formFactor,
  });

  /// Builds a theme for a palette and an amount of room.
  factory ZakuraThemeData.of({
    required ZakuraColors colors,
    required FormFactor formFactor,
  }) =>
      ZakuraThemeData(
        colors: colors,
        typography: ZakuraTypography.forFactor(formFactor),
        spacing: ZakuraSpacing.forFactor(formFactor),
        radii: ZakuraRadii.standard,
        formFactor: formFactor,
      );

  /// Returns a copy with some parts replaced.
  ///
  /// The seam for a demo that wants this design with different colours: replace
  /// the palette and every widget follows, because none of them names a colour
  /// of its own.
  ZakuraThemeData copyWith({
    ZakuraColors? colors,
    ZakuraTypography? typography,
    ZakuraSpacing? spacing,
    ZakuraRadii? radii,
    FormFactor? formFactor,
  }) =>
      ZakuraThemeData(
        colors: colors ?? this.colors,
        typography: typography ?? this.typography,
        spacing: spacing ?? this.spacing,
        radii: radii ?? this.radii,
        formFactor: formFactor ?? this.formFactor,
      );
}

/// Provides a [ZakuraThemeData] to the widgets below it.
class ZakuraTheme extends InheritedWidget {
  /// The theme in force.
  final ZakuraThemeData data;

  /// Creates a theme scope.
  const ZakuraTheme({required this.data, required super.child, super.key});

  /// The theme in force at [context].
  ///
  /// Throws if there is none, rather than falling back to a default. A widget
  /// silently drawing itself in the wrong palette is harder to notice, and
  /// harder to explain, than one that does not build.
  static ZakuraThemeData of(BuildContext context) {
    final theme = context.dependOnInheritedWidgetOfExactType<ZakuraTheme>();
    assert(theme != null, 'No ZakuraTheme found. Wrap the app in ZakuraApp.');
    return theme!.data;
  }

  @override
  bool updateShouldNotify(ZakuraTheme oldWidget) => data != oldWidget.data;
}

/// Establishes a theme, choosing the palette and form factor from the
/// surroundings.
///
/// Form factor comes from the space actually available rather than from the
/// platform: a narrow window on a desktop is a compact layout, and pretending
/// otherwise produces a cramped one.
class ZakuraThemeScope extends StatelessWidget {
  /// What to draw.
  final Widget child;

  /// Forces a palette instead of following the platform.
  final ZakuraColors? colors;

  /// Forces a form factor instead of measuring.
  final FormFactor? formFactor;

  /// Creates a theme scope.
  const ZakuraThemeScope({
    required this.child,
    this.colors,
    this.formFactor,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    final dark =
        MediaQuery.maybePlatformBrightnessOf(context) == Brightness.dark;
    final palette =
        colors ?? (dark ? ZakuraColors.dark : ZakuraColors.light);

    return LayoutBuilder(
      builder: (context, constraints) {
        final factor = formFactor ??
            FormFactor.fromWidth(
              constraints.hasBoundedWidth
                  ? constraints.maxWidth
                  : MediaQuery.sizeOf(context).width,
            );
        return ZakuraTheme(
          data: ZakuraThemeData.of(colors: palette, formFactor: factor),
          child: child,
        );
      },
    );
  }
}
