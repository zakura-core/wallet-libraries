import 'package:flutter/widgets.dart';

import '../theme/theme.dart';

/// How much a button is asking for.
enum ZakuraButtonKind {
  /// The one thing this screen is for.
  primary,

  /// A reasonable alternative.
  secondary,

  /// Something destructive or irreversible.
  danger,
}

/// A button.
///
/// Deliberately not a Material button: this package draws from its own tokens
/// so that an application embedding it does not have to adopt a Material theme
/// to make it look right.
class ZakuraButton extends StatefulWidget {
  /// What it says.
  final String label;

  /// What it does. Null disables it.
  final VoidCallback? onPressed;

  /// How much it is asking for.
  final ZakuraButtonKind kind;

  /// Whether it is working, in which case it is also disabled.
  final bool busy;

  /// Whether it fills the width available.
  final bool expand;

  /// Creates a button.
  const ZakuraButton({
    required this.label,
    required this.onPressed,
    this.kind = ZakuraButtonKind.primary,
    this.busy = false,
    this.expand = false,
    super.key,
  });

  @override
  State<ZakuraButton> createState() => _ZakuraButtonState();
}

class _ZakuraButtonState extends State<ZakuraButton> {
  bool _down = false;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final enabled = widget.onPressed != null && !widget.busy;

    final (background, foreground) = switch (widget.kind) {
      ZakuraButtonKind.primary => (
          theme.colors.accent,
          theme.colors.textOnAccent,
        ),
      ZakuraButtonKind.secondary => (
          theme.colors.surfaceRaised,
          theme.colors.text,
        ),
      ZakuraButtonKind.danger => (
          theme.colors.danger,
          theme.colors.textOnAccent,
        ),
    };

    final button = Semantics(
      button: true,
      enabled: enabled,
      label: widget.label,
      child: GestureDetector(
        onTapDown: enabled ? (_) => setState(() => _down = true) : null,
        onTapUp: enabled ? (_) => setState(() => _down = false) : null,
        onTapCancel: enabled ? () => setState(() => _down = false) : null,
        onTap: enabled ? widget.onPressed : null,
        child: AnimatedOpacity(
          duration: const Duration(milliseconds: 90),
          opacity: !enabled
              ? 0.45
              : _down
                  ? 0.75
                  : 1,
          child: Container(
            padding: EdgeInsets.symmetric(
              horizontal: theme.spacing.xl,
              vertical: theme.spacing.md,
            ),
            decoration: BoxDecoration(
              color: background,
              borderRadius: theme.radii.medium,
              border: widget.kind == ZakuraButtonKind.secondary
                  ? Border.all(color: theme.colors.border)
                  : null,
            ),
            // The label is kept while busy rather than replaced by an
            // ellipsis. A button that is busy for a few seconds is exactly the
            // one whose label matters most: "Proving…" tells somebody the wait
            // is expected, and "…" tells them nothing at all. Being busy is
            // already shown by the dimming above.
            child: Text(
              widget.label,
              textAlign: TextAlign.center,
              style: theme.typography.body.copyWith(
                color: foreground,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
      ),
    );

    return widget.expand ? SizedBox(width: double.infinity, child: button) : button;
  }
}

/// A panel that groups related things.
class ZakuraCard extends StatelessWidget {
  /// What is in it.
  final Widget child;

  /// Room around the contents. Defaults to the standard gutter.
  final EdgeInsetsGeometry? padding;

  /// Creates a card.
  const ZakuraCard({required this.child, this.padding, super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Container(
      padding: padding ?? EdgeInsets.all(theme.spacing.lg),
      decoration: BoxDecoration(
        color: theme.colors.surface,
        borderRadius: theme.radii.large,
        border: Border.all(color: theme.colors.border),
      ),
      child: child,
    );
  }
}

/// Says why there is nothing to show.
///
/// An empty list with no explanation reads as a wallet that is broken rather
/// than one that is new.
class ZakuraEmptyState extends StatelessWidget {
  /// The headline.
  final String title;

  /// What to do about it, if anything.
  final String? subtitle;

  /// Creates an empty state.
  const ZakuraEmptyState({required this.title, this.subtitle, super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Padding(
      padding: EdgeInsets.symmetric(
        vertical: theme.spacing.xxl,
        horizontal: theme.spacing.lg,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            title,
            textAlign: TextAlign.center,
            style: theme.typography.body.copyWith(color: theme.colors.textMuted),
          ),
          if (subtitle != null) ...[
            SizedBox(height: theme.spacing.sm),
            Text(
              subtitle!,
              textAlign: TextAlign.center,
              style: theme.typography.caption
                  .copyWith(color: theme.colors.textMuted),
            ),
          ],
        ],
      ),
    );
  }
}

/// Something the person reading needs to know before they act.
class ZakuraNotice extends StatelessWidget {
  /// What it says.
  final String message;

  /// Whether this is a problem rather than information.
  final bool isError;

  /// Creates a notice.
  const ZakuraNotice({required this.message, this.isError = false, super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final colour = isError ? theme.colors.danger : theme.colors.pending;
    return Container(
      width: double.infinity,
      padding: EdgeInsets.all(theme.spacing.md),
      decoration: BoxDecoration(
        // A tint of the meaning colour rather than a block of it: this has to
        // be readable behind text, and a saturated background is not.
        color: colour.withValues(alpha: 0.12),
        borderRadius: theme.radii.medium,
        border: Border.all(color: colour.withValues(alpha: 0.4)),
      ),
      child: Text(
        message,
        style: theme.typography.caption.copyWith(color: theme.colors.text),
      ),
    );
  }
}
