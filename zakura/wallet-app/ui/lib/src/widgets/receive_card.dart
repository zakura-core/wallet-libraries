import 'package:flutter/widgets.dart';

import '../theme/theme.dart';
import 'primitives.dart';

/// An address to be paid to.
///
/// Deliberately does not draw a QR code: doing so would pull a dependency into
/// a package whose whole purpose is to be embeddable. [qr] is a slot for
/// whatever the application already uses.
class ReceiveCard extends StatelessWidget {
  /// The address, encoded.
  final String address;

  /// A QR code for the address, if the application has one to draw.
  final Widget? qr;

  /// Copies the address.
  final VoidCallback? onCopy;

  /// Issues a different address.
  final VoidCallback? onNew;

  /// Creates a receive card.
  const ReceiveCard({
    required this.address,
    this.qr,
    this.onCopy,
    this.onNew,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);

    return ZakuraCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (qr != null) ...[
            Center(child: qr),
            SizedBox(height: theme.spacing.lg),
          ],
          Text(
            'Your address',
            style:
                theme.typography.caption.copyWith(color: theme.colors.textMuted),
          ),
          SizedBox(height: theme.spacing.sm),
          // Plain text rather than a selectable field: selection controls
          // live in Material, and this package deliberately does not depend on
          // it. Copying is the button below, which is the action people
          // actually want.
          Text(
            address,
            style: theme.typography.mono.copyWith(color: theme.colors.text),
          ),
          SizedBox(height: theme.spacing.md),
          // Reuse is the privacy loss nobody asks for and nobody can undo, so
          // the wallet says why it keeps handing out new ones.
          Text(
            'A new address is issued each time. Reusing one lets anybody who '
            'has seen it link your payments together.',
            style:
                theme.typography.caption.copyWith(color: theme.colors.textMuted),
          ),
          SizedBox(height: theme.spacing.lg),
          Row(
            children: [
              Expanded(
                child: ZakuraButton(
                  label: 'Copy',
                  onPressed: onCopy,
                  expand: true,
                ),
              ),
              SizedBox(width: theme.spacing.md),
              Expanded(
                child: ZakuraButton(
                  label: 'New address',
                  kind: ZakuraButtonKind.secondary,
                  onPressed: onNew,
                  expand: true,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
