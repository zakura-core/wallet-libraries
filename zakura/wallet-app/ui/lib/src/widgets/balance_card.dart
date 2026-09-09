import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../overrides.dart';
import '../theme/theme.dart';
import 'primitives.dart';

/// What the account is worth.
///
/// Shows spendable prominently and pending beside it, because they are
/// different things: a card showing only the total invites somebody to try to
/// send money that is still settling, and a card showing only what is spendable
/// tells them their money has vanished.
class BalanceCard extends StatelessWidget {
  /// What the account holds.
  final Balance balance;

  /// Whether to hide the figures, as when the screen may be overlooked.
  final bool obscured;

  /// The chain tip the wallet's server reports, if known. Transparent
  /// coverage within a few blocks of it is shown as current rather than as
  /// incomplete; see [TransparentCoverage.statusAgainst].
  final int? chainTip;

  /// What to say after a transparent figure.
  ///
  /// The default names the step ordinary transparent funds need before they
  /// can be sent. A build that cannot send says something else.
  final String transparentSuffix;

  /// Creates a balance card.
  const BalanceCard({
    required this.balance,
    this.obscured = false,
    this.chainTip,
    this.transparentSuffix = 'shield to spend',
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final override = ZakuraUiOverridesScope.of(context).balanceCard;
    final transparentStatus = balance.coverage.statusAgainst(chainTip);
    final model = BalanceCardModel(
      spendable: balance.spendable.format(),
      pending: balance.pending.isZero ? null : balance.pending.format(),
      obscured: obscured,
      transparentStatus: transparentStatus,
    );
    if (override != null) return override(context, model);

    return ZakuraCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Spendable',
            style: theme.typography.caption.copyWith(
              color: theme.colors.textMuted,
            ),
          ),
          SizedBox(height: theme.spacing.xs),
          Row(
            crossAxisAlignment: CrossAxisAlignment.baseline,
            textBaseline: TextBaseline.alphabetic,
            children: [
              Flexible(
                child: Text(
                  obscured ? '••••••' : model.spendable,
                  style: theme.typography.display.copyWith(
                    color: theme.colors.text,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              SizedBox(width: theme.spacing.sm),
              Text(
                'ZEC',
                style: theme.typography.body.copyWith(
                  color: theme.colors.textMuted,
                ),
              ),
            ],
          ),
          if (model.pending != null) ...[
            SizedBox(height: theme.spacing.md),
            Row(
              children: [
                Container(
                  width: 6,
                  height: 6,
                  decoration: BoxDecoration(
                    color: theme.colors.pending,
                    shape: BoxShape.circle,
                  ),
                ),
                SizedBox(width: theme.spacing.sm),
                Expanded(
                  child: Text(
                    obscured
                        ? '•••• settling'
                        : '${model.pending} ZEC still settling',
                    style: theme.typography.caption.copyWith(
                      color: theme.colors.textMuted,
                    ),
                  ),
                ),
              ],
            ),
          ],
          SizedBox(height: theme.spacing.xs),
          Text(
            transparentStatus,
            style: theme.typography.caption.copyWith(
              color: theme.colors.textMuted,
            ),
          ),
          if (!balance.transparent.isZero) ...[
            SizedBox(height: theme.spacing.xs),
            // Named as needing a step rather than folded into the figure above:
            // transparent funds cannot be sent without being shielded first,
            // and showing them as spendable would offer money the send path
            // then refuses.
            Text(
              obscured
                  ? '•••• transparent'
                  : '${balance.transparent.format()} ZEC transparent, $transparentSuffix',
              style: theme.typography.caption.copyWith(
                color: theme.colors.textMuted,
              ),
            ),
          ],
          if (!balance.spentUnconfirmed.isZero) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              obscured
                  ? '•••• on its way out'
                  : '${balance.spentUnconfirmed.format()} ZEC sent, not yet mined',
              style: theme.typography.caption.copyWith(
                color: theme.colors.textMuted,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
