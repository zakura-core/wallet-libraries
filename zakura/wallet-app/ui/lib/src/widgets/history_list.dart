import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../overrides.dart';
import '../theme/theme.dart';
import 'primitives.dart';

/// One transaction.
class HistoryTile extends StatelessWidget {
  /// What the transaction did to the wallet.
  final HistoryEntry entry;

  /// What to do when it is tapped.
  final VoidCallback? onTap;

  /// Creates a history row.
  const HistoryTile({required this.entry, this.onTap, super.key});

  /// Describes what a transaction was, from the wallet's side.
  ///
  /// A transaction whose every received note is change is the wallet paying
  /// somebody else, and calling it "received" would be actively misleading.
  static String describe(HistoryEntry entry) {
    if (entry.isChangeOnly) return 'Sent';
    if (entry.received > entry.spent) return 'Received';
    if (entry.spent > Zatoshi.zero) return 'Sent';
    return 'Transaction';
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final incoming = entry.isIncoming;
    final net = entry.net;
    final model = HistoryTileModel(
      amount: '${incoming ? '+' : '−'}${Zatoshi(net.value.abs()).format()}',
      title: describe(entry),
      subtitle: entry.isPending
          ? 'Waiting to be mined'
          : 'Block ${entry.minedHeight}',
      incoming: incoming,
      pending: entry.isPending,
      pools: entry.poolLabel,
      touchedTransparent: entry.touchedTransparent,
    );

    final override = ZakuraUiOverridesScope.of(context).historyTile;
    if (override != null) return override(context, model);

    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Padding(
        padding: EdgeInsets.symmetric(vertical: theme.spacing.md),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    model.title,
                    style:
                        theme.typography.body.copyWith(color: theme.colors.text),
                  ),
                  SizedBox(height: theme.spacing.xs),
                  Row(
                    children: [
                      if (model.pools.isNotEmpty) ...[
                        // Whether a payment was private is the question behind
                        // reading this list at all, so it is said on the row
                        // rather than a screen deeper. A transparent leg is
                        // marked, because it was public whatever else it was.
                        _PoolTag(
                          label: model.pools,
                          public: model.touchedTransparent,
                        ),
                        SizedBox(width: theme.spacing.sm),
                      ],
                      Flexible(
                        child: Text(
                          model.subtitle,
                          style: theme.typography.caption.copyWith(
                            color: model.pending
                                ? theme.colors.pending
                                : theme.colors.textMuted,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            SizedBox(width: theme.spacing.md),
            Text(
              model.amount,
              style: theme.typography.body.copyWith(
                color: incoming ? theme.colors.positive : theme.colors.text,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// The account's transactions, most recent first.
class HistoryList extends StatelessWidget {
  /// What to show.
  final List<HistoryEntry> entries;

  /// What to do when a row is tapped.
  final void Function(HistoryEntry)? onTap;

  /// Whether to scroll, or lay out at full height inside another scroller.
  final bool shrinkWrap;

  /// Whether the wallet is still looking through the chain.
  ///
  /// An empty list means two very different things, and saying the wrong one
  /// is how somebody concludes their money is gone: before a recovery has
  /// finished it means "not found yet", and only afterwards does it mean
  /// "there is nothing here".
  final bool searching;

  /// Creates a history list.
  const HistoryList({
    required this.entries,
    this.onTap,
    this.shrinkWrap = false,
    this.searching = false,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);

    if (entries.isEmpty) {
      final override = ZakuraUiOverridesScope.of(context).historyEmpty;
      return override?.call(context) ??
          (searching
              ? const ZakuraEmptyState(
                  title: 'Still looking…',
                  subtitle: 'The wallet is working through the chain. Anything '
                      'it finds will appear here as it goes.',
                )
              : const ZakuraEmptyState(
                  title: 'No transactions yet',
                  subtitle: 'Payments to this wallet will appear here once '
                      'they are found on the chain.',
                ));
    }

    return ListView.separated(
      shrinkWrap: shrinkWrap,
      physics: shrinkWrap ? const NeverScrollableScrollPhysics() : null,
      itemCount: entries.length,
      separatorBuilder: (_, _) => Container(
        height: 1,
        color: theme.colors.border,
      ),
      itemBuilder: (context, index) {
        final entry = entries[index];
        return HistoryTile(
          entry: entry,
          onTap: onTap == null ? null : () => onTap!(entry),
        );
      },
    );
  }
}

/// Says where a transaction's value sat.
///
/// Coloured by whether any of it was public rather than by which pool, because
/// that is the distinction that matters to somebody scanning the list: the
/// pools are both private and telling them apart is detail, while transparent
/// is a different kind of thing entirely.
class _PoolTag extends StatelessWidget {
  const _PoolTag({required this.label, required this.public});

  final String label;
  final bool public;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final colour = public ? theme.colors.pending : theme.colors.textMuted;

    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: theme.spacing.sm,
        vertical: 1,
      ),
      decoration: BoxDecoration(
        color: colour.withValues(alpha: 0.12),
        borderRadius: theme.radii.small,
      ),
      child: Text(
        label,
        style: theme.typography.caption.copyWith(color: colour),
      ),
    );
  }
}
