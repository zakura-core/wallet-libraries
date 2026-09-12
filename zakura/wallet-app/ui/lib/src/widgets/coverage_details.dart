import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../theme/theme.dart';
import 'primitives.dart';

/// Everything the wallet knows about how far its transparent ledger has read,
/// laid out so that a partial recovery cannot be mistaken for a finished one.
///
/// The balance card carries one sentence; this carries the facts behind it:
/// the target the last complete sync accepted, the height coverage reaches,
/// the height sealed shards alone reach, why the last sync stopped, the work
/// still owed, and the spends the ledger could not resolve. A figure that is
/// missing is shown as missing rather than as zero, because a wallet that
/// has read nothing and a wallet that read the whole chain and found nothing
/// show the same balance.
class CoverageDetails extends StatelessWidget {
  /// What the ledger reports.
  final TransparentCoverage coverage;

  /// The chain tip the wallet's own server reports, if known.
  final int? chainTip;

  /// Creates the details panel.
  const CoverageDetails({required this.coverage, this.chainTip, super.key});

  /// One line for the panel's headline.
  static String headline(TransparentCoverage coverage) {
    if (coverage.synchronized) return 'Transparent coverage is complete';
    if (!coverage.established) return 'Transparent coverage not established';
    return 'Transparent coverage is incomplete';
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    String height(int? value) => value == null ? 'none' : _grouped(value);
    final rows = <(String, String)>[
      ('Accepted target', height(coverage.anchorHeight)),
      ('Covered through', height(coverage.coveredThrough)),
      ('Settled through', height(coverage.settledThrough)),
      if (chainTip != null) ('Server chain tip', _grouped(chainTip!)),
      ('Last sync', coverage.completion ?? 'never run'),
      ('Pages still owed', '${coverage.pendingPages}'),
      ('Unresolved spends', '${coverage.unresolvedSpends}'),
      ('Addresses outside coverage', '${coverage.outsideCoverage}'),
    ];
    final reason = coverage.reasonDescription;

    return ZakuraCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            headline(coverage),
            style: theme.typography.body.copyWith(
              color: coverage.synchronized
                  ? theme.colors.text
                  : theme.colors.negative,
            ),
          ),
          if (reason != null) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              reason,
              style: theme.typography.caption.copyWith(
                color: theme.colors.textMuted,
              ),
            ),
          ],
          if (coverage.unresolvedSpends > 0) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              'An unresolved spend is an output still counted that something '
              'has already consumed: the transparent balance is too high '
              'until it resolves.',
              style: theme.typography.caption.copyWith(
                color: theme.colors.textMuted,
              ),
            ),
          ],
          if (coverage.outsideCoverage > 0) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              'An address outside coverage uses a script the private tables '
              'cannot index. Nothing recovers its history, so it is unknown '
              'rather than empty, and the transparent balance may be too low.',
              style: theme.typography.caption.copyWith(
                color: theme.colors.textMuted,
              ),
            ),
          ],
          SizedBox(height: theme.spacing.md),
          for (final (label, value) in rows) ...[
            Row(
              children: [
                Expanded(
                  child: Text(
                    label,
                    style: theme.typography.caption.copyWith(
                      color: theme.colors.textMuted,
                    ),
                  ),
                ),
                Text(
                  value,
                  style: theme.typography.mono.copyWith(
                    color: theme.colors.text,
                  ),
                ),
              ],
            ),
            SizedBox(height: theme.spacing.xs),
          ],
        ],
      ),
    );
  }
}

/// A block height with thousands separated, so 3476813 reads as a height.
String _grouped(int height) {
  final digits = height.toString();
  final out = StringBuffer();
  for (var i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 == 0) out.write(',');
    out.write(digits[i]);
  }
  return out.toString();
}
