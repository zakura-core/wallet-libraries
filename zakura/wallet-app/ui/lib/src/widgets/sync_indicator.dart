import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../overrides.dart';
import '../theme/theme.dart';
import 'primitives.dart';

/// How far synchronisation has got.
///
/// Takes an already-smoothed [fraction] rather than smoothing here, so that the
/// widget rebuilding sixty times a second is this one and not everything that
/// happens to share a provider with it.
class SyncIndicator extends StatelessWidget {
  /// What the engine reports.
  final SyncProgress progress;

  /// The smoothed figure for the bar, if one is being interpolated.
  ///
  /// Falls back to the raw fraction, which moves in jumps.
  final double? displayFraction;

  /// Why the sync stopped, when it stopped because of a failure.
  final String? failureReason;

  /// Starts synchronising again.
  final VoidCallback? onRetry;

  /// Creates a synchronisation indicator.
  const SyncIndicator({
    required this.progress,
    this.displayFraction,
    this.failureReason,
    this.onRetry,
    super.key,
  });

  /// A sentence for what is happening.
  ///
  /// Idle is deliberately not called "synchronised". An empty fetch reports
  /// idle too, so a transient failure to reach the server looks exactly like
  /// having caught up, and only the heights can tell them apart.
  static String describe(SyncProgress progress) {
    // Checked before anything else. A failed attempt leaves the engine stopped
    // with nothing queued, which is indistinguishable from having caught up
    // unless the failure is asked about first.
    //
    // Deliberately says nothing about the cause. A sync can stop because the
    // server is unreachable, because the chain could not be interpreted, or
    // because the engine gave up, and naming the wrong one sends somebody to
    // fix something that is not broken. The reason is shown underneath, from
    // the wallet, which knows.
    if (progress.failed) return 'Synchronisation stopped';
    if (progress.isCaughtUp) return 'Up to date';
    return switch (progress.phase) {
      SyncPhase.bootstrapping => 'Starting…',
      SyncPhase.recovering => 'Looking for your transactions…',
      SyncPhase.tracking => 'Catching up…',
      SyncPhase.idle => 'Waiting for new blocks',
      SyncPhase.stopped => 'Not synchronising',
    };
  }

  /// How much is left to do, in the terms that actually move.
  ///
  /// Recovery works downwards from the tip, so the highest scanned block sits
  /// at the tip from the first batch onwards and "block X of Y" reads as
  /// finished while there is still an hour of work left. What moves is the
  /// queue.
  static String? remaining(SyncProgress progress) {
    if (progress.isCaughtUp || progress.failed) return null;
    if (progress.blocksRemaining > 0) {
      return '${_thousands(progress.blocksRemaining)} blocks left to check';
    }
    if (progress.scannedTo != null && progress.tip != null) {
      return 'Block ${progress.scannedTo} of ${progress.tip}';
    }
    return null;
  }

  static String _thousands(int n) {
    final digits = n.toString();
    final out = StringBuffer();
    for (var i = 0; i < digits.length; i++) {
      if (i > 0 && (digits.length - i) % 3 == 0) out.write(',');
      out.write(digits[i]);
    }
    return out.toString();
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final fraction = displayFraction ?? progress.fraction;
    final model = SyncIndicatorModel(
      fraction: fraction,
      label: describe(progress),
      running: progress.isRunning,
    );

    final override = ZakuraUiOverridesScope.of(context).syncIndicator;
    if (override != null) return override(context, model);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                model.label,
                style: theme.typography.caption.copyWith(
                  color: progress.failed
                      ? theme.colors.danger
                      : theme.colors.textMuted,
                ),
              ),
            ),
            if (fraction != null && !progress.isCaughtUp)
              Text(
                '${(fraction * 100).round()}%',
                style: theme.typography.caption
                    .copyWith(color: theme.colors.textMuted),
              ),
          ],
        ),
        if (progress.failed) ...[
          if (failureReason != null) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              failureReason!,
              style: theme.typography.caption
                  .copyWith(color: theme.colors.textMuted),
            ),
          ],
          if (onRetry != null) ...[
            SizedBox(height: theme.spacing.md),
            ZakuraButton(
              label: 'Try again',
              kind: ZakuraButtonKind.secondary,
              onPressed: onRetry,
            ),
          ],
        ] else if (!progress.isCaughtUp) ...[
          SizedBox(height: theme.spacing.sm),
          _Bar(fraction: fraction),
          // What is left matters more than the bar: it is what
          // distinguishes "caught up" from "stopped", and unlike the
          // scanned height it is the number that actually moves during a
          // recovery.
          if (remaining(progress) != null) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              remaining(progress)!,
              style: theme.typography.caption
                  .copyWith(color: theme.colors.textMuted),
            ),
          ],
        ],
      ],
    );
  }
}

class _Bar extends StatelessWidget {
  const _Bar({required this.fraction});

  final double? fraction;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return ClipRRect(
      borderRadius: theme.radii.small,
      child: Container(
        height: 4,
        color: theme.colors.border,
        child: FractionallySizedBox(
          alignment: Alignment.centerLeft,
          // An unknown fraction shows a sliver rather than nothing, so the bar
          // reads as "starting" instead of "broken".
          widthFactor: (fraction ?? 0.02).clamp(0.0, 1.0),
          child: Container(color: theme.colors.accent),
        ),
      ),
    );
  }
}
