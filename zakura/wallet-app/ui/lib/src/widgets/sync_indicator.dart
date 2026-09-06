import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../overrides.dart';
import '../theme/theme.dart';

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

  /// Creates a synchronisation indicator.
  const SyncIndicator({
    required this.progress,
    this.displayFraction,
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
    if (progress.failed) return 'Could not reach the server';
    if (progress.isCaughtUp) return 'Up to date';
    return switch (progress.phase) {
      SyncPhase.bootstrapping => 'Starting…',
      SyncPhase.recovering => 'Recovering history…',
      SyncPhase.tracking => 'Catching up…',
      SyncPhase.idle => 'Waiting for new blocks',
      SyncPhase.stopped => 'Not synchronising',
    };
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
        if (!progress.isCaughtUp) ...[
          SizedBox(height: theme.spacing.sm),
          _Bar(fraction: fraction),
          // The heights matter more than the bar: they are what distinguishes
          // "caught up" from "could not reach the server".
          if (progress.scannedTo != null && progress.tip != null) ...[
            SizedBox(height: theme.spacing.xs),
            Text(
              'Block ${progress.scannedTo} of ${progress.tip}',
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
