import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';

import 'wallet_provider.dart';

/// How far synchronisation has got, as the engine reports it.
///
/// Deliberately alone. The wallet this design replaces fused progress,
/// twenty balance figures and recent history into one notifier, so a balance
/// refresh rebuilt every progress consumer and vice versa. Splitting them is
/// most of the reason this package exists.
final syncProgressProvider = StreamProvider<SyncProgress>((ref) {
  final wallet = ref.watch(walletProvider);
  // Start from the last known value so a widget built between two ticks has
  // something to draw rather than a spinner.
  return wallet.progress.transform(
    StreamTransformer.fromBind(
      (stream) async* {
        yield wallet.lastProgress;
        yield* stream;
      },
    ),
  );
});

/// Whether a sync is running.
final isSyncingProvider = Provider<bool>((ref) {
  return ref.watch(syncProgressProvider).value?.isRunning ?? false;
});

/// A smoothed progress figure, for a bar that has to move.
///
/// The engine reports progress in jumps, one per batch, which on a slow
/// connection means a bar that sits still for seconds and then leaps. This
/// interpolates between reports on a timer.
///
/// It is a separate provider from [syncProgressProvider] on purpose: this one
/// changes sixty times a second and only a progress bar should be watching it.
/// Labels watch [syncPercentageProvider], which changes a hundred times in
/// total.
final syncDisplayProgressProvider =
    NotifierProvider<SyncDisplayProgress, double>(SyncDisplayProgress.new);

/// Interpolates the reported progress so a bar moves smoothly.
class SyncDisplayProgress extends Notifier<double> {
  static const _tick = Duration(milliseconds: 32);

  /// How much of the remaining distance to close each tick.
  ///
  /// Exponential rather than linear so the bar never overshoots and never
  /// stops: it approaches the target and is nudged again when the next report
  /// lands.
  static const _easing = 0.12;

  Timer? _timer;
  double _target = 0;

  @override
  double build() {
    ref.listen(syncProgressProvider, (_, next) {
      final fraction = next.value?.fraction;
      if (fraction != null) _target = fraction.clamp(0.0, 1.0);
    }, fireImmediately: true);

    _timer = Timer.periodic(_tick, (_) => _step());
    ref.onDispose(() => _timer?.cancel());

    return 0;
  }

  void _step() {
    final distance = _target - state;
    // Below a pixel's worth there is nothing to animate, and continuing to
    // publish would wake every listener for no visible change.
    if (distance.abs() < 0.0005) {
      if (state != _target) state = _target;
      return;
    }
    state = state + distance * _easing;
  }
}

/// The progress figure as a whole percentage.
///
/// Separate from [syncDisplayProgressProvider] so that a label rebuilds a
/// hundred times over a sync rather than sixty times a second.
final syncPercentageProvider = Provider<int>((ref) {
  return (ref.watch(syncDisplayProgressProvider) * 100).round();
});
