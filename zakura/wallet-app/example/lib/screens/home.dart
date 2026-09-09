import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

import '../main.dart';
import '../mode.dart';
import 'diagnostics.dart';
import 'forget.dart';
import 'heights.dart';
import 'receive.dart';

/// Balance, sync, coverage, and recent history.
///
/// Thin on purpose. Every piece it shows comes from `zakura_ui` and every
/// figure from a provider, so there is nothing here to get wrong.
///
/// There is no Send here in any mode, and no Receive in a beta mode: this
/// application recovers and reads. The native build refuses to send whatever
/// it is asked, and the interface does not ask.
class HomeScreen extends ConsumerWidget {
  /// Creates the home screen.
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final mode = ref.watch(currentModeProvider) ?? ZakuraMode.demo;
    final balance = ref.watch(balanceProvider);
    final history = ref.watch(historyProvider);
    final progress = ref.watch(syncProgressProvider);

    // The bar reads the smoothed value; the label reads whole percentages.
    // Two providers so that a widget redrawing at sixty hertz is only ever the
    // bar itself.
    final display = ref.watch(syncDisplayProgressProvider);
    final obscured = ref.watch(balanceObscuredProvider);
    final coverage = balance.value?.coverage ?? const TransparentCoverage();
    final tip = progress.value?.tip;

    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              SyncIndicator(
                progress: progress.value ?? const SyncProgress(),
                displayFraction: display,
                failureReason: ref.watch(syncFailureProvider).value,
                onRetry: () => ref.read(retrySyncProvider)(),
              ),
              SizedBox(height: theme.spacing.lg),
              BalanceCard(
                balance: balance.value ?? const Balance(),
                obscured: obscured,
                chainTip: tip,
                transparentSuffix: switch (mode) {
                  ZakuraMode.demo => 'shield to spend',
                  ZakuraMode.shadow => 'shadow validation figure, not a balance',
                  ZakuraMode.recovery => 'recovered privately, unverified',
                },
              ),
              SizedBox(height: theme.spacing.sm),
              ZakuraButton(
                label: obscured ? 'Show balances' : 'Hide balances',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                onPressed: () =>
                    ref.read(balanceObscuredProvider.notifier).toggle(),
              ),
              SizedBox(height: theme.spacing.lg),
              // The facts behind the balance card's one sentence: what was
              // accepted, what was covered, why the last sync stopped, what
              // is still owed. Always shown, because a partial recovery that
              // hid its details would look like a finished one.
              CoverageDetails(coverage: coverage, chainTip: tip),
              if (mode.isBeta) ...[
                SizedBox(height: theme.spacing.sm),
                ZakuraNotice(
                  message: mode == ZakuraMode.shadow
                      ? 'Transparent figures on this profile are validation '
                            'output for comparison with an independent '
                            'reconstruction. Do not act on them.'
                      : 'Transparent figures come from private retrieval. '
                            'They are not authoritative until the independent '
                            'correctness gate passes.',
                ),
              ],
              if (!mode.isBeta) ...[
                SizedBox(height: theme.spacing.lg),
                ZakuraButton(
                  label: 'Receive',
                  kind: ZakuraButtonKind.secondary,
                  expand: true,
                  onPressed: () => _push(context, const ReceiveScreen()),
                ),
              ],
              SizedBox(height: theme.spacing.xl),
              Text(
                'Activity',
                style:
                    theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              if (coverage.unresolvedSpends > 0) ...[
                ZakuraNotice(
                  message: 'Transparent history is incomplete: '
                      '${coverage.unresolvedSpends} spend'
                      '${coverage.unresolvedSpends == 1 ? '' : 's'} could not '
                      'be matched to a receive. Entries below may be missing '
                      'or too high.',
                  isError: true,
                ),
                SizedBox(height: theme.spacing.sm),
              ] else if (!coverage.synchronized) ...[
                ZakuraNotice(
                  message: 'Transparent history below is partial: '
                      '${coverage.statusAgainst(tip)}',
                ),
                SizedBox(height: theme.spacing.sm),
              ],
              HistoryList(
                entries: history.value ?? const [],
                shrinkWrap: true,
                obscured: obscured,
                // Before a recovery finishes, an empty list means "not found
                // yet" rather than "there is nothing here". Transparent
                // coverage counts: a shielded scan that reached the tip is
                // not the whole recovery.
                searching:
                    !(progress.value ?? const SyncProgress()).isCaughtUp ||
                    !coverage.synchronized,
              ),
              SizedBox(height: theme.spacing.xl),
              // What the servers say the chain is at, per environment. The
              // sync bar shows this wallet's own progress against one server;
              // this shows the servers themselves.
              ZakuraButton(
                label: 'Live chain heights',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                onPressed: () => _push(context, const HeightsScreen()),
              ),
              SizedBox(height: theme.spacing.md),
              ZakuraButton(
                label: 'Diagnostics',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                onPressed: () => _push(context, const DiagnosticsScreen()),
              ),
              SizedBox(height: theme.spacing.md),
              // The store holds one account, so this is the way to another
              // wallet, and the way to run a recovery again.
              ZakuraButton(
                label: 'Forget this wallet',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                onPressed: () => _push(context, const ForgetScreen()),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Pushes a screen, keeping the theme scope above it.
void _push(BuildContext context, Widget screen) {
  Navigator.of(context).push(
    PageRouteBuilder<void>(
      pageBuilder: (context, _, _) => Container(
        color: ZakuraTheme.of(context).colors.background,
        child: screen,
      ),
    ),
  );
}
