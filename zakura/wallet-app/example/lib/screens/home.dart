import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

import 'forget.dart';
import 'receive.dart';
import 'send.dart';

/// Balance, sync, and recent history.
///
/// Thin on purpose. Every piece it shows comes from `zakura_ui` and every
/// figure from a provider, so there is nothing here to get wrong.
class HomeScreen extends ConsumerWidget {
  /// Creates the home screen.
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final balance = ref.watch(balanceProvider);
    final history = ref.watch(historyProvider);
    final progress = ref.watch(syncProgressProvider);

    // The bar reads the smoothed value; the label reads whole percentages.
    // Two providers so that a widget redrawing at sixty hertz is only ever the
    // bar itself.
    final display = ref.watch(syncDisplayProgressProvider);

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
              BalanceCard(balance: balance.value ?? const Balance()),
              SizedBox(height: theme.spacing.lg),
              Row(
                children: [
                  Expanded(
                    child: ZakuraButton(
                      label: 'Receive',
                      kind: ZakuraButtonKind.secondary,
                      expand: true,
                      onPressed: () => _push(context, const ReceiveScreen()),
                    ),
                  ),
                  SizedBox(width: theme.spacing.md),
                  Expanded(
                    child: ZakuraButton(
                      label: 'Send',
                      expand: true,
                      onPressed: () => _push(context, const SendScreen()),
                    ),
                  ),
                ],
              ),
              SizedBox(height: theme.spacing.xl),
              Text(
                'Activity',
                style:
                    theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              HistoryList(
                entries: history.value ?? const [],
                shrinkWrap: true,
                // Before a recovery finishes, an empty list means "not found
                // yet" rather than "there is nothing here".
                searching: !(progress.value ?? const SyncProgress()).isCaughtUp,
              ),
              SizedBox(height: theme.spacing.xl),
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
