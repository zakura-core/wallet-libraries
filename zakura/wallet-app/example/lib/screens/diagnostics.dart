import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

import '../main.dart';
import '../mode.dart';
import '../startup.dart';

/// What this build is, what it is talking to, and how far it has got —
/// everything a report about a recovery needs and nothing that identifies
/// the wallet.
///
/// No seed, key, address, script, transaction identifier or amount appears
/// here or in the text the copy button produces. Heights, counts, reasons,
/// hosts and versions do. A diagnostic that carried an address would turn
/// every bug report into a disclosure.
class DiagnosticsScreen extends ConsumerWidget {
  /// Creates the diagnostics screen.
  const DiagnosticsScreen({super.key});

  /// The report as plain text.
  static String report({
    required ZakuraMode? mode,
    required StartupReady? startup,
    required Balance? balance,
    required SyncProgress? progress,
    required String? syncFailure,
    required int historyEntries,
    required int? accountBirthday,
  }) {
    final coverage = balance?.coverage ?? const TransparentCoverage();
    final lines = <String>[
      'zakura recovery diagnostics',
      'mode: ${mode?.name ?? 'none'}',
      if (startup?.buildInfo case final info?) ...[
        'native send enabled: ${info.sendEnabled}',
        'transparent schema: ${info.transparentSchema}',
        'layout version: ${info.layoutVersion}',
      ],
      if (startup?.server case final server?) ...[
        'server chain: ${server.chainName}',
        'server height: ${server.blockHeight}',
        'server branch: ${server.consensusBranchId}',
        'server software: ${server.vendor} ${server.version}',
      ],
      if (startup?.profileDirectory case final directory?)
        'profile: ${_redactHome(directory)}',
      if (accountBirthday != null) 'account birthday: $accountBirthday',
      'sync phase: ${progress?.phase.name ?? 'unknown'}',
      'sync failed: ${progress?.failed ?? false}',
      if (syncFailure != null) 'sync failure: ${_redactUrls(syncFailure)}',
      'scanned to: ${progress?.scannedTo ?? 'none'}',
      'server tip: ${progress?.tip ?? 'none'}',
      'blocks remaining: ${progress?.blocksRemaining ?? 0}',
      'transparent accepted target: ${coverage.anchorHeight ?? 'none'}',
      'transparent covered through: ${coverage.coveredThrough ?? 'none'}',
      'transparent settled through: ${coverage.settledThrough ?? 'none'}',
      'transparent completion: ${coverage.completion ?? 'never'}',
      'transparent pending pages: ${coverage.pendingPages}',
      'transparent unresolved spends: ${coverage.unresolvedSpends}',
      'transparent synchronized: ${coverage.synchronized}',
      'history entries shown: $historyEntries',
    ];
    return lines.join('\n');
  }

  /// A path with the home directory replaced, so a report names the profile
  /// without naming the person.
  static String _redactHome(String path) {
    final marker = '/Library/Application Support/';
    final at = path.indexOf(marker);
    return at < 0 ? path : '~${path.substring(at)}';
  }

  /// A failure message with any URL reduced to its host, so a report can say
  /// which service failed without carrying a path or a query.
  static String _redactUrls(String text) => text.replaceAllMapped(
    RegExp(r'https?://([^/\s]+)[^\s]*'),
    (m) => 'https://${m[1]}/…',
  );

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final mode = ref.watch(currentModeProvider);
    final startup = ref.watch(startupProvider);
    final balance = ref.watch(balanceProvider).value;
    final progress = ref.watch(syncProgressProvider).value;
    final failure = ref.watch(syncFailureProvider).value;
    final history = ref.watch(historyProvider).value ?? const [];
    final accounts = ref.watch(accountsProvider).value ?? const [];
    final text = report(
      mode: mode,
      startup: startup,
      balance: balance,
      progress: progress,
      syncFailure: failure,
      historyEntries: history.length,
      accountBirthday: accounts.isEmpty ? null : accounts.first.birthday,
    );

    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              GestureDetector(
                onTap: () => Navigator.of(context).pop(),
                behavior: HitTestBehavior.opaque,
                child: Text(
                  '‹ Back',
                  style: theme.typography.body.copyWith(
                    color: theme.colors.accent,
                  ),
                ),
              ),
              SizedBox(height: theme.spacing.lg),
              Text(
                'Diagnostics',
                style:
                    theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              Text(
                'Heights, counts, reasons and versions. No seed, key, address, '
                'script, transaction or amount is included, here or when '
                'copied.',
                style: theme.typography.caption.copyWith(
                  color: theme.colors.textMuted,
                ),
              ),
              SizedBox(height: theme.spacing.lg),
              ZakuraCard(
                child: Text(
                  text,
                  style: theme.typography.mono.copyWith(color: theme.colors.text),
                ),
              ),
              SizedBox(height: theme.spacing.lg),
              ZakuraButton(
                label: 'Copy diagnostics',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                onPressed: () => Clipboard.setData(ClipboardData(text: text)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
