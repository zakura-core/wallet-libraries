import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';

import 'wallet_provider.dart';

/// The active account's balance.
///
/// Read on demand and re-read when the wallet says its contents changed, rather
/// than held as state that a scan has to remember to update. There is only one
/// answer to what the wallet is worth, and it lives in the database.
final balanceProvider = FutureProvider<Balance>((ref) async {
  ref.watch(walletChangedProvider);
  final account = ref.watch(activeAccountProvider);
  if (account == null) return const Balance();
  return ref.watch(walletProvider).balance(account);
});

/// The active account's transactions, most recent first.
final historyProvider = FutureProvider<List<HistoryEntry>>((ref) async {
  ref.watch(walletChangedProvider);
  final account = ref.watch(activeAccountProvider);
  if (account == null) return const [];
  return ref.watch(walletProvider).history(account);
});

/// A freshly issued receive address.
///
/// Refreshing this provider issues a new one. That is the intended way to get
/// another: two calls returning the same address would let anybody who has seen
/// it link the payments made to it.
/// Whether balances and amounts are hidden on screen.
///
/// A person showing their wallet to someone else, or in public, wants the
/// figures gone and everything else still working. Held in memory: it is a
/// choice about this screen now, not about the wallet.
final balanceObscuredProvider = NotifierProvider<BalanceObscured, bool>(
  BalanceObscured.new,
);

/// The notifier behind [balanceObscuredProvider].
class BalanceObscured extends Notifier<bool> {
  @override
  bool build() => false;

  /// Flips between hidden and shown.
  void toggle() => state = !state;
}

final receiveAddressProvider = FutureProvider<String>((ref) async {
  final account = ref.watch(activeAccountProvider);
  if (account == null) {
    throw StateError('no account is selected');
  }
  return ref.watch(walletProvider).nextAddress(account);
});
