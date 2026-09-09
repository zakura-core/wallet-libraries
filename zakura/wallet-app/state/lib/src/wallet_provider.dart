import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';

import 'onboarding_controller.dart';

/// The open wallet.
///
/// Overridden at the top of the application, because constructing it needs a
/// directory and a server URL that only the application knows, and because
/// overriding it with a fake is how every screen becomes testable.
final walletProvider = Provider<ZakuraWallet>((ref) {
  throw UnimplementedError(
    'walletProvider must be overridden with an open ZakuraWallet',
  );
});

/// The account the application found already in the wallet at startup.
///
/// Overridden where the wallet is opened. Without it a returning user would be
/// shown onboarding again over the top of a wallet they already have — and
/// creating or restoring from there would either add a second account or be
/// refused as a duplicate.
final initialAccountProvider = Provider<int?>((ref) => null);

/// The account currently being looked at.
///
/// A single wallet still has an active account, because the rest of the
/// providers need to know whose balance to read. It is settable so that adding
/// multiple accounts later is a change to this file rather than to every
/// screen.
final activeAccountProvider = NotifierProvider<ActiveAccount, int?>(
  ActiveAccount.new,
);

/// Which account the interface is showing.
class ActiveAccount extends Notifier<int?> {
  @override
  int? build() => ref.watch(initialAccountProvider);

  /// Selects an account.
  void select(int id) => state = id;

  /// Clears the selection, as on lock or reset.
  void clear() => state = null;
}

/// Forgets the open wallet and returns the application to onboarding.
///
/// The wallet's files are deleted and it is reopened empty, so what follows is
/// a create or a restore, exactly as on first launch. That is the only way to
/// change wallets while the store holds one account, and it is also how a
/// recovery is re-run with a lower birthday.
///
/// The wallet goes first and the selection second, deliberately: if forgetting
/// fails the person is still in the wallet they had, with nothing on screen
/// claiming otherwise. The failure is thrown for the caller to show.
final forgetWalletProvider = Provider<Future<void> Function()>((ref) {
  final wallet = ref.watch(walletProvider);
  return () async {
    await wallet.reset();
    ref.read(activeAccountProvider.notifier).clear();
    ref.read(onboardingControllerProvider.notifier).reset();
  };
});

/// Every account the wallet holds.
final accountsProvider = FutureProvider<List<Account>>((ref) async {
  // Re-read whenever the wallet says its contents may have changed, rather
  // than on a timer: the signal already exists and a timer would be both
  // slower and busier.
  ref.watch(_changeTickProvider);
  return ref.watch(walletProvider).accounts();
});

/// Ticks whenever the wallet's contents may have changed.
///
/// Balance, history and accounts all watch this. Keeping it separate is what
/// lets them refresh independently of the progress bar, which changes far more
/// often and matters far less.
final _changeTickProvider = StreamProvider<void>((ref) {
  return ref.watch(walletProvider).changed;
});

/// Ticks whenever the wallet's contents may have changed.
///
/// Exposed so an application can invalidate its own derived state on the same
/// signal.
final walletChangedProvider = Provider<AsyncValue<void>>(
  (ref) => ref.watch(_changeTickProvider),
);
