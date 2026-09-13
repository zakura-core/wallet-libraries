import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';

import 'wallet_provider.dart';

/// Where getting into a wallet has got to.
sealed class OnboardingState {
  const OnboardingState();
}

/// Nothing chosen yet.
class OnboardingIdle extends OnboardingState {
  const OnboardingIdle();
}

/// A new phrase has been generated and is waiting to be written down.
class OnboardingCreated extends OnboardingState {
  /// The phrase, which is the wallet.
  final String phrase;

  /// What went wrong last time, if anything.
  ///
  /// A failed creation belongs here rather than on the restore form: the
  /// person never had a phrase to restore from, and asking them for one
  /// because saving failed would be nonsense.
  final String? error;

  const OnboardingCreated(this.phrase, {this.error});
}

/// Restoring: the form is open.
class OnboardingImporting extends OnboardingState {
  /// The earliest height worth scanning, when known.
  final int? earliestBirthday;

  /// The current chain tip, when known.
  final int? chainTip;

  /// Whether an attempt is in progress.
  final bool busy;

  /// What went wrong last time, if anything.
  final String? error;

  const OnboardingImporting({
    this.earliestBirthday,
    this.chainTip,
    this.busy = false,
    this.error,
  });

  /// Returns a copy with some parts replaced.
  OnboardingImporting copyWith({bool? busy, String? error, bool clearError = false}) =>
      OnboardingImporting(
        earliestBirthday: earliestBirthday,
        chainTip: chainTip,
        busy: busy ?? this.busy,
        error: clearError ? null : (error ?? this.error),
      );
}

/// A wallet is open.
class OnboardingDone extends OnboardingState {
  /// The account that was created or restored.
  final int account;

  const OnboardingDone(this.account);
}

/// Drives creating or restoring a wallet.
final onboardingControllerProvider =
    NotifierProvider<OnboardingController, OnboardingState>(
  OnboardingController.new,
);

/// Creating a new wallet, or restoring an existing one.
class OnboardingController extends Notifier<OnboardingState> {
  @override
  OnboardingState build() => const OnboardingIdle();

  /// Returns to the beginning.
  void reset() => state = const OnboardingIdle();

  /// Generates a phrase for a new wallet.
  ///
  /// The wallet is not created yet: the phrase is shown first, because it
  /// cannot be shown again and nobody can recover it.
  Future<void> beginCreate() async {
    state = OnboardingCreated(await ref.read(walletProvider).generateMnemonic());
  }

  /// Opens the restore form, fetching what is needed to guide the birthday.
  ///
  /// The heights are guidance only, so failing to reach the server opens the
  /// form anyway rather than blocking a restore on the network.
  Future<void> beginImport() async {
    state = const OnboardingImporting();
    final wallet = ref.read(walletProvider);

    int? earliest;
    int? tip;
    try {
      earliest = await wallet.earliestBirthday();
    } on Object {
      earliest = null;
    }
    try {
      tip = await wallet.chainTip();
    } on Object {
      tip = null;
    }

    if (state is OnboardingImporting) {
      state = OnboardingImporting(earliestBirthday: earliest, chainTip: tip);
    }
  }

  /// Creates the wallet whose phrase was just shown.
  Future<void> confirmCreate() async {
    final current = state;
    if (current is! OnboardingCreated) return;

    final int id;
    try {
      // No birthday: a wallet that did not exist a moment ago has no history,
      // so the tip is where it starts.
      id = await ref.read(walletProvider).createAccount(phrase: current.phrase);
    } on ZakuraException catch (e) {
      state = OnboardingCreated(current.phrase, error: _explain(e));
      return;
    }

    ref.read(activeAccountProvider.notifier).select(id);
    state = OnboardingDone(id);
    await _beginSyncing();
  }

  /// Restores a wallet from a phrase.
  Future<void> import({required String phrase, int? birthday}) async {
    final current = state;
    final form = current is OnboardingImporting
        ? current
        : const OnboardingImporting();
    state = form.copyWith(busy: true, clearError: true);

    final int id;
    try {
      id = await ref
          .read(walletProvider)
          .importAccount(phrase: phrase, birthday: birthday);
    } on ZakuraException catch (e) {
      state = form.copyWith(busy: false, error: _explain(e));
      return;
    }

    ref.read(activeAccountProvider.notifier).select(id);
    state = OnboardingDone(id);
    await _beginSyncing();
  }

  /// Starts synchronising, without letting a failure here undo what already
  /// happened.
  ///
  /// The wallet exists by this point. Reporting a failure to start scanning as
  /// a failure to create or restore would tell somebody their money is not
  /// there when it is — and scanning is something the wallet retries anyway,
  /// with its own place to report that it could not.
  Future<void> _beginSyncing() async {
    try {
      await ref.read(walletProvider).startSync();
    } on ZakuraException {
      // Deliberately swallowed. `SyncProgress.failed` is where a sync that
      // could not start belongs, and it is already watched.
    }
  }

  /// A sentence to show somebody, chosen for what they can do about it.
  static String _explain(ZakuraException e) => switch (e.code) {
        ZakuraErrorCode.badMnemonic =>
          'That seed phrase is not valid. Check for a mistyped or missing '
              'word — the order matters.',
        ZakuraErrorCode.accountExists =>
          'This wallet is already here. Importing it twice would count every '
              'balance in it twice.',
        ZakuraErrorCode.badViewingKey => 'That viewing key could not be read.',
        ZakuraErrorCode.source =>
          'Could not reach the server. The wallet was not restored; try again.',
        ZakuraErrorCode.storage => 'The wallet file could not be written.',
        _ => 'The wallet could not be restored.',
      };
}
