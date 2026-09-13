import 'dart:async';

import 'bindings.dart';
import 'models.dart';
import 'zatoshi.dart';

/// An open wallet.
///
/// A thin, deliberately boring wrapper over [ZakuraBindings]. It adds three
/// things the native side does not: progress as a stream rather than a poll, a
/// notification when the wallet's contents change, and Dart types in place of
/// the plain integers that cross the boundary.
///
/// It holds no derived state. Balance and history are read when asked for,
/// because caching them here would mean two places could disagree about what
/// the wallet is worth, and the wrong one is always the one on screen.
class ZakuraWallet {
  ZakuraWallet(this._bindings, {Duration pollInterval = const Duration(seconds: 1)})
      : _pollInterval = pollInterval;

  final ZakuraBindings _bindings;
  final Duration _pollInterval;

  final _progress = StreamController<SyncProgress>.broadcast();
  final _changed = StreamController<void>.broadcast();

  Timer? _poll;
  SyncProgress _last = const SyncProgress();
  bool _closed = false;
  bool _polling = false;

  /// How far synchronisation has got, as it changes.
  ///
  /// Only distinct values are emitted: the underlying poll runs on a timer and
  /// most ticks find nothing new, and waking the interface to redraw the same
  /// thing is the cheapest waste available.
  Stream<SyncProgress> get progress => _progress.stream;

  /// The most recent progress, without waiting for the stream.
  SyncProgress get lastProgress => _last;

  /// Fires when the wallet's contents may have changed.
  ///
  /// A scanned batch, or a sent payment. Balance and history are read on
  /// demand, so this is the signal to read them again — it carries no data of
  /// its own precisely so that it cannot be stale.
  Stream<void> get changed => _changed.stream;

  /// What the native build is.
  Future<BuildInfo> buildInfo() => _bindings.buildInfo();

  /// Asks the lightwalletd server at [lightwalletdUrl] which chain it serves.
  Future<NetworkIdentity> networkIdentity({required String lightwalletdUrl}) =>
      _bindings.networkIdentity(lightwalletdUrl: lightwalletdUrl);

  /// Generates a new seed phrase.
  Future<String> generateMnemonic() => _bindings.generateMnemonic();

  /// Returns whether a phrase is a valid mnemonic.
  Future<bool> validateMnemonic(String phrase) =>
      _bindings.validateMnemonic(phrase);

  /// Opens or creates the wallet in [directory].
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    bool mainnet = true,
    String? transparentFiltersUrl,
    String? transparentShardsUrl,
  }) =>
      _bindings.open(
        directory: directory,
        lightwalletdUrl: lightwalletdUrl,
        mainnet: mainnet,
        transparentFiltersUrl: transparentFiltersUrl,
        transparentShardsUrl: transparentShardsUrl,
      );

  /// Creates an account from a seed phrase.
  ///
  /// [birthday] is the height below which the account has no history. Too high
  /// loses transactions; too low only costs scanning time, so when in doubt go
  /// lower.
  Future<int> createAccount({required String phrase, int? birthday}) async {
    final id = await _bindings.createAccount(phrase: phrase, birthday: birthday);
    _changed.add(null);
    return id;
  }

  /// Restores an existing wallet from its seed phrase.
  ///
  /// [birthday] is the height below which the wallet is known to have no
  /// history. Leave it unset when it is not known: scanning from the earliest
  /// possible height costs time, while a birthday that is too high loses
  /// transactions and does so silently.
  Future<int> importAccount({required String phrase, int? birthday}) async {
    final id = await _bindings.importAccount(phrase: phrase, birthday: birthday);
    _changed.add(null);
    return id;
  }

  /// Imports a watch-only account from a unified full viewing key.
  ///
  /// It can see everything and sign nothing.
  Future<int> importViewingKey({required String key, int? birthday}) async {
    final id = await _bindings.importViewingKey(key: key, birthday: birthday);
    _changed.add(null);
    return id;
  }

  /// The earliest height an account on this network could have history at.
  Future<int> earliestBirthday() => _bindings.earliestBirthday();

  /// Asks the server for the current chain tip.
  Future<int> chainTip() => _bindings.chainTip();

  /// Asks the lightwalletd server at [lightwalletdUrl] for its chain tip.
  Future<int> liveHeight({required String lightwalletdUrl}) =>
      _bindings.liveHeight(lightwalletdUrl: lightwalletdUrl);

  /// Returns every account, in creation order.
  Future<List<Account>> accounts() => _bindings.accounts();

  /// Returns an account's balance across every shielded pool.
  ///
  /// Transparent value is not included: this build cannot spend it, and
  /// reporting a balance the wallet cannot back is worse than reporting none.
  Future<Balance> balance(int account) => _bindings.balance(account);

  /// Returns an account's transactions, most recent first.
  Future<List<HistoryEntry>> history(int account, {int limit = 50}) =>
      _bindings.history(account, limit);

  /// Issues the next unused receive address.
  Future<String> nextAddress(int account) => _bindings.nextAddress(account);

  /// Starts synchronising and begins polling for progress.
  Future<void> startSync() async {
    await _bindings.startSync();
    _poll ??= Timer.periodic(_pollInterval, (_) => _tick());
    await _tick();
  }

  /// Stops synchronising.
  Future<void> stopSync() async {
    _poll?.cancel();
    _poll = null;
    await _bindings.stopSync();
    await _tick();
  }

  /// Returns why the last sync stopped, if it stopped because of a failure.
  Future<String?> syncFailure() => _bindings.syncFailure();

  /// Works out what a payment would cost, without proving it.
  Future<SpendQuote> quote({
    required int account,
    required String to,
    required Zatoshi amount,
  }) =>
      _bindings.quote(account: account, to: to, amount: amount.value);

  /// Builds, proves, signs and broadcasts a payment.
  ///
  /// Takes seconds, and longer on a phone: proving is the expensive part and
  /// there is no way around it. Whatever calls this should already be showing
  /// that something is happening.
  Future<SendReceipt> send({
    required int account,
    required String to,
    required Zatoshi amount,
    required String phrase,
  }) async {
    final receipt = await _bindings.send(
      account: account,
      to: to,
      amount: amount.value,
      phrase: phrase,
    );
    _changed.add(null);
    return receipt;
  }

  Future<void> _tick() async {
    // A poll that has not come back yet must not be joined by another. The
    // timer does not wait, so on a slow call two answers could otherwise land
    // out of order and the older one would win.
    if (_closed || _polling) return;
    _polling = true;

    late final SyncProgress next;
    try {
      next = await _bindings.progress();
    } on Object {
      // A failed poll is not worth surfacing: the next one is a second away,
      // and tearing down the stream over it would take the interface with it.
      return;
    } finally {
      _polling = false;
    }
    if (_closed || next == _last) return;

    // Any change in progress means a batch was applied, and a batch that was
    // applied may have found something.
    //
    // Deliberately not "the highest scanned block went up". Recovery works
    // *downwards* from the tip, so that height jumps to near the tip on the
    // first batch and then never moves again — which is the mode every restore
    // uses. Keying off it meant the wallet found somebody's notes and never
    // told the interface, which sat there showing an empty history and a zero
    // balance for the whole recovery.
    //
    // This only runs when the value actually changed, and reading a balance is
    // a query against a local file, so firing on all of them is cheap.
    _last = next;
    _progress.add(next);
    _changed.add(null);
  }

  /// Forgets the wallet: deletes its files and leaves it open and empty.
  ///
  /// Polling stops first, because a poll landing between the delete and the
  /// reopen would report progress for a wallet that no longer exists. Progress
  /// is reset to nothing, and [changed] fires so that balance and history are
  /// read again and found empty.
  Future<void> reset() async {
    _poll?.cancel();
    _poll = null;
    await _bindings.reset();
    _last = const SyncProgress();
    if (_closed) return;
    _progress.add(_last);
    _changed.add(null);
  }

  /// Closes the wallet and stops polling.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _poll?.cancel();
    _poll = null;
    await _bindings.close();
    await _progress.close();
    await _changed.close();
  }
}
