import 'dart:async';

import 'package:zakura_client/zakura_client.dart';

/// A wallet that exists entirely in memory, so the example runs today.
///
/// The native bindings are not built yet. Because `client` talks to a
/// [ZakuraBindings] interface rather than to generated code, that costs the
/// example nothing: this is a second implementation, and swapping it for the
/// generated one is a single line in `main.dart`.
///
/// It is a demonstration, not a simulation. It syncs on a timer and pays
/// nobody.
class DemoBindings implements ZakuraBindings {
  static const _phrase =
      'ridge zone pause pledge quality artefact spirit lounge marble '
      'harvest fossil summit velvet cradle rally window meadow copper '
      'anchor timber puzzle orbit shallow ribbon';

  final List<Account> _accounts = [];
  final List<HistoryEntry> _history = [];

  Balance _balance = const Balance();
  SyncProgress _progress = const SyncProgress();
  Timer? _sync;
  int _scanned = 2_900_000;
  int _address = 0;

  static const _tip = 3_000_000;

  @override
  Future<String> generateMnemonic() async => _phrase;

  @override
  Future<bool> validateMnemonic(String phrase) async {
    final words = phrase.trim().split(RegExp(r'\s+'));
    return words.length == 12 || words.length == 24;
  }

  @override
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
  }) async {}

  @override
  Future<int> createAccount({required String phrase, int? birthday}) async {
    if (!await validateMnemonic(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.badMnemonic,
        'that is not a valid seed phrase',
      );
    }
    final id = _accounts.length + 1;
    _accounts.add(
      Account(
        id: id,
        birthday: birthday ?? await chainTip(),
        canSpend: true,
        hdAccountIndex: _accounts.length,
      ),
    );
    return id;
  }

  @override
  Future<List<Account>> accounts() async => List.unmodifiable(_accounts);

  @override
  Future<Balance> balance(int account) async => _balance;

  @override
  Future<List<HistoryEntry>> history(int account, int limit) async =>
      List.unmodifiable(_history.take(limit));

  @override
  Future<String> nextAddress(int account) async =>
      'u1demo${(_address++).toString().padLeft(2, '0')}'
      'q9k3xhk2v8n4mzp7r6t5s0wcx2f8j4h7d3g5b9n2m6k8p4r7t3w5y9c2';

  @override
  Future<void> startSync() async {
    _sync?.cancel();
    _sync = Timer.periodic(const Duration(milliseconds: 400), (_) {
      _scanned += 7000;
      if (_scanned >= _tip) {
        _scanned = _tip;
        _sync?.cancel();
        _sync = null;
        // Money appears once there is a chain to have found it on.
        _balance = const Balance(
          spendable: Zatoshi(142500000),
          pending: Zatoshi(25000000),
        );
        _history
          ..clear()
          ..addAll([
            HistoryEntry(
              txid: List<int>.generate(32, (i) => (i * 7) % 256),
              minedHeight: null,
              received: const Zatoshi(25000000),
              spent: Zatoshi.zero,
              isChangeOnly: false,
            ),
            HistoryEntry(
              txid: List<int>.generate(32, (i) => (i * 13) % 256),
              minedHeight: 2_998_400,
              received: const Zatoshi(120000000),
              spent: Zatoshi.zero,
              isChangeOnly: false,
            ),
            HistoryEntry(
              txid: List<int>.generate(32, (i) => (i * 29) % 256),
              minedHeight: 2_995_100,
              received: const Zatoshi(22500000),
              spent: const Zatoshi(40000000),
              isChangeOnly: true,
            ),
          ]);
      }
      _progress = SyncProgress(
        phase: _scanned >= _tip ? SyncPhase.idle : SyncPhase.recovering,
        fraction: (_scanned - 2_900_000) / (_tip - 2_900_000),
        tip: _tip,
        scannedTo: _scanned,
        blocksRemaining: _tip - _scanned,
      );
    });
  }

  @override
  Future<void> stopSync() async {
    _sync?.cancel();
    _sync = null;
    _progress = SyncProgress(
      phase: SyncPhase.stopped,
      fraction: _progress.fraction,
      tip: _progress.tip,
      scannedTo: _progress.scannedTo,
    );
  }

  @override
  Future<SyncProgress> progress() async => _progress;

  @override
  Future<SpendQuote> quote({
    required int account,
    required String to,
    required int amount,
  }) async {
    if (!to.startsWith('u')) {
      throw const ZakuraException(
        ZakuraErrorCode.badAddress,
        'not a unified address',
      );
    }
    const fee = 15000;
    if (_balance.spendable.value < amount + fee) {
      throw const ZakuraException(
        ZakuraErrorCode.insufficientFunds,
        'not enough spendable value',
      );
    }
    return SpendQuote(
      amount: Zatoshi(amount),
      fee: const Zatoshi(fee),
      change: Zatoshi(_balance.spendable.value - amount - fee),
      inputs: 1,
    );
  }

  @override
  Future<SendReceipt> send({
    required int account,
    required String to,
    required int amount,
    required String phrase,
  }) async {
    final quote = await this.quote(account: account, to: to, amount: amount);
    // Proving really does take seconds, so the demo waits too rather than
    // teaching a shape the real thing cannot keep to.
    await Future<void>.delayed(const Duration(seconds: 3));
    _balance = Balance(
      spendable: _balance.spendable - quote.total,
      pending: _balance.pending,
      spentUnconfirmed: quote.total,
    );
    final txid = List<int>.generate(32, (i) => (i * 31 + amount) % 256);
    _history.insert(
      0,
      HistoryEntry(
        txid: txid,
        minedHeight: null,
        received: Zatoshi.zero,
        spent: quote.total,
        isChangeOnly: false,
      ),
    );
    return SendReceipt(txid: txid, serverResponse: 'accepted');
  }

  @override
  Future<int> importAccount({required String phrase, int? birthday}) async {
    if (!await validateMnemonic(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.badMnemonic,
        'that is not a valid seed phrase',
      );
    }
    // A restore has history to find, so the demo starts behind the tip and
    // shows the recovery it would really do.
    _scanned = 2_900_000;
    return createAccount(
      phrase: phrase,
      birthday: birthday ?? await earliestBirthday(),
    );
  }

  @override
  Future<int> importViewingKey({required String key, int? birthday}) async {
    throw const ZakuraException(
      ZakuraErrorCode.badViewingKey,
      'the demo wallet has no viewing keys',
    );
  }

  @override
  Future<int> earliestBirthday() async => 2_800_000;

  @override
  Future<int> chainTip() async => _tip;

  @override
  Future<String?> syncFailure() async => null;

  @override
  Future<void> close() async {
    _sync?.cancel();
    _sync = null;
  }
}
