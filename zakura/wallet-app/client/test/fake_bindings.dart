import 'package:zakura_client/zakura_client.dart';

/// A wallet that exists entirely in memory.
///
/// This is the reason [ZakuraBindings] is an interface. Everything above the
/// bindings can be exercised against this, with no Rust toolchain, no native
/// library and no chain — which is what makes the widgets testable at all.
class FakeBindings implements ZakuraBindings {
  FakeBindings({this.mnemonic = _defaultPhrase});

  static const _defaultPhrase =
      'abandon abandon abandon abandon abandon abandon abandon abandon '
      'abandon abandon abandon about';

  final String mnemonic;

  final List<Account> _accounts = [];
  final List<HistoryEntry> _history = [];
  Balance _balance = const Balance();
  SyncProgress _progress = const SyncProgress();
  int _addressCounter = 0;
  bool opened = false;
  bool closed = false;

  /// Set to have the next call throw.
  ZakuraException? nextError;

  void _maybeThrow() {
    final error = nextError;
    if (error != null) {
      nextError = null;
      throw error;
    }
  }

  /// Sets the balance the wallet will report.
  void setBalance(Balance balance) => _balance = balance;

  /// Sets the progress the wallet will report.
  void setProgress(SyncProgress progress) => _progress = progress;

  /// Adds an entry to the history.
  void addHistory(HistoryEntry entry) => _history.insert(0, entry);

  @override
  Future<String> generateMnemonic() async => mnemonic;

  @override
  Future<bool> validateMnemonic(String phrase) async =>
      phrase.trim().split(RegExp(r'\s+')).length == 12 ||
      phrase.trim().split(RegExp(r'\s+')).length == 24;

  @override
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
  }) async {
    _maybeThrow();
    opened = true;
  }

  @override
  Future<int> createAccount({
    required String phrase,
    required int birthday,
  }) async {
    _maybeThrow();
    if (!await validateMnemonic(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.badMnemonic,
        'not a valid seed phrase',
      );
    }
    final id = _accounts.length;
    _accounts.add(
      Account(
        id: id,
        birthday: birthday,
        canSpend: true,
        hdAccountIndex: id,
      ),
    );
    return id;
  }

  @override
  Future<List<Account>> accounts() async => List.unmodifiable(_accounts);

  void _requireAccount(int account) {
    if (account < 0 || account >= _accounts.length) {
      throw ZakuraException(
        ZakuraErrorCode.noSuchAccount,
        'there is no account $account',
      );
    }
  }

  @override
  Future<Balance> balance(int account) async {
    _maybeThrow();
    _requireAccount(account);
    return _balance;
  }

  @override
  Future<List<HistoryEntry>> history(int account, int limit) async {
    _maybeThrow();
    _requireAccount(account);
    return List.unmodifiable(_history.take(limit));
  }

  @override
  Future<String> nextAddress(int account) async {
    _maybeThrow();
    _requireAccount(account);
    return 'utest1address${_addressCounter++}';
  }

  @override
  Future<void> startSync() async {
    _maybeThrow();
    _progress = const SyncProgress(phase: SyncPhase.bootstrapping);
  }

  @override
  Future<void> stopSync() async {
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
    _maybeThrow();
    _requireAccount(account);
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
    _maybeThrow();
    await quote(account: account, to: to, amount: amount);
    return SendReceipt(
      txid: List<int>.generate(32, (i) => i),
      serverResponse: 'accepted',
    );
  }

  @override
  Future<void> close() async {
    closed = true;
  }
}
