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

  /// A real wallet refuses everything until it has been opened, and a fake that
  /// does not is a fake that hides a caller forgetting to.
  void _requireOpen() {
    if (!opened) {
      throw const ZakuraException(ZakuraErrorCode.storage, 'no wallet is open');
    }
  }

  /// Sets the balance the wallet will report.
  void setBalance(Balance balance) => _balance = balance;

  /// Sets the progress the wallet will report.
  void setProgress(SyncProgress progress) => _progress = progress;

  /// Adds an entry to the history.
  void addHistory(HistoryEntry entry) => _history.insert(0, entry);

  @override
  Future<BuildInfo> buildInfo() async => const BuildInfo(
        sendEnabled: true,
        transparentSchema: 'fake',
        layoutVersion: 0,
      );

  @override
  Future<NetworkIdentity> networkIdentity({
    required String lightwalletdUrl,
  }) async =>
      NetworkIdentity(
        chainName: lightwalletdUrl.contains('testnet') ? 'test' : 'main',
        saplingActivationHeight: 419200,
        consensusBranchId: 'fake',
        blockHeight: 3000000,
        vendor: 'fake',
        version: '0',
      );

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
    String? transparentFiltersUrl,
    String? transparentShardsUrl,
  }) async {
    _maybeThrow();
    opened = true;
  }

  @override
  Future<int> createAccount({required String phrase, int? birthday}) async {
    _requireOpen();
    _maybeThrow();
    if (!await validateMnemonic(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.badMnemonic,
        'not a valid seed phrase',
      );
    }
    // The store numbers accounts from one, not zero. Matching that here stops
    // a caller quietly depending on the first account being account zero.
    _imported.add(phrase);
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
  Future<List<Account>> accounts() async {
    _requireOpen();
    return List.unmodifiable(_accounts);
  }

  void _requireAccount(int account) {
    if (!_accounts.any((a) => a.id == account)) {
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
    _requireOpen();
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

  /// How many times progress has been polled.
  int progressCalls = 0;

  @override
  Future<SyncProgress> progress() async {
    progressCalls++;
    return _progress;
  }

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

  /// Set to have the wallet report a sync failure.
  String? failure;

  @override
  Future<String?> syncFailure() async => failure;

  /// Mirrors the store: the same viewing key cannot be held twice.
  final Set<String> _imported = {};

  @override
  Future<int> importAccount({required String phrase, int? birthday}) async {
    _requireOpen();
    _maybeThrow();
    if (!await validateMnemonic(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.badMnemonic,
        'not a valid seed phrase',
      );
    }
    if (_imported.contains(phrase)) {
      throw const ZakuraException(
        ZakuraErrorCode.accountExists,
        'this wallet has already been imported',
      );
    }
    return createAccount(
      phrase: phrase,
      birthday: birthday ?? await earliestBirthday(),
    );
  }

  @override
  Future<int> importViewingKey({required String key, int? birthday}) async {
    _maybeThrow();
    if (!key.startsWith('uview')) {
      throw const ZakuraException(
        ZakuraErrorCode.badViewingKey,
        'not a viewing key',
      );
    }
    final id = _accounts.length + 1;
    _accounts.add(
      Account(
        id: id,
        birthday: birthday ?? await earliestBirthday(),
        canSpend: false,
        hdAccountIndex: null,
      ),
    );
    return id;
  }

  @override
  Future<int> earliestBirthday() async => 2000000;

  @override
  Future<int> chainTip() async => 3000000;

  @override
  Future<int> liveHeight({required String lightwalletdUrl}) async => 3000000;

  @override
  Future<void> close() async {
    closed = true;
  }

  /// How many times the wallet has been forgotten.
  int resets = 0;

  @override
  Future<void> reset() async {
    _requireOpen();
    _maybeThrow();
    resets++;
    _accounts.clear();
    // A forgotten wallet is not "already here": the same phrase restores.
    _imported.clear();
    _history.clear();
    _balance = const Balance();
    _progress = const SyncProgress();
  }
}
