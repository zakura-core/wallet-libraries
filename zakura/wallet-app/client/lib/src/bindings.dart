import 'models.dart';

/// The native wallet, as this package needs it.
///
/// `client` talks to Rust through this interface rather than to generated code
/// directly, for one reason that matters: it means everything above — the
/// models, the providers, the widgets — can be built and tested with no native
/// library present. The generated foreign-function binding is one
/// implementation; a fake is another.
///
/// It also keeps a bridge regeneration from being a change to the application.
/// Generated code moves when the code generator does; this does not.
///
/// Every method may throw [ZakuraException].
abstract interface class ZakuraBindings {
  /// Generates a new seed phrase.
  ///
  /// The phrase is the wallet. Whoever receives it is responsible for showing
  /// it once and then storing it where the operating system protects it.
  Future<String> generateMnemonic();

  /// Returns whether a phrase is a valid mnemonic.
  Future<bool> validateMnemonic(String phrase);

  /// Opens or creates the wallet in [directory].
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
  });

  /// Creates an account from a seed phrase, and returns its identifier.
  Future<int> createAccount({
    required String phrase,
    required int birthday,
  });

  /// Returns every account, in creation order.
  Future<List<Account>> accounts();

  /// Returns an account's balance across every shielded pool.
  Future<Balance> balance(int account);

  /// Returns an account's transactions, most recent first.
  Future<List<HistoryEntry>> history(int account, int limit);

  /// Issues the next unused receive address.
  ///
  /// Two calls return two different addresses; reusing one lets anybody who has
  /// seen it link the payments made to it.
  Future<String> nextAddress(int account);

  /// Starts synchronising, returning immediately.
  Future<void> startSync();

  /// Stops synchronising.
  Future<void> stopSync();

  /// Returns how far synchronisation has got.
  ///
  /// A poll rather than a stream, because the underlying channel is lossy by
  /// design: a reader that falls behind should see the latest value, not a
  /// queue of stale ones. [ZakuraWallet] turns it into a stream.
  Future<SyncProgress> progress();

  /// Works out what a payment would cost, without proving it.
  Future<SpendQuote> quote({
    required int account,
    required String to,
    required int amount,
  });

  /// Builds, proves, signs and broadcasts a payment.
  ///
  /// Takes seconds. The seed phrase is needed because the wallet stores only
  /// viewing keys; it is used to derive the spending key and then dropped.
  Future<SendReceipt> send({
    required int account,
    required String to,
    required int amount,
    required String phrase,
  });

  /// Releases the wallet.
  Future<void> close();
}
