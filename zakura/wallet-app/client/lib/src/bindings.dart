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
  /// What the native build is: whether it can send, and which protocol
  /// schema and database layout it carries.
  Future<BuildInfo> buildInfo();

  /// Asks the lightwalletd server at [lightwalletdUrl] which chain it
  /// serves, with no wallet open.
  ///
  /// What an application checks before it opens anything: a mainnet wallet
  /// pointed at a testnet server scans a chain its keys were never paid on
  /// and reports an honest, wrong zero.
  Future<NetworkIdentity> networkIdentity({required String lightwalletdUrl});

  /// Generates a new seed phrase.
  ///
  /// The phrase is the wallet. Whoever receives it is responsible for showing
  /// it once and then storing it where the operating system protects it.
  Future<String> generateMnemonic();

  /// Returns whether a phrase is a valid mnemonic.
  Future<bool> validateMnemonic(String phrase);

  /// Opens or creates the wallet in [directory].
  ///
  /// The two transparent services are named separately and both are needed:
  /// public filter bytes reveal nothing about who asked, private queries
  /// reveal which chain ranges had probable activity, and one host serving
  /// both can join those facts. With either absent, transparent tracking is
  /// off and reported as uncovered, which is not a zero balance.
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
    String? transparentFiltersUrl,
    String? transparentShardsUrl,
  });

  /// Creates a new wallet from a seed phrase, and returns its account.
  ///
  /// For a wallet that has never existed. Leaving [birthday] unset uses the
  /// current chain tip, because an account created now cannot have been paid
  /// earlier.
  Future<int> createAccount({required String phrase, int? birthday});

  /// Restores an existing wallet from its seed phrase.
  ///
  /// [birthday] is the height below which the wallet is known to have no
  /// history. Leaving it unset means "not known" and scans from
  /// [earliestBirthday] rather than guessing — a guess that is too high skips
  /// the blocks the money arrived in, and the wallet then shows a balance
  /// that is missing funds with nothing to say so.
  Future<int> importAccount({required String phrase, int? birthday});

  /// Imports a watch-only account from a unified full viewing key.
  Future<int> importViewingKey({required String key, int? birthday});

  /// The earliest height an account on this network could have history at.
  Future<int> earliestBirthday();

  /// Asks the server for the current chain tip.
  Future<int> chainTip();

  /// Asks the lightwalletd server at [lightwalletdUrl] for its current chain
  /// tip, with no wallet involved.
  ///
  /// For a diagnostic view of each environment's endpoint. The server answers
  /// for whichever chain it serves; the caller pairs the height with the
  /// environment it expects the URL to be.
  Future<int> liveHeight({required String lightwalletdUrl});

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
  ///
  /// A recovery-only build refuses with [ZakuraErrorCode.sendDisabled]
  /// before it reads the phrase; see [buildInfo].
  Future<SendReceipt> send({
    required int account,
    required String to,
    required int amount,
    required String phrase,
  });

  /// Returns why the last sync stopped, if it stopped because of a failure.
  ///
  /// Cleared when a new sync starts. The message is for a log or a details
  /// pane; [SyncProgress.failed] is what an interface branches on.
  Future<String?> syncFailure();

  /// Forgets the wallet: deletes its files and leaves it open and empty.
  ///
  /// The only way to change wallets while the store holds one account. What
  /// follows is a create or a restore, exactly as on first launch; restoring
  /// the same phrase again is how a recovery is re-run with a lower birthday.
  Future<void> reset();

  /// Releases the wallet.
  Future<void> close();
}
