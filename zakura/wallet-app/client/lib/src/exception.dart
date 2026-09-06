/// Why something the wallet was asked to do could not be done.
///
/// These mirror the facade's stable error codes. They are an enum rather than
/// message matching because a message is for a person and will be reworded, and
/// control flow that depends on wording breaks the first time somebody improves
/// it.
enum ZakuraErrorCode {
  /// The wallet database could not be opened, read or written.
  storage(1),

  /// The wallet's schema is not the one this build understands.
  ///
  /// Carries a remedy, which differs by which version disagreed. Rebuilding
  /// the cache costs a rescan, so it is a decision to put to somebody rather
  /// than take.
  versionMismatch(2),

  /// The server could not be reached, or misbehaved.
  source(3),

  /// The network refused a broadcast transaction.
  ///
  /// The transport succeeded and the network said no, which is not the same as
  /// a failure to send and must not be reported as one.
  rejected(4),

  /// Scanning found a chain that does not join up, and could not recover.
  unrecoverable(5),

  /// No account with that identifier exists.
  noSuchAccount(6),

  /// The seed does not derive the account it was given.
  wrongSeed(7),

  /// The account can see but not spend.
  watchOnly(8),

  /// That is not a valid seed phrase.
  badMnemonic(9),

  /// That is not a valid address.
  badAddress(10),

  /// A real address, with no receiver this wallet can pay.
  unsupportedAddress(11),

  /// The account does not hold enough spendable value.
  insufficientFunds(12),

  /// The wallet has not scanned enough of the chain to build a spend.
  ///
  /// Syncing further resolves it; this is a wait, not a failure.
  noAnchor(13),

  /// The payment would have to cross pools, which this build cannot do
  /// without making the transaction identifiable.
  ///
  /// The funds are there. They are in the Orchard pool, and spending them to
  /// somebody else is necessarily a ZIP 318 crossing whose canonical shape this
  /// build cannot yet produce. See `docs/wallet_app.md`.
  crossingUnavailable(14),

  /// Building, proving or signing the transaction failed.
  build(15),

  /// A sync is already running.
  alreadySyncing(16),

  /// The amount cannot leave the Orchard pool in one step.
  ///
  /// Value leaves Orchard only as a ZIP 318 crossing, and every crossing
  /// carries one of a fixed set of denominations so that they cannot be told
  /// apart. An arbitrary amount is not one of them.
  notCanonicalDenomination(17),

  /// A code this build does not know.
  ///
  /// Present so that a newer facade adding a code does not crash an older
  /// application.
  unknown(0);

  const ZakuraErrorCode(this.value);

  /// The wire value.
  final int value;

  /// Returns the code for a wire value, or [unknown].
  static ZakuraErrorCode fromValue(int value) {
    for (final code in ZakuraErrorCode.values) {
      if (code.value == value) return code;
    }
    return unknown;
  }
}

/// Something the wallet could not do.
class ZakuraException implements Exception {
  /// What went wrong, in a form worth branching on.
  final ZakuraErrorCode code;

  /// What went wrong, in a form worth logging.
  ///
  /// Not for display without thought: it is written for whoever is debugging.
  final String message;

  const ZakuraException(this.code, this.message);

  /// Whether trying again later might work.
  ///
  /// A server that could not be reached and a wallet that has not scanned far
  /// enough are both waits. Everything else needs somebody to do something
  /// different.
  bool get isTransient =>
      code == ZakuraErrorCode.source || code == ZakuraErrorCode.noAnchor;

  @override
  String toString() => 'ZakuraException(${code.name}: $message)';
}
