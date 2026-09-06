import 'zatoshi.dart';

/// What an account is worth.
///
/// Three figures rather than one, because they are the same funds at different
/// stages of becoming usable. An interface that shows only [total] will offer
/// funds and then refuse to send them; one that shows only [spendable] will
/// tell somebody their money has vanished while it settles.
class Balance {
  /// Received, unspent, and buried deeply enough that a reorg cannot take it
  /// back. This is what can be sent right now.
  final Zatoshi spendable;

  /// Received and unspent, but not yet settled. Real money, not yet usable.
  final Zatoshi pending;

  /// Committed by a transaction that has not been mined yet.
  final Zatoshi spentUnconfirmed;

  /// Value held on transparent addresses.
  ///
  /// Kept apart from [spendable] because it cannot be sent directly:
  /// transparent funds have to be shielded first. Folding the two together
  /// would offer money the send path would then refuse.
  final Zatoshi transparent;

  const Balance({
    this.spendable = Zatoshi.zero,
    this.pending = Zatoshi.zero,
    this.spentUnconfirmed = Zatoshi.zero,
    this.transparent = Zatoshi.zero,
  });

  /// Everything the account holds, however it is held.
  Zatoshi get total => spendable + pending + transparent;

  /// The shielded value, which is what can be sent directly.
  Zatoshi get shielded => spendable + pending;

  /// Whether any of it is waiting on something.
  bool get hasUnsettled => !pending.isZero || !spentUnconfirmed.isZero;

  @override
  String toString() =>
      'Balance(spendable: $spendable, pending: $pending, '
      'spentUnconfirmed: $spentUnconfirmed)';

  @override
  bool operator ==(Object other) =>
      other is Balance &&
      other.spendable == spendable &&
      other.pending == pending &&
      other.spentUnconfirmed == spentUnconfirmed &&
      other.transparent == transparent;

  @override
  int get hashCode =>
      Object.hash(spendable, pending, spentUnconfirmed, transparent);
}

/// One transaction, as it affected this wallet.
class HistoryEntry {
  /// The transaction's identifier, in protocol byte order.
  final List<int> txid;

  /// The height it was mined at, or null while it is still unmined.
  final int? minedHeight;

  /// What the wallet received.
  final Zatoshi received;

  /// What the wallet spent.
  final Zatoshi spent;

  /// Whether everything received was change.
  ///
  /// A transaction that only returns change is the wallet paying somebody
  /// else, and showing it as money coming in would be wrong.
  final bool isChangeOnly;

  const HistoryEntry({
    required this.txid,
    required this.minedHeight,
    required this.received,
    required this.spent,
    required this.isChangeOnly,
  });

  /// Whether the chain has recorded this yet.
  bool get isPending => minedHeight == null;

  /// Whether this was, on balance, money arriving.
  bool get isIncoming => received > spent && !isChangeOnly;

  /// The net effect on the wallet.
  ///
  /// Negative when the wallet paid out. The fee is included, because from the
  /// wallet's side a fee is indistinguishable from value that left.
  Zatoshi get net => received - spent;

  /// The identifier as it is conventionally displayed: hex, byte-reversed.
  String get displayId {
    final buffer = StringBuffer();
    for (final byte in txid.reversed) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  @override
  String toString() => 'HistoryEntry($displayId, net: $net)';
}

/// An account the wallet holds.
class Account {
  /// The wallet-local identifier.
  final int id;

  /// The height below which this account has no history.
  final int birthday;

  /// Whether the wallet can spend, or only watch.
  final bool canSpend;

  /// The ZIP 32 account index, for accounts derived from a seed.
  final int? hdAccountIndex;

  const Account({
    required this.id,
    required this.birthday,
    required this.canSpend,
    required this.hdAccountIndex,
  });

  @override
  String toString() => 'Account($id, birthday: $birthday)';
}

/// What the synchronisation engine is doing.
enum SyncPhase {
  /// Nothing has been scanned yet.
  bootstrapping,

  /// Working backwards through history.
  recovering,

  /// Following the chain tip.
  tracking,

  /// Nothing left to scan right now.
  ///
  /// Not the same as finished. An empty fetch also reports idle, so a
  /// transient failure to reach the server looks identical to having caught
  /// up. Show the scanned height and the tip rather than a settled result.
  idle,

  /// The engine is not running.
  stopped,
}

/// How far synchronisation has got.
///
/// [fraction] is note-commitment coverage, not blocks scanned. Blocks are a
/// poor proxy: the empty stretches of the chain scan orders of magnitude faster
/// than the busy ones, so a block-count bar moves in lurches and lies about how
/// much time is left.
class SyncProgress {
  /// What the engine is doing.
  final SyncPhase phase;

  /// Coverage between 0 and 1, or null when there is nothing to measure yet.
  final double? fraction;

  /// The highest block the server reported.
  final int? tip;

  /// The highest block the wallet has scanned.
  final int? scannedTo;

  /// How many blocks remain queued.
  final int blocksRemaining;

  /// Whether the last attempt ended in a failure rather than a finish.
  ///
  /// An unreachable server leaves the engine stopped with nothing queued,
  /// which is exactly what having caught up looks like. Without this an
  /// interface would tell somebody their wallet is up to date when it has not
  /// spoken to a server in an hour.
  final bool failed;

  const SyncProgress({
    this.phase = SyncPhase.stopped,
    this.fraction,
    this.tip,
    this.scannedTo,
    this.blocksRemaining = 0,
    this.failed = false,
  });

  /// Whether the engine is doing work right now.
  bool get isRunning =>
      phase == SyncPhase.bootstrapping ||
      phase == SyncPhase.recovering ||
      phase == SyncPhase.tracking;

  /// Whether the wallet has reached the tip, as far as it can tell.
  ///
  /// Deliberately requires having actually scanned to the tip rather than
  /// trusting [SyncPhase.idle], which an empty fetch also produces.
  bool get isCaughtUp =>
      !failed &&
      tip != null &&
      scannedTo != null &&
      scannedTo! >= tip! &&
      blocksRemaining == 0;

  @override
  String toString() =>
      'SyncProgress($phase, ${fraction ?? '-'}, $scannedTo/$tip)';

  @override
  bool operator ==(Object other) =>
      other is SyncProgress &&
      other.phase == phase &&
      other.fraction == fraction &&
      other.tip == tip &&
      other.scannedTo == scannedTo &&
      other.blocksRemaining == blocksRemaining &&
      other.failed == failed;

  @override
  int get hashCode =>
      Object.hash(phase, fraction, tip, scannedTo, blocksRemaining, failed);
}

/// What a payment would cost, worked out before anything is proved.
class SpendQuote {
  /// What the recipient receives.
  final Zatoshi amount;

  /// The fee.
  final Zatoshi fee;

  /// What comes back to the wallet.
  final Zatoshi change;

  /// How many notes would be spent.
  ///
  /// Each one is a proof, so this is also roughly how long the send will take.
  final int inputs;

  /// Whether this payment leaves the Orchard pool as a ZIP 318 crossing.
  ///
  /// A crossing pays a fixed denomination for a fixed fee, so its numbers are
  /// not negotiable the way an ordinary payment's are.
  final bool crossing;

  const SpendQuote({
    required this.amount,
    required this.fee,
    required this.change,
    required this.inputs,
    this.crossing = false,
  });

  /// What leaves the wallet in total.
  Zatoshi get total => amount + fee;

  @override
  String toString() => 'SpendQuote($amount + $fee fee, $inputs inputs)';
}

/// What came back from broadcasting.
class SendReceipt {
  /// The transaction's identifier.
  final List<int> txid;

  /// What the server said when it accepted the transaction.
  ///
  /// Acceptance means it reached the network, not that it will be mined.
  final String serverResponse;

  /// Set when the payment was sent but the wallet could not record it.
  ///
  /// Not a failure of the send — the money is gone either way — but the balance
  /// and history will not account for it until the next scan finds it, which is
  /// worth saying rather than leaving somebody to notice a figure that looks
  /// wrong.
  final String? warning;

  const SendReceipt({
    required this.txid,
    required this.serverResponse,
    this.warning,
  });

  /// The identifier as it is conventionally displayed.
  String get displayId {
    final buffer = StringBuffer();
    for (final byte in txid.reversed) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}
