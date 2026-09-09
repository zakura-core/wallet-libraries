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

  final TransparentCoverage coverage;

  const Balance({
    this.spendable = Zatoshi.zero,
    this.pending = Zatoshi.zero,
    this.spentUnconfirmed = Zatoshi.zero,
    this.transparent = Zatoshi.zero,
    this.coverage = const TransparentCoverage(),
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
      other.transparent == transparent &&
      other.coverage == coverage;

  @override
  int get hashCode =>
      Object.hash(spendable, pending, spentUnconfirmed, transparent, coverage);
}

/// How far the private transparent ledger has read, and what forbids calling
/// the transparent balance synchronized.
///
/// Coverage is independent of the amount recovered and of shielded scanning.
/// A transparent balance is true as of [coveredThrough]; [anchorHeight] is the
/// target the last complete sync accepted; [completion] is why the last sync
/// stopped, in the ledger's own words; [pendingPages] is work still owed; and
/// [unresolvedSpends] are spends of outputs the ledger has never seen, each
/// of which means the balance is too high.
class TransparentCoverage {
  /// The last height covered, including a shard that can still be replaced.
  /// Null when nothing has been read, which is not a height of zero.
  final int? coveredThrough;

  /// The last height covered by sealed shards alone.
  final int? settledThrough;

  /// The target the last complete sync accepted.
  final int? anchorHeight;

  /// Why the last sync stopped: `complete`, or a reason. Null before any sync.
  final String? completion;

  /// Spends whose receive the ledger has never seen.
  final int unresolvedSpends;

  /// Page retrievals still owed.
  final int pendingPages;

  const TransparentCoverage({
    this.coveredThrough,
    this.settledThrough,
    this.anchorHeight,
    this.completion,
    this.unresolvedSpends = 0,
    this.pendingPages = 0,
  });

  /// Whether the transparent balance may be called synchronized: the last
  /// sync completed to its accepted target and nothing the ledger holds
  /// contradicts it.
  bool get synchronized =>
      completion == 'complete' &&
      coveredThrough != null &&
      anchorHeight != null &&
      coveredThrough! >= anchorHeight! &&
      unresolvedSpends == 0 &&
      pendingPages == 0;

  /// Whether anything has been read at all.
  bool get established => coveredThrough != null;

  /// How far behind the chain tip coverage may sit before it is called out.
  ///
  /// The publisher republishes the tail a moment after each block and the
  /// wallet reads it a moment after that, so coverage trails the tip by a
  /// block or two whenever the chain is moving. Naming that as incomplete
  /// would flag every wallet all the time; a lag past this is something
  /// else — a stalled publisher, a stopped sync — and is named.
  static const int tolerableLag = 10;

  /// Whether [completion] is one of the reasons that only describe coverage
  /// trailing a moving chain, as opposed to a sync that stopped short.
  ///
  /// `scan-ahead` is the wallet having scanned past the ledger's accepted
  /// target; `publication-behind` is the publisher not yet having reached
  /// it. Within [tolerableLag] of the tip these are the ordinary state of a
  /// wallet that is keeping up. Everything else — a budget, an outage, a
  /// chain the wallet has not scanned, a stopped or failed run, a sync still
  /// in progress — is a reason the balance is incomplete, and is shown
  /// however close to the tip the coverage sits.
  bool get isTrailingReason =>
      completion == 'scan-ahead' ||
      (completion?.startsWith('publication-behind:') ?? false);

  /// A sentence for [completion], or null when it needs no explaining.
  String? get reasonDescription {
    final reason = completion;
    if (reason == null) return 'No transparent sync has run yet.';
    if (reason == 'complete') return null;
    if (reason == 'scan-ahead') {
      return 'The wallet has scanned past the last accepted target.';
    }
    if (reason == 'sync-in-progress') return 'A transparent sync is running.';
    if (reason == 'stopped') return 'The last transparent sync was stopped.';
    if (reason == 'failed') return 'The last transparent sync failed.';
    if (reason == 'chain-rewound') {
      return 'The chain was rewound and coverage was rolled back.';
    }
    if (reason == 'query-budget') {
      return 'The last sync reached its private query budget.';
    }
    if (reason == 'byte-budget') {
      return 'The last sync reached its private byte budget.';
    }
    if (reason == 'pending-limit') {
      return 'The last sync reached the limit on work it may carry.';
    }
    if (reason == 'unresolved-spends') {
      return 'Spends were found whose receives are not yet covered.';
    }
    if (reason == 'discovery-unbounded') {
      return 'New addresses kept being discovered; the next sync continues.';
    }
    if (reason.startsWith('overloaded:')) {
      return 'The service was at capacity (shard ${reason.split(':').last}).';
    }
    if (reason.startsWith('chain-unknown:')) {
      return 'The wallet has not scanned block ${reason.split(':').last} yet.';
    }
    if (reason.startsWith('publication-behind:')) {
      return 'Waiting for publication through block ${reason.split(':').last}.';
    }
    return 'The last sync stopped: $reason.';
  }

  String get status => statusAgainst(null);

  /// The status as shown beside the balance, judged against [chainTip], the
  /// height the wallet's own server reports.
  ///
  /// Coverage that is [synchronized] is reported as its height. Anything
  /// short of that is reported with why, with one exception: coverage that
  /// merely trails a moving chain — a [isTrailingReason] within
  /// [tolerableLag] of the tip — is reported as current, because naming that
  /// would flag every wallet all the time. A reason that is not a trailing
  /// one is never suppressed by proximity to the tip: a sync that ran out
  /// of budget one block from the tip is still a sync that ran out of budget.
  /// Nothing read at all is never a height.
  String statusAgainst(int? chainTip) {
    final coverage = coveredThrough == null
        ? 'Transparent coverage not yet established'
        : 'Transparent coverage through block $coveredThrough';
    if (synchronized) return coverage;
    if (unresolvedSpends > 0) {
      return '$coverage. Transaction history is incomplete: '
          '$unresolvedSpends unresolved spend${unresolvedSpends == 1 ? '' : 's'}.';
    }
    if (pendingPages > 0) {
      return '$coverage. Transparent sync is incomplete: '
          '$pendingPages page${pendingPages == 1 ? '' : 's'} still owed.';
    }
    if (coveredThrough != null &&
        chainTip != null &&
        isTrailingReason &&
        chainTip - coveredThrough! <= tolerableLag) {
      return coverage;
    }
    final reason = reasonDescription;
    if (reason != null) return '$coverage. $reason';
    return '$coverage. Transparent sync is incomplete.';
  }

  @override
  bool operator ==(Object other) =>
      other is TransparentCoverage &&
      coveredThrough == other.coveredThrough &&
      settledThrough == other.settledThrough &&
      anchorHeight == other.anchorHeight &&
      completion == other.completion &&
      unresolvedSpends == other.unresolvedSpends &&
      pendingPages == other.pendingPages;
  @override
  int get hashCode => Object.hash(
    coveredThrough,
    settledThrough,
    anchorHeight,
    completion,
    unresolvedSpends,
    pendingPages,
  );
}

/// Value, by where in the protocol it sat.
///
/// A total alone cannot answer what somebody actually wants to know about a
/// transaction — whether it was private, and if so in which pool.
class PoolAmounts {
  /// Value in the Orchard pool.
  final Zatoshi orchard;

  /// Value in the Ironwood pool.
  final Zatoshi ironwood;

  /// Value on transparent addresses, which is to say in public.
  final Zatoshi transparent;

  const PoolAmounts({
    this.orchard = Zatoshi.zero,
    this.ironwood = Zatoshi.zero,
    this.transparent = Zatoshi.zero,
  });

  /// The sum across every pool.
  Zatoshi get total => orchard + ironwood + transparent;

  /// Whether nothing moved anywhere.
  bool get isZero => total.isZero;

  /// The pools involved, in protocol order.
  List<Pool> get pools => [
    if (!transparent.isZero) Pool.transparent,
    if (!orchard.isZero) Pool.orchard,
    if (!ironwood.isZero) Pool.ironwood,
  ];

  @override
  String toString() =>
      'PoolAmounts(orchard: $orchard, ironwood: $ironwood, '
      'transparent: $transparent)';
}

/// Where value sat in the protocol.
enum Pool {
  /// In public, on a transparent address.
  transparent('Transparent'),

  /// Shielded, in the Orchard pool.
  orchard('Orchard'),

  /// Shielded, in the Ironwood pool.
  ironwood('Ironwood');

  const Pool(this.label);

  /// What to call it on screen.
  final String label;

  /// Whether value here is private.
  bool get isShielded => this != Pool.transparent;
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

  /// What the wallet received, by where it landed.
  final PoolAmounts receivedByPool;

  /// What the wallet spent, by where it came from.
  final PoolAmounts spentByPool;

  /// Value this transaction paid out to transparent addresses.
  ///
  /// Read from the transaction's own bytes rather than from this wallet's
  /// notes. The wallet's own side says only that value left a pool, not
  /// whether it went somewhere public — and for an unshielding that is the
  /// most important part.
  final Zatoshi paidToTransparent;

  const HistoryEntry({
    required this.txid,
    required this.minedHeight,
    required this.received,
    required this.spent,
    required this.isChangeOnly,
    this.receivedByPool = const PoolAmounts(),
    this.spentByPool = const PoolAmounts(),
    this.paidToTransparent = Zatoshi.zero,
  });

  /// Whether this transaction made value public.
  ///
  /// Shielded notes spent, value paid out in the open. Worth its own name
  /// because it is the one movement somebody might not have intended.
  bool get isUnshielding =>
      !paidToTransparent.isZero && !spentByPool.total.isZero;

  /// Where this transaction's value moved, for somebody reading the list.
  ///
  /// The question behind it is whether the transaction was private, so a
  /// transparent leg is never hidden behind a shielded one: a payment that
  /// touched a transparent address was public in that leg however it ended up.
  ///
  /// Value leaving one pool and arriving in another is named as the crossing it
  /// is, rather than as two unrelated facts.
  String get poolLabel {
    final from = spentByPool.pools;
    final to = receivedByPool.pools;

    if (from.isEmpty && to.isEmpty) return '';
    if (from.isEmpty) return to.map((p) => p.label).join(' and ');

    // Where it actually went, which this wallet's own notes cannot say. An
    // unshielding spends shielded notes and pays out in the open, and naming it
    // after the pool it left keeps the important half to itself.
    if (isUnshielding) {
      return '${from.map((p) => p.label).join(' and ')} → Transparent';
    }

    if (to.isEmpty) return from.map((p) => p.label).join(' and ');

    // Change coming back to the pool it left is not a crossing, it is the same
    // pool, and saying "Ironwood → Ironwood" would be noise.
    if (from.length == 1 && to.length == 1 && from.first == to.first) {
      return from.first.label;
    }
    return '${from.map((p) => p.label).join(' and ')} → '
        '${to.map((p) => p.label).join(' and ')}';
  }

  /// Whether any part of this transaction was public.
  bool get touchedTransparent =>
      !receivedByPool.transparent.isZero ||
      !spentByPool.transparent.isZero ||
      isUnshielding;

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

/// What the native build is.
///
/// The one question an application asks before trusting the mode it thinks
/// it is in: the Dart side knows what it was told to be, and this is what the
/// native side actually is.
class BuildInfo {
  /// Whether the native build can send at all.
  ///
  /// A recovery build cannot, and says so here rather than only when asked.
  final bool sendEnabled;

  /// The transparent protocol schema the build reads.
  final String transparentSchema;

  /// The derived database layout the build writes.
  final int layoutVersion;

  const BuildInfo({
    required this.sendEnabled,
    required this.transparentSchema,
    required this.layoutVersion,
  });

  @override
  String toString() =>
      'BuildInfo(send: $sendEnabled, schema: $transparentSchema, '
      'layout: $layoutVersion)';
}

/// What a lightwalletd server says it is.
class NetworkIdentity {
  /// `main` or `test`, as the server names its chain.
  final String chainName;

  /// Where Sapling activated on that chain.
  final int saplingActivationHeight;

  /// The consensus branch the server is on, in its own encoding.
  final String consensusBranchId;

  /// The latest block the server holds.
  final int blockHeight;

  /// The server software.
  final String vendor;

  /// Its version.
  final String version;

  const NetworkIdentity({
    required this.chainName,
    required this.saplingActivationHeight,
    required this.consensusBranchId,
    required this.blockHeight,
    required this.vendor,
    required this.version,
  });

  /// Whether the server serves mainnet.
  bool get isMainnet => chainName == 'main';

  @override
  String toString() => 'NetworkIdentity($chainName at $blockHeight)';
}
