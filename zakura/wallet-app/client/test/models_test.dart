import 'package:test/test.dart';
import 'package:zakura_client/zakura_client.dart';

void main() {
  _unshieldingTests();
  _poolLabelTests();
  group('Balance', () {
    test('totals spendable and pending, but not what has been spent', () {
      const balance = Balance(
        spendable: Zatoshi(100),
        pending: Zatoshi(50),
        spentUnconfirmed: Zatoshi(25),
      );
      expect(balance.total, const Zatoshi(150));
    });

    test('knows when something is still settling', () {
      expect(const Balance(spendable: Zatoshi(100)).hasUnsettled, isFalse);
      expect(const Balance(pending: Zatoshi(1)).hasUnsettled, isTrue);
      expect(const Balance(spentUnconfirmed: Zatoshi(1)).hasUnsettled, isTrue);
    });
  });

  group('HistoryEntry', () {
    HistoryEntry entry({
      int received = 0,
      int spent = 0,
      bool changeOnly = false,
      int? height,
    }) =>
        HistoryEntry(
          txid: List<int>.filled(32, 0),
          minedHeight: height,
          received: Zatoshi(received),
          spent: Zatoshi(spent),
          isChangeOnly: changeOnly,
        );

    test('reports the net effect on the wallet', () {
      expect(entry(received: 100).net, const Zatoshi(100));
      expect(entry(spent: 100).net, const Zatoshi(-100));
    });

    test('a change-only transaction is not money arriving', () {
      expect(entry(received: 100, changeOnly: true).isIncoming, isFalse);
      expect(entry(received: 100).isIncoming, isTrue);
    });

    test('is pending until it is mined', () {
      expect(entry().isPending, isTrue);
      expect(entry(height: 100).isPending, isFalse);
    });

    test('displays the identifier byte-reversed, as everything else does', () {
      final e = HistoryEntry(
        txid: [for (var i = 0; i < 32; i++) i],
        minedHeight: null,
        received: Zatoshi.zero,
        spent: Zatoshi.zero,
        isChangeOnly: false,
      );
      expect(e.displayId.substring(0, 4), '1f1e');
      expect(e.displayId.length, 64);
    });
  });

  group('SyncProgress', () {
    test('an idle phase alone does not mean caught up', () {
      // An empty fetch reports idle too, so a transient source failure looks
      // exactly like having reached the tip. Only the heights settle it.
      const idle = SyncProgress(phase: SyncPhase.idle);
      expect(idle.isCaughtUp, isFalse);
    });

    test('is caught up when it has scanned to the tip', () {
      const caught = SyncProgress(
        phase: SyncPhase.idle,
        tip: 100,
        scannedTo: 100,
      );
      expect(caught.isCaughtUp, isTrue);
    });

    test('is not caught up with blocks still queued', () {
      const queued = SyncProgress(
        phase: SyncPhase.idle,
        tip: 100,
        scannedTo: 100,
        blocksRemaining: 5,
      );
      expect(queued.isCaughtUp, isFalse);
    });

    test('knows when it is working', () {
      expect(const SyncProgress(phase: SyncPhase.recovering).isRunning, isTrue);
      expect(const SyncProgress(phase: SyncPhase.stopped).isRunning, isFalse);
      expect(const SyncProgress(phase: SyncPhase.idle).isRunning, isFalse);
    });
  });
}

/// Whether a payment was private, and if so in which pool, is the question
/// behind reading a history at all.
void _poolLabelTests() {
  HistoryEntry entry({
    PoolAmounts received = const PoolAmounts(),
    PoolAmounts spent = const PoolAmounts(),
  }) =>
      HistoryEntry(
        txid: List<int>.filled(32, 0),
        minedHeight: 1,
        received: received.total,
        spent: spent.total,
        isChangeOnly: false,
        receivedByPool: received,
        spentByPool: spent,
      );

  group('poolLabel', () {
    test('a shielded receipt names its pool', () {
      expect(
        entry(received: const PoolAmounts(ironwood: Zatoshi(100))).poolLabel,
        'Ironwood',
      );
      expect(
        entry(received: const PoolAmounts(orchard: Zatoshi(100))).poolLabel,
        'Orchard',
      );
    });

    test('a public receipt says so', () {
      final e = entry(received: const PoolAmounts(transparent: Zatoshi(100)));
      expect(e.poolLabel, 'Transparent');
      expect(e.touchedTransparent, isTrue);
    });

    /// Spending Ironwood and getting Ironwood change back is one pool, not a
    /// crossing, and saying "Ironwood → Ironwood" would be noise.
    test('change returning to its own pool is not a crossing', () {
      expect(
        entry(
          spent: const PoolAmounts(ironwood: Zatoshi(100)),
          received: const PoolAmounts(ironwood: Zatoshi(40)),
        ).poolLabel,
        'Ironwood',
      );
    });

    /// Value leaving one pool and arriving in another is a crossing, and is
    /// named as the one thing it is rather than two unrelated facts.
    test('a crossing is named as one', () {
      expect(
        entry(
          spent: const PoolAmounts(orchard: Zatoshi(100)),
          received: const PoolAmounts(ironwood: Zatoshi(90)),
        ).poolLabel,
        'Orchard → Ironwood',
      );
    });

    test('shielding names both ends', () {
      expect(
        entry(
          spent: const PoolAmounts(transparent: Zatoshi(100)),
          received: const PoolAmounts(ironwood: Zatoshi(90)),
        ).poolLabel,
        'Transparent → Ironwood',
      );
    });

    /// A transparent leg is never hidden behind a shielded one: that leg was
    /// public whatever else the transaction did.
    test('a mixed transaction still reports being public', () {
      final e = entry(
        received: const PoolAmounts(
          ironwood: Zatoshi(50),
          transparent: Zatoshi(50),
        ),
      );
      expect(e.poolLabel, 'Transparent and Ironwood');
      expect(e.touchedTransparent, isTrue);
    });

    test('a shielded transaction is not reported as public', () {
      expect(
        entry(received: const PoolAmounts(ironwood: Zatoshi(1))).touchedTransparent,
        isFalse,
      );
    });

    test('pool amounts total across every pool', () {
      const a = PoolAmounts(
        orchard: Zatoshi(1),
        ironwood: Zatoshi(2),
        transparent: Zatoshi(3),
      );
      expect(a.total, const Zatoshi(6));
      expect(const PoolAmounts().isZero, isTrue);
    });
  });
}

/// An unshielding spends shielded notes and pays out in the open. The wallet's
/// own notes only say value left a pool; where it went comes from the
/// transaction's bytes, and it is the half that matters most.
void _unshieldingTests() {
  HistoryEntry unshield({int paidOut = 929985000}) => HistoryEntry(
        txid: List<int>.filled(32, 0),
        minedHeight: 3443766,
        received: Zatoshi.zero,
        spent: const Zatoshi(930000000),
        isChangeOnly: false,
        spentByPool: const PoolAmounts(ironwood: Zatoshi(930000000)),
        paidToTransparent: Zatoshi(paidOut),
      );

  group('unshielding', () {
    test('is named as going transparent, not as the pool it left', () {
      expect(unshield().poolLabel, 'Ironwood → Transparent');
    });

    test('counts as having touched the open', () {
      expect(unshield().touchedTransparent, isTrue);
      expect(unshield().isUnshielding, isTrue);
    });

    /// A shielded payment to somebody else spends notes and pays out nothing
    /// transparent, and must not be called an unshielding.
    test('a shielded payment is not one', () {
      final shielded = HistoryEntry(
        txid: List<int>.filled(32, 0),
        minedHeight: 1,
        received: Zatoshi.zero,
        spent: const Zatoshi(100),
        isChangeOnly: false,
        spentByPool: const PoolAmounts(ironwood: Zatoshi(100)),
      );
      expect(shielded.isUnshielding, isFalse);
      expect(shielded.touchedTransparent, isFalse);
      expect(shielded.poolLabel, 'Ironwood');
    });

    /// A receipt pays out nothing, so it is never an unshielding however the
    /// transaction was shaped.
    test('a receipt is never one', () {
      final receipt = HistoryEntry(
        txid: List<int>.filled(32, 0),
        minedHeight: 1,
        received: const Zatoshi(100),
        spent: Zatoshi.zero,
        isChangeOnly: false,
        receivedByPool: const PoolAmounts(ironwood: Zatoshi(100)),
        paidToTransparent: const Zatoshi(50),
      );
      expect(receipt.isUnshielding, isFalse);
      expect(receipt.poolLabel, 'Ironwood');
    });
  });
}
