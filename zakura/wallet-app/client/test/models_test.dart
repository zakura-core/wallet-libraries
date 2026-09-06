import 'package:test/test.dart';
import 'package:zakura_client/zakura_client.dart';

void main() {
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
