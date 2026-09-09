import 'package:test/test.dart';
import 'package:zakura_client/zakura_client.dart';

/// What the balance card says about transparent coverage.
///
/// The M0 baseline found that any incomplete reason was silenced within ten
/// blocks of the tip: a sync that ran out of budget one block short read as
/// current. Only the two reasons that describe coverage trailing a moving
/// chain may be softened by proximity to the tip; everything else is said.
void main() {
  group('TransparentCoverage.statusAgainst', () {
    test('a reason short of the tip is never silenced by proximity', () {
      for (final reason in [
        'query-budget',
        'byte-budget',
        'pending-limit',
        'chain-unknown:110',
        'sync-in-progress',
        'stopped',
        'failed',
        'chain-rewound',
        'overloaded:3',
        'discovery-unbounded',
        'unresolved-spends',
      ]) {
        final coverage = TransparentCoverage(
          coveredThrough: 100,
          anchorHeight: 100,
          completion: reason,
        );
        final text = coverage.statusAgainst(105);
        expect(coverage.synchronized, isFalse, reason: reason);
        expect(
          text,
          isNot('Transparent coverage through block 100'),
          reason: '$reason was silenced',
        );
        expect(text, startsWith('Transparent coverage through block 100. '));
        expect(text, equals(coverage.statusAgainst(null)),
            reason: '$reason reads the same with or without a tip');
      }
    });

    test('trailing the tip by a few blocks is current, further is not', () {
      for (final reason in ['scan-ahead', 'publication-behind:3477105']) {
        final coverage = TransparentCoverage(
          coveredThrough: 3477100,
          anchorHeight: 3477100,
          completion: reason,
        );
        expect(coverage.isTrailingReason, isTrue);
        expect(
          coverage.statusAgainst(3477105),
          'Transparent coverage through block 3477100',
        );
        expect(
          coverage.statusAgainst(3477120),
          contains('Transparent coverage through block 3477100. '),
        );
        expect(coverage.statusAgainst(null), contains('. '));
      }
      expect(
        const TransparentCoverage(
          coveredThrough: 3473686,
          completion: 'publication-behind:3476067',
        ).statusAgainst(3476070),
        'Transparent coverage through block 3473686. Waiting for publication '
        'through block 3476067.',
      );
    });

    test('nothing read is never a height, however close the tip', () {
      const coverage = TransparentCoverage();
      expect(coverage.established, isFalse);
      expect(coverage.synchronized, isFalse);
      expect(
        coverage.statusAgainst(3000000),
        'Transparent coverage not yet established. No transparent sync has '
        'run yet.',
      );
      expect(
        const TransparentCoverage(completion: 'chain-unknown:3428342')
            .statusAgainst(3000000),
        contains('not yet established. The wallet has not scanned block '
            '3428342 yet.'),
      );
    });

    test('unresolved spends and owed pages are counted, not just flagged', () {
      const unresolved = TransparentCoverage(
        coveredThrough: 200,
        anchorHeight: 200,
        completion: 'complete',
        unresolvedSpends: 2,
      );
      expect(unresolved.synchronized, isFalse);
      expect(
        unresolved.statusAgainst(201),
        'Transparent coverage through block 200. Transaction history is '
        'incomplete: 2 unresolved spends.',
      );
      const owed = TransparentCoverage(
        coveredThrough: 200,
        anchorHeight: 200,
        completion: 'query-budget',
        pendingPages: 1,
      );
      expect(
        owed.statusAgainst(201),
        'Transparent coverage through block 200. Transparent sync is '
        'incomplete: 1 page still owed.',
      );
    });

    test('a complete sync to its accepted target is simply current', () {
      const coverage = TransparentCoverage(
        coveredThrough: 200,
        settledThrough: 190,
        anchorHeight: 200,
        completion: 'complete',
      );
      expect(coverage.synchronized, isTrue);
      expect(coverage.reasonDescription, isNull);
      expect(
        coverage.statusAgainst(240),
        'Transparent coverage through block 200',
        reason: 'the ledger accepted 200 as complete; the tip is the scan\'s',
      );
    });

    test('coverage below the accepted target is not synchronized', () {
      const coverage = TransparentCoverage(
        coveredThrough: 150,
        anchorHeight: 200,
        completion: 'complete',
      );
      expect(coverage.synchronized, isFalse);
      expect(coverage.statusAgainst(151), contains('incomplete'));
    });
  });

  test('the two recovery-only error codes round-trip', () {
    expect(ZakuraErrorCode.fromValue(20), ZakuraErrorCode.sendDisabled);
    expect(ZakuraErrorCode.fromValue(21), ZakuraErrorCode.configuration);
    expect(
      const ZakuraException(ZakuraErrorCode.sendDisabled, 'x').isTransient,
      isFalse,
    );
  });
}
