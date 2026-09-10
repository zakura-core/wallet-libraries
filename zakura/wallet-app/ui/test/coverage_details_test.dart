import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_ui/zakura_ui.dart';

Widget host(Widget child) => Directionality(
  textDirection: TextDirection.ltr,
  child: MediaQuery(
    data: const MediaQueryData(size: Size(400, 800)),
    child: ZakuraThemeScope(child: Center(child: child)),
  ),
);

/// The panel behind the balance card's one sentence: every figure the ledger
/// reports, with a missing one shown as missing rather than as zero.
void main() {
  testWidgets('nothing read shows no heights and says no sync has run', (
    tester,
  ) async {
    await tester.pumpWidget(
      host(const CoverageDetails(coverage: TransparentCoverage())),
    );
    expect(find.text('Transparent coverage not established'), findsOneWidget);
    expect(find.text('No transparent sync has run yet.'), findsOneWidget);
    expect(find.text('Accepted target'), findsOneWidget);
    expect(find.text('none'), findsNWidgets(3));
    expect(find.text('never run'), findsOneWidget);
    expect(find.text('0'), findsNWidgets(3));
    expect(find.text('Addresses outside coverage'), findsOneWidget);
  });

  testWidgets('a sync that stopped short names its reason and its debts', (
    tester,
  ) async {
    await tester.pumpWidget(
      host(
        const CoverageDetails(
          coverage: TransparentCoverage(
            coveredThrough: 3477090,
            settledThrough: 3477000,
            anchorHeight: 3476500,
            completion: 'query-budget',
            pendingPages: 12,
            unresolvedSpends: 1,
          ),
          chainTip: 3477098,
        ),
      ),
    );
    expect(find.text('Transparent coverage is incomplete'), findsOneWidget);
    expect(
      find.text('The last sync reached its private query budget.'),
      findsOneWidget,
    );
    expect(find.text('3,476,500'), findsOneWidget);
    expect(find.text('3,477,090'), findsOneWidget);
    expect(find.text('3,477,000'), findsOneWidget);
    expect(find.text('3,477,098'), findsOneWidget);
    expect(find.text('query-budget'), findsOneWidget);
    expect(find.text('12'), findsOneWidget);
    expect(find.text('1'), findsOneWidget);
    expect(find.textContaining('too high until it resolves'), findsOneWidget);
  });

  testWidgets('a complete sync is complete', (tester) async {
    await tester.pumpWidget(
      host(
        const CoverageDetails(
          coverage: TransparentCoverage(
            coveredThrough: 200,
            settledThrough: 200,
            anchorHeight: 200,
            completion: 'complete',
          ),
        ),
      ),
    );
    expect(find.text('Transparent coverage is complete'), findsOneWidget);
    expect(find.text('complete'), findsOneWidget);
  });

  testWidgets('the balance card can name a build that cannot shield', (
    tester,
  ) async {
    await tester.pumpWidget(
      host(
        const BalanceCard(
          balance: Balance(transparent: Zatoshi(150000000)),
          transparentSuffix: 'recovered privately, unverified',
        ),
      ),
    );
    expect(
      find.textContaining('transparent, recovered privately, unverified'),
      findsOneWidget,
    );
    expect(find.textContaining('shield to spend'), findsNothing);
  });
  testWidgets('an address outside coverage is named, not hidden', (
    tester,
  ) async {
    await tester.pumpWidget(
      host(
        const CoverageDetails(
          coverage: TransparentCoverage(
            coveredThrough: 3477090,
            settledThrough: 3477000,
            anchorHeight: 3477090,
            completion: 'complete',
            outsideCoverage: 1,
          ),
        ),
      ),
    );
    expect(find.text('Transparent coverage is incomplete'), findsOneWidget);
    expect(find.text('Addresses outside coverage'), findsOneWidget);
    expect(find.text('1'), findsOneWidget);
    expect(find.textContaining('cannot index'), findsOneWidget);
  });

}
