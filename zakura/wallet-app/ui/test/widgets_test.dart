import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// Wraps a widget in the minimum needed to render it.
///
/// Notably not a MaterialApp: this package draws from its own tokens, and if a
/// test needed Material to make it look right then so would an application.
Widget host(
  Widget child, {
  ZakuraColors? colors,
  FormFactor? formFactor,
  ZakuraUiOverrides overrides = ZakuraUiOverrides.none,
}) =>
    Directionality(
      textDirection: TextDirection.ltr,
      child: MediaQuery(
        data: const MediaQueryData(size: Size(400, 800)),
        child: ZakuraThemeScope(
          colors: colors,
          formFactor: formFactor,
          child: ZakuraUiOverridesScope(
            overrides: overrides,
            child: Center(child: child),
          ),
        ),
      ),
    );

void main() {
  group('BalanceCard', () {
    testWidgets('shows the spendable figure', (tester) async {
      await tester.pumpWidget(
        host(
          const BalanceCard(
            balance: Balance(spendable: Zatoshi(150000000)),
          ),
        ),
      );
      expect(find.text('Spendable'), findsOneWidget);
      expect(find.text('1.50'), findsOneWidget);
    });

    /// Pending is real money that cannot yet be sent. A card that folded it
    /// into the total would offer funds and then refuse them.
    testWidgets('names pending value separately', (tester) async {
      await tester.pumpWidget(
        host(
          const BalanceCard(
            balance: Balance(
              spendable: Zatoshi(100000000),
              pending: Zatoshi(50000000),
            ),
          ),
        ),
      );
      expect(find.text('1.00'), findsOneWidget);
      expect(find.textContaining('0.50 ZEC still settling'), findsOneWidget);
    });

    testWidgets('says nothing about pending when there is none', (tester) async {
      await tester.pumpWidget(
        host(const BalanceCard(balance: Balance(spendable: Zatoshi(1)))),
      );
      expect(find.textContaining('settling'), findsNothing);
    });

    testWidgets('hides the figures when asked', (tester) async {
      await tester.pumpWidget(
        host(
          const BalanceCard(
            balance: Balance(spendable: Zatoshi(150000000)),
            obscured: true,
          ),
        ),
      );
      expect(find.text('1.50'), findsNothing);
      expect(find.text('••••••'), findsOneWidget);
    });

    testWidgets('can be replaced without forking the package', (tester) async {
      await tester.pumpWidget(
        host(
          const BalanceCard(balance: Balance(spendable: Zatoshi(1))),
          overrides: ZakuraUiOverrides(
            balanceCard: (context, model) => Text(
              'mine: ${model.spendable}',
              textDirection: TextDirection.ltr,
            ),
          ),
        ),
      );
      expect(find.text('mine: 0.00000001'), findsOneWidget);
      expect(find.text('Spendable'), findsNothing);
    });
  });

  group('SyncIndicator', () {
    /// An empty fetch reports idle too, so calling idle "synchronised" would
    /// tell somebody they were up to date when the server was unreachable.
    testWidgets('idle alone is not called up to date', (tester) async {
      await tester.pumpWidget(
        host(const SyncIndicator(progress: SyncProgress(phase: SyncPhase.idle))),
      );
      expect(find.text('Up to date'), findsNothing);
      expect(find.text('Waiting for new blocks'), findsOneWidget);
    });

    testWidgets('is up to date once it has scanned to the tip', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.idle,
              tip: 100,
              scannedTo: 100,
            ),
          ),
        ),
      );
      expect(find.text('Up to date'), findsOneWidget);
    });

    testWidgets('shows the heights, which are what settle it', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.recovering,
              tip: 200,
              scannedTo: 50,
              fraction: 0.25,
            ),
          ),
        ),
      );
      expect(find.text('Block 50 of 200'), findsOneWidget);
      expect(find.text('25%'), findsOneWidget);
    });

    testWidgets('prefers the smoothed figure when given one', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(phase: SyncPhase.recovering, fraction: 0.5),
            displayFraction: 0.42,
          ),
        ),
      );
      expect(find.text('42%'), findsOneWidget);
    });
  });

  group('HistoryList', () {
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

    testWidgets('explains an empty history rather than showing nothing',
        (tester) async {
      await tester.pumpWidget(host(const HistoryList(entries: [])));
      expect(find.text('No transactions yet'), findsOneWidget);
    });

    testWidgets('shows a receipt as money in', (tester) async {
      await tester.pumpWidget(
        host(
          SizedBox(
            height: 400,
            child: HistoryList(entries: [entry(received: 100000000, height: 5)]),
          ),
        ),
      );
      expect(find.text('Received'), findsOneWidget);
      expect(find.text('+1.00'), findsOneWidget);
      expect(find.text('Block 5'), findsOneWidget);
    });

    /// A transaction whose every received note is change is the wallet paying
    /// somebody else, and showing it as an incoming payment would be wrong.
    testWidgets('a change-only transaction reads as sent', (tester) async {
      await tester.pumpWidget(
        host(
          SizedBox(
            height: 400,
            child: HistoryList(
              entries: [
                entry(received: 90000000, spent: 100000000, changeOnly: true, height: 5),
              ],
            ),
          ),
        ),
      );
      expect(find.text('Sent'), findsOneWidget);
      expect(find.text('Received'), findsNothing);
    });

    testWidgets('an unmined transaction says it is waiting', (tester) async {
      await tester.pumpWidget(
        host(
          SizedBox(
            height: 400,
            child: HistoryList(entries: [entry(received: 1, height: null)]),
          ),
        ),
      );
      expect(find.text('Waiting to be mined'), findsOneWidget);
    });
  });

  group('theme', () {
    testWidgets('form factor follows the room available, not the platform',
        (tester) async {
      late ZakuraThemeData captured;
      await tester.pumpWidget(
        host(
          Builder(
            builder: (context) {
              captured = ZakuraTheme.of(context);
              return const SizedBox();
            },
          ),
          formFactor: FormFactor.expanded,
        ),
      );
      expect(captured.formFactor, FormFactor.expanded);
      expect(captured.typography.display.fontSize, 42);
    });

    testWidgets('a compact scale is smaller', (tester) async {
      late ZakuraThemeData captured;
      await tester.pumpWidget(
        host(
          Builder(
            builder: (context) {
              captured = ZakuraTheme.of(context);
              return const SizedBox();
            },
          ),
          formFactor: FormFactor.compact,
        ),
      );
      expect(captured.typography.display.fontSize, 34);
    });

    /// The seam for a demo that wants this design in different colours.
    testWidgets('a palette can be swapped wholesale', (tester) async {
      const custom = ZakuraColors(
        background: Color(0xFF000000),
        surface: Color(0xFF111111),
        surfaceRaised: Color(0xFF222222),
        border: Color(0xFF333333),
        text: Color(0xFFFFFFFF),
        textMuted: Color(0xFF888888),
        textOnAccent: Color(0xFF000000),
        accent: Color(0xFFFF00FF),
        positive: Color(0xFF00FF00),
        negative: Color(0xFFFF0000),
        danger: Color(0xFFFF0000),
        pending: Color(0xFFFFFF00),
      );
      late ZakuraThemeData captured;
      await tester.pumpWidget(
        host(
          Builder(
            builder: (context) {
              captured = ZakuraTheme.of(context);
              return const SizedBox();
            },
          ),
          colors: custom,
        ),
      );
      expect(captured.colors.accent, const Color(0xFFFF00FF));
    });

    test('width chooses the form factor', () {
      expect(FormFactor.fromWidth(320), FormFactor.compact);
      expect(FormFactor.fromWidth(599), FormFactor.compact);
      expect(FormFactor.fromWidth(600), FormFactor.expanded);
      expect(FormFactor.fromWidth(1400), FormFactor.expanded);
    });
  });

  group('SendForm', () {
    testWidgets('shows the fee before it is charged', (tester) async {
      await tester.pumpWidget(
        host(
          const SendForm(
            stage: SendStage.quoted,
            quote: SpendQuote(
              amount: Zatoshi(100000000),
              fee: Zatoshi(15000),
              change: Zatoshi(5000),
              inputs: 2,
            ),
          ),
        ),
      );
      expect(find.text('1.00 ZEC'), findsOneWidget);
      expect(find.text('0.00015 ZEC'), findsOneWidget);
      expect(find.text('1.00015 ZEC'), findsOneWidget);
      expect(find.textContaining('Spending 2 notes'), findsOneWidget);
    });

    /// Proving takes seconds, and a silent spinner for that long looks broken.
    testWidgets('says which slow step it is on', (tester) async {
      await tester.pumpWidget(host(const SendForm(stage: SendStage.proving)));
      expect(find.text('Proving…'), findsNothing, reason: 'busy shows an ellipsis');
      await tester.pumpWidget(host(const SendForm(stage: SendStage.editing)));
      expect(find.text('Continue'), findsOneWidget);
    });

    testWidgets('shows an error where it will be read', (tester) async {
      await tester.pumpWidget(
        host(const SendForm(stage: SendStage.editing, error: 'Nope')),
      );
      expect(find.text('Nope'), findsOneWidget);
    });
  });
}
