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
  _syncFailureTests();
  _emptyHistoryTests();
  _syncReasonTests();
  _importTests();
  _transparentAndCrossingTests();
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

    /// Recovery works downwards from the tip, so the highest scanned block sits
    /// at the tip from the first batch and "block X of Y" reads as finished
    /// while there is an hour of work left. The queue is what moves.
    testWidgets('during recovery it counts down the queue, not the height',
        (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.recovering,
              tip: 3000000,
              scannedTo: 3000000,
              blocksRemaining: 52341,
              fraction: 0.25,
            ),
          ),
        ),
      );
      expect(find.text('52,341 blocks left to check'), findsOneWidget);
      expect(find.text('Block 3000000 of 3000000'), findsNothing);
      expect(find.text('25%'), findsOneWidget);
    });

    testWidgets('with nothing queued it falls back to the heights',
        (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.tracking,
              tip: 200,
              scannedTo: 50,
            ),
          ),
        ),
      );
      expect(find.text('Block 50 of 200'), findsOneWidget);
    });

    testWidgets('recovery says what it is doing in plain terms', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(phase: SyncPhase.recovering),
          ),
        ),
      );
      expect(find.text('Looking for your transactions…'), findsOneWidget);
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

    /// Proving takes seconds, and a button showing only an ellipsis for that
    /// long looks broken. The label is what says the wait is expected.
    testWidgets('says which slow step it is on', (tester) async {
      await tester.pumpWidget(host(const SendForm(stage: SendStage.proving)));
      expect(find.text('Proving…'), findsOneWidget);

      await tester.pumpWidget(host(const SendForm(stage: SendStage.quoting)));
      expect(find.text('Working out the fee…'), findsOneWidget);

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

/// Added after a review found that a failed sync was indistinguishable from a
/// finished one everywhere above the engine.
void _syncFailureTests() {
  group('SyncIndicator failure', () {
    /// The engine stops with nothing queued whether it caught up or could not
    /// reach anybody. Reporting the second as the first tells somebody their
    /// wallet is current when it has not seen a server.
    testWidgets('a failure is not reported as up to date', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.stopped,
              tip: 100,
              scannedTo: 100,
              failed: true,
            ),
          ),
        ),
      );
      expect(find.text('Up to date'), findsNothing);
      expect(find.text('Synchronisation stopped'), findsOneWidget);
    });

    testWidgets('the same progress without a failure is up to date',
        (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.stopped,
              tip: 100,
              scannedTo: 100,
            ),
          ),
        ),
      );
      expect(find.text('Up to date'), findsOneWidget);
    });

    test('a failed progress is never caught up', () {
      const failed = SyncProgress(
        phase: SyncPhase.idle,
        tip: 100,
        scannedTo: 100,
        failed: true,
      );
      expect(failed.isCaughtUp, isFalse);
    });
  });
}

/// Added after transparent value and pool crossings became things the wallet
/// can actually report.
void _transparentAndCrossingTests() {
  group('transparent and crossings', () {
    /// Transparent funds cannot be sent without shielding first, so showing
    /// them as spendable would offer money the send path then refuses.
    testWidgets('transparent value is named as needing a step', (tester) async {
      await tester.pumpWidget(
        host(
          const BalanceCard(
            balance: Balance(
              spendable: Zatoshi(100000000),
              transparent: Zatoshi(50000000),
            ),
          ),
        ),
      );
      expect(find.text('1.00'), findsOneWidget);
      expect(
        find.textContaining('0.50 ZEC transparent, shield to spend'),
        findsOneWidget,
      );
    });

    testWidgets('nothing is said when there is no transparent value',
        (tester) async {
      await tester.pumpWidget(
        host(const BalanceCard(balance: Balance(spendable: Zatoshi(1)))),
      );
      expect(find.textContaining('transparent'), findsNothing);
    });

    test('transparent counts toward the total but not toward the sendable', () {
      const balance = Balance(
        spendable: Zatoshi(100),
        pending: Zatoshi(50),
        transparent: Zatoshi(25),
      );
      expect(balance.total, const Zatoshi(175));
      expect(balance.shielded, const Zatoshi(150));
    });

    /// A crossing's amount and fee are fixed by the shape every crossing
    /// shares, so somebody should not be left wondering why they cannot be
    /// adjusted.
    testWidgets('a crossing says why its numbers are fixed', (tester) async {
      await tester.pumpWidget(
        host(
          const SendForm(
            stage: SendStage.quoted,
            quote: SpendQuote(
              amount: Zatoshi(100000000),
              fee: Zatoshi(15000),
              change: Zatoshi(0),
              inputs: 1,
              crossing: true,
            ),
          ),
        ),
      );
      expect(find.textContaining('set amount'), findsOneWidget);
      expect(find.textContaining('Spending 1 note'), findsNothing);
    });
  });
}

/// Restoring a wallet. The birthday is the field somebody can get
/// catastrophically wrong, so most of this is about that.
void _importTests() {
  group('ImportForm', () {
    ImportForm form({
      void Function(String, int?)? onImport,
      bool busy = false,
      String? error,
      int? tip,
      int? earliest,
    }) =>
        ImportForm(
          busy: busy,
          error: error,
          chainTip: tip,
          earliestBirthday: earliest,
          onImport: onImport,
        );

    Future<void> type(WidgetTester tester, int field, String text) async {
      final editables = find.byType(EditableText);
      final state = tester.state<EditableTextState>(editables.at(field));
      state.updateEditingValue(TextEditingValue(text: text));
      await tester.pump();
    }

    testWidgets('an empty phrase is refused before anything is attempted',
        (tester) async {
      var called = false;
      await tester.pumpWidget(host(form(onImport: (_, _) => called = true)));

      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(find.text('Enter your seed phrase'), findsOneWidget);
      expect(called, isFalse);
    });

    /// A wrong word count is worth catching here, where it can say what is
    /// wrong, rather than coming back as a checksum failure.
    testWidgets('a phrase of the wrong length says so', (tester) async {
      await tester.pumpWidget(host(form(onImport: (_, _) {})));
      await type(tester, 0, 'one two three');
      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(find.textContaining('This has 3'), findsOneWidget);
    });

    testWidgets('a valid phrase with no birthday imports with none',
        (tester) async {
      String? phrase;
      int? birthday = 999;
      await tester.pumpWidget(
        host(form(onImport: (p, b) {
          phrase = p;
          birthday = b;
        })),
      );
      await type(tester, 0, List.filled(24, 'abandon').join(' '));
      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(phrase, isNotNull);
      expect(
        birthday,
        isNull,
        reason: 'an unknown birthday must stay unknown, not become a guess',
      );
    });

    /// The direction that loses money. A birthday after the money arrived skips
    /// the blocks it arrived in, and the wallet then shows a balance that is
    /// simply short, with nothing to say why.
    testWidgets('a birthday above the tip is refused', (tester) async {
      var called = false;
      await tester.pumpWidget(
        host(form(tip: 3000000, onImport: (_, _) => called = true)),
      );
      await type(tester, 0, List.filled(24, 'abandon').join(' '));
      await type(tester, 1, '4000000');
      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(find.textContaining('above the current block'), findsOneWidget);
      expect(called, isFalse);
    });

    testWidgets('a birthday within range is passed through', (tester) async {
      int? birthday;
      await tester.pumpWidget(
        host(form(tip: 3000000, onImport: (_, b) => birthday = b)),
      );
      await type(tester, 0, List.filled(24, 'abandon').join(' '));
      await type(tester, 1, '2500000');
      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(birthday, 2500000);
    });

    testWidgets('nonsense in the birthday is refused', (tester) async {
      await tester.pumpWidget(host(form(onImport: (_, _) {})));
      await type(tester, 0, List.filled(24, 'abandon').join(' '));
      await type(tester, 1, 'sometime last year');
      await tester.tap(find.text('Restore wallet'));
      await tester.pump();

      expect(find.textContaining('Enter a block height'), findsOneWidget);
    });

    /// Leaving it blank has to read as the safe answer, because it is.
    testWidgets('blank is offered as safe rather than lazy', (tester) async {
      await tester.pumpWidget(host(form(earliest: 2800000)));
      expect(find.textContaining('cannot miss anything'), findsOneWidget);
      expect(find.textContaining('2800000'), findsOneWidget);
    });

    testWidgets('an error is shown where it will be read', (tester) async {
      await tester.pumpWidget(host(form(error: 'Already here')));
      expect(find.text('Already here'), findsOneWidget);
    });

    testWidgets('a busy form says what it is doing and cannot be resubmitted',
        (tester) async {
      var called = false;
      await tester.pumpWidget(
        host(form(busy: true, onImport: (_, _) => called = true)),
      );
      expect(find.text('Restoring…'), findsOneWidget);

      await tester.tap(find.text('Restoring…'));
      await tester.pump();
      expect(called, isFalse);
    });
  });
}

/// Added after the interface told somebody their connection was down when the
/// server had been fine and a sync had died on an assertion.
void _syncReasonTests() {
  group('SyncIndicator reasons', () {
    /// The indicator does not know why a sync stopped, so it must not say. A
    /// sync can stop because the server is unreachable, because the chain could
    /// not be interpreted, or because the engine gave up, and naming the wrong
    /// one sends somebody to fix something that is not broken.
    testWidgets('it does not guess at a cause', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(phase: SyncPhase.stopped, failed: true),
          ),
        ),
      );
      expect(find.textContaining('reach the server'), findsNothing);
      expect(find.text('Synchronisation stopped'), findsOneWidget);
    });

    testWidgets('it shows the reason the wallet gave', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(phase: SyncPhase.stopped, failed: true),
            failureReason: 'the source would not serve blocks 10 to 20',
          ),
        ),
      );
      expect(
        find.text('the source would not serve blocks 10 to 20'),
        findsOneWidget,
      );
    });

    testWidgets('it offers a way out', (tester) async {
      var retried = false;
      await tester.pumpWidget(
        host(
          SyncIndicator(
            progress: const SyncProgress(phase: SyncPhase.stopped, failed: true),
            onRetry: () => retried = true,
          ),
        ),
      );
      await tester.tap(find.text('Try again'));
      expect(retried, isTrue);
    });

    testWidgets('a healthy sync offers nothing to retry', (tester) async {
      await tester.pumpWidget(
        host(
          const SyncIndicator(
            progress: SyncProgress(
              phase: SyncPhase.recovering,
              tip: 100,
              scannedTo: 50,
            ),
          ),
        ),
      );
      expect(find.text('Try again'), findsNothing);
    });
  });
}

/// An empty history means two different things, and saying the wrong one is how
/// somebody concludes their money is gone.
void _emptyHistoryTests() {
  group('HistoryList while searching', () {
    testWidgets('a recovery in progress says it is still looking',
        (tester) async {
      await tester.pumpWidget(
        host(const HistoryList(entries: [], searching: true)),
      );
      expect(find.text('Still looking…'), findsOneWidget);
      expect(find.text('No transactions yet'), findsNothing);
    });

    testWidgets('a finished sync says there is nothing', (tester) async {
      await tester.pumpWidget(
        host(const HistoryList(entries: [])),
      );
      expect(find.text('No transactions yet'), findsOneWidget);
    });
  });
}
