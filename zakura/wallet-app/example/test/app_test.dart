import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';
import 'package:zakura_example/demo_bindings.dart';
import 'package:zakura_example/main.dart';
import 'package:zakura_example/mode.dart';
import 'package:zakura_example/screens/failure.dart';

void main() {
  _restoreTests();
  _navigationTests();
  _forgetTests();
  _modeTests();
  testWidgets('the app starts at onboarding and creates a wallet',
      (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [walletProvider.overrideWithValue(wallet)],
        child: const ZakuraExampleApp(mode: ZakuraMode.demo),
      ),
    );
    await tester.pump();

    expect(find.text('Zakura'), findsWidgets);
    expect(find.text('Create a wallet'), findsOneWidget);

    await tester.tap(find.text('Create a wallet'));
    await tester.pump();
    await tester.pump();

    // The phrase is the wallet, so it is shown before the wallet exists and
    // hidden until it is asked for.
    expect(find.text('Reveal'), findsOneWidget);
    expect(find.text('I have written it down'), findsOneWidget);
  });

  testWidgets('revealing shows all twenty-four numbered words', (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [walletProvider.overrideWithValue(wallet)],
        child: const ZakuraExampleApp(mode: ZakuraMode.demo),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Create a wallet'));
    await tester.pump();
    await tester.pump();

    await tester.tap(find.text('Reveal'));
    await tester.pump();

    expect(find.text('1'), findsOneWidget);
    expect(find.text('24'), findsOneWidget);
  });
}

/// Brings a row of the home screen's lazily built list into the viewport.
///
/// The test surface is 800 by 600 and the home screen is longer than that,
/// so a row below the fold is neither built nor tappable until scrolled to,
/// and one that is merely partly visible cannot be tapped at its centre.
Future<void> reveal(WidgetTester tester, Finder finder) async {
  await tester.scrollUntilVisible(finder, 200);
  await tester.ensureVisible(finder);
  // A plain pump: the demo's sync timers would keep a settle waiting.
  await tester.pump();
}

/// An open demo wallet with no account yet.
Future<ZakuraWallet> openedWallet(WidgetTester tester) async {
  final wallet = ZakuraWallet(DemoBindings());
  addTearDown(wallet.close);
  await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
  return wallet;
}

/// Creates an account and starts the app on its home screen, as a returning
/// user would find it.
Future<void> intoWallet(
  WidgetTester tester,
  ZakuraWallet wallet, {
  ZakuraMode mode = ZakuraMode.demo,
}) async {
  final id = await wallet.createAccount(
    phrase: await wallet.generateMnemonic(),
  );
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        walletProvider.overrideWithValue(wallet),
        initialAccountProvider.overrideWithValue(id),
        currentModeProvider.overrideWithValue(mode),
      ],
      child: ZakuraExampleApp(mode: mode),
    ),
  );
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 50));
}

/// Restoring is offered alongside creating, and reaches a form that asks for
/// the two things a restore needs.
void _restoreTests() {
  testWidgets('the app offers restoring an existing wallet', (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [walletProvider.overrideWithValue(wallet)],
        child: const ZakuraExampleApp(mode: ZakuraMode.demo),
      ),
    );
    await tester.pump();

    expect(find.text('Restore an existing wallet'), findsOneWidget);

    await tester.tap(find.text('Restore an existing wallet'));
    await tester.pump();
    await tester.pump();

    expect(find.text('Seed phrase'), findsOneWidget);
    expect(find.text('Wallet birthday (optional)'), findsOneWidget);
    expect(find.text('Restore wallet'), findsOneWidget);
  });

  /// Leaving the birthday blank has to read as the safe answer, because a
  /// birthday that is too high skips the blocks the money arrived in.
  testWidgets('the restore form says why blank is safe', (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [walletProvider.overrideWithValue(wallet)],
        child: const ZakuraExampleApp(mode: ZakuraMode.demo),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Restore an existing wallet'));
    await tester.pump();
    await tester.pump();

    expect(find.textContaining('cannot miss anything'), findsOneWidget);
  });
}

/// Added after Receive did nothing at all.
///
/// The app builds its own `WidgetsApp`, which creates a Navigator only when it
/// is given a route to start from. Without one every `Navigator.of` below it
/// has nothing to push onto, and a button wired to one is inert — no error, no
/// screen, nothing. Only tapping it finds that out, which is why these exist.
void _navigationTests() {
  testWidgets('the demo home screen offers Receive and never Send',
      (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Receive'));
    expect(find.text('Receive'), findsOneWidget);
    expect(find.text('Send'), findsNothing);
  });

  testWidgets('Receive opens the receive screen', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Receive'));
    await tester.tap(find.text('Receive'));
    await tester.pumpAndSettle();

    expect(find.text('Your address'), findsOneWidget);
    expect(find.textContaining('A new address is issued each time'),
        findsOneWidget);
  });

  testWidgets('and comes back', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Receive'));
    await tester.tap(find.text('Receive'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('‹ Back'));
    await tester.pumpAndSettle();

    expect(find.text('Activity'), findsOneWidget);
  });

  testWidgets('Diagnostics opens and names nothing about the wallet',
      (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Diagnostics'));
    await tester.tap(find.text('Diagnostics'));
    await tester.pumpAndSettle();

    expect(find.textContaining('mode: demo'), findsOneWidget);
    expect(find.textContaining('transparent synchronized: false'),
        findsOneWidget);
    expect(find.textContaining('transparent addresses outside coverage: 0'),
        findsOneWidget);
    // The report has grown past one screen; the copy button sits below it.
    await tester.dragUntilVisible(
      find.text('Copy diagnostics'),
      find.byType(ListView),
      const Offset(0, -200),
    );
    expect(find.text('Copy diagnostics'), findsOneWidget);
    // The demo's address prefix, and the word: neither belongs in a report.
    expect(find.textContaining('u1demo'), findsNothing);
    expect(find.textContaining('address:'), findsNothing);
  });
}

/// The store holds one account, so there was no way to import a different
/// wallet, or to import the same one again with a lower birthday, without
/// deleting files by hand. Forgetting is that way.
void _forgetTests() {
  Future<void> type(WidgetTester tester, int field, String text) async {
    final editables = find.byType(EditableText);
    final state = tester.state<EditableTextState>(editables.at(field));
    state.updateEditingValue(TextEditingValue(text: text));
    await tester.pump();
  }

  testWidgets('the home screen offers forgetting the wallet', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    // Below the history, so scroll to it before asserting it is visible.
    await reveal(tester, find.text('Forget this wallet'));
    await tester.tap(find.text('Forget this wallet'));
    await tester.pumpAndSettle();

    expect(find.text('‹ Back'), findsOneWidget);
    expect(find.textContaining('seed phrase is the only way back'),
        findsOneWidget);
    // The title and the confirming button share a label.
    expect(find.text('Forget this wallet'), findsNWidgets(2));
  });

  testWidgets('Back leaves the wallet alone', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Forget this wallet'));
    await tester.tap(find.text('Forget this wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('‹ Back'));
    await tester.pumpAndSettle();

    expect(find.text('Activity'), findsOneWidget);
    expect(await wallet.accounts(), hasLength(1));
  });

  testWidgets('confirming returns to onboarding with nothing left',
      (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Forget this wallet'));
    await tester.tap(find.text('Forget this wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(ZakuraButton, 'Forget this wallet'));
    await tester.pumpAndSettle();

    expect(find.text('Create a wallet'), findsOneWidget);
    expect(find.text('Restore an existing wallet'), findsOneWidget);
    expect(find.text('Activity'), findsNothing);
    expect(await wallet.accounts(), isEmpty);
  });

  /// The point of forgetting: a restore afterwards lands in a wallet.
  testWidgets('a wallet can be restored after forgetting', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await reveal(tester, find.text('Forget this wallet'));
    await tester.tap(find.text('Forget this wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(ZakuraButton, 'Forget this wallet'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Restore an existing wallet'));
    await tester.pump();
    await tester.pump();
    await type(tester, 0, await wallet.generateMnemonic());
    await tester.ensureVisible(find.text('Restore wallet'));
    await tester.tap(find.text('Restore wallet'));
    // Restoring starts the demo's sync, whose timers would keep a
    // `pumpAndSettle` waiting, so the frames are pumped by hand and the sync
    // is stopped before the test ends, whatever happens in between.
    try {
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));
      await tester.pump(const Duration(milliseconds: 50));

      await reveal(tester, find.text('Activity'));
      expect(find.text('Activity'), findsOneWidget);
      expect(await wallet.accounts(), hasLength(1));
    } finally {
      await wallet.stopSync();
      await tester.pump();
    }
  });
}

/// What each mode shows and withholds.
void _modeTests() {
  testWidgets('the demo says it is the demo on every screen', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);
    expect(find.textContaining('Demo wallet'), findsOneWidget);
  });

  testWidgets('a recovery build offers restore alone', (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          walletProvider.overrideWithValue(wallet),
          currentModeProvider.overrideWithValue(ZakuraMode.recovery),
        ],
        child: const ZakuraExampleApp(mode: ZakuraMode.recovery),
      ),
    );
    await tester.pump();

    expect(find.textContaining('Recovery beta'), findsOneWidget);
    expect(find.textContaining('Sending is disabled'), findsOneWidget);
    expect(find.text('Create a wallet'), findsNothing);
    expect(find.text('Restore an existing wallet'), findsOneWidget);
    expect(find.textContaining('This build cannot send'), findsOneWidget);
  });

  testWidgets('a recovery home has no Send, no Receive, and shows coverage',
      (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet, mode: ZakuraMode.recovery);

    expect(find.text('Accepted target'), findsOneWidget);
    expect(find.text('Transparent coverage not established'), findsOneWidget);
    await reveal(tester, find.textContaining('not authoritative'));
    expect(find.textContaining('not authoritative'), findsOneWidget);
    // Nothing read is never a height, and never "synchronized".
    expect(find.textContaining('coverage through block'), findsNothing);
    // The whole list, top to bottom: no way to send or receive anywhere on
    // it, and the way to run a recovery again is still there.
    await reveal(tester, find.text('Forget this wallet'));
    expect(find.text('Send'), findsNothing);
    expect(find.text('Receive'), findsNothing);
    expect(find.text('Forget this wallet'), findsOneWidget);
  });

  testWidgets('a shadow home names its figures as validation output',
      (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet, mode: ZakuraMode.shadow);

    expect(find.textContaining('Shadow validation'), findsOneWidget);
    await reveal(tester, find.textContaining('Do not act on them'));
    expect(find.textContaining('Do not act on them'), findsOneWidget);
    await reveal(tester, find.text('Forget this wallet'));
    expect(find.text('Send'), findsNothing);
    expect(find.text('Receive'), findsNothing);
  });

  testWidgets('a build that could not come up shows why, not a wallet',
      (tester) async {
    await tester.pumpWidget(
      const ZakuraStartupGateHarness(
        failure: FailureScreen(
          mode: ZakuraMode.recovery,
          step: 'Native library',
          problems: ['The native wallet library could not be loaded.'],
        ),
      ),
    );
    await tester.pump();

    expect(find.text('This build cannot run'), findsOneWidget);
    expect(find.textContaining('Native library check failed'), findsOneWidget);
    expect(find.textContaining('could not be loaded'), findsOneWidget);
    expect(find.textContaining('never falls back to the demonstration'),
        findsOneWidget);
    expect(find.text('Create a wallet'), findsNothing);
    expect(find.text('Restore an existing wallet'), findsNothing);
    expect(find.text('Activity'), findsNothing);
  });

  testWidgets('a build with no mode says so and shows nothing else',
      (tester) async {
    await tester.pumpWidget(
      const ZakuraStartupGateHarness(
        mode: null,
        failure: FailureScreen(
          mode: null,
          step: 'Configuration',
          problems: ['No mode was configured.'],
        ),
      ),
    );
    await tester.pump();
    expect(find.textContaining('No mode configured'), findsOneWidget);
    expect(find.text('This build cannot run'), findsOneWidget);
  });
}

/// The app with a failure in place of a wallet, as the gate would show it.
class ZakuraStartupGateHarness extends StatelessWidget {
  const ZakuraStartupGateHarness({
    required this.failure,
    this.mode = ZakuraMode.recovery,
    super.key,
  });

  final Widget failure;
  final ZakuraMode? mode;

  @override
  Widget build(BuildContext context) => ProviderScope(
        overrides: [currentModeProvider.overrideWithValue(mode)],
        child: ZakuraExampleApp(mode: mode, failure: failure),
      );
}
