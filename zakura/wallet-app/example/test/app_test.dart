import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';
import 'package:zakura_example/demo_bindings.dart';
import 'package:zakura_example/main.dart';

void main() {
  _restoreTests();
  _navigationTests();
  _forgetTests();
  testWidgets('the app starts at onboarding and creates a wallet',
      (tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [walletProvider.overrideWithValue(wallet)],
        child: const ZakuraExampleApp(demo: true),
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
        child: const ZakuraExampleApp(demo: true),
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

/// An open demo wallet with no account yet.
Future<ZakuraWallet> openedWallet(WidgetTester tester) async {
  final wallet = ZakuraWallet(DemoBindings());
  addTearDown(wallet.close);
  await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
  return wallet;
}

/// Creates an account and starts the app on its home screen, as a returning
/// user would find it.
Future<void> intoWallet(WidgetTester tester, ZakuraWallet wallet) async {
  final id = await wallet.createAccount(
    phrase: await wallet.generateMnemonic(),
  );
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        walletProvider.overrideWithValue(wallet),
        initialAccountProvider.overrideWithValue(id),
      ],
      child: const ZakuraExampleApp(demo: true),
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
        child: const ZakuraExampleApp(demo: true),
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
        child: const ZakuraExampleApp(demo: true),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Restore an existing wallet'));
    await tester.pump();
    await tester.pump();

    expect(find.textContaining('cannot miss anything'), findsOneWidget);
  });
}

/// Added after Receive and Send did nothing at all.
///
/// The app builds its own `WidgetsApp`, which creates a Navigator only when it
/// is given a route to start from. Without one every `Navigator.of` below it
/// has nothing to push onto, and a button wired to one is inert — no error, no
/// screen, nothing. Only tapping it finds that out, which is why these exist.
void _navigationTests() {
  testWidgets('the home screen offers Receive and Send', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    expect(find.text('Receive'), findsOneWidget);
    expect(find.text('Send'), findsOneWidget);
  });

  testWidgets('Receive opens the receive screen', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await tester.tap(find.text('Receive'));
    await tester.pumpAndSettle();

    expect(find.text('Your address'), findsOneWidget);
    expect(find.textContaining('A new address is issued each time'),
        findsOneWidget);
  });

  testWidgets('and comes back', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await tester.tap(find.text('Receive'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('‹ Back'));
    await tester.pumpAndSettle();

    expect(find.text('Activity'), findsOneWidget);
  });

  testWidgets('Send opens the send screen', (tester) async {
    final wallet = await openedWallet(tester);
    await intoWallet(tester, wallet);

    await tester.tap(find.text('Send'));
    await tester.pumpAndSettle();

    expect(find.text('To'), findsOneWidget);
    expect(find.text('Amount (ZEC)'), findsOneWidget);
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
    await tester.scrollUntilVisible(find.text('Forget this wallet'), 200);
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

    await tester.scrollUntilVisible(find.text('Forget this wallet'), 200);
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

    await tester.scrollUntilVisible(find.text('Forget this wallet'), 200);
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

    await tester.scrollUntilVisible(find.text('Forget this wallet'), 200);
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

      expect(find.text('Activity'), findsOneWidget);
      expect(await wallet.accounts(), hasLength(1));
    } finally {
      await wallet.stopSync();
      await tester.pump();
    }
  });
}
