import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_example/demo_bindings.dart';
import 'package:zakura_example/main.dart';

void main() {
  _restoreTests();
  _navigationTests();
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
  Future<ZakuraWallet> openedWallet(WidgetTester tester) async {
    final wallet = ZakuraWallet(DemoBindings());
    addTearDown(wallet.close);
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    return wallet;
  }

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
