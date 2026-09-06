import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_example/demo_bindings.dart';
import 'package:zakura_example/main.dart';

void main() {
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
