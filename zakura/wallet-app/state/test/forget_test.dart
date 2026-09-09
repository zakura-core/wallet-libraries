import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';

import 'fake_bindings.dart';

/// Forgetting a wallet is the only way to change wallets while the store holds
/// one account, and the only way to re-run a recovery. Both paths go through
/// onboarding afterwards, so the test is: forget, then get back in.
void main() {
  late FakeBindings bindings;
  late ZakuraWallet wallet;
  late ProviderContainer container;

  setUp(() async {
    bindings = FakeBindings();
    wallet = ZakuraWallet(
      bindings,
      pollInterval: const Duration(milliseconds: 10),
    );
    container = ProviderContainer(
      overrides: [walletProvider.overrideWithValue(wallet)],
    );
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
  });

  tearDown(() {
    container.dispose();
    wallet.close();
  });

  OnboardingController onboarding() =>
      container.read(onboardingControllerProvider.notifier);

  Future<void> intoWallet() async {
    await onboarding().beginCreate();
    await onboarding().confirmCreate();
    expect(container.read(activeAccountProvider), isNotNull);
  }

  Future<void> forget() => container.read(forgetWalletProvider)();

  test('forgetting empties the wallet and returns to onboarding', () async {
    await intoWallet();

    await forget();

    expect(bindings.resets, 1);
    expect(container.read(activeAccountProvider), isNull);
    expect(container.read(onboardingControllerProvider), isA<OnboardingIdle>());
    expect(await wallet.accounts(), isEmpty);
  });

  /// Re-import: the same phrase is not "already here" once forgotten.
  test('the same phrase can be restored again afterwards', () async {
    await intoWallet();
    final phrase = await wallet.generateMnemonic();

    await forget();
    await onboarding().beginImport();
    await onboarding().import(phrase: phrase, birthday: 1000);

    expect(container.read(onboardingControllerProvider), isA<OnboardingDone>());
    final accounts = await wallet.accounts();
    expect(accounts, hasLength(1));
    expect(container.read(activeAccountProvider), accounts.single.id);
    expect(accounts.single.birthday, 1000);
  });

  /// A different wallet: what forgetting exists for.
  test('a different phrase can be restored afterwards', () async {
    await intoWallet();

    await forget();
    await onboarding().beginImport();
    await onboarding().import(
      phrase: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo',
      birthday: 2000,
    );

    expect(container.read(onboardingControllerProvider), isA<OnboardingDone>());
    expect(container.read(activeAccountProvider), isNotNull);
    expect((await wallet.accounts()).single.birthday, 2000);
  });

  /// If the files could not be removed the person is still in the wallet they
  /// had, and nothing on screen may claim otherwise.
  test('a failure to forget leaves the wallet selected', () async {
    await intoWallet();
    final selected = container.read(activeAccountProvider);
    bindings.nextError =
        const ZakuraException(ZakuraErrorCode.storage, 'read-only disk');

    await expectLater(
      forget(),
      throwsA(isA<ZakuraException>().having(
        (e) => e.code,
        'code',
        ZakuraErrorCode.storage,
      )),
    );

    expect(bindings.resets, 0);
    expect(container.read(activeAccountProvider), selected);
    expect(container.read(onboardingControllerProvider), isA<OnboardingDone>());
    expect(await wallet.accounts(), hasLength(1));
  });
}
