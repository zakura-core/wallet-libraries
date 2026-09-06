import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';

import 'fake_bindings.dart';

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

  OnboardingController controller() =>
      container.read(onboardingControllerProvider.notifier);
  OnboardingState state() => container.read(onboardingControllerProvider);

  /// A step that runs after the wallet already exists must not be able to
  /// report that it does not. Telling somebody their restore failed, when their
  /// money is right there, is the worst answer available.
  test('a sync that fails after restoring does not undo the restore', () async {
    await controller().beginImport();
    bindings.failOnStartSync = true;

    await controller().import(
      phrase: await wallet.generateMnemonic(),
      birthday: 2500000,
    );

    expect(await wallet.accounts(), hasLength(1), reason: 'it was restored');
    expect(
      state(),
      isA<OnboardingDone>(),
      reason: 'the restore succeeded, so the state must say so',
    );
  });

  test('a sync that fails after creating does not undo the creation', () async {
    await controller().beginCreate();
    bindings.failOnStartSync = true;

    await controller().confirmCreate();

    expect(await wallet.accounts(), hasLength(1));
    expect(state(), isA<OnboardingDone>());
  });

  /// A failed creation belongs on the creation screen, not dumped into the
  /// restore form, which asks for something the person never had.
  test('a failed creation stays on the creation screen', () async {
    await controller().beginCreate();
    bindings.nextError = const ZakuraException(
      ZakuraErrorCode.storage,
      'disk full',
    );

    await controller().confirmCreate();

    expect(
      state(),
      isA<OnboardingCreated>(),
      reason: 'it should not become a restore',
    );
  });
}
