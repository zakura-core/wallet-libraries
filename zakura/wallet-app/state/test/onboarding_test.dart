import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';

import 'fake_bindings.dart';

void main() {
  _returningUserTests();
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

  test('it starts with neither path chosen', () {
    expect(state(), isA<OnboardingIdle>());
  });

  group('creating', () {
    /// The phrase is shown before the wallet exists, because it cannot be shown
    /// again and nobody can recover it.
    test('the phrase is shown before the wallet is created', () async {
      await controller().beginCreate();
      expect(state(), isA<OnboardingCreated>());
      expect((state() as OnboardingCreated).phrase.split(' '), isNotEmpty);
      expect(await wallet.accounts(), isEmpty, reason: 'nothing created yet');
    });

    /// A wallet that did not exist a moment ago has no history, so it starts at
    /// the tip rather than scanning years of chain for nothing.
    test('a new wallet starts at the tip', () async {
      await controller().beginCreate();
      await controller().confirmCreate();

      expect(state(), isA<OnboardingDone>());
      final accounts = await wallet.accounts();
      expect(accounts.single.birthday, await wallet.chainTip());
    });

    test('the account is selected and syncing starts', () async {
      await controller().beginCreate();
      await controller().confirmCreate();

      expect(container.read(activeAccountProvider), isNotNull);
      expect(wallet.lastProgress, isNotNull);
    });
  });

  group('restoring', () {
    test('opening the form fetches the guidance heights', () async {
      await controller().beginImport();

      final form = state() as OnboardingImporting;
      expect(form.earliestBirthday, await wallet.earliestBirthday());
      expect(form.chainTip, await wallet.chainTip());
      expect(form.busy, isFalse);
    });

    /// Guidance is guidance: an unreachable server must not block a restore.
    test('the form opens even when the heights cannot be fetched', () async {
      bindings.nextError =
          const ZakuraException(ZakuraErrorCode.source, 'down');
      await controller().beginImport();

      expect(state(), isA<OnboardingImporting>());
    });

    test('a valid phrase restores and selects the account', () async {
      await controller().beginImport();
      await controller().import(
        phrase: await wallet.generateMnemonic(),
        birthday: 2500000,
      );

      expect(state(), isA<OnboardingDone>());
      final accounts = await wallet.accounts();
      expect(accounts.single.birthday, 2500000);
      expect(container.read(activeAccountProvider), accounts.single.id);
    });

    /// An unknown birthday must stay unknown rather than becoming a guess: a
    /// guess that is too high skips the blocks the money arrived in.
    test('no birthday scans from the earliest possible height', () async {
      await controller().beginImport();
      await controller().import(phrase: await wallet.generateMnemonic());

      final accounts = await wallet.accounts();
      expect(accounts.single.birthday, await wallet.earliestBirthday());
    });

    test('a bad phrase is explained in terms of what to check', () async {
      await controller().beginImport();
      await controller().import(phrase: 'not a phrase');

      final form = state() as OnboardingImporting;
      expect(form.busy, isFalse);
      expect(form.error, contains('mistyped'));
    });

    /// Importing the same wallet twice would count every balance in it twice.
    test('importing the same wallet twice is explained, not silently done',
        () async {
      final phrase = await wallet.generateMnemonic();
      await controller().beginImport();
      await controller().import(phrase: phrase, birthday: 2500000);

      controller().reset();
      await controller().beginImport();
      await controller().import(phrase: phrase, birthday: 2500000);

      final form = state() as OnboardingImporting;
      expect(form.error, contains('already here'));
      expect((await wallet.accounts()).length, 1, reason: 'and none was added');
    });

    test('a failed restore keeps the guidance so the form still helps',
        () async {
      await controller().beginImport();
      final earliest = (state() as OnboardingImporting).earliestBirthday;

      await controller().import(phrase: 'not a phrase');

      expect((state() as OnboardingImporting).earliestBirthday, earliest);
    });

    test('going back returns to the choice', () async {
      await controller().beginImport();
      controller().reset();
      expect(state(), isA<OnboardingIdle>());
    });
  });
}

/// A wallet that already exists must not be asked for again.
void _returningUserTests() {
  test('an account found at startup is the active one', () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(bindings);
    addTearDown(wallet.close);
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    final id = await wallet.importAccount(
      phrase: await wallet.generateMnemonic(),
      birthday: 2500000,
    );

    // What the application does at startup once it has opened the wallet and
    // found an account already in it.
    final container = ProviderContainer(
      overrides: [
        walletProvider.overrideWithValue(wallet),
        initialAccountProvider.overrideWithValue(id),
      ],
    );
    addTearDown(container.dispose);

    expect(
      container.read(activeAccountProvider),
      id,
      reason: 'a returning user must not be shown onboarding again',
    );
  });

  test('with no account there is nothing active, and onboarding is right',
      () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(bindings);
    addTearDown(wallet.close);
    final container = ProviderContainer(
      overrides: [
        walletProvider.overrideWithValue(wallet),
        initialAccountProvider.overrideWithValue(null),
      ],
    );
    addTearDown(container.dispose);

    expect(container.read(activeAccountProvider), isNull);
  });

  /// The store refuses a duplicate viewing key however it got there, so
  /// creating a wallet and then importing the same phrase is the same mistake.
  test('a created wallet cannot then be imported again', () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(bindings);
    addTearDown(wallet.close);
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');

    final phrase = await wallet.generateMnemonic();
    await wallet.createAccount(phrase: phrase);

    await expectLater(
      wallet.importAccount(phrase: phrase),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.accountExists,
        ),
      ),
    );
  });

  /// A wallet refuses everything until it is opened; a caller that forgets must
  /// find out here rather than on a device.
  test('nothing works before the wallet is opened', () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(bindings);
    addTearDown(wallet.close);

    await expectLater(
      wallet.createAccount(phrase: await wallet.generateMnemonic()),
      throwsA(isA<ZakuraException>()),
    );
  });
}
