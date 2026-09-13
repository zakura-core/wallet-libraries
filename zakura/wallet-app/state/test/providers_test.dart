import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';

import 'fake_bindings.dart';

void main() {
  _sendPhaseTests();
  late FakeBindings bindings;
  late ZakuraWallet wallet;
  late ProviderContainer container;

  setUp(() {
    bindings = FakeBindings();
    wallet = ZakuraWallet(
      bindings,
      pollInterval: const Duration(milliseconds: 10),
    );
    container = ProviderContainer(
      overrides: [walletProvider.overrideWithValue(wallet)],
    );
  });

  tearDown(() {
    container.dispose();
    wallet.close();
  });

  Future<int> anAccount() async {
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    final id = await wallet.createAccount(
      phrase: await wallet.generateMnemonic(),
      birthday: 0,
    );
    container.read(activeAccountProvider.notifier).select(id);
    return id;
  }

  test('with no account selected the balance is zero rather than an error', () async {
    final balance = await container.read(balanceProvider.future);
    expect(balance.total, Zatoshi.zero);
  });

  test('the balance is read for the selected account', () async {
    await anAccount();
    bindings.setBalance(
      const Balance(spendable: Zatoshi(500), pending: Zatoshi(100)),
    );
    final balance = await container.read(balanceProvider.future);
    expect(balance.spendable, const Zatoshi(500));
    expect(balance.total, const Zatoshi(600));
  });

  test('history is empty until there is an account', () async {
    expect(await container.read(historyProvider.future), isEmpty);
  });

  test('accounts are listed', () async {
    await anAccount();
    final accounts = await container.read(accountsProvider.future);
    expect(accounts, hasLength(1));
  });

  test('a receive address needs an account', () async {
    expect(
      () => container.read(receiveAddressProvider.future),
      throwsA(isA<StateError>()),
    );
  });

  test('refreshing the receive address issues a different one', () async {
    await anAccount();
    final first = await container.read(receiveAddressProvider.future);
    container.invalidate(receiveAddressProvider);
    final second = await container.read(receiveAddressProvider.future);
    expect(first, isNot(second));
  });

  group('send', () {
    test('starts idle', () {
      expect(container.read(sendControllerProvider), isA<SendIdle>());
    });

    test('quotes before it sends', () async {
      final id = await anAccount();
      bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));
      final controller = container.read(sendControllerProvider.notifier);

      await controller.quote(to: 'utest1a', amount: const Zatoshi(100000));

      final state = container.read(sendControllerProvider);
      expect(state, isA<SendQuoted>());
      expect((state as SendQuoted).quote.fee, const Zatoshi(15000));
      // Account identifiers come from the store and do not start at zero.
      expect(id, isPositive);
    });

    test('reports insufficient funds in words somebody can act on', () async {
      await anAccount();
      bindings.setBalance(const Balance(spendable: Zatoshi(1)));
      final controller = container.read(sendControllerProvider.notifier);

      await controller.quote(to: 'utest1a', amount: const Zatoshi(100000));

      final state = container.read(sendControllerProvider);
      expect(state, isA<SendFailed>());
      expect((state as SendFailed).message, contains('settling'));
    });

    /// The funds are visible in the balance, so "not enough funds" would be the
    /// most confusing thing the wallet could say.
    test('an unavailable crossing is explained as a pool problem', () async {
      await anAccount();
      final controller = container.read(sendControllerProvider.notifier);
      bindings.nextError = const ZakuraException(
        ZakuraErrorCode.crossingUnavailable,
        'no grid anchor',
      );

      await controller.quote(to: 'utest1a', amount: const Zatoshi(1));

      final state = container.read(sendControllerProvider);
      expect((state as SendFailed).message, contains('pool'));
    });

    test('confirming without a quote does nothing', () async {
      await anAccount();
      final controller = container.read(sendControllerProvider.notifier);
      await controller.confirm(phrase: 'whatever');
      expect(container.read(sendControllerProvider), isA<SendIdle>());
    });

    test('a quoted payment sends', () async {
      await anAccount();
      bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));
      final controller = container.read(sendControllerProvider.notifier);

      await controller.quote(to: 'utest1a', amount: const Zatoshi(100000));
      await controller.confirm(phrase: await wallet.generateMnemonic());

      final state = container.read(sendControllerProvider);
      expect(state, isA<SendSent>());
      expect((state as SendSent).receipt.serverResponse, 'accepted');
    });

    test('resetting returns to the beginning', () async {
      await anAccount();
      bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));
      final controller = container.read(sendControllerProvider.notifier);
      await controller.quote(to: 'utest1a', amount: const Zatoshi(100000));
      controller.reset();
      expect(container.read(sendControllerProvider), isA<SendIdle>());
    });
  });
}

/// Added after a review found the send controller claiming to know a phase
/// boundary the native call does not report.
void _sendPhaseTests() {
  test('a send stays in proving rather than claiming to be broadcasting',
      () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(
      bindings,
      pollInterval: const Duration(milliseconds: 10),
    );
    addTearDown(wallet.close);
    final container = ProviderContainer(
      overrides: [walletProvider.overrideWithValue(wallet)],
    );
    addTearDown(container.dispose);

    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    final id = await wallet.createAccount(
      phrase: await wallet.generateMnemonic(),
      birthday: 0,
    );
    container.read(activeAccountProvider.notifier).select(id);
    bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));

    final controller = container.read(sendControllerProvider.notifier);
    await controller.quote(to: 'utest1a', amount: const Zatoshi(100000));

    // Hold the send open, as proving would.
    final gate = Completer<void>();
    bindings.sendGate = gate;
    final sending = controller.confirm(phrase: 'whatever');
    await Future<void>.delayed(const Duration(milliseconds: 20));

    // Proving is the seconds-long part, so it is what the interface must be
    // showing while the call is outstanding.
    expect(container.read(sendControllerProvider), isA<SendProving>());

    gate.complete();
    await sending;
    expect(container.read(sendControllerProvider), isA<SendSent>());
  });
}
