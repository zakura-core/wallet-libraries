import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';

import 'fake_bindings.dart';

void main() {
  /// Balance and history are read on demand and re-read when the wallet says
  /// its contents changed. If that signal does not actually invalidate them,
  /// the wallet shows a stale balance for as long as it is open.
  test('a change signal refreshes the balance', () async {
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

    bindings.setBalance(const Balance(spendable: Zatoshi(100)));

    // Keep the provider alive so that a later signal can invalidate it.
    final sub = container.listen(balanceProvider, (_, _) {});
    addTearDown(sub.close);

    expect((await container.read(balanceProvider.future)).spendable,
        const Zatoshi(100));

    // Money arrives, and the wallet announces it twice — as it would over two
    // scanned batches.
    bindings.setBalance(const Balance(spendable: Zatoshi(500)));
    await wallet.startSync();
    bindings.setProgress(const SyncProgress(scannedTo: 10));
    await Future<void>.delayed(const Duration(milliseconds: 40));
    bindings.setProgress(const SyncProgress(scannedTo: 20));
    await Future<void>.delayed(const Duration(milliseconds: 40));

    expect(
      (await container.read(balanceProvider.future)).spendable,
      const Zatoshi(500),
      reason: 'the balance never refreshed on the change signal',
    );
  });
}
