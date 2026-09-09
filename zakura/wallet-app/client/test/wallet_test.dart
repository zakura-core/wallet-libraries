import 'package:test/test.dart';
import 'package:zakura_client/zakura_client.dart';

import 'fake_bindings.dart';

void main() {
  _recoveryTests();
  late FakeBindings bindings;
  late ZakuraWallet wallet;

  setUp(() {
    bindings = FakeBindings();
    wallet = ZakuraWallet(
      bindings,
      pollInterval: const Duration(milliseconds: 10),
    );
  });

  tearDown(() => wallet.close());

  Future<int> anAccount() async {
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    return wallet.createAccount(
      phrase: await wallet.generateMnemonic(),
      birthday: 1000,
    );
  }

  test('an account is created and read back', () async {
    final id = await anAccount();
    final accounts = await wallet.accounts();
    expect(accounts, hasLength(1));
    expect(accounts.single.id, id);
    expect(accounts.single.birthday, 1000);
  });

  test('a bad phrase is refused', () async {
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    expect(
      () => wallet.createAccount(phrase: 'nonsense', birthday: 0),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.badMnemonic,
        ),
      ),
    );
  });

  test('an unknown account is refused rather than reported as empty', () async {
    await anAccount();
    expect(
      () => wallet.balance(99),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.noSuchAccount,
        ),
      ),
    );
  });

  test('each address is issued once', () async {
    final id = await anAccount();
    expect(await wallet.nextAddress(id), isNot(await wallet.nextAddress(id)));
  });

  test('progress reaches the stream', () async {
    await anAccount();
    final seen = <SyncProgress>[];
    final sub = wallet.progress.listen(seen.add);

    await wallet.startSync();
    bindings.setProgress(
      const SyncProgress(phase: SyncPhase.recovering, tip: 100, scannedTo: 50),
    );
    await Future<void>.delayed(const Duration(milliseconds: 40));

    expect(seen, isNotEmpty);
    expect(seen.last.phase, SyncPhase.recovering);
    expect(seen.last.scannedTo, 50);
    await sub.cancel();
  });

  /// Redrawing the interface to show the same thing is the cheapest waste
  /// available, and the poll ticks far more often than the value changes.
  test('an unchanged progress value is not re-emitted', () async {
    await anAccount();
    final seen = <SyncProgress>[];
    final sub = wallet.progress.listen(seen.add);

    await wallet.startSync();
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(seen, hasLength(1), reason: 'the poll ran repeatedly');
    await sub.cancel();
  });

  /// Balance and history are read on demand, so something has to say when
  /// reading them again is worth it.
  test('scanning further announces that the wallet may have changed', () async {
    await anAccount();
    final changes = <void>[];
    final sub = wallet.changed.listen(changes.add);

    await wallet.startSync();
    bindings.setProgress(const SyncProgress(phase: SyncPhase.recovering, scannedTo: 10));
    await Future<void>.delayed(const Duration(milliseconds: 30));

    expect(changes, isNotEmpty);
    await sub.cancel();
  });

  /// Forgetting is the one operation after which everything on screen is
  /// stale at once, so it has to say so.
  test('forgetting the wallet announces a change and reaches the bindings',
      () async {
    await anAccount();
    final changes = <void>[];
    final sub = wallet.changed.listen(changes.add);

    await wallet.reset();
    await Future<void>.delayed(Duration.zero);

    expect(bindings.resets, 1);
    expect(changes, hasLength(1));
    expect(await wallet.accounts(), isEmpty);
    await sub.cancel();
  });

  /// A poll landing between the delete and the reopen would report progress
  /// for a wallet that no longer exists.
  test('forgetting the wallet stops polling', () async {
    await anAccount();
    await wallet.startSync();
    await Future<void>.delayed(const Duration(milliseconds: 30));
    expect(bindings.progressCalls, greaterThan(1), reason: 'polling ran');

    await wallet.reset();
    final after = bindings.progressCalls;
    await Future<void>.delayed(const Duration(milliseconds: 40));

    expect(bindings.progressCalls, after, reason: 'polling continued');
  });

  test('forgetting the wallet clears the last progress', () async {
    await anAccount();
    await wallet.startSync();
    bindings.setProgress(
      const SyncProgress(phase: SyncPhase.recovering, tip: 100, scannedTo: 50),
    );
    await Future<void>.delayed(const Duration(milliseconds: 30));
    expect(wallet.lastProgress.scannedTo, 50);

    await wallet.reset();

    expect(wallet.lastProgress, const SyncProgress());
  });

  test('creating an account announces a change', () async {
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    final changes = <void>[];
    final sub = wallet.changed.listen(changes.add);

    await wallet.createAccount(
      phrase: await wallet.generateMnemonic(),
      birthday: 0,
    );
    await Future<void>.delayed(Duration.zero);

    expect(changes, hasLength(1));
    await sub.cancel();
  });

  /// A poll that throws must not take the stream, and so the interface, with
  /// it: the next poll is a few milliseconds away.
  test('a failed poll is survivable', () async {
    await anAccount();
    await wallet.startSync();
    bindings.nextError = const ZakuraException(ZakuraErrorCode.source, 'down');
    await Future<void>.delayed(const Duration(milliseconds: 30));

    expect(wallet.progress, isNotNull);
    bindings.setProgress(const SyncProgress(phase: SyncPhase.tracking, scannedTo: 7));
    await Future<void>.delayed(const Duration(milliseconds: 30));
    expect(wallet.lastProgress.phase, SyncPhase.tracking);
  });

  test('a quote covers the fee and the change', () async {
    final id = await anAccount();
    bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));

    final quote = await wallet.quote(
      account: id,
      to: 'utest1address0',
      amount: const Zatoshi(100000),
    );
    expect(quote.amount, const Zatoshi(100000));
    expect(quote.fee, const Zatoshi(15000));
    expect(quote.change, const Zatoshi(885000));
    expect(quote.total, const Zatoshi(115000));
  });

  test('a payment beyond the spendable balance is refused', () async {
    final id = await anAccount();
    bindings.setBalance(const Balance(spendable: Zatoshi(1000)));
    expect(
      () => wallet.quote(
        account: id,
        to: 'utest1address0',
        amount: const Zatoshi(100000),
      ),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.insufficientFunds,
        ),
      ),
    );
  });

  test('sending announces a change and returns a receipt', () async {
    final id = await anAccount();
    bindings.setBalance(const Balance(spendable: Zatoshi(1000000)));
    final changes = <void>[];
    final sub = wallet.changed.listen(changes.add);

    final receipt = await wallet.send(
      account: id,
      to: 'utest1address0',
      amount: const Zatoshi(100000),
      phrase: await wallet.generateMnemonic(),
    );

    await Future<void>.delayed(Duration.zero);
    expect(receipt.displayId.length, 64);
    expect(receipt.serverResponse, 'accepted');
    expect(changes, hasLength(1));
    await sub.cancel();
  });

  test('closing stops the poll and releases the native side', () async {
    await anAccount();
    await wallet.startSync();
    await wallet.close();
    expect(bindings.closed, isTrue);
    await wallet.close(); // and is safe to repeat
  });
}

/// Added after a restore found somebody's notes and the interface never heard
/// about it.
void _recoveryTests() {
  test('progress that is not a rising block height still announces a change',
      () async {
    final bindings = FakeBindings();
    final wallet = ZakuraWallet(
      bindings,
      pollInterval: const Duration(milliseconds: 10),
    );
    addTearDown(wallet.close);
    await wallet.open(directory: '/tmp/x', lightwalletdUrl: 'https://x');
    await wallet.createAccount(phrase: await wallet.generateMnemonic());

    final changes = <void>[];
    final sub = wallet.changed.listen(changes.add);
    await wallet.startSync();

    // Recovery works downwards from the tip, so the highest scanned block is
    // pinned there from the first batch while the queue drains behind it. A
    // wallet that only noticed a rising height would never re-read anything.
    bindings.setProgress(
      const SyncProgress(
        phase: SyncPhase.recovering,
        tip: 3000000,
        scannedTo: 3000000,
        blocksRemaining: 50000,
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 40));
    final afterFirst = changes.length;

    bindings.setProgress(
      const SyncProgress(
        phase: SyncPhase.recovering,
        tip: 3000000,
        scannedTo: 3000000,
        blocksRemaining: 20000,
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 40));

    expect(
      changes.length,
      greaterThan(afterFirst),
      reason: 'the queue drained, so something may have been found',
    );
    await sub.cancel();
  });
}
