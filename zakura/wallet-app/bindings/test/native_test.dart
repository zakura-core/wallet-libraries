@Tags(['native'])
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_bindings/zakura_bindings.dart';
import 'package:zakura_client/zakura_client.dart';

/// Drives the real Rust wallet through the generated bridge.
///
/// This is the check the whole native stack exists for: every layer above it
/// runs against a fake, so without this nothing would ever have proved that the
/// generated glue, the facade and the core agree.
///
/// Needs the library built first:
///
/// ```
/// cargo build -p zakura_wallet_bridge --release
/// fvm flutter test --tags native
/// ```
///
/// Tagged so an ordinary `flutter test` skips it: the rest of the suite is
/// meant to run with no Rust toolchain present.
void main() {
  final root = Directory.current.path.split('/zakura/wallet-app').first;
  final library = '$root/target/release/libzakura_wallet_bridge.dylib';

  late NativeBindings bindings;
  late Directory dir;

  // Skipped rather than failed when the library is absent, so that a checkout
  // with no Rust toolchain still gets a green suite. Everything else in this
  // project is designed to run without one; this is the one file that cannot.
  final built = File(library).existsSync();

  setUpAll(() async {
    if (!built) return;
    bindings = await NativeBindings.load(libraryPath: library);
  });

  setUp(() {
    dir = Directory.systemTemp.createTempSync('zakura-native-');
  });

  tearDown(() async {
    await bindings.close();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  _failureTests(bindings: () => bindings, dir: () => dir, built: built);

  Future<void> open() => bindings.open(
        directory: dir.path,
        lightwalletdUrl: 'https://testnet.example.invalid:443',
        mainnet: false,
      );

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'a phrase is generated and validated by the real BIP 39', () async {
    final phrase = await bindings.generateMnemonic();
    expect(phrase.split(' '), hasLength(24));
    expect(await bindings.validateMnemonic(phrase), isTrue);
    expect(await bindings.validateMnemonic('not a phrase'), isFalse);
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'opening creates both databases on disk', () async {
    await open();
    expect(File('${dir.path}/wallet.db').existsSync(), isTrue);
    expect(File('${dir.path}/cache.db').existsSync(), isTrue);
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'an account is created from a phrase and read back', () async {
    await open();
    final phrase = await bindings.generateMnemonic();
    final id = await bindings.createAccount(phrase: phrase, birthday: 3000000);

    final accounts = await bindings.accounts();
    expect(accounts, hasLength(1));
    expect(accounts.single.id, id);
    expect(accounts.single.birthday, 3000000);
    expect(accounts.single.canSpend, isTrue);
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'a new account is worth nothing, in all three figures', () async {
    await open();
    final id = await bindings.createAccount(
      phrase: await bindings.generateMnemonic(),
      birthday: 3000000,
    );

    final balance = await bindings.balance(id);
    expect(balance.spendable, Zatoshi.zero);
    expect(balance.pending, Zatoshi.zero);
    expect(balance.spentUnconfirmed, Zatoshi.zero);
    expect(await bindings.history(id, 10), isEmpty);
  });

  /// Reusing an address lets anybody who has seen it link the payments made to
  /// it, so the wallet issues a new one every time.
  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'each address is issued once, and is unified', () async {
    await open();
    final id = await bindings.createAccount(
      phrase: await bindings.generateMnemonic(),
      birthday: 3000000,
    );

    final first = await bindings.nextAddress(id);
    final second = await bindings.nextAddress(id);
    expect(first, startsWith('utest'));
    expect(first, isNot(second));
  });

  /// The error taxonomy is the reason the bridge carries a code rather than a
  /// message: this asserts a real Rust error arrives as something branchable.
  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'an unknown account arrives as a typed error, not a zero', () async {
    await open();
    await expectLater(
      bindings.balance(99),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.noSuchAccount,
        ),
      ),
    );
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'a bad phrase arrives as badMnemonic', () async {
    await open();
    await expectLater(
      bindings.createAccount(phrase: 'nonsense words here', birthday: 0),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.badMnemonic,
        ),
      ),
    );
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'calling before opening is refused rather than crashing', () async {
    await expectLater(bindings.accounts(), throwsA(isA<ZakuraException>()));
  });

  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'progress reports stopped before a sync starts', () async {
    await open();
    final progress = await bindings.progress();
    expect(progress.phase, SyncPhase.stopped);
    expect(progress.isCaughtUp, isFalse);
  });

  /// The whole point of the facade holding a second connection: the engine owns
  /// the writing handle while it runs, and the interface still has to be able
  /// to read a balance.
  test(skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null, 'the wallet is readable while a sync is running', () async {
    await open();
    final id = await bindings.createAccount(
      phrase: await bindings.generateMnemonic(),
      birthday: 3000000,
    );

    await bindings.startSync();
    // The server is unreachable by design here; what matters is that the read
    // path answers while the engine holds the writer.
    final balance = await bindings.balance(id);
    expect(balance.total, Zatoshi.zero);
    expect(await bindings.accounts(), hasLength(1));
    await bindings.stopSync();
  });
}

/// Added after a review found that a failed sync was reported as a finished
/// one all the way up the stack.
void _failureTests({
  required NativeBindings Function() bindings,
  required Directory Function() dir,
  required bool built,
}) {
  test(
    skip: !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null,
    'an unreachable server is reported as a failure, not as being up to date',
    () async {
      final b = bindings();
      await b.open(
        directory: dir().path,
        lightwalletdUrl: 'https://127.0.0.1:1/',
        mainnet: false,
      );
      await b.createAccount(
        phrase: await b.generateMnemonic(),
        birthday: 3000000,
      );

      await b.startSync();

      // Waited for rather than slept through: how long a refused connection
      // takes to give up belongs to the transport and changes with it.
      final deadline = DateTime.now().add(const Duration(seconds: 60));
      var progress = await b.progress();
      while (!progress.failed && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
        progress = await b.progress();
      }

      expect(progress.failed, isTrue, reason: 'the failure did not cross');
      expect(progress.isCaughtUp, isFalse);
      expect(await b.syncFailure(), contains('127.0.0.1'));
    },
  );
}
