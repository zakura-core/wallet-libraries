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
/// Transparent services the tests name and never reach. A recovery build
/// refuses to open without both, over TLS, on separate hosts; nothing here
/// connects to them, because nothing here syncs against a reachable server.
const filters = 'https://filters.example.invalid';
const shards = 'https://shards.example.invalid';

void main() {
  final root = Directory.current.path.split('/zakura/wallet-app').first;
  final library = Platform.environment['ZAKURA_BRIDGE_LIBRARY'] ??
      '$root/target/release/libzakura_wallet_bridge.dylib';

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
  _importTests(bindings: () => bindings, dir: () => dir, built: built);
  _recoveryOnlyTests(bindings: () => bindings, dir: () => dir, built: built);

  Future<void> open() => bindings.open(
        directory: dir.path,
        lightwalletdUrl: 'https://testnet.example.invalid:443',
        mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
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
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
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

/// Restoring a wallet, through the real bridge to the real Rust wallet.
void _importTests({
  required NativeBindings Function() bindings,
  required Directory Function() dir,
  required bool built,
}) {
  final skip =
      !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null;

  /// Forgetting is the only way to change wallets while the store holds one
  /// account. The files go, the wallet is empty, and the same phrase is no
  /// longer "already here".
  test(skip: skip, 'forgetting empties the wallet and frees the phrase',
      () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    final phrase = await b.generateMnemonic();
    await b.importAccount(phrase: phrase, birthday: 2500000);
    expect(File('${dir().path}/wallet.db').existsSync(), isTrue);

    await b.reset();

    expect(await b.accounts(), isEmpty);
    // Reopened at once, so the next open is not up to the application: the
    // files exist again and are empty.
    expect(File('${dir().path}/wallet.db').existsSync(), isTrue);
    final again = await b.importAccount(phrase: phrase, birthday: 2500000);
    expect((await b.accounts()).single.id, again);
  });

  test(skip: skip, 'the same phrase restores the same wallet', () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    final phrase = await b.generateMnemonic();
    final id = await b.importAccount(phrase: phrase, birthday: 2500000);
    final address = await b.nextAddress(id);

    // A second wallet, in its own files, restored from the same words.
    final other = Directory.systemTemp.createTempSync('zakura-restore-');
    addTearDown(() => other.deleteSync(recursive: true));
    await b.open(
      directory: other.path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    final restored = await b.importAccount(phrase: phrase, birthday: 2500000);

    expect(await b.nextAddress(restored), address,
        reason: 'the same seed must issue the same address');
  });

  test(skip: skip, 'an unknown birthday scans from the earliest height',
      () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    await b.importAccount(phrase: await b.generateMnemonic());

    final accounts = await b.accounts();
    expect(accounts.single.birthday, await b.earliestBirthday());
  });

  /// Two accounts sharing a viewing key would double every balance.
  test(skip: skip, 'importing the same wallet twice is refused', () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    final phrase = await b.generateMnemonic();
    await b.importAccount(phrase: phrase, birthday: 2500000);

    await expectLater(
      b.importAccount(phrase: phrase, birthday: 2500000),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.accountExists,
        ),
      ),
    );
    expect((await b.accounts()).length, 1);
  });

  test(skip: skip, 'a bad phrase is refused', () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://127.0.0.1:1/',
      mainnet: false,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
    );
    await expectLater(
      b.importAccount(phrase: 'nonsense words here'),
      throwsA(
        isA<ZakuraException>().having(
          (e) => e.code,
          'code',
          ZakuraErrorCode.badMnemonic,
        ),
      ),
    );
  });
}

/// What a recovery build is, through the real bridge.
///
/// Built without the bridge's `send` feature, the native library refuses to
/// send whatever it is given, refuses to open without both transparent
/// services, and says so when asked. These are the properties the beta's
/// custody boundary rests on, so they are checked against the real library
/// rather than a fake.
void _recoveryOnlyTests({
  required NativeBindings Function() bindings,
  required Directory Function() dir,
  required bool built,
}) {
  final skip =
      !built ? 'run: cargo build -p zakura_wallet_bridge --release' : null;

  test(skip: skip, 'the native build identifies itself as recovery-only',
      () async {
    final info = await bindings().buildInfo();
    expect(info.sendEnabled, isFalse,
        reason: 'the bridge was built with the send feature');
    expect(info.transparentSchema, isNotEmpty);
    expect(info.layoutVersion, 4);
  });

  test(skip: skip, 'opening without transparent services is refused', () async {
    final b = bindings();
    await expectLater(
      b.open(
        directory: dir().path,
        lightwalletdUrl: 'https://testnet.example.invalid:443',
        mainnet: false,
      ),
      throwsA(isA<ZakuraException>()
          .having((e) => e.code, 'code', ZakuraErrorCode.configuration)
          .having((e) => e.message, 'message', contains('not an empty history'))),
    );
    expect(File('${dir().path}/wallet.db').existsSync(), isFalse,
        reason: 'a refused open left a file behind');
  });

  test(skip: skip, 'one host for both services is refused', () async {
    await expectLater(
      bindings().open(
        directory: dir().path,
        lightwalletdUrl: 'https://testnet.example.invalid:443',
        mainnet: false,
        transparentFiltersUrl: 'https://one.example.invalid/a',
        transparentShardsUrl: 'https://one.example.invalid/b',
      ),
      throwsA(isA<ZakuraException>()
          .having((e) => e.code, 'code', ZakuraErrorCode.configuration)),
    );
  });

  test(skip: skip, 'a direct send is refused before the phrase is read',
      () async {
    final b = bindings();
    await b.open(
      directory: dir().path,
      lightwalletdUrl: 'https://testnet.example.invalid:443',
      mainnet: false,
      transparentFiltersUrl: filters,
      transparentShardsUrl: shards,
    );
    final id = await b.createAccount(
      phrase: await b.generateMnemonic(),
      birthday: 3000000,
    );
    // A phrase that is not one: a build that read it would say so. This one
    // refuses first.
    await expectLater(
      b.send(account: id, to: 'not an address', amount: 1, phrase: 'nonsense'),
      throwsA(isA<ZakuraException>()
          .having((e) => e.code, 'code', ZakuraErrorCode.sendDisabled)),
    );
    await expectLater(
      b.quote(account: id, to: 'not an address', amount: 1),
      throwsA(isA<ZakuraException>()
          .having((e) => e.code, 'code', ZakuraErrorCode.sendDisabled)),
    );
    // Reading still works.
    final balance = await b.balance(id);
    expect(balance.total.value, 0);
    expect(balance.coverage.coveredThrough, isNull,
        reason: 'nothing read is not a height');
    expect(balance.coverage.synchronized, isFalse);
  });

  test(skip: skip, 'a server that cannot be reached has no identity', () async {
    await expectLater(
      bindings().networkIdentity(lightwalletdUrl: 'https://127.0.0.1:1/'),
      throwsA(isA<ZakuraException>()
          .having((e) => e.code, 'code', ZakuraErrorCode.source)),
    );
  });
}
