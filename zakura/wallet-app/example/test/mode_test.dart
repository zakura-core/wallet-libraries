import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_example/demo_bindings.dart';
import 'package:zakura_example/mode.dart';
import 'package:zakura_example/startup.dart';

/// A fake native build that reports what a recovery build reports.
class _RecoveryFake extends DemoBindings {
  _RecoveryFake({this.chain = 'main', this.openError});

  final String chain;
  final ZakuraException? openError;

  @override
  Future<BuildInfo> buildInfo() async => const BuildInfo(
        sendEnabled: false,
        transparentSchema: 'test',
        layoutVersion: 4,
      );

  @override
  Future<NetworkIdentity> networkIdentity({
    required String lightwalletdUrl,
  }) async =>
      NetworkIdentity(
        chainName: chain,
        saplingActivationHeight: 419200,
        consensusBranchId: 'test',
        blockHeight: 3000000,
        vendor: 'test',
        version: '0',
      );

  @override
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
    String? transparentFiltersUrl,
    String? transparentShardsUrl,
  }) async {
    if (openError != null) throw openError!;
    return super.open(
      directory: directory,
      lightwalletdUrl: lightwalletdUrl,
      mainnet: mainnet,
      transparentFiltersUrl: transparentFiltersUrl,
      transparentShardsUrl: transparentShardsUrl,
    );
  }
}

BetaConfig config({
  String mode = 'recovery',
  String filters = 'https://filters.example',
  String shards = 'https://shards.example',
  String lwd = '',
}) =>
    BetaConfig.fromValues(
      mode: mode,
      lightwalletdUrl: lwd,
      filters: filters,
      shards: shards,
    );

void main() {
  group('BetaConfig', () {
    test('a mode is required and must be one of three', () {
      expect(ZakuraMode.parse('recovery'), ZakuraMode.recovery);
      expect(ZakuraMode.parse('Shadow '), ZakuraMode.shadow);
      expect(ZakuraMode.parse('production'), isNull);
      expect(config(mode: '').problems().single, contains('No mode'));
      expect(config(mode: 'prod').problems().single, contains('"prod"'));
    });

    test('a beta mode needs both services, over TLS, on separate hosts', () {
      expect(config().problems(), isEmpty);
      expect(config(filters: '').problems().single, contains('Both'));
      expect(config(shards: '').problems().single, contains('Both'));
      expect(
        config(filters: 'http://filters.example').problems().single,
        contains('TLS'),
      );
      expect(
        config(lwd: 'http://lwd.example:9067').problems().single,
        contains('light server must be reached over TLS'),
      );
      expect(
        config(
          filters: 'https://one.example/filters',
          shards: 'https://one.example/shards',
        ).problems().single,
        contains('one host'),
      );
      // A port is part of the host: two services on one machine are two.
      expect(
        config(
          filters: 'https://127.0.0.1:8090',
          shards: 'https://127.0.0.1:8092',
        ).problems(),
        isEmpty,
      );
    });

    test('the demo needs nothing', () {
      expect(config(mode: 'demo', filters: '', shards: '').problems(), isEmpty);
    });

    test('the light server has one public mainnet default', () {
      expect(config().lightwalletdUrl, BetaConfig.defaultLightwalletdUrl);
      expect(BetaConfig.defaultLightwalletdUrl, startsWith('https://'));
    });
  });

  group('BetaProfile', () {
    test('lives under the application namespace, per mode', () {
      final profile = BetaProfile.under('/h', ZakuraMode.recovery);
      expect(
        profile.directory,
        '/h/Library/Application Support/${BetaProfile.namespace}/recovery',
      );
      expect(
        BetaProfile.under('/h', ZakuraMode.shadow).directory,
        isNot(profile.directory),
      );
      expect(profile.directory, isNot(contains('.zakura-example')));
    });

    test('is created with a marker, reopened, and refused for another mode',
        () async {
      final home = Directory.systemTemp.createTempSync('zakura-profile-');
      addTearDown(() => home.deleteSync(recursive: true));
      final profile = BetaProfile.under(home.path, ZakuraMode.recovery);
      expect(await profile.prepare(), isNull);
      expect(File(profile.marker).existsSync(), isTrue);
      expect(await profile.prepare(), isNull, reason: 'idempotent');

      // The same directory, claimed by the other mode: refused, unchanged.
      final other = BetaProfile(directory: profile.directory, mode: ZakuraMode.shadow);
      final before = File(profile.marker).readAsStringSync();
      expect(await other.prepare(), contains('another mode'));
      expect(File(profile.marker).readAsStringSync(), before);
    });

    test('a directory with wallet files and no marker is left alone',
        () async {
      final home = Directory.systemTemp.createTempSync('zakura-profile-');
      addTearDown(() => home.deleteSync(recursive: true));
      final profile = BetaProfile.under(home.path, ZakuraMode.recovery);
      Directory(profile.directory).createSync(recursive: true);
      final wallet = File('${profile.directory}/wallet.db')
        ..writeAsStringSync('somebody else\'s');
      expect(await profile.prepare(), contains('not made by this application'));
      expect(wallet.readAsStringSync(), 'somebody else\'s');
      expect(File(profile.marker).existsSync(), isFalse);
    });
  });

  group('startUp', () {
    late Directory home;
    setUp(() => home = Directory.systemTemp.createTempSync('zakura-home-'));
    tearDown(() => home.deleteSync(recursive: true));

    test('a misconfigured beta stops before the native library', () async {
      var loaded = false;
      final result = await startUp(
        config(filters: ''),
        home: home.path,
        loadNative: () async {
          loaded = true;
          return DemoBindings();
        },
      );
      expect(result, isA<StartupFailed>());
      expect((result as StartupFailed).step, 'Configuration');
      expect(loaded, isFalse);
    });

    test('a native library that will not load is a failure, not a demo',
        () async {
      final result = await startUp(
        config(),
        home: home.path,
        loadNative: () async => throw StateError('dlopen failed'),
      );
      expect(result, isA<StartupFailed>());
      final failed = result as StartupFailed;
      expect(failed.step, 'Native library');
      expect(failed.problems.single, contains('dlopen failed'));
    });

    test('a native build that can send is not a recovery build', () async {
      // The demo reports that it can send, as a spending build would.
      final result = await startUp(
        config(),
        home: home.path,
        loadNative: () async => DemoBindings(),
      );
      expect((result as StartupFailed).step, 'Native build');
      expect(result.problems.single, contains('sending enabled'));
    });

    test('a server on another chain is refused before anything opens',
        () async {
      final result = await startUp(
        config(),
        home: home.path,
        loadNative: () async => _RecoveryFake(chain: 'test'),
      );
      expect((result as StartupFailed).step, 'Network identity');
      expect(result.problems.single, contains('"test" chain'));
      expect(
        Directory('${home.path}/Library').existsSync(),
        isFalse,
        reason: 'no profile was made',
      );
    });

    test('a wallet another build wrote is reported and left as it was',
        () async {
      final result = await startUp(
        config(),
        home: home.path,
        loadNative: () async => _RecoveryFake(
          openError: const ZakuraException(
            ZakuraErrorCode.versionMismatch,
            'layout schema version is 3, but this build expects 4',
          ),
        ),
      );
      expect((result as StartupFailed).step, 'Wallet');
      expect(result.problems.single, contains('left as it was'));
      expect(result.problems.single, contains('expects 4'));
    });

    test('a recovery build comes up in its own profile with no account',
        () async {
      final result = await startUp(
        config(),
        home: home.path,
        loadNative: () async => _RecoveryFake(),
      );
      expect(result, isA<StartupReady>());
      final ready = result as StartupReady;
      addTearDown(ready.wallet.close);
      expect(ready.mode, ZakuraMode.recovery);
      expect(ready.existingAccount, isNull);
      expect(ready.buildInfo?.sendEnabled, isFalse);
      expect(ready.server?.isMainnet, isTrue);
      expect(ready.profileDirectory, endsWith('/recovery'));
      expect(File('${ready.profileDirectory}/profile.json').existsSync(), isTrue);
    });

    test('the demo comes up with no native library at all', () async {
      final result = await startUp(
        config(mode: 'demo', filters: '', shards: ''),
        home: home.path,
        loadNative: () async => throw StateError('never called'),
      );
      expect(result, isA<StartupReady>());
      addTearDown((result as StartupReady).wallet.close);
      expect(result.mode, ZakuraMode.demo);
    });
  });
}
