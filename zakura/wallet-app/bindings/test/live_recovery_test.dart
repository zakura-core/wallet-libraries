@Tags(['native', 'live'])
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_bindings/zakura_bindings.dart';
import 'package:zakura_client/zakura_client.dart';

/// The recovery lifecycle against the real services, through the real
/// native library: restore, synchronise, read, stop, restart, resume.
///
/// Runs only when asked, because it talks to the public light server and the
/// public transparent services, and a fresh wallet is what it restores: a
/// phrase generated here, never written anywhere, with a birthday a few
/// blocks below the tip so the shielded scan is short. Such a wallet matches
/// no filter and therefore sends no private query; what it exercises is the
/// whole path around them — map, geometry, filters, the accepted target, the
/// store, and the interface's view of all of it — and the persistence of
/// that across a close and a reopen.
///
/// ```
/// cargo build -p zakura_wallet_bridge --release
/// ZAKURA_LIVE=1 ZAKURA_TRANSPARENT_FILTERS=https://... \
///   ZAKURA_TRANSPARENT_SHARDS=https://... \
///   fvm flutter test --tags live test/live_recovery_test.dart
/// ```
///
/// Everything it prints is a height, a count or a reason. No phrase, key,
/// address or script is printed.
void main() {
  final root = Directory.current.path.split('/zakura/wallet-app').first;
  final library = Platform.environment['ZAKURA_BRIDGE_LIBRARY'] ??
      '$root/target/release/libzakura_wallet_bridge.dylib';
  final env = Platform.environment;
  final live = env['ZAKURA_LIVE'] == '1';
  final filters = env['ZAKURA_TRANSPARENT_FILTERS'];
  final shards = env['ZAKURA_TRANSPARENT_SHARDS'];
  final lightwalletd =
      env['ZAKURA_LIGHTWALLETD'] ?? 'https://us.zec.stardust.rest:443';
  final skip = !live
      ? 'set ZAKURA_LIVE=1 with both transparent service URLs to run'
      : !File(library).existsSync()
          ? 'run: cargo build -p zakura_wallet_bridge --release'
          : (filters == null || shards == null)
              ? 'set ZAKURA_TRANSPARENT_FILTERS and ZAKURA_TRANSPARENT_SHARDS'
              : null;

  test(
    skip: skip,
    'a fresh wallet restores, syncs, stops, reopens and resumes with its '
    'coverage intact',
    timeout: const Timeout(Duration(minutes: 20)),
    () async {
      final bindings = await NativeBindings.load(libraryPath: library);
      final dir = Directory.systemTemp.createTempSync('zakura-live-');
      addTearDown(() async {
        await bindings.close();
        if (dir.existsSync()) dir.deleteSync(recursive: true);
      });
      final out = <String>[];
      void note(String line) {
        out.add(line);
        // ignore: avoid_print
        print('LIVE $line');
      }

      final info = await bindings.buildInfo();
      expect(info.sendEnabled, isFalse);
      note('build send_enabled=${info.sendEnabled} schema=${info.transparentSchema} layout=${info.layoutVersion}');

      final identity =
          await bindings.networkIdentity(lightwalletdUrl: lightwalletd);
      expect(identity.isMainnet, isTrue);
      note('server chain=${identity.chainName} height=${identity.blockHeight} software=${identity.vendor} ${identity.version}');

      Future<void> open() => bindings.open(
            directory: dir.path,
            lightwalletdUrl: lightwalletd,
            mainnet: true,
            transparentFiltersUrl: filters,
            transparentShardsUrl: shards,
          );
      await open();

      // A phrase that exists only in this process, for a wallet born a few
      // blocks ago: nothing on the chain is its money, and the scan is short.
      final phrase = await bindings.generateMnemonic();
      final tip = await bindings.chainTip();
      final birthday = tip - 30;
      final id = await bindings.importAccount(phrase: phrase, birthday: birthday);
      note('restored account birthday=$birthday tip=$tip');

      // Direct sends are refused by the library, before the phrase is read.
      await expectLater(
        bindings.send(account: id, to: 'x', amount: 1, phrase: 'nonsense'),
        throwsA(isA<ZakuraException>()
            .having((e) => e.code, 'code', ZakuraErrorCode.sendDisabled)),
      );

      Future<(SyncProgress, Balance)> waitFor(
        String what,
        bool Function(SyncProgress, Balance) done, {
        Duration limit = const Duration(minutes: 8),
      }) async {
        final deadline = DateTime.now().add(limit);
        var progress = await bindings.progress();
        var balance = await bindings.balance(id);
        while (!done(progress, balance)) {
          if (DateTime.now().isAfter(deadline)) {
            final failure = await bindings.syncFailure();
            fail('timed out waiting for $what: $progress '
                'coverage=${balance.coverage.completion} '
                'covered=${balance.coverage.coveredThrough} '
                'failure=${failure == null ? 'none' : 'recorded'}');
          }
          await Future<void>.delayed(const Duration(milliseconds: 500));
          progress = await bindings.progress();
          balance = await bindings.balance(id);
        }
        return (progress, balance);
      }

      final started = DateTime.now();
      await bindings.startSync();
      // The shielded scan reaches the tip, then the transparent ledger runs
      // once and records why it stopped.
      final (progress, balance) = await waitFor(
        'the transparent ledger to report',
        (p, b) => p.failed || b.coverage.completion != null && b.coverage.completion != 'sync-in-progress',
      );
      final firstFailure = await bindings.syncFailure();
      note('first sync elapsed_ms=${DateTime.now().difference(started).inMilliseconds} phase=${progress.phase.name} failed=${progress.failed} scanned_to=${progress.scannedTo} tip=${progress.tip}');
      note('coverage completion=${balance.coverage.completion} anchor=${balance.coverage.anchorHeight} covered=${balance.coverage.coveredThrough} settled=${balance.coverage.settledThrough} pending=${balance.coverage.pendingPages} unresolved=${balance.coverage.unresolvedSpends} synchronized=${balance.coverage.synchronized}');
      note('status="${balance.coverage.statusAgainst(progress.tip)}"');
      expect(progress.failed, isFalse, reason: 'sync failed: ${firstFailure == null ? '' : 'a failure was recorded'}');
      expect(balance.transparent.value, 0);
      expect(balance.total.value, 0);
      expect(balance.coverage.completion, isNotNull);
      // Whatever the completion, the presentation is honest about it: a
      // sync that fell short is never shown as a bare height.
      if (!balance.coverage.synchronized) {
        expect(balance.coverage.statusAgainst(progress.tip), contains('. '));
      }
      final history = await bindings.history(id, 50);
      expect(history, isEmpty);
      final firstCoverage = balance.coverage;

      // Stop, close, reopen: what was validated is still there.
      await bindings.stopSync();
      final stopped = await bindings.progress();
      note('stopped phase=${stopped.phase.name}');
      await bindings.close();
      await open();
      final accounts = await bindings.accounts();
      expect(accounts.single.id, id);
      expect(accounts.single.birthday, birthday);
      final reopened = await bindings.balance(id);
      note('reopened completion=${reopened.coverage.completion} anchor=${reopened.coverage.anchorHeight} covered=${reopened.coverage.coveredThrough}');
      expect(reopened.coverage.anchorHeight, firstCoverage.anchorHeight);
      expect(reopened.coverage.coveredThrough, firstCoverage.coveredThrough);
      expect(reopened.coverage.completion, firstCoverage.completion);

      // Resume: a second run continues from what was kept.
      final resumed = DateTime.now();
      await bindings.startSync();
      final (again, after) = await waitFor(
        'the second run to report',
        (p, b) => p.failed || (b.coverage.completion != null && b.coverage.completion != 'sync-in-progress' && (b.coverage.anchorHeight ?? -1) >= (firstCoverage.anchorHeight ?? -1) && p.scannedTo != null),
      );
      note('second sync elapsed_ms=${DateTime.now().difference(resumed).inMilliseconds} failed=${again.failed} completion=${after.coverage.completion} anchor=${after.coverage.anchorHeight} covered=${after.coverage.coveredThrough}');
      expect(again.failed, isFalse);
      expect(
        (after.coverage.coveredThrough ?? -1) >= (firstCoverage.coveredThrough ?? -1),
        isTrue,
        reason: 'coverage went backwards without a rewind',
      );
      await bindings.stopSync();

      final report = env['ZAKURA_LIVE_REPORT'];
      if (report != null) {
        File(report).writeAsStringSync('${out.join('\n')}\n');
      }
    },
  );
}
