@Tags(['native', 'live', 'kill'])
library;

// The process dies in the middle of a private query, through the release
// bridge library, against the public services, with a wallet that has real
// transparent history.
//
// Not run by default, and not run in M3: it sends private queries to the
// public services, which needs a window agreed with the M1 operator, and it
// needs a wallet with history whose phrase lives in a file outside the
// repository. The loopback rehearsal in `kill_fixture_test.dart` establishes
// the same property against fixture services.
//
//   ZAKURA_LIVE=1 ZAKURA_KILL=1 \
//   ZAKURA_TRANSPARENT_FILTERS=https://enhance-pir.valargroup.dev \
//   ZAKURA_TRANSPARENT_SHARDS=https://transparent-pir.valargroup.dev \
//   ZAKURA_PHRASE_FILE=<outside the repository> ZAKURA_BIRTHDAY=<height> \
//   ZAKURA_LIVE_REPORT=<evidence>/kill-live-report.txt \
//   fvm flutter test --tags kill test/kill_recovery_test.dart
//
// The report carries heights, counts and reasons only.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_bindings/zakura_bindings.dart';

void main() {
  final root = Directory.current.path.split('/zakura/wallet-app').first;
  final env = Platform.environment;
  final library = env['ZAKURA_BRIDGE_LIBRARY'] ??
      '$root/target/release/libzakura_wallet_bridge.dylib';
  final filters = env['ZAKURA_TRANSPARENT_FILTERS'];
  final shards = env['ZAKURA_TRANSPARENT_SHARDS'];
  final lightwalletd =
      env['ZAKURA_LIGHTWALLETD'] ?? 'https://us.zec.stardust.rest:443';
  final phraseFile = env['ZAKURA_PHRASE_FILE'];
  final birthday = int.tryParse(env['ZAKURA_BIRTHDAY'] ?? '');
  final skip = env['ZAKURA_LIVE'] != '1' || env['ZAKURA_KILL'] != '1'
      ? 'set ZAKURA_LIVE=1 and ZAKURA_KILL=1, in a window agreed with the operator'
      : !File(library).existsSync()
          ? 'run: cargo build -p zakura_wallet_bridge --release'
          : filters == null || shards == null
              ? 'set ZAKURA_TRANSPARENT_FILTERS and ZAKURA_TRANSPARENT_SHARDS'
              : phraseFile == null || birthday == null
                  ? 'set ZAKURA_PHRASE_FILE and ZAKURA_BIRTHDAY'
                  : null;

  test(
    'a wallet with history killed during a private query reopens interrupted and resumes',
    () async {
      final notes = <String>[];
      void note(String line) {
        notes.add(line);
        // ignore: avoid_print
        print('LIVE $line');
      }

      final walletDir = Directory.systemTemp.createTempSync('zakura-kill-live-');
      addTearDown(() => walletDir.deleteSync(recursive: true));
      final phrase = File(phraseFile!).readAsStringSync().trim();

      // The wallet under test, in its own process, through the same child
      // the loopback rehearsal uses.
      final child = await Process.start(
        'fvm',
        ['flutter', 'test', '-r', 'expanded', '--tags', 'fixture-child', 'test/kill_fixture_child_test.dart'],
        workingDirectory: Directory.current.path,
        environment: {
          'ZAKURA_BRIDGE_LIBRARY': library,
          'ZAKURA_FIXTURE_PHRASE': phrase,
          'ZAKURA_FIXTURE_WALLET_DIR': walletDir.path,
          'ZAKURA_FIXTURE_LWD': lightwalletd,
          'ZAKURA_FIXTURE_FILTERS': filters!,
          'ZAKURA_FIXTURE_SHARDS': shards!,
          'ZAKURA_FIXTURE_BIRTHDAY': '$birthday',
        },
      );
      int? childPid;
      final named = Completer<void>();
      final querying = Completer<void>();
      var lastChildLine = '';
      final pidLine = RegExp(r'CHILD_PID=(\d+)');
      child.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
        final m = pidLine.firstMatch(line);
        if (m != null && childPid == null) {
          childPid = int.parse(m.group(1)!);
          named.complete();
        }
        if (line.contains('CHILD ')) lastChildLine = line;
        // The shielded scan has reached the tip and the transparent run is
        // in progress: private queries are in flight from here on.
        if (line.contains('completion=sync-in-progress') &&
            line.contains('phase=idle') &&
            !querying.isCompleted) {
          querying.complete();
        }
      });
      child.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((_) {});
      await named.future.timeout(const Duration(minutes: 5));
      await querying.future.timeout(const Duration(minutes: 20), onTimeout: () {
        fail('the transparent run never started; last line: $lastChildLine');
      });
      // Let a query or two go out, then kill.
      await Future<void>.delayed(const Duration(seconds: 2));
      expect(Process.killPid(childPid!, ProcessSignal.sigkill), isTrue);
      await child.exitCode.timeout(const Duration(minutes: 2));
      note('child killed with SIGKILL during the transparent run; last line: ${lastChildLine.replaceAll(RegExp(r'^.*CHILD '), '')}');

      final bindings = await NativeBindings.load(libraryPath: library);
      await bindings.open(
        directory: walletDir.path,
        lightwalletdUrl: lightwalletd,
        mainnet: true,
        transparentFiltersUrl: filters,
        transparentShardsUrl: shards,
      );
      final id = (await bindings.accounts()).single.id;
      final reopened = await bindings.balance(id);
      note('reopened completion=${reopened.coverage.completion} anchor=${reopened.coverage.anchorHeight} '
          'covered=${reopened.coverage.coveredThrough} pending=${reopened.coverage.pendingPages}');
      expect(reopened.coverage.completion, 'interrupted');
      expect(reopened.coverage.synchronized, isFalse);

      final resumed = DateTime.now();
      await bindings.startSync();
      final deadline = DateTime.now().add(const Duration(minutes: 20));
      var balance = reopened;
      var progress = await bindings.progress();
      while (!(balance.coverage.synchronized || progress.failed)) {
        if (DateTime.now().isAfter(deadline)) {
          fail('timed out resuming: completion=${balance.coverage.completion}');
        }
        await Future<void>.delayed(const Duration(milliseconds: 500));
        progress = await bindings.progress();
        balance = await bindings.balance(id);
      }
      expect(progress.failed, isFalse, reason: await bindings.syncFailure());
      final history = await bindings.history(id, 1000);
      note('resumed in ${DateTime.now().difference(resumed).inMilliseconds} ms: completion=${balance.coverage.completion} '
          'anchor=${balance.coverage.anchorHeight} synchronized=${balance.coverage.synchronized} '
          'history_entries=${history.length}');
      await bindings.stopSync();
      await bindings.close();
      final report = env['ZAKURA_LIVE_REPORT'];
      if (report != null) File(report).writeAsStringSync('${notes.join('\n')}\n');
    },
    skip: skip,
    timeout: const Timeout(Duration(minutes: 60)),
  );
}
