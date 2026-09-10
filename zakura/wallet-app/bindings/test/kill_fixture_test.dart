@Tags(['native', 'fixture'])
library;

// The process dies in the middle of a private query, through the real
// bridge library, against fixture services on this machine.
//
// The fixture services program (a Rust test run as a program) makes a wallet
// from a fresh phrase, publishes a chain paying it, serves the shards with
// one query held, and serves the same blocks from a fixture light server.
// The wallet under test runs in a second process, restores from that phrase
// and syncs; when the held query arrives the parent kills it with SIGKILL,
// then reopens the same files through the bridge, checks what a kill leaves
// behind, and resumes to the exact balance the fixture predicted.
//
// Needs a bridge library built with `--features fixture-loopback`, and
// `ZAKURA_FIXTURE_LOOPBACK=1` in this process's environment, because the
// facade refuses plaintext loopback services without both. The beta build
// has neither.
//
//   ZAKURA_FIXTURE=1 ZAKURA_FIXTURE_LOOPBACK=1 \
//   ZAKURA_BRIDGE_LIBRARY=<fixture-loopback dylib> \
//   CARGO_TARGET_DIR=<target> \
//   fvm flutter test --tags fixture test/kill_fixture_test.dart

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_bindings/zakura_bindings.dart';

void main() {
  final root = Directory.current.path.split('/zakura/wallet-app').first;
  final env = Platform.environment;
  final library = env['ZAKURA_BRIDGE_LIBRARY'];
  final enabled = env['ZAKURA_FIXTURE'] == '1';
  final loopback = env['ZAKURA_FIXTURE_LOOPBACK'] == '1';
  final skip = !enabled
      ? 'set ZAKURA_FIXTURE=1'
      : library == null
          ? 'set ZAKURA_BRIDGE_LIBRARY to a fixture-loopback build'
          : !loopback
              ? 'set ZAKURA_FIXTURE_LOOPBACK=1'
              : null;

  test(
    'a wallet killed during a private query reopens interrupted and resumes exactly',
    () async {
      final notes = <String>[];
      void note(String line) {
        notes.add(line);
        // ignore: avoid_print
        print('FIXTURE $line');
      }

      // 1. The fixture services.
      final services = await Process.start(
        'cargo',
        [
          'test',
          '--offline',
          '--release',
          '-p',
          'zakura-wallet-transparent',
          '--test',
          'fixture_services',
          '--',
          '--nocapture',
          '--test-threads=1',
        ],
        workingDirectory: root,
        environment: {
          'ZAKURA_FIXTURE_SERVE': '1',
          'ZAKURA_FIXTURE_HOLD_SHARD': env['ZAKURA_FIXTURE_HOLD_SHARD'] ?? '1',
          'ZAKURA_FIXTURE_HOLD_TABLE': env['ZAKURA_FIXTURE_HOLD_TABLE'] ?? 'pages',
          'ZAKURA_FIXTURE_HOLD_NTH': env['ZAKURA_FIXTURE_HOLD_NTH'] ?? '2',
        },
      );
      final serviceLines = StreamController<String>.broadcast();
      services.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen(serviceLines.add, onDone: serviceLines.close);
      services.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((_) {});
      final facts = <String, String>{};
      final held = Completer<void>();
      final ready = Completer<void>();
      final fact = RegExp(r'(?:^|\s)([A-Z_]+)=(.*)$');
      serviceLines.stream.listen((line) {
        if (line.trim().endsWith('READY')) {
          if (!ready.isCompleted) ready.complete();
        } else if (line.trim().endsWith('HELD')) {
          if (!held.isCompleted) held.complete();
        } else {
          final m = fact.firstMatch(line);
          if (m != null) facts[m.group(1)!] = m.group(2)!;
        }
      });
      addTearDown(() {
        services.stdin.writeln('exit');
        services.kill();
      });
      await ready.future.timeout(const Duration(minutes: 15));
      final phrase = facts['PHRASE']!;
      final birthday = int.parse(facts['BIRTHDAY']!);
      final expectedBalance = int.parse(facts['EXPECTED_BALANCE']!);
      final expectedSpendable = int.parse(facts['EXPECTED_SPENDABLE']!);
      final expectedHistory = int.parse(facts['EXPECTED_HISTORY']!);
      final expectedUtxos = int.parse(facts['EXPECTED_UTXOS']!);
      note('services up: lwd, filters and shards on loopback; hold=${facts['HOLD']}; '
          'tip=${facts['TIP']} birthday=$birthday shards=${facts['MAP_SHARDS']}');

      // 2. The wallet under test, in its own process.
      final walletDir = Directory.systemTemp.createTempSync('zakura-kill-fixture-');
      addTearDown(() => walletDir.deleteSync(recursive: true));
      final child = await Process.start(
        'fvm',
        ['flutter', 'test', '-r', 'expanded', '--tags', 'fixture-child', 'test/kill_fixture_child_test.dart'],
        workingDirectory: Directory.current.path,
        environment: {
          'ZAKURA_BRIDGE_LIBRARY': library!,
          'ZAKURA_FIXTURE_LOOPBACK': '1',
          'ZAKURA_FIXTURE_PHRASE': phrase,
          'ZAKURA_FIXTURE_WALLET_DIR': walletDir.path,
          'ZAKURA_FIXTURE_LWD': facts['LWD']!,
          'ZAKURA_FIXTURE_FILTERS': facts['FILTERS']!,
          'ZAKURA_FIXTURE_SHARDS': facts['SHARDS']!,
          'ZAKURA_FIXTURE_BIRTHDAY': '$birthday',
        },
      );
      int? childPid;
      final named = Completer<void>();
      final syncing = Completer<void>();
      var lastChildLine = '';
      final childLines = child.stdout.transform(utf8.decoder).transform(const LineSplitter());
      final childDone = Completer<void>();
      final pidLine = RegExp(r'CHILD_PID=(\d+)');
      childLines.listen((line) {
        final m = pidLine.firstMatch(line);
        if (m != null && childPid == null) {
          childPid = int.parse(m.group(1)!);
          named.complete();
        }
        if (line.contains('CHILD_SYNCING') && !syncing.isCompleted) syncing.complete();
        if (line.contains('CHILD ')) lastChildLine = line;
        if (line.contains('CHILD_FAILED')) note('child reported a failure: $line');
      }, onDone: childDone.complete);
      child.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((_) {});

      // 3. Kill while the held query is in flight.
      await named.future.timeout(const Duration(minutes: 5), onTimeout: () {
        fail('the child never named its process');
      });
      await syncing.future.timeout(const Duration(minutes: 5), onTimeout: () {
        fail('the child never started syncing; last line: $lastChildLine');
      });
      await held.future.timeout(const Duration(minutes: 10), onTimeout: () {
        fail('the held query never arrived; last child line: $lastChildLine');
      });
      expect(childPid, isNotNull, reason: 'the child named its process');
      note('held query in flight; child was: $lastChildLine');
      final killed = Process.killPid(childPid!, ProcessSignal.sigkill);
      expect(killed, isTrue);
      final exit = await child.exitCode.timeout(const Duration(minutes: 2));
      note('child killed with SIGKILL; runner exit=$exit');
      services.stdin.writeln('release');

      // 4. Reopen the same files through the bridge.
      final bindings = await NativeBindings.load(libraryPath: library);
      Future<void> open() => bindings.open(
            directory: walletDir.path,
            lightwalletdUrl: facts['LWD']!,
            mainnet: true,
            transparentFiltersUrl: facts['FILTERS']!,
            transparentShardsUrl: facts['SHARDS']!,
          );
      await open();
      final accounts = await bindings.accounts();
      expect(accounts, hasLength(1));
      final id = accounts.single.id;
      final reopened = await bindings.balance(id);
      note('reopened completion=${reopened.coverage.completion} anchor=${reopened.coverage.anchorHeight} '
          'covered=${reopened.coverage.coveredThrough} pending=${reopened.coverage.pendingPages}');
      expect(reopened.coverage.completion, 'interrupted',
          reason: 'a killed run is reported as interrupted on reopen, never as in progress');
      expect(reopened.coverage.anchorHeight, isNull, reason: 'nothing was accepted as complete');
      expect(reopened.coverage.synchronized, isFalse);
      // The sentence beside the balance names the work still owed, or the
      // interruption when nothing is owed; never a bare height.
      expect(reopened.coverage.statusAgainst(null), contains('. '));

      // 5. Resume.
      final resumed = DateTime.now();
      await bindings.startSync();
      final deadline = DateTime.now().add(const Duration(minutes: 8));
      var balance = reopened;
      var progress = await bindings.progress();
      while (!(balance.coverage.synchronized || progress.failed)) {
        if (DateTime.now().isAfter(deadline)) {
          fail('timed out resuming: $progress completion=${balance.coverage.completion}');
        }
        await Future<void>.delayed(const Duration(milliseconds: 250));
        progress = await bindings.progress();
        balance = await bindings.balance(id);
      }
      expect(progress.failed, isFalse, reason: await bindings.syncFailure());
      note('resumed in ${DateTime.now().difference(resumed).inMilliseconds} ms: completion=${balance.coverage.completion} '
          'anchor=${balance.coverage.anchorHeight} covered=${balance.coverage.coveredThrough} '
          'synchronized=${balance.coverage.synchronized}');
      expect(balance.coverage.completion, 'complete');
      expect(balance.coverage.anchorHeight, int.parse(facts['TIP']!));
      // The bridge shows spendable transparent value: every recovered output
      // but the coinbase, which the wallet's maturity rule holds back.
      expect(balance.transparent.value, expectedSpendable,
          reason: 'the spendable balance after the resume is what the reducer predicted');
      expect(expectedBalance >= expectedSpendable, isTrue);
      final history = await bindings.history(id, 1000);
      expect(history.length, expectedHistory);
      note('balance and history match the reducer: spendable $expectedSpendable of $expectedBalance zat, '
          '${history.length} transactions, $expectedUtxos unspent outputs');
      await bindings.stopSync();
      await bindings.close();

      final report = env['ZAKURA_FIXTURE_REPORT'];
      if (report != null) {
        File(report).writeAsStringSync('${notes.join('\n')}\n');
      }
    },
    skip: skip,
    timeout: const Timeout(Duration(minutes: 40)),
  );
}
