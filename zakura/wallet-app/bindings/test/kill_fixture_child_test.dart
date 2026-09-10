@Tags(['fixture-child'])
library;

// The wallet under test in the loopback kill rehearsal. Not a test of its
// own: `kill_fixture_test.dart` runs it as a separate process, hands it the
// fixture's phrase and endpoints through the environment, and kills it while
// a private query is in flight. It restores, starts syncing and reports
// until it is killed.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zakura_bindings/zakura_bindings.dart';

void main() {
  final env = Platform.environment;
  final library = env['ZAKURA_BRIDGE_LIBRARY'];
  final phrase = env['ZAKURA_FIXTURE_PHRASE'];
  final dir = env['ZAKURA_FIXTURE_WALLET_DIR'];
  final skip = library == null || phrase == null || dir == null
      ? 'run by kill_fixture_test.dart'
      : null;

  test('the wallet under test syncs until it is killed', () async {
    // The parent kills this process by this identifier.
    stdout.writeln('CHILD_PID=$pid');
    await stdout.flush();
    final bindings = await NativeBindings.load(libraryPath: library!);
    await bindings.open(
      directory: dir!,
      lightwalletdUrl: env['ZAKURA_FIXTURE_LWD']!,
      mainnet: true,
      transparentFiltersUrl: env['ZAKURA_FIXTURE_FILTERS']!,
      transparentShardsUrl: env['ZAKURA_FIXTURE_SHARDS']!,
    );
    final birthday = int.parse(env['ZAKURA_FIXTURE_BIRTHDAY']!);
    final id = await bindings.importAccount(phrase: phrase!, birthday: birthday);
    stdout.writeln('CHILD_ACCOUNT=$id');
    await bindings.startSync();
    stdout.writeln('CHILD_SYNCING');
    await stdout.flush();
    final deadline = DateTime.now().add(const Duration(minutes: 10));
    while (DateTime.now().isBefore(deadline)) {
      final progress = await bindings.progress();
      final balance = await bindings.balance(id);
      stdout.writeln(
        'CHILD phase=${progress.phase.name} scanned_to=${progress.scannedTo} '
        'tip=${progress.tip} completion=${balance.coverage.completion} '
        'anchor=${balance.coverage.anchorHeight} failed=${progress.failed}',
      );
      await stdout.flush();
      if (progress.failed) {
        final failure = await bindings.syncFailure();
        stdout.writeln('CHILD_FAILED ${failure ?? ''}');
        await stdout.flush();
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
  }, skip: skip, timeout: const Timeout(Duration(minutes: 12)));
}
