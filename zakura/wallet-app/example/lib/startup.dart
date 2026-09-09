import 'dart:io';

import 'package:zakura_bindings/zakura_bindings.dart';
import 'package:zakura_client/zakura_client.dart';

import 'demo_bindings.dart';
import 'mode.dart';

/// How the application came up: with a wallet it can show, or with a reason
/// it cannot.
///
/// There is no third outcome. A beta mode that cannot load its native
/// library, confirm its server's chain, or open its own profile stops here
/// and says so; it never shows the demonstration in place of a wallet.
sealed class Startup {
  const Startup();
}

/// A wallet is open and the interface may show it.
class StartupReady extends Startup {
  /// The mode the build is in.
  final ZakuraMode mode;

  /// The open wallet.
  final ZakuraWallet wallet;

  /// The account found already in the wallet, if any.
  final int? existingAccount;

  /// What the native build is, or null in the demo.
  final BuildInfo? buildInfo;

  /// What the light server said it is, or null in the demo.
  final NetworkIdentity? server;

  /// Where the wallet lives, for the diagnostics screen. Null in the demo.
  final String? profileDirectory;

  const StartupReady({
    required this.mode,
    required this.wallet,
    required this.existingAccount,
    this.buildInfo,
    this.server,
    this.profileDirectory,
  });
}

/// The application cannot show a wallet, and this is why.
class StartupFailed extends Startup {
  /// The mode the build was asked for, if it named one.
  final ZakuraMode? mode;

  /// Which step refused.
  final String step;

  /// What is wrong, in the words the person fixing it needs.
  final List<String> problems;

  const StartupFailed({
    required this.mode,
    required this.step,
    required this.problems,
  });
}

/// Brings the application up under [config].
///
/// Each step either passes or is the answer. The order is the order in which
/// a wrong answer is cheapest to get: configuration before the native
/// library, the library before the network, the network before the files.
Future<Startup> startUp(
  BetaConfig config, {
  String? home,
  Future<ZakuraBindings> Function()? loadNative,
}) async {
  final problems = config.problems();
  final mode = config.mode;
  if (mode == null || problems.isNotEmpty) {
    return StartupFailed(mode: mode, step: 'Configuration', problems: problems);
  }

  if (!mode.isBeta) {
    final wallet = ZakuraWallet(DemoBindings());
    await wallet.open(
      directory: 'demo',
      lightwalletdUrl: config.lightwalletdUrl,
    );
    return StartupReady(mode: mode, wallet: wallet, existingAccount: null);
  }

  // The native library, or nothing. Cargokit builds it as part of a normal
  // Flutter build, so failing to load it means the build is wrong, and a
  // wrong build is not a wallet.
  final ZakuraBindings bindings;
  try {
    bindings = await (loadNative ?? NativeBindings.load)();
  } on Object catch (e) {
    return StartupFailed(
      mode: mode,
      step: 'Native library',
      problems: [
        'The native wallet library could not be loaded, so there is no '
            'wallet to show. This build is broken: $e',
      ],
    );
  }
  final wallet = ZakuraWallet(bindings);

  // The Dart side knows what it was told to be; this is what the native side
  // is. A recovery build that can send is not a recovery build.
  final BuildInfo info;
  try {
    info = await wallet.buildInfo();
  } on Object catch (e) {
    return StartupFailed(
      mode: mode,
      step: 'Native build',
      problems: ['The native build would not identify itself: $e'],
    );
  }
  if (info.sendEnabled) {
    return StartupFailed(
      mode: mode,
      step: 'Native build',
      problems: [
        'The native library was built with sending enabled, which a '
            '${mode.label.toLowerCase()} build must not be. Rebuild without '
            'the bridge\'s "send" feature.',
      ],
    );
  }

  // The server has to be serving mainnet. The sync checks again on every
  // connection; this is what lets the screen say so before anything opens.
  final NetworkIdentity server;
  try {
    server = await wallet.networkIdentity(
      lightwalletdUrl: config.lightwalletdUrl,
    );
  } on Object catch (e) {
    return StartupFailed(
      mode: mode,
      step: 'Network identity',
      problems: [
        'Could not confirm which chain ${config.lightwalletdUrl} serves. '
            'The wallet was not opened. $e',
      ],
    );
  }
  if (!server.isMainnet) {
    return StartupFailed(
      mode: mode,
      step: 'Network identity',
      problems: [
        '${config.lightwalletdUrl} serves the "${server.chainName}" chain, '
            'and this beta is mainnet only.',
      ],
    );
  }

  final profile = BetaProfile.under(
    home ?? Platform.environment['HOME'] ?? Directory.systemTemp.path,
    mode,
  );
  final refused = await profile.prepare();
  if (refused != null) {
    return StartupFailed(mode: mode, step: 'Profile', problems: [refused]);
  }

  try {
    await wallet.open(
      directory: profile.directory,
      lightwalletdUrl: config.lightwalletdUrl,
      transparentFiltersUrl: config.transparentFiltersUrl,
      transparentShardsUrl: config.transparentShardsUrl,
    );
  } on ZakuraException catch (e) {
    return StartupFailed(
      mode: mode,
      step: 'Wallet',
      problems: [
        switch (e.code) {
          ZakuraErrorCode.versionMismatch =>
            'The wallet in this profile was written by another build and has '
                'been left as it was. ${e.message}',
          ZakuraErrorCode.configuration =>
            'The native wallet refused this configuration. ${e.message}',
          _ => 'The wallet could not be opened. ${e.message}',
        },
      ],
    );
  }

  int? existing;
  try {
    final accounts = await wallet.accounts();
    if (accounts.isNotEmpty) {
      existing = accounts.first.id;
      await wallet.startSync();
    }
  } on ZakuraException catch (e) {
    // The wallet is open; a sync that could not start is reported where a
    // sync that failed is reported, and the wallet is still shown.
    if (existing == null) {
      return StartupFailed(
        mode: mode,
        step: 'Wallet',
        problems: ['The wallet opened but could not be read. ${e.message}'],
      );
    }
  }

  return StartupReady(
    mode: mode,
    wallet: wallet,
    existingAccount: existing,
    buildInfo: info,
    server: server,
    profileDirectory: profile.directory,
  );
}
