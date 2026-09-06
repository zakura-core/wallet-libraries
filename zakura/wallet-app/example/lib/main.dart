import 'dart:io';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_bindings/zakura_bindings.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

import 'demo_bindings.dart';
import 'screens/home.dart';
import 'screens/onboarding.dart';

/// Whether the demo wallet was asked for explicitly.
///
/// `--dart-define=ZAKURA_DEMO=true` runs against the in-memory wallet, which is
/// useful for working on the interface without waiting for a chain.
const _forceDemo = bool.fromEnvironment('ZAKURA_DEMO');

/// Where the wallet's two files live.
///
/// Under the home directory rather than a temporary one, because a wallet that
/// forgets itself when the machine is tidied up is not a wallet.
String _walletDirectory() {
  final home = Platform.environment['HOME'] ?? Directory.systemTemp.path;
  return '$home/.zakura-example';
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // The whole of the rest of this application is written against
  // `ZakuraBindings`, so choosing between the real wallet and the demo one is
  // this single expression. Nothing below it knows which it got.
  final (ZakuraBindings bindings, bool demo) = await _bindings();
  final wallet = ZakuraWallet(bindings);

  // Opened here rather than when a wallet is created, so that a returning user
  // gets the wallet they already have. Onboarding is for people who have none.
  int? existing;
  try {
    await wallet.open(
      directory: _walletDirectory(),
      lightwalletdUrl: 'https://us.zec.stardust.rest:443',
    );
    final accounts = await wallet.accounts();
    if (accounts.isNotEmpty) {
      existing = accounts.first.id;
      await wallet.startSync();
    }
  } on Object catch (e) {
    // Nothing to show yet, so this goes to the log and onboarding is offered.
    // Whatever went wrong will come back the moment a wallet is created.
    debugPrint('Could not open the wallet: $e');
  }

  runApp(
    ProviderScope(
      overrides: [
        walletProvider.overrideWithValue(wallet),
        initialAccountProvider.overrideWithValue(existing),
      ],
      child: ZakuraExampleApp(demo: demo),
    ),
  );
}

Future<(ZakuraBindings, bool)> _bindings() async {
  if (_forceDemo) return (DemoBindings(), true);
  try {
    return (await NativeBindings.load(), false);
  } on Object catch (e) {
    // The native library is built by Cargokit as part of a normal Flutter
    // build, so failing to load it means something is wrong with the build
    // rather than with the wallet. Falling back keeps the example runnable and
    // says so on screen, rather than presenting a demo as the real thing.
    debugPrint('Native wallet unavailable, falling back to the demo: $e');
    return (DemoBindings(), true);
  }
}

/// The example wallet.
class ZakuraExampleApp extends StatelessWidget {
  /// Whether this is running against the in-memory demo wallet.
  final bool demo;

  /// Creates the app.
  const ZakuraExampleApp({this.demo = false, super.key});

  @override
  Widget build(BuildContext context) {
    return WidgetsApp(
      title: 'Zakura',
      color: const Color(0xFF3B5BDB),
      builder: (context, _) => ZakuraThemeScope(child: _Root(demo: demo)),
      pageRouteBuilder: <T>(settings, builder) => PageRouteBuilder<T>(
        settings: settings,
        pageBuilder: (c, _, _) => builder(c),
      ),
    );
  }
}

class _Root extends ConsumerWidget {
  const _Root({required this.demo});

  final bool demo;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final account = ref.watch(activeAccountProvider);

    return Container(
      color: theme.colors.background,
      child: Column(
        children: [
          if (demo)
            SafeArea(
              bottom: false,
              child: Padding(
                padding: EdgeInsets.fromLTRB(
                  theme.spacing.lg,
                  theme.spacing.sm,
                  theme.spacing.lg,
                  0,
                ),
                child: const ZakuraNotice(
                  message: 'Demo wallet: nothing here touches a chain, and no '
                      'money is real.',
                ),
              ),
            ),
          Expanded(
            child: account == null
                ? const OnboardingScreen()
                : const HomeScreen(),
          ),
        ],
      ),
    );
  }
}
