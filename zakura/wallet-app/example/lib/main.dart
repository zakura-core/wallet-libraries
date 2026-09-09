import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

import 'mode.dart';
import 'screens/failure.dart';
import 'screens/home.dart';
import 'screens/onboarding.dart';
import 'startup.dart';

/// The mode this build is in, and what it should talk to, from
/// `--dart-define`s. See [BetaConfig] for the names.
///
/// ```text
/// fvm flutter build macos --release \
///   --dart-define=ZAKURA_MODE=recovery \
///   --dart-define=ZAKURA_TRANSPARENT_FILTERS=https://... \
///   --dart-define=ZAKURA_TRANSPARENT_SHARDS=https://...
/// ```
final BetaConfig _config = BetaConfig.fromEnvironment();

/// The mode this build is in, or null when it was not told.
///
/// Read once here so that every screen can ask, and so that a build without
/// a mode has nowhere to hide it.
final currentModeProvider = Provider<ZakuraMode?>((ref) => null);

/// What was learned bringing the wallet up, for the diagnostics screen.
final startupProvider = Provider<StartupReady?>((ref) => null);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(ZakuraStartupGate(startup: await startUp(_config)));
}

/// Shows the wallet, or the reason there is none.
///
/// Two outcomes and no third: a beta mode that could not come up is a screen
/// that says what is wrong, never the demonstration.
class ZakuraStartupGate extends StatelessWidget {
  /// How the application came up.
  final Startup startup;

  /// Creates the gate.
  const ZakuraStartupGate({required this.startup, super.key});

  @override
  Widget build(BuildContext context) {
    return switch (startup) {
      StartupReady(:final wallet, :final existingAccount, :final mode) =>
        ProviderScope(
          overrides: [
            walletProvider.overrideWithValue(wallet),
            initialAccountProvider.overrideWithValue(existingAccount),
            currentModeProvider.overrideWithValue(mode),
            startupProvider.overrideWithValue(startup as StartupReady),
          ],
          child: ZakuraExampleApp(mode: mode),
        ),
      StartupFailed(:final mode, :final step, :final problems) =>
        ProviderScope(
          overrides: [currentModeProvider.overrideWithValue(mode)],
          child: ZakuraExampleApp(
            mode: mode,
            failure: FailureScreen(mode: mode, step: step, problems: problems),
          ),
        ),
    };
  }
}

/// The recovery wallet.
class ZakuraExampleApp extends StatelessWidget {
  /// The mode this build is in, or null when it was not told one.
  final ZakuraMode? mode;

  /// What to show instead of a wallet, when there is none.
  final Widget? failure;

  /// Creates the app.
  const ZakuraExampleApp({required this.mode, this.failure, super.key});

  @override
  Widget build(BuildContext context) {
    return WidgetsApp(
      title: 'Zakura Recovery Beta',
      color: const Color(0xFF3B5BDB),
      // `home` is what makes `WidgetsApp` build a Navigator at all: given
      // none of `home`, `routes` or `onGenerateRoute` it builds no navigator,
      // and every `Navigator.of` below it has nothing to push onto.
      home: _Root(mode: mode, failure: failure),
      // The navigator arrives here as `child` and must be passed through. The
      // theme sits above it so that pushed screens inherit it too.
      builder: (context, child) => ZakuraThemeScope(
        child: child ?? const SizedBox.shrink(),
      ),
      pageRouteBuilder: <T>(settings, builder) => PageRouteBuilder<T>(
        settings: settings,
        pageBuilder: (c, _, _) => builder(c),
      ),
    );
  }
}

class _Root extends ConsumerWidget {
  const _Root({required this.mode, required this.failure});

  final ZakuraMode? mode;
  final Widget? failure;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final failure = this.failure;

    return Container(
      color: theme.colors.background,
      child: Column(
        children: [
          ModeBanner(mode: mode),
          Expanded(
            child: failure ??
                (ref.watch(activeAccountProvider) == null
                    ? const OnboardingScreen()
                    : const HomeScreen()),
          ),
        ],
      ),
    );
  }
}

/// Says which mode the build is in, on every screen, all the time.
///
/// A demonstration that could be mistaken for a wallet, or a recovery build
/// that could be mistaken for one that sends, is the mistake this exists to
/// make impossible.
class ModeBanner extends StatelessWidget {
  /// The mode, or null when the build was not told one.
  final ZakuraMode? mode;

  /// Creates the banner.
  const ModeBanner({required this.mode, super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return SafeArea(
      bottom: false,
      child: Padding(
        padding: EdgeInsets.fromLTRB(
          theme.spacing.lg,
          theme.spacing.sm,
          theme.spacing.lg,
          0,
        ),
        child: ZakuraNotice(
          message: mode?.banner ?? 'No mode configured: this build cannot run.',
          isError: mode == null,
        ),
      ),
    );
  }
}
