import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// Creating a wallet, and showing the phrase that is the wallet.
class OnboardingScreen extends ConsumerStatefulWidget {
  /// Creates the onboarding screen.
  const OnboardingScreen({super.key});

  @override
  ConsumerState<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends ConsumerState<OnboardingScreen> {
  String? _phrase;
  bool _busy = false;
  String? _error;

  Future<void> _generate() async {
    setState(() => _busy = true);
    final phrase = await ref.read(walletProvider).generateMnemonic();
    if (mounted) setState(() => (_phrase = phrase, _busy = false));
  }

  Future<void> _create() async {
    final phrase = _phrase;
    if (phrase == null) return;
    setState(() => (_busy = true, _error = null));

    final wallet = ref.read(walletProvider);
    try {
      await wallet.open(
        directory: '/tmp/zakura-example',
        lightwalletdUrl: 'https://us.zec.stardust.rest:443',
      );
      // A brand new wallet has no history below the current tip, so its
      // birthday is now. Restoring an existing one is where a real wallet has
      // to ask, because guessing too high loses transactions.
      final id = await wallet.createAccount(phrase: phrase, birthday: 2900000);
      ref.read(activeAccountProvider.notifier).select(id);
      await wallet.startSync();
    } on Object catch (e) {
      if (mounted) setState(() => (_error = e.toString(), _busy = false));
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);

    return SafeArea(
      child: Padding(
        padding: EdgeInsets.all(theme.spacing.lg),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'Zakura',
                    style: theme.typography.display
                        .copyWith(color: theme.colors.text),
                  ),
                  SizedBox(height: theme.spacing.sm),
                  Text(
                    'A minimal wallet built on the Zakura core.',
                    style: theme.typography.body
                        .copyWith(color: theme.colors.textMuted),
                  ),
                  SizedBox(height: theme.spacing.xxl),
                  if (_error != null) ...[
                    ZakuraNotice(message: _error!, isError: true),
                    SizedBox(height: theme.spacing.lg),
                  ],
                  if (_phrase == null)
                    ZakuraButton(
                      label: 'Create a wallet',
                      busy: _busy,
                      expand: true,
                      onPressed: _busy ? null : _generate,
                    )
                  else ...[
                    SeedPhraseView(words: _phrase!.split(RegExp(r'\s+'))),
                    SizedBox(height: theme.spacing.lg),
                    ZakuraButton(
                      label: 'I have written it down',
                      busy: _busy,
                      expand: true,
                      onPressed: _busy ? null : _create,
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
