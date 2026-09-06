import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// Getting into a wallet: a new one, or one that already exists.
///
/// Thin by construction. Which of the two paths is showing is the controller's
/// state, and every message somebody reads comes from there too, so there is
/// nothing here to get wrong.
class OnboardingScreen extends ConsumerWidget {
  /// Creates the onboarding screen.
  const OnboardingScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final state = ref.watch(onboardingControllerProvider);
    final controller = ref.read(onboardingControllerProvider.notifier);

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
                    _subtitle(state),
                    style: theme.typography.body
                        .copyWith(color: theme.colors.textMuted),
                  ),
                  SizedBox(height: theme.spacing.xxl),
                  switch (state) {
                    OnboardingIdle() => _Choice(controller: controller),
                    OnboardingCreated(:final phrase, :final error) =>
                      _Created(
                        phrase: phrase,
                        error: error,
                        controller: controller,
                      ),
                    OnboardingImporting() =>
                      _Importing(state: state, controller: controller),
                    // Replaced by the home screen as soon as the account is
                    // selected; this is the frame in between.
                    OnboardingDone() => const ZakuraEmptyState(
                        title: 'Opening your wallet…',
                      ),
                  },
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  static String _subtitle(OnboardingState state) => switch (state) {
        OnboardingCreated() =>
          'Write these words down before you go on. They are the only way back '
              'into this wallet.',
        OnboardingImporting() =>
          'Enter the seed phrase of a wallet you already have.',
        _ => 'A minimal wallet built on the Zakura core.',
      };
}

class _Choice extends StatelessWidget {
  const _Choice({required this.controller});

  final OnboardingController controller;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ZakuraButton(
          label: 'Create a wallet',
          expand: true,
          onPressed: controller.beginCreate,
        ),
        SizedBox(height: theme.spacing.md),
        ZakuraButton(
          label: 'Restore an existing wallet',
          kind: ZakuraButtonKind.secondary,
          expand: true,
          onPressed: controller.beginImport,
        ),
      ],
    );
  }
}

class _Created extends StatelessWidget {
  const _Created({
    required this.phrase,
    required this.controller,
    this.error,
  });

  final String phrase;
  final String? error;
  final OnboardingController controller;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (error != null) ...[
          ZakuraNotice(message: error!, isError: true),
          SizedBox(height: theme.spacing.lg),
        ],
        SeedPhraseView(words: phrase.split(RegExp(r'\s+'))),
        SizedBox(height: theme.spacing.lg),
        ZakuraButton(
          label: 'I have written it down',
          expand: true,
          onPressed: controller.confirmCreate,
        ),
        SizedBox(height: theme.spacing.md),
        ZakuraButton(
          label: 'Back',
          kind: ZakuraButtonKind.secondary,
          expand: true,
          onPressed: controller.reset,
        ),
      ],
    );
  }
}

class _Importing extends StatelessWidget {
  const _Importing({required this.state, required this.controller});

  final OnboardingImporting state;
  final OnboardingController controller;

  @override
  Widget build(BuildContext context) {
    return ImportForm(
      busy: state.busy,
      error: state.error,
      earliestBirthday: state.earliestBirthday,
      chainTip: state.chainTip,
      onImport: (phrase, birthday) =>
          controller.import(phrase: phrase, birthday: birthday),
      onCancel: controller.reset,
    );
  }
}
