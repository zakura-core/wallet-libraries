import 'package:flutter/widgets.dart';
import 'package:zakura_ui/zakura_ui.dart';

import '../mode.dart';

/// Why there is no wallet to show.
///
/// Reached only from a beta mode that could not come up. Every reason is one
/// the person building or configuring the application can act on, and none
/// of them is shown as a balance: a wallet that could not load its native
/// library does not become a demonstration, and one that could not confirm
/// its server's chain does not become an empty history.
class FailureScreen extends StatelessWidget {
  /// The mode that was asked for, if any.
  final ZakuraMode? mode;

  /// Which step refused.
  final String step;

  /// What is wrong.
  final List<String> problems;

  /// Creates the failure screen.
  const FailureScreen({
    required this.mode,
    required this.step,
    required this.problems,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              Text(
                'This build cannot run',
                style: theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              Text(
                '$step check failed'
                '${mode == null ? '' : ' in ${mode!.label.toLowerCase()} mode'}. '
                'No wallet was opened and nothing was written.',
                style: theme.typography.body.copyWith(
                  color: theme.colors.textMuted,
                ),
              ),
              SizedBox(height: theme.spacing.lg),
              for (final problem in problems) ...[
                ZakuraNotice(message: problem, isError: true),
                SizedBox(height: theme.spacing.md),
              ],
              Text(
                'Fix the build or its configuration and start the application '
                'again. A beta build never falls back to the demonstration.',
                style: theme.typography.caption.copyWith(
                  color: theme.colors.textMuted,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
