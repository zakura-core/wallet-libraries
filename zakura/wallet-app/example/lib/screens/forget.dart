import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// Forgetting this wallet, so that another can be restored.
///
/// The store holds one account, so changing wallets is deleting this one and
/// going back through onboarding. The same path re-runs a recovery: restore
/// the same phrase with a lower birthday.
class ForgetScreen extends ConsumerStatefulWidget {
  /// Creates the forget screen.
  const ForgetScreen({super.key});

  @override
  ConsumerState<ForgetScreen> createState() => _ForgetScreenState();
}

class _ForgetScreenState extends ConsumerState<ForgetScreen> {
  bool _busy = false;
  String? _error;

  Future<void> _forget() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(forgetWalletProvider)();
    } on ZakuraException catch (e) {
      // Nothing was forgotten; the wallet is still here and so is this
      // screen, with the reason.
      if (mounted) {
        setState(() {
          _busy = false;
          _error = 'The wallet could not be forgotten: ${e.message}';
        });
      }
      return;
    }
    // The root swaps to onboarding as soon as the account is cleared; this
    // route is still stacked above it and has to go.
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);

    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              _Back(onTap: () => Navigator.of(context).pop()),
              SizedBox(height: theme.spacing.lg),
              Text(
                'Forget this wallet',
                style:
                    theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              Text(
                'This deletes the app\'s copy of the wallet. Your seed phrase '
                'is the only way back in, so make sure you have it. This is '
                'how to switch to another wallet, and how to restore this one '
                'again from an earlier birthday.',
                style: theme.typography.body
                    .copyWith(color: theme.colors.textMuted),
              ),
              if (_error != null) ...[
                SizedBox(height: theme.spacing.lg),
                ZakuraNotice(message: _error!, isError: true),
              ],
              SizedBox(height: theme.spacing.lg),
              ZakuraButton(
                label: 'Forget this wallet',
                expand: true,
                busy: _busy,
                onPressed: _forget,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Back extends StatelessWidget {
  const _Back({required this.onTap});

  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Text(
        '‹ Back',
        style: theme.typography.body.copyWith(color: theme.colors.accent),
      ),
    );
  }
}
