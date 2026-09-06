import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// Making a payment.
///
/// The screen holds no logic of its own: it maps the controller's state onto
/// the form's stage and passes the callbacks through. Everything that could be
/// wrong about a payment is decided a layer down, where it is tested.
class SendScreen extends ConsumerWidget {
  /// Creates the send screen.
  const SendScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final state = ref.watch(sendControllerProvider);
    final controller = ref.read(sendControllerProvider.notifier);

    final stage = switch (state) {
      SendIdle() => SendStage.editing,
      SendQuoting() => SendStage.quoting,
      SendQuoted() => SendStage.quoted,
      SendProving() => SendStage.proving,
      SendBroadcasting() => SendStage.broadcasting,
      SendSent() => SendStage.sent,
      SendFailed() => SendStage.editing,
    };

    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              GestureDetector(
                onTap: () {
                  controller.reset();
                  Navigator.of(context).pop();
                },
                behavior: HitTestBehavior.opaque,
                child: Text(
                  '‹ Back',
                  style: theme.typography.body
                      .copyWith(color: theme.colors.accent),
                ),
              ),
              SizedBox(height: theme.spacing.lg),
              if (state case SendSent(:final receipt)) ...[
                ZakuraNotice(
                  message: receipt.warning ??
                      'Sent. Reaching the network is not the same as being '
                          'mined; it will appear as confirmed once a block '
                          'includes it.',
                  isError: receipt.warning != null,
                ),
                SizedBox(height: theme.spacing.lg),
                Text(
                  receipt.displayId,
                  style:
                      theme.typography.mono.copyWith(color: theme.colors.text),
                ),
                SizedBox(height: theme.spacing.lg),
                ZakuraButton(
                  label: 'Done',
                  expand: true,
                  onPressed: () {
                    controller.reset();
                    Navigator.of(context).pop();
                  },
                ),
              ] else
                SendForm(
                  stage: stage,
                  quote: state is SendQuoted ? state.quote : null,
                  error: state is SendFailed ? state.message : null,
                  onQuote: (to, amount) =>
                      controller.quote(to: to, amount: amount),
                  onCancel: controller.reset,
                  onConfirm: () async {
                    // A real wallet reads this from the platform keystore. The
                    // seed is needed because the wallet stores only viewing
                    // keys, by design.
                    final phrase =
                        await ref.read(walletProvider).generateMnemonic();
                    await controller.confirm(phrase: phrase);
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}
