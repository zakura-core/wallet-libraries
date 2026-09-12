import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// An address to be paid to.
class ReceiveScreen extends ConsumerWidget {
  /// Creates the receive screen.
  const ReceiveScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = ZakuraTheme.of(context);
    final address = ref.watch(receiveAddressProvider);

    return SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: ListView(
            padding: EdgeInsets.all(theme.spacing.lg),
            children: [
              _Back(onTap: () => Navigator.of(context).pop()),
              SizedBox(height: theme.spacing.lg),
              switch (address) {
                AsyncData(:final value) => ReceiveCard(
                    address: value,
                    onCopy: () =>
                        Clipboard.setData(ClipboardData(text: value)),
                    onNew: () => ref.invalidate(receiveAddressProvider),
                  ),
                AsyncError(:final error) =>
                  ZakuraNotice(message: '$error', isError: true),
                _ => const ZakuraEmptyState(title: 'Issuing an address…'),
              },
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
