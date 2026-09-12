import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_state/zakura_state.dart';
import 'package:zakura_ui/zakura_ui.dart';

/// What each environment's lightwalletd server says the chain is at.
///
/// A diagnostic. The sync indicator on the home screen shows this wallet's
/// progress against the one server it uses; this asks the servers themselves,
/// one per environment, with no wallet involved. A height that does not move
/// between refreshes, or a server that does not answer, is what a stalled
/// sync looks like from the other side.
class HeightsScreen extends ConsumerStatefulWidget {
  /// Creates the live heights screen.
  const HeightsScreen({super.key});

  @override
  ConsumerState<HeightsScreen> createState() => _HeightsScreenState();
}

/// One environment's endpoint.
class _Environment {
  const _Environment({required this.name, required this.url});

  final String name;
  final String url;
}

/// The endpoints asked, one per environment.
///
/// Mainnet is the server the example wallet syncs against. Testnet is a
/// public server for the same software; the wallet itself never uses it here.
const _environments = [
  _Environment(name: 'Mainnet', url: 'https://us.zec.stardust.rest:443'),
  _Environment(name: 'Testnet', url: 'https://testnet.zec.rocks:443'),
];

class _HeightsScreenState extends ConsumerState<HeightsScreen> {
  /// The latest answer per environment name, or the error it failed with.
  final Map<String, AsyncValue<int>> _heights = {
    for (final env in _environments) env.name: const AsyncValue.loading(),
  };
  DateTime? _asked;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final wallet = ref.read(walletProvider);
    setState(() {
      for (final env in _environments) {
        _heights[env.name] = const AsyncValue.loading();
      }
      _asked = DateTime.now();
    });
    // Asked together rather than in turn: a server that hangs must not hold
    // up the answer from one that does not.
    await Future.wait([
      for (final env in _environments)
        wallet
            .liveHeight(lightwalletdUrl: env.url)
            .then<AsyncValue<int>>(AsyncValue.data)
            .catchError((Object e, StackTrace s) => AsyncValue<int>.error(e, s))
            .then((value) {
          if (mounted) setState(() => _heights[env.name] = value);
        }),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final busy = _heights.values.any((v) => v.isLoading);

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
                'Live chain heights',
                style:
                    theme.typography.title.copyWith(color: theme.colors.text),
              ),
              SizedBox(height: theme.spacing.sm),
              Text(
                'What each lightwalletd server reports as its chain tip right '
                'now. The server answers for the chain it serves.',
                style: theme.typography.caption
                    .copyWith(color: theme.colors.textMuted),
              ),
              SizedBox(height: theme.spacing.lg),
              for (final env in _environments) ...[
                _EnvironmentCard(
                  environment: env,
                  height: _heights[env.name]!,
                ),
                SizedBox(height: theme.spacing.md),
              ],
              if (_asked != null)
                Text(
                  'Asked at ${_clock(_asked!)}',
                  style: theme.typography.caption
                      .copyWith(color: theme.colors.textMuted),
                ),
              SizedBox(height: theme.spacing.lg),
              ZakuraButton(
                label: 'Refresh',
                kind: ZakuraButtonKind.secondary,
                expand: true,
                busy: busy,
                onPressed: busy ? null : _refresh,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _EnvironmentCard extends StatelessWidget {
  const _EnvironmentCard({required this.environment, required this.height});

  final _Environment environment;
  final AsyncValue<int> height;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return ZakuraCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            environment.name,
            style: theme.typography.body.copyWith(color: theme.colors.text),
          ),
          SizedBox(height: theme.spacing.xs),
          Text(
            environment.url,
            style: theme.typography.caption
                .copyWith(color: theme.colors.textMuted),
          ),
          SizedBox(height: theme.spacing.md),
          switch (height) {
            AsyncData(:final value) => Text(
                _grouped(value),
                style: theme.typography.title
                    .copyWith(color: theme.colors.text),
              ),
            AsyncError(:final error) => ZakuraNotice(
                message: 'Could not be reached: $error',
                isError: true,
              ),
            _ => Text(
                'Asking…',
                style: theme.typography.body
                    .copyWith(color: theme.colors.textMuted),
              ),
          },
        ],
      ),
    );
  }
}

/// A block height with thousands separated, so 3476813 reads as a height.
String _grouped(int height) {
  final digits = height.toString();
  final out = StringBuffer();
  for (var i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 == 0) out.write(',');
    out.write(digits[i]);
  }
  return out.toString();
}

String _clock(DateTime at) {
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(at.hour)}:${two(at.minute)}:${two(at.second)}';
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
