import 'package:flutter/widgets.dart';

import '../theme/theme.dart';
import '../theme/tokens.dart';
import 'primitives.dart';

/// A seed phrase, numbered and laid out to be copied onto paper.
///
/// Numbered because the order is part of the secret and somebody transcribing
/// twenty-four words will lose their place. Hidden until asked for, because the
/// most likely way to lose a phrase is to have it on screen when somebody else
/// is looking.
class SeedPhraseView extends StatefulWidget {
  /// The words, in order.
  final List<String> words;

  /// Whether to start hidden.
  final bool startHidden;

  /// Creates a seed phrase view.
  const SeedPhraseView({
    required this.words,
    this.startHidden = true,
    super.key,
  });

  @override
  State<SeedPhraseView> createState() => _SeedPhraseViewState();
}

class _SeedPhraseViewState extends State<SeedPhraseView> {
  late bool _hidden = widget.startHidden;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final columns = theme.formFactor == FormFactor.compact ? 2 : 4;

    return ZakuraCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const ZakuraNotice(
            message: 'These words are your wallet. Anybody who has them can '
                'spend your money, and nobody can recover them for you. Write '
                'them down and keep them somewhere safe.',
          ),
          SizedBox(height: theme.spacing.lg),
          if (_hidden)
            ZakuraButton(
              label: 'Reveal',
              kind: ZakuraButtonKind.secondary,
              expand: true,
              onPressed: () => setState(() => _hidden = false),
            )
          else
            GridView.count(
              crossAxisCount: columns,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              childAspectRatio: 4,
              mainAxisSpacing: theme.spacing.sm,
              crossAxisSpacing: theme.spacing.sm,
              children: [
                for (var i = 0; i < widget.words.length; i++)
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.baseline,
                    textBaseline: TextBaseline.alphabetic,
                    children: [
                      SizedBox(
                        width: 24,
                        child: Text(
                          '${i + 1}',
                          style: theme.typography.caption
                              .copyWith(color: theme.colors.textMuted),
                        ),
                      ),
                      Expanded(
                        child: Text(
                          widget.words[i],
                          style: theme.typography.mono
                              .copyWith(color: theme.colors.text),
                        ),
                      ),
                    ],
                  ),
              ],
            ),
        ],
      ),
    );
  }
}
