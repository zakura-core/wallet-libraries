import 'package:flutter/widgets.dart';

import '../theme/theme.dart';
import 'primitives.dart';

/// Asks for a seed phrase and, optionally, where to start looking for its
/// history.
///
/// The birthday is the one field somebody can get catastrophically wrong. Too
/// high and the wallet skips the blocks their money arrived in, then shows a
/// balance that is simply missing funds with nothing on screen to suggest why.
/// Too low only costs time. So the field is optional, leaving it blank is
/// presented as the safe answer rather than the lazy one, and nothing here
/// guesses on somebody's behalf.
class ImportForm extends StatefulWidget {
  /// Whether an import is in progress.
  final bool busy;

  /// What went wrong, if anything.
  final String? error;

  /// The earliest height worth scanning, shown as guidance.
  final int? earliestBirthday;

  /// The current chain tip, shown as the upper end of the sensible range.
  final int? chainTip;

  /// Called with the phrase and the birthday, which is null when not given.
  final void Function(String phrase, int? birthday)? onImport;

  /// Called when the person backs out.
  final VoidCallback? onCancel;

  /// Creates an import form.
  const ImportForm({
    required this.busy,
    this.error,
    this.earliestBirthday,
    this.chainTip,
    this.onImport,
    this.onCancel,
    super.key,
  });

  @override
  State<ImportForm> createState() => _ImportFormState();
}

class _ImportFormState extends State<ImportForm> {
  final _phrase = TextEditingController();
  final _birthday = TextEditingController();
  final _phraseFocus = FocusNode();
  final _birthdayFocus = FocusNode();

  String? _phraseError;
  String? _birthdayError;

  @override
  void dispose() {
    _phrase.dispose();
    _birthday.dispose();
    _phraseFocus.dispose();
    _birthdayFocus.dispose();
    super.dispose();
  }

  /// The word count a valid phrase can have.
  static const _lengths = {12, 15, 18, 21, 24};

  void _submit() {
    final words = _phrase.text.trim().split(RegExp(r'\s+'))
      ..removeWhere((w) => w.isEmpty);

    if (words.isEmpty) {
      setState(() => _phraseError = 'Enter your seed phrase');
      return;
    }
    // Checked here only to say something useful about the shape. Whether the
    // words are real and the checksum holds is the wallet's answer, not this
    // form's.
    if (!_lengths.contains(words.length)) {
      setState(() {
        _phraseError =
            'A seed phrase is 12, 15, 18, 21 or 24 words. This has ${words.length}.';
      });
      return;
    }

    int? birthday;
    final typed = _birthday.text.trim();
    if (typed.isNotEmpty) {
      birthday = int.tryParse(typed);
      if (birthday == null || birthday < 0) {
        setState(() => _birthdayError = 'Enter a block height, or leave blank');
        return;
      }
      final tip = widget.chainTip;
      if (tip != null && birthday > tip) {
        setState(() {
          _birthdayError =
              'That is above the current block ($tip). A birthday after your '
              'money arrived would skip it.';
        });
        return;
      }
    }

    setState(() {
      _phraseError = null;
      _birthdayError = null;
    });
    widget.onImport?.call(words.join(' '), birthday);
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final earliest = widget.earliestBirthday;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (widget.error != null) ...[
          ZakuraNotice(message: widget.error!, isError: true),
          SizedBox(height: theme.spacing.lg),
        ],
        _Field(
          label: 'Seed phrase',
          controller: _phrase,
          focusNode: _phraseFocus,
          enabled: !widget.busy,
          error: _phraseError,
          mono: true,
          lines: 4,
        ),
        SizedBox(height: theme.spacing.lg),
        _Field(
          label: 'Wallet birthday (optional)',
          controller: _birthday,
          focusNode: _birthdayFocus,
          enabled: !widget.busy,
          error: _birthdayError,
        ),
        SizedBox(height: theme.spacing.sm),
        Text(
          earliest == null
              ? 'The block your wallet was created at. Leave it blank if you '
                  'do not know — the wallet will scan everything, which takes '
                  'longer and cannot miss anything.'
              : 'The block your wallet was created at, between $earliest and '
                  'now. Leave it blank if you do not know — the wallet will '
                  'scan from $earliest, which takes longer and cannot miss '
                  'anything.',
          style: theme.typography.caption.copyWith(color: theme.colors.textMuted),
        ),
        SizedBox(height: theme.spacing.xl),
        ZakuraButton(
          label: widget.busy ? 'Restoring…' : 'Restore wallet',
          busy: widget.busy,
          expand: true,
          onPressed: widget.busy ? null : _submit,
        ),
        if (widget.onCancel != null) ...[
          SizedBox(height: theme.spacing.md),
          ZakuraButton(
            label: 'Back',
            kind: ZakuraButtonKind.secondary,
            expand: true,
            onPressed: widget.busy ? null : widget.onCancel,
          ),
        ],
      ],
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({
    required this.label,
    required this.controller,
    required this.focusNode,
    required this.enabled,
    this.error,
    this.mono = false,
    this.lines = 1,
  });

  final String label;
  final TextEditingController controller;
  final FocusNode focusNode;
  final bool enabled;
  final String? error;
  final bool mono;
  final int lines;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: theme.typography.caption.copyWith(color: theme.colors.textMuted),
        ),
        SizedBox(height: theme.spacing.sm),
        Container(
          padding: EdgeInsets.all(theme.spacing.md),
          decoration: BoxDecoration(
            color: theme.colors.surface,
            borderRadius: theme.radii.medium,
            border: Border.all(
              color: error != null ? theme.colors.danger : theme.colors.border,
            ),
          ),
          child: EditableText(
            controller: controller,
            focusNode: focusNode,
            readOnly: !enabled,
            maxLines: lines,
            style: (mono ? theme.typography.mono : theme.typography.body)
                .copyWith(color: theme.colors.text),
            cursorColor: theme.colors.accent,
            backgroundCursorColor: theme.colors.border,
            selectionColor: theme.colors.accent.withValues(alpha: 0.3),
          ),
        ),
        if (error != null) ...[
          SizedBox(height: theme.spacing.xs),
          Text(
            error!,
            style: theme.typography.caption.copyWith(color: theme.colors.danger),
          ),
        ],
      ],
    );
  }
}
