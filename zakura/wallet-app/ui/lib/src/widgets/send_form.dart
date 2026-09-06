import 'package:flutter/widgets.dart';
import 'package:zakura_client/zakura_client.dart';

import '../theme/theme.dart';
import 'primitives.dart';

/// Where a payment has got to, as far as this widget needs to know.
///
/// Deliberately not the state machine from `zakura_state`: this package does
/// not depend on riverpod, so an application using something else can still
/// draw this form.
enum SendStage {
  /// Waiting for an amount and an address.
  editing,

  /// Working out the fee.
  quoting,

  /// A quote is ready to confirm.
  quoted,

  /// Building and proving, which is the slow part.
  proving,

  /// Talking to the network.
  broadcasting,

  /// Done.
  sent,
}

/// Asks for an amount and an address, then confirms the cost.
///
/// Two steps rather than one, because the fee is not knowable until the notes
/// to spend have been chosen, and somebody should see what they are paying
/// before they pay it.
class SendForm extends StatefulWidget {
  /// Where the payment has got to.
  final SendStage stage;

  /// The quote to confirm, once there is one.
  final SpendQuote? quote;

  /// What went wrong, if anything.
  final String? error;

  /// Asks for a quote.
  final void Function(String to, Zatoshi amount)? onQuote;

  /// Confirms the quote.
  final VoidCallback? onConfirm;

  /// Goes back to editing.
  final VoidCallback? onCancel;

  /// Creates a send form.
  const SendForm({
    required this.stage,
    this.quote,
    this.error,
    this.onQuote,
    this.onConfirm,
    this.onCancel,
    super.key,
  });

  @override
  State<SendForm> createState() => _SendFormState();
}

class _SendFormState extends State<SendForm> {
  final _address = TextEditingController();
  final _amount = TextEditingController();
  String? _amountError;

  @override
  void dispose() {
    _address.dispose();
    _amount.dispose();
    super.dispose();
  }

  void _submit() {
    final text = _amount.text.trim();
    final zec = double.tryParse(text);
    if (zec == null || zec <= 0) {
      setState(() => _amountError = 'Enter an amount');
      return;
    }
    late final Zatoshi amount;
    try {
      amount = Zatoshi.fromZec(zec);
    } on ArgumentError {
      setState(() => _amountError = 'Too many decimal places');
      return;
    }
    setState(() => _amountError = null);
    widget.onQuote?.call(_address.text.trim(), amount);
  }

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final busy = widget.stage == SendStage.quoting ||
        widget.stage == SendStage.proving ||
        widget.stage == SendStage.broadcasting;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (widget.error != null) ...[
          ZakuraNotice(message: widget.error!, isError: true),
          SizedBox(height: theme.spacing.lg),
        ],
        if (widget.stage == SendStage.quoted && widget.quote != null)
          _Confirmation(quote: widget.quote!)
        else ...[
          _Field(
            label: 'To',
            hint: 'Unified address',
            controller: _address,
            enabled: !busy,
            mono: true,
          ),
          SizedBox(height: theme.spacing.lg),
          _Field(
            label: 'Amount (ZEC)',
            hint: '0.00',
            controller: _amount,
            enabled: !busy,
            error: _amountError,
            keyboardType:
                const TextInputType.numberWithOptions(decimal: true),
          ),
        ],
        SizedBox(height: theme.spacing.xl),
        if (widget.stage == SendStage.quoted)
          Row(
            children: [
              Expanded(
                child: ZakuraButton(
                  label: 'Back',
                  kind: ZakuraButtonKind.secondary,
                  onPressed: widget.onCancel,
                  expand: true,
                ),
              ),
              SizedBox(width: theme.spacing.md),
              Expanded(
                child: ZakuraButton(
                  label: 'Send',
                  onPressed: widget.onConfirm,
                  expand: true,
                ),
              ),
            ],
          )
        else
          ZakuraButton(
            label: switch (widget.stage) {
              SendStage.quoting => 'Working out the fee…',
              // Proving is seconds long, so it says what it is doing rather
              // than spinning silently and looking stuck.
              SendStage.proving => 'Proving…',
              SendStage.broadcasting => 'Sending…',
              SendStage.sent => 'Sent',
              _ => 'Continue',
            },
            busy: busy,
            onPressed: busy || widget.stage == SendStage.sent ? null : _submit,
            expand: true,
          ),
      ],
    );
  }
}

class _Confirmation extends StatelessWidget {
  const _Confirmation({required this.quote});

  final SpendQuote quote;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return ZakuraCard(
      child: Column(
        children: [
          _Row(label: 'Amount', value: '${quote.amount.format()} ZEC'),
          SizedBox(height: theme.spacing.md),
          _Row(label: 'Fee', value: '${quote.fee.format()} ZEC'),
          SizedBox(height: theme.spacing.md),
          Container(height: 1, color: theme.colors.border),
          SizedBox(height: theme.spacing.md),
          _Row(
            label: 'Total',
            value: '${quote.total.format()} ZEC',
            emphasise: true,
          ),
          SizedBox(height: theme.spacing.md),
          Text(
            quote.crossing
                // The amount and the fee are fixed by the shape every crossing
                // shares, so somebody should not be left wondering why they
                // cannot be adjusted.
                ? 'Paid out of the Orchard pool in a set amount and at a set '
                    'fee, so it cannot be told apart from other such payments. '
                    'This takes a few seconds.'
                : quote.inputs == 1
                    ? 'Spending 1 note. This takes a few seconds.'
                    : 'Spending ${quote.inputs} notes. This takes a few seconds.',
            style:
                theme.typography.caption.copyWith(color: theme.colors.textMuted),
          ),
        ],
      ),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row({required this.label, required this.value, this.emphasise = false});

  final String label;
  final String value;
  final bool emphasise;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    final style = theme.typography.body.copyWith(
      color: theme.colors.text,
      fontWeight: emphasise ? FontWeight.w600 : FontWeight.w400,
    );
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: emphasise
              ? style
              : theme.typography.body.copyWith(color: theme.colors.textMuted),
        ),
        Text(value, style: style),
      ],
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({
    required this.label,
    required this.hint,
    required this.controller,
    required this.enabled,
    this.error,
    this.mono = false,
    this.keyboardType,
  });

  final String label;
  final String hint;
  final TextEditingController controller;
  final bool enabled;
  final String? error;
  final bool mono;
  final TextInputType? keyboardType;

  @override
  Widget build(BuildContext context) {
    final theme = ZakuraTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style:
              theme.typography.caption.copyWith(color: theme.colors.textMuted),
        ),
        SizedBox(height: theme.spacing.sm),
        Container(
          padding: EdgeInsets.symmetric(
            horizontal: theme.spacing.md,
            vertical: theme.spacing.md,
          ),
          decoration: BoxDecoration(
            color: theme.colors.surface,
            borderRadius: theme.radii.medium,
            border: Border.all(
              color: error != null ? theme.colors.danger : theme.colors.border,
            ),
          ),
          child: EditableText(
            controller: controller,
            focusNode: FocusNode(),
            readOnly: !enabled,
            keyboardType: keyboardType,
            style: (mono ? theme.typography.mono : theme.typography.body)
                .copyWith(color: theme.colors.text),
            cursorColor: theme.colors.accent,
            backgroundCursorColor: theme.colors.border,
            selectionColor: theme.colors.accent.withValues(alpha: 0.3),
            maxLines: mono ? 3 : 1,
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
