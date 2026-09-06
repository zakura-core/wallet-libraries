import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zakura_client/zakura_client.dart';

import 'wallet_provider.dart';

/// Where a payment has got to.
///
/// A state machine rather than a boolean, because proving takes seconds and an
/// interface that shows an undifferentiated spinner for that long looks broken.
/// Each state is something worth saying out loud.
sealed class SendState {
  const SendState();
}

/// Nothing is happening.
class SendIdle extends SendState {
  const SendIdle();
}

/// Working out the fee, which is cheap.
class SendQuoting extends SendState {
  const SendQuoting();
}

/// A quote is ready and waiting to be confirmed.
class SendQuoted extends SendState {
  /// What the payment would cost.
  final SpendQuote quote;

  /// Who is being paid.
  final String recipient;

  const SendQuoted(this.quote, this.recipient);
}

/// Building and proving, which is the slow part.
class SendProving extends SendState {
  const SendProving();
}

/// Proved and signed; talking to the network.
class SendBroadcasting extends SendState {
  const SendBroadcasting();
}

/// The network accepted it.
///
/// Accepted means it reached the network, not that it will be mined.
class SendSent extends SendState {
  /// What came back.
  final SendReceipt receipt;

  const SendSent(this.receipt);
}

/// It did not work.
class SendFailed extends SendState {
  /// Why.
  final ZakuraException error;

  const SendFailed(this.error);

  /// A sentence to show somebody, chosen for what they can do about it.
  String get message => switch (error.code) {
        ZakuraErrorCode.insufficientFunds =>
          'Not enough spendable funds. Some of your balance may still be '
              'settling.',
        ZakuraErrorCode.crossingUnavailable =>
          'Your funds are in a pool this version cannot spend from yet.',
        ZakuraErrorCode.noAnchor =>
          'The wallet has not synchronised far enough to send yet.',
        ZakuraErrorCode.badAddress => 'That address could not be read.',
        ZakuraErrorCode.unsupportedAddress =>
          'That is a valid address, but not one this wallet can pay.',
        ZakuraErrorCode.rejected => 'The network refused the transaction.',
        ZakuraErrorCode.source => 'Could not reach the server. Try again.',
        ZakuraErrorCode.wrongSeed => 'That seed phrase is not this wallet\'s.',
        ZakuraErrorCode.watchOnly => 'This account can watch but not spend.',
        _ => 'The payment could not be sent.',
      };
}

/// Drives one payment from an amount and an address to a broadcast.
final sendControllerProvider =
    NotifierProvider<SendController, SendState>(SendController.new);

/// The send flow.
class SendController extends Notifier<SendState> {
  @override
  SendState build() => const SendIdle();

  /// Returns to the beginning.
  void reset() => state = const SendIdle();

  /// Works out what a payment would cost, without proving it.
  ///
  /// Always run before [confirm]: the fee is not knowable without choosing the
  /// notes to spend, and somebody should see it before it is charged.
  Future<void> quote({required String to, required Zatoshi amount}) async {
    final account = ref.read(activeAccountProvider);
    if (account == null) {
      state = const SendFailed(
        ZakuraException(ZakuraErrorCode.noSuchAccount, 'no account selected'),
      );
      return;
    }

    state = const SendQuoting();
    try {
      final quote = await ref
          .read(walletProvider)
          .quote(account: account, to: to, amount: amount);
      state = SendQuoted(quote, to);
    } on ZakuraException catch (e) {
      state = SendFailed(e);
    }
  }

  /// Sends the payment that was quoted.
  ///
  /// Does nothing unless a quote is waiting, so a double tap cannot pay twice.
  Future<void> confirm({required String phrase}) async {
    final current = state;
    if (current is! SendQuoted) return;

    final account = ref.read(activeAccountProvider);
    if (account == null) return;

    state = const SendProving();
    try {
      // Proving and broadcasting are one call on the native side, because the
      // signature commits to the transaction and there is nothing useful to do
      // between them. The two states exist because the wait is long enough
      // that saying which part it is in is worth it.
      final wallet = ref.read(walletProvider);
      final future = wallet.send(
        account: account,
        to: current.recipient,
        amount: current.quote.amount,
        phrase: phrase,
      );
      state = const SendBroadcasting();
      state = SendSent(await future);
    } on ZakuraException catch (e) {
      state = SendFailed(e);
    }
  }
}
