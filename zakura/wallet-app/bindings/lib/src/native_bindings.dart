import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;
import 'package:zakura_client/zakura_client.dart';

import 'rust/api.dart' as rust;
import 'rust/api/types.dart' as rust;
import 'rust/frb_generated.dart';

/// The wallet, backed by the Rust core.
///
/// This is the only file in the project that touches generated code. That is
/// deliberate: everything above it is written against [ZakuraBindings], so
/// regenerating the bridge can change types here and nowhere else. The wallet
/// this design replaces typed its widgets against generated structs directly,
/// which made every regeneration a change to the interface.
///
/// Its whole job is translation — generated types to plain models, and
/// generated errors to [ZakuraException].
class NativeBindings implements ZakuraBindings {
  /// Loads the native library.
  ///
  /// Call once, before anything else. Repeated calls are harmless.
  ///
  /// [libraryPath] overrides where the library is found. In an application it
  /// should be left alone: Cargokit puts the library where the platform's
  /// loader already looks. It exists for tests and command-line tools, which
  /// run on the Dart VM with no plugin registrant to have done that.
  static Future<NativeBindings> load({String? libraryPath}) async {
    await RustLib.init(
      externalLibrary: libraryPath == null
          ? null
          : ExternalLibrary.open(libraryPath),
    );
    return const NativeBindings();
  }

  /// Creates the bindings. [load] must have run first.
  const NativeBindings();

  /// Runs [body], turning a generated error into a [ZakuraException].
  ///
  /// Anything that is not an [rust.ApiError] is a failure of the bridge itself
  /// rather than of the wallet, and is reported as such rather than being
  /// squeezed into a code that would misdescribe it.
  static Future<T> _translate<T>(Future<T> Function() body) async {
    try {
      return await body();
    } on rust.ApiError catch (e) {
      throw ZakuraException(ZakuraErrorCode.fromValue(e.code), e.message);
    } on Object catch (e) {
      throw ZakuraException(ZakuraErrorCode.unknown, e.toString());
    }
  }

  @override
  Future<String> generateMnemonic() => _translate(rust.generateMnemonic);

  @override
  Future<bool> validateMnemonic(String phrase) =>
      _translate(() => rust.validateMnemonic(phrase: phrase));

  @override
  Future<void> open({
    required String directory,
    required String lightwalletdUrl,
    required bool mainnet,
  }) =>
      _translate(
        () => rust.open(
          directory: directory,
          lightwalletdUrl: lightwalletdUrl,
          mainnet: mainnet,
        ),
      );

  @override
  Future<int> createAccount({
    required String phrase,
    required int birthday,
  }) =>
      _translate(
        () => rust.createAccount(phrase: phrase, birthday: birthday),
      );

  @override
  Future<List<Account>> accounts() => _translate(() async {
        final accounts = await rust.accounts();
        return [
          for (final a in accounts)
            Account(
              id: a.id,
              birthday: a.birthday,
              canSpend: a.canSpend,
              hdAccountIndex: a.hdAccountIndex,
            ),
        ];
      });

  @override
  Future<Balance> balance(int account) => _translate(() async {
        final b = await rust.balance(account: account);
        return Balance(
          spendable: Zatoshi(b.spendable.toInt()),
          pending: Zatoshi(b.pending.toInt()),
          spentUnconfirmed: Zatoshi(b.spentUnconfirmed.toInt()),
          transparent: Zatoshi(b.transparent.toInt()),
        );
      });

  @override
  Future<List<HistoryEntry>> history(int account, int limit) =>
      _translate(() async {
        final entries = await rust.history(account: account, limit: limit);
        return [
          for (final e in entries)
            HistoryEntry(
              txid: e.txid,
              minedHeight: e.minedHeight,
              received: Zatoshi(e.received.toInt()),
              spent: Zatoshi(e.spent.toInt()),
              isChangeOnly: e.isChangeOnly,
            ),
        ];
      });

  @override
  Future<String> nextAddress(int account) =>
      _translate(() => rust.nextAddress(account: account));

  @override
  Future<void> startSync() => _translate(rust.startSync);

  @override
  Future<void> stopSync() => _translate(rust.stopSync);

  @override
  Future<SyncProgress> progress() => _translate(() async {
        final p = await rust.progress();
        return SyncProgress(
          phase: switch (p.phase) {
            rust.ApiSyncPhase.bootstrapping => SyncPhase.bootstrapping,
            rust.ApiSyncPhase.recovering => SyncPhase.recovering,
            rust.ApiSyncPhase.tracking => SyncPhase.tracking,
            rust.ApiSyncPhase.idle => SyncPhase.idle,
            rust.ApiSyncPhase.stopped => SyncPhase.stopped,
          },
          fraction: p.fraction,
          tip: p.tip,
          scannedTo: p.scannedTo,
          blocksRemaining: p.blocksRemaining.toInt(),
          failed: p.failed,
        );
      });

  @override
  Future<SpendQuote> quote({
    required int account,
    required String to,
    required int amount,
  }) =>
      _translate(() async {
        final q = await rust.quote(
          account: account,
          to: to,
          amount: BigInt.from(amount),
        );
        return SpendQuote(
          amount: Zatoshi(q.amount.toInt()),
          fee: Zatoshi(q.fee.toInt()),
          change: Zatoshi(q.change.toInt()),
          inputs: q.inputs,
          crossing: q.crossing,
        );
      });

  @override
  Future<SendReceipt> send({
    required int account,
    required String to,
    required int amount,
    required String phrase,
  }) =>
      _translate(() async {
        final r = await rust.send(
          account: account,
          to: to,
          amount: BigInt.from(amount),
          phrase: phrase,
        );
        return SendReceipt(
          txid: r.txid,
          serverResponse: r.serverResponse,
        );
      });

  @override
  Future<String?> syncFailure() => _translate(rust.syncFailure);

  @override
  Future<void> close() => _translate(rust.close);
}
