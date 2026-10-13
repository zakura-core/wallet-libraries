//! The world a scenario runs in: the chain, NEAR, the receiver directory, and the
//! wallets that observe payments, plus what the scenario expects of them.

pub mod chain;
pub mod device;
pub mod directory;
pub mod near;

use std::collections::BTreeSet;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_one_time_ivk_scenarios::{Check, Class, Event, Metric, PaymentResult, zec};
use zcash_client_sqlite::wallet::one_time_ivk::swap::ReservationPolicy;
use zcash_protocol::consensus::BlockHeight;

use chain::{Chain, Mined, Payer, day_of};
use device::{Device, IncomingSwap, RefundSwap, SyncReport};
use near::Near;

/// What each send of [`Ctx::spend_one_time_notes`] pays a stranger.
const SPEND_PROBE: u64 = 10_000;
/// Sends [`Ctx::spend_one_time_notes`] makes at most. Each should spend at least one
/// one-time note, and no scenario applying it holds more than a dozen.
const MAX_SPENDS: usize = 16;

/// How a check's detail names the output `m`: its txid's first bytes and action index.
fn output_name(m: &Mined) -> String {
    let txid: String = m.txid.as_ref()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{txid}:{}", m.action_index)
}

/// A wallet in a scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dev(usize);

/// What a scenario expects one wallet to make of one payment.
struct Expectation {
    payment: String,
    key: String,
    mined: Mined,
    wallet: Dev,
    expected: Class,
    rationale: String,
}

/// A scenario's world and its findings.
pub struct Ctx {
    pub chain: Chain,
    pub near: Near,
    devices: Vec<Device>,
    timeline: Vec<Event>,
    expectations: Vec<Expectation>,
    checks: Vec<Check>,
    metrics: Vec<Metric>,
    /// Balances checked once every wallet has settled.
    final_balances: Vec<(Dev, u64)>,
    /// NEAR's own wallet, created on its first real payout.
    near_wallet: Option<Dev>,
    /// Wallet pairs whose balances must match once settled.
    same_balances: Vec<(Dev, Dev)>,
}

impl Ctx {
    /// A chain with only its activation block and a NEAR with no history.
    pub fn new() -> Self {
        Self {
            chain: Chain::new(),
            near: Near::default(),
            devices: Vec::new(),
            timeline: Vec::new(),
            expectations: Vec::new(),
            checks: Vec::new(),
            metrics: Vec::new(),
            final_balances: Vec::new(),
            same_balances: Vec::new(),
            near_wallet: None,
        }
    }

    /// Adds a timeline entry.
    pub fn log(&mut self, actor: &str, text: impl Into<String>) {
        self.timeline.push(Event {
            day: day_of(self.chain.now()),
            height: u32::from(self.chain.tip()),
            actor: actor.into(),
            text: text.into(),
        });
    }

    /// A new wallet for `seed` with its birthday at `birthday`.
    pub fn device(&mut self, name: &str, seed: [u8; 32], birthday: BlockHeight) -> Dev {
        self.device_with_skew(name, seed, birthday, 0)
    }

    /// [`Self::device`] on a device whose clock runs `skew` seconds ahead.
    pub fn device_with_skew(
        &mut self,
        name: &str,
        seed: [u8; 32],
        birthday: BlockHeight,
        skew: i64,
    ) -> Dev {
        let device = Device::new(name, &mut self.chain, seed, birthday, skew);
        self.devices.push(device);
        let text = format!("wallet created, birthday {}", u32::from(birthday));
        self.log(name, text);
        Dev(self.devices.len() - 1)
    }

    /// The wallet `dev`.
    pub fn dev(&mut self, dev: Dev) -> &mut Device {
        &mut self.devices[dev.0]
    }

    /// The wallet `dev`, read only.
    pub fn get(&self, dev: Dev) -> &Device {
        &self.devices[dev.0]
    }

    fn name(&self, dev: Dev) -> String {
        self.devices[dev.0].name.clone()
    }

    /// Syncs `dev` and logs what it found.
    pub fn sync(&mut self, dev: Dev) -> SyncReport {
        let rewinds = self.devices[dev.0].rewinds.len();
        let report = self.devices[dev.0].sync(&self.chain, &self.near);
        let name = self.name(dev);
        for (at, to) in self.devices[dev.0].rewinds[rewinds..].to_vec() {
            self.log(&name, format!("reorg: conflict at {at}, rewinds to {to}"));
        }
        self.log_sync(dev, &report);
        report
    }

    /// Runs only the scanning half of `dev`'s sync, returning the blocks it scanned.
    pub fn scan_only(&mut self, dev: Dev) -> u64 {
        self.devices[dev.0].scan(&self.chain)
    }

    /// Replaces the chain above `to`: the next mined blocks form the new branch.
    pub fn reorg(&mut self, to: BlockHeight) {
        let from = self.chain.tip();
        self.chain.rewind(to);
        self.log(
            "chain",
            format!(
                "reorg: blocks {}..={} are replaced; the new branch grows from {}",
                u32::from(to) + 1,
                u32::from(from),
                u32::from(to)
            ),
        );
    }

    /// Runs "Check swap history" on `dev`, then keeps syncing a block at a time, as
    /// Vizor's polling would, until a sync scans nothing new, defers nothing and leaves
    /// nothing pending, at most six more syncs. Logs each.
    pub fn check_swap_history(&mut self, dev: Dev) {
        let (queued, mut report) = self.devices[dev.0].check_swap_history(&self.chain, &self.near);
        let name = self.name(dev);
        self.log(
            &name,
            format!("runs Check swap history: {queued} closed keys queued"),
        );
        self.log_sync(dev, &report);
        for _ in 0..6 {
            let quiet = !report.pending && report.problems.is_empty() && report.scanned_blocks <= 1;
            if quiet {
                break;
            }
            self.chain.mine(1);
            report = self.devices[dev.0].continue_recheck(&self.chain, &self.near);
            self.log_sync(dev, &report);
        }
        let quiet = !report.pending && report.problems.is_empty() && report.scanned_blocks <= 1;
        if !quiet {
            self.log(&name, "still busy after the recheck's syncs");
        }
    }

    /// Keeps every wallet syncing a block at a time, as Vizor's polling would, until each
    /// is quiet: nothing pending, deferred or left to scan. At most six rounds per wallet.
    /// Runs after every scenario so a find that needs another sync (a spend-history replay,
    /// a sweep's rescan) counts.
    pub fn settle(&mut self) {
        // Let the directory, which publishes two blocks behind the tip, catch up.
        self.chain.mine(3);
        for i in 0..self.devices.len() {
            let dev = Dev(i);
            for round in 0..40 {
                let report = self.devices[i].sync(&self.chain, &self.near);
                let quiet =
                    !report.pending && report.problems.is_empty() && report.scanned_blocks <= 1;
                if report.found_live + report.found_by_sweep > 0
                    || !report.problems.is_empty()
                    || round == 0 && report.scanned_blocks > 1
                {
                    self.log_sync(dev, &report);
                }
                if quiet {
                    break;
                }
                self.chain.mine(1);
            }
        }
    }

    /// Logs a sync's outcome and any sweep problems.
    fn log_sync(&mut self, dev: Dev, report: &SyncReport) {
        let balance = self.devices[dev.0].balance();
        let text = format!(
            "syncs: scanned {} blocks, {} found live, {} by sweep, {} sweeps finished, {} lookups, {} keys open, balance {}{}",
            report.scanned_blocks,
            report.found_live,
            report.found_by_sweep,
            report.sweeps_finished,
            report.lookups,
            report.open_keys,
            zec(balance),
            if report.pending {
                ", history pending"
            } else {
                ""
            }
        );
        let name = self.name(dev);
        self.log(&name, text);
        for problem in &report.problems {
            self.log(&name, problem.clone());
        }
    }

    /// Quotes an incoming swap on `dev` with a deposit deadline `deadline_in` seconds out.
    /// Like the app, it answers a refusal by catching up and trying again, at most three
    /// times: `Gap` by running the restore sweeps it waits for, `Coverage` by syncing.
    pub fn quote_incoming(
        &mut self,
        dev: Dev,
        deadline_in: i64,
    ) -> Result<IncomingSwap, ReservationPolicy> {
        let name = self.name(dev);
        let mut attempt = 0;
        loop {
            let quoted =
                self.devices[dev.0].quote_incoming(&self.chain, &mut self.near, deadline_in);
            match quoted {
                Ok(swap) => {
                    let text = format!(
                        "quotes an incoming swap on {}, deadline in {} min",
                        swap.label(),
                        deadline_in / 60
                    );
                    self.log(&name, text);
                    return Ok(swap);
                }
                Err(policy)
                    if attempt < 3
                        && matches!(
                            policy,
                            ReservationPolicy::Gap | ReservationPolicy::Coverage
                        ) =>
                {
                    attempt += 1;
                    self.log(
                        &name,
                        format!("quote refused ({policy:?}), catching up and retrying"),
                    );
                    self.sync(dev);
                }
                Err(policy) => {
                    self.log(&name, format!("quote refused: {policy:?}"));
                    return Err(policy);
                }
            }
        }
    }

    /// Reserves an incoming address on `dev` without sending a quote.
    pub fn prepare_incoming(&mut self, dev: Dev) -> Result<u64, ReservationPolicy> {
        self.devices[dev.0].prepare_incoming(&self.chain, &self.near)
    }

    /// Saves a quote request on `dev` for the reservation at `index`.
    pub fn begin_incoming(
        &mut self,
        dev: Dev,
        index: u64,
        deadline_in: i64,
    ) -> Result<String, ReservationPolicy> {
        self.devices[dev.0].begin_incoming(&self.chain, index, deadline_in)
    }

    /// Restarts the app on `dev`: its wallet database closes and opens again.
    pub fn restart(&mut self, dev: Dev) {
        self.devices[dev.0].reopen();
        let name = self.name(dev);
        self.log(&name, "the app restarts and reopens its wallet database");
    }

    /// Starts `dev`'s accepted quote `request`, returning the deposit instructions the
    /// store kept for it.
    pub fn start_incoming(
        &mut self,
        dev: Dev,
        request: &str,
    ) -> Result<zcash_client_sqlite::wallet::one_time_ivk::swap::ReceiveDeposit, ReservationPolicy>
    {
        self.devices[dev.0].start_incoming(&self.chain, request)
    }

    /// Records how `dev`'s quote request ended.
    pub fn finish_incoming(
        &mut self,
        dev: Dev,
        request: &str,
        outcome: &zcash_client_sqlite::wallet::one_time_ivk::swap::OperationOutcome,
    ) {
        self.devices[dev.0].finish_incoming(request, outcome);
    }

    /// Quotes a ZEC-to-X swap on `dev`, reserving a refund key for it.
    pub fn quote_refund(
        &mut self,
        dev: Dev,
        deadline_in: i64,
    ) -> Result<RefundSwap, ReservationPolicy> {
        let quoted = self.devices[dev.0].quote_refund(&self.chain, &mut self.near, deadline_in);
        let name = self.name(dev);
        match &quoted {
            Ok(swap) => {
                let text = format!(
                    "quotes a ZEC-to-X swap with refund key {}, deposit {}, deadline in {} min",
                    swap.label(),
                    swap.deposit,
                    deadline_in / 60
                );
                self.log(&name, text);
            }
            Err(policy) => self.log(&name, format!("refund quote refused: {policy:?}")),
        }
        quoted
    }

    /// Funds a ZEC-to-X swap from `dev`'s Ironwood notes and mines the transaction.
    /// Returns the height and the transaction, which a reorg test can mine again.
    pub fn fund_refund(
        &mut self,
        dev: Dev,
        swap: &RefundSwap,
        amount: u64,
    ) -> (BlockHeight, zcash_primitives::transaction::Transaction) {
        let tx = self.devices[dev.0].fund_refund(swap, amount);
        let height = self.chain.mine_tx(&tx);
        let name = self.name(dev);
        self.log(
            &name,
            format!(
                "funds the deposit with {} (refund memo for {} on Ironwood change), mined at {}",
                zec(amount),
                swap.label(),
                u32::from(height)
            ),
        );
        (height, tx)
    }

    /// Records a NEAR status for a ZEC-to-X swap on `dev`.
    pub fn observe_refund(
        &mut self,
        dev: Dev,
        swap: &RefundSwap,
        status: &str,
        refunded: Option<u64>,
    ) {
        let matched = self.devices[dev.0].observe_refund(&self.chain, swap, status, refunded);
        let name = self.name(dev);
        let amount = refunded.map_or(String::new(), |v| format!(", refundedAmount {}", zec(v)));
        self.log(
            &name,
            format!(
                "records NEAR status {status} for {}{amount}{}",
                swap.label(),
                if matched { "" } else { " (no match)" }
            ),
        );
    }

    /// Records a NEAR status for an incoming swap on `dev`.
    pub fn observe_incoming(
        &mut self,
        dev: Dev,
        swap: &IncomingSwap,
        status: &str,
        amount_out: Option<u64>,
    ) {
        let matched = self.devices[dev.0].observe_incoming(&self.chain, swap, status, amount_out);
        let name = self.name(dev);
        let amount = amount_out.map_or(String::new(), |v| format!(", amountOut {}", zec(v)));
        self.log(
            &name,
            format!(
                "records NEAR status {status} for {}{amount}{}",
                swap.label(),
                if matched { "" } else { " (no match)" }
            ),
        );
    }

    /// Mines one block paying `value` to `fvk`'s address, from `payer`.
    pub fn pay(
        &mut self,
        label: &str,
        key: &str,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> Mined {
        self.pay_many(label, &[(key, fvk, value)], payer).remove(0)
    }

    /// Mines one block with one transaction paying every output, from `payer`.
    pub fn pay_many(
        &mut self,
        label: &str,
        outputs: &[(&str, &FullViewingKey, u64)],
        payer: Payer,
    ) -> Vec<Mined> {
        let pairs: Vec<_> = outputs
            .iter()
            .map(|(_, fvk, v)| ((*fvk).clone(), *v))
            .collect();
        let mined = self.chain.pay(&pairs, payer);
        let to = outputs
            .iter()
            .map(|(key, _, v)| format!("{} to {key}", zec(*v)))
            .collect::<Vec<_>>()
            .join(", ");
        self.log("chain", format!("{label}: {} pays {to}", payer.label()));
        mined
    }

    /// NEAR's wallet, funded with 1,000 ZEC of Ironwood notes on first use. It pays with
    /// real signed transactions, which a reorg can return to the chain.
    fn near_wallet(&mut self) -> Dev {
        if let Some(dev) = self.near_wallet {
            return dev;
        }
        let birthday = self.chain.tip() + 1;
        let device = Device::new("NEAR", &mut self.chain, [0x99; 32], birthday, 0);
        self.devices.push(device);
        let dev = Dev(self.devices.len() - 1);
        let fvk = self.devices[dev.0].fvk.clone();
        self.chain.pay(&[(fvk, 1_000 * chain::ZEC)], Payer::Wallet);
        self.chain.mine(10);
        self.devices[dev.0].scan(&self.chain);
        self.near_wallet = Some(dev);
        dev
    }

    /// Mines a real transaction from NEAR's wallet paying `value` to `fvk`'s address, with
    /// the zero OVK when `payer` is NEAR, and returns the payment. Returns the transaction
    /// too, so a reorg test can mine it again.
    pub fn pay_tx(
        &mut self,
        label: &str,
        key: &str,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> (Mined, zcash_primitives::transaction::Transaction) {
        let near = self.near_wallet();
        let ovk = match payer {
            Payer::Near => {
                zcash_client_backend::wallet::OvkPolicy::custom_from_common_bytes(&[0; 32])
            }
            Payer::Wallet => zcash_client_backend::wallet::OvkPolicy::Sender,
        };
        let to = fvk.address_at(0u32, orchard::keys::Scope::External);
        let tx = self.devices[near.0].send_to(to, value, ovk);
        let height = self.chain.mine_tx(&tx);
        let mined = self.chain.record_payment(height, fvk, value, payer);
        self.devices[near.0].scan(&self.chain);
        self.log(
            "chain",
            format!(
                "{label}: {} pays {} to {key} in a signed transaction",
                payer.label(),
                zec(value)
            ),
        );
        (mined, tx)
    }

    /// Builds and signs a payment from NEAR's wallet without mining it.
    pub fn near_tx(
        &mut self,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> zcash_primitives::transaction::Transaction {
        let near = self.near_wallet();
        let ovk = match payer {
            Payer::Near => {
                zcash_client_backend::wallet::OvkPolicy::custom_from_common_bytes(&[0; 32])
            }
            Payer::Wallet => zcash_client_backend::wallet::OvkPolicy::Sender,
        };
        let to = fvk.address_at(0u32, orchard::keys::Scope::External);
        self.devices[near.0].send_to(to, value, ovk)
    }

    /// Shows `tx` to `dev` in the mempool.
    pub fn mempool(
        &mut self,
        dev: Dev,
        label: &str,
        tx: &zcash_primitives::transaction::Transaction,
    ) {
        let found = self.devices[dev.0].receive_mempool(tx);
        let balance = self.devices[dev.0].balance();
        let name = self.name(dev);
        self.log(
            &name,
            format!(
                "sees {label} in the mempool: {found} found, balance {}",
                zec(balance)
            ),
        );
    }

    /// Mines `tx` and records the payment it makes to `fvk`.
    pub fn mine_payment(
        &mut self,
        label: &str,
        tx: &zcash_primitives::transaction::Transaction,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> Mined {
        let height = self.chain.mine_tx(tx);
        self.log(
            "chain",
            format!("{label} is mined at {}", u32::from(height)),
        );
        self.chain.record_payment(height, fvk, value, payer)
    }

    /// Mines `tx` again, as after a reorg that returned it to the mempool.
    pub fn remine(
        &mut self,
        label: &str,
        tx: &zcash_primitives::transaction::Transaction,
        fvk: &FullViewingKey,
        value: u64,
        payer: Payer,
    ) -> Mined {
        let height = self.chain.mine_tx(tx);
        self.log(
            "chain",
            format!(
                "{label}: the same transaction is mined again at {}",
                u32::from(height)
            ),
        );
        self.chain.record_payment(height, fvk, value, payer)
    }

    /// Mines empty blocks until `secs` have passed.
    pub fn wait(&mut self, secs: i64) {
        self.chain.wait(secs);
    }

    /// Mines `n` empty blocks.
    pub fn mine(&mut self, n: u32) {
        self.chain.mine(n);
    }

    /// Expects `dev` to make `class` of the payment `mined`, for `rationale`.
    pub fn expect(
        &mut self,
        dev: Dev,
        payment: &str,
        key: &str,
        mined: &Mined,
        expected: Class,
        rationale: impl Into<String>,
    ) {
        self.expectations.push(Expectation {
            payment: payment.into(),
            key: key.into(),
            mined: mined.clone(),
            wallet: dev,
            expected,
            rationale: rationale.into(),
        });
    }

    /// Records a check.
    pub fn check(&mut self, name: impl Into<String>, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            ok,
            detail: detail.into(),
            documented_gap: false,
        });
    }

    /// Records a documented weakness: `ok` is whether the wallet behaved as the library
    /// documents, and `detail` names the documentation.
    pub fn documented_gap(&mut self, name: impl Into<String>, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            ok,
            detail: detail.into(),
            documented_gap: true,
        });
    }

    /// Records a measurement.
    pub fn metric(&mut self, name: impl Into<String>, value: f64, unit: &str) {
        self.metrics.push(Metric {
            name: name.into(),
            value,
            unit: unit.into(),
        });
    }

    /// Checks, once every wallet has settled, that `dev`'s balance is `expected` zatoshis.
    pub fn check_balance(&mut self, dev: Dev, expected: u64) {
        self.final_balances.push((dev, expected));
    }

    /// Checks, once every wallet has settled, that `a` and `b` hold the same balance.
    pub fn check_same_balance(&mut self, a: Dev, b: Dev) {
        self.same_balances.push((a, b));
    }

    /// Checks that `dev` holds the output `mined` where the chain has it now: at its
    /// block and tree position.
    pub fn check_receipt(&mut self, dev: Dev, payment: &str, mined: &Mined) {
        let receipt = self.devices[dev.0].receipt(mined.id());
        let name = self.name(dev);
        let (height, position) = (u32::from(mined.height), mined.position);
        let ok = receipt
            .as_ref()
            .is_some_and(|r| r.mined_height == Some(height) && r.position == Some(position));
        self.check(
            format!("{name} holds {payment} at height {height}, tree position {position}"),
            ok,
            format!("{receipt:?}"),
        );
    }

    /// Checks whether `dev`'s key `label` is open.
    pub fn check_key_open(&mut self, dev: Dev, label: &str, open: bool) {
        let state = self.devices[dev.0]
            .keys()
            .into_iter()
            .find(|k| k.label() == label);
        let name = self.name(dev);
        let actual = state.as_ref().is_some_and(|k| k.open());
        let detail = match &state {
            Some(k) => format!(
                "active_from {:?}, closed_at {:?}, used {}",
                k.active_from, k.closed_at, k.used
            ),
            None => "no such key".into(),
        };
        self.check(
            format!("{name} {label} is {}", if open { "open" } else { "closed" }),
            actual == open,
            detail,
        );
    }

    /// Settles every wallet and judges the balance checks registered so far, then spends
    /// every one-time-key note `dev` holds through ordinary sends to a stranger, at most
    /// [`MAX_SPENDS`] of them. Each send must be one consensus accepts
    /// ([`Chain::accepts`]) before it is mined and `dev` syncs.
    ///
    /// The notes it must spend are the outputs the chain holds that pay a one-time
    /// receiver the harness derived for `dev`'s seed, not what the wallet labels as
    /// one-time notes. Each needs a wallet note row, found by txid and action index,
    /// whose nullifier ends up on chain. A wrong stored nullifier never does, since the
    /// proof binds the revealed one to the note.
    /// Records one check: every such nullifier is on chain, every send was accepted, the
    /// wallet holds no unspent one-time value, and its balance fell by exactly the value
    /// sent plus fees.
    pub fn spend_one_time_notes(&mut self, dev: Dev) {
        self.settle();
        self.judge_balances();
        let name = self.name(dev);
        let stranger = FullViewingKey::from(&SpendingKey::from_bytes([0xf5; 32]).expect("a key"))
            .address_at(0u32, Scope::External);
        let seed = self.devices[dev.0].fvk.to_bytes();
        let receivers: BTreeSet<[u8; 43]> = self
            .devices
            .iter()
            .filter(|device| device.fvk.to_bytes() == seed)
            .flat_map(Device::derived_receivers)
            .collect();
        let payments: Vec<Mined> = self
            .chain
            .mined()
            .iter()
            .filter(|m| receivers.contains(&m.receiver))
            .cloned()
            .collect();
        let mut nullifiers = Vec::new();
        let mut unknown = Vec::new();
        for m in &payments {
            match self.devices[dev.0]
                .receipt(m.id())
                .and_then(|r| r.nullifier)
            {
                Some(nf) => nullifiers.push(nf),
                None => unknown.push(output_name(m)),
            }
        }
        let unspent = |chain: &Chain| {
            let revealed = chain.nullifiers();
            nullifiers
                .iter()
                .filter(|nf| !revealed.contains(*nf))
                .count()
        };
        let (value_before, balance_before) = {
            let device = &self.devices[dev.0];
            (device.unspent_one_time_value(), device.balance())
        };
        let mut paid = 0u64;
        let mut sends = Vec::new();
        let mut problem = None;
        for _ in 0..MAX_SPENDS {
            let done =
                unspent(&self.chain) == 0 && self.devices[dev.0].unspent_one_time_value() == 0;
            if done {
                break;
            }
            let tx = match self.devices[dev.0].send_ordinary(stranger, SPEND_PROBE) {
                Ok(tx) => tx,
                Err(why) => {
                    problem = Some(format!("{name} cannot send: {why}"));
                    break;
                }
            };
            let fee = tx.fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None));
            let Some(fee) = fee.ok().flatten().map(|fee| fee.into_u64()) else {
                problem = Some(format!("{} pays no readable fee", tx.txid()));
                break;
            };
            let accepted = match self.chain.accepts(&tx) {
                Ok(accepted) => accepted,
                Err(why) => {
                    problem = Some(format!("consensus would reject {}: {why}", tx.txid()));
                    break;
                }
            };
            let height = self.chain.mine_tx(&tx);
            self.log(
                &name,
                format!(
                    "sends {} to a stranger, fee {}: {} Ironwood actions verify, anchored at {}, mined at {}",
                    zec(SPEND_PROBE),
                    zec(fee),
                    accepted.actions,
                    u32::from(accepted.anchor_height),
                    u32::from(height)
                ),
            );
            paid += SPEND_PROBE + fee;
            sends.push(u32::from(height));
            self.sync(dev);
        }
        let left = unspent(&self.chain);
        let device = &self.devices[dev.0];
        let (value_after, balance_after) = (device.unspent_one_time_value(), device.balance());
        let fell = balance_before.checked_sub(balance_after);
        let ok = problem.is_none()
            && !payments.is_empty()
            && unknown.is_empty()
            && left == 0
            && value_after == 0
            && fell == Some(paid);
        let mut detail = format!(
            "{} payments to one-time receivers, {} of their nullifiers on chain, no note or nullifier for {unknown:?}; {} sends mined at {sends:?}; one-time value {} before, {} after; balance {} before, {} after, sent plus fees {}",
            payments.len(),
            nullifiers.len() - left,
            sends.len(),
            zec(value_before),
            zec(value_after),
            zec(balance_before),
            zec(balance_after),
            zec(paid)
        );
        if let Some(problem) = problem {
            detail = format!("{problem}; {detail}");
        }
        self.check(
            format!("every one-time note {name} found is spendable"),
            ok,
            detail,
        );
    }

    /// Judges and clears the balance checks registered with [`Self::check_balance`] and
    /// [`Self::check_same_balance`].
    fn judge_balances(&mut self) {
        for (dev, expected) in std::mem::take(&mut self.final_balances) {
            let actual = self.devices[dev.0].balance();
            let name = self.name(dev);
            self.check(
                format!("{name} final balance"),
                actual == expected,
                format!("{} (expected {})", zec(actual), zec(expected)),
            );
        }
        for (a, b) in std::mem::take(&mut self.same_balances) {
            let (x, y) = (self.devices[a.0].balance(), self.devices[b.0].balance());
            let (na, nb) = (self.name(a), self.name(b));
            self.check(
                format!("{nb} ends with {na}'s balance"),
                x == y,
                format!("{na} {}, {nb} {}", zec(x), zec(y)),
            );
        }
    }

    /// Payment observations, checks, metrics and the timeline.
    pub fn finish(mut self) -> (Vec<Event>, Vec<PaymentResult>, Vec<Check>, Vec<Metric>) {
        self.judge_balances();
        let mut payments = Vec::new();
        for e in &self.expectations {
            let device = &self.devices[e.wallet.0];
            let actual = device
                .found(e.mined.id())
                .map_or(Class::Missed, |found| found.class);
            payments.push(PaymentResult {
                payment: e.payment.clone(),
                key: e.key.clone(),
                wallet: device.name.clone(),
                value: e.mined.value,
                height: u32::from(e.mined.height),
                day: day_of(chain::block_time(e.mined.height)),
                payer: e.mined.payer.label().into(),
                expected: e.expected,
                actual,
                rationale: e.rationale.clone(),
            });
        }
        // NEAR's wallet only signs payouts, so its numbers would be noise.
        let near = self.near_wallet.map(|dev| dev.0);
        for (_, device) in self
            .devices
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != near)
        {
            self.metrics.push(Metric {
                name: format!("{} directory lookups", device.name),
                value: device.lookups as f64,
                unit: "lookups".into(),
            });
            self.metrics.push(Metric {
                name: format!("{} syncs", device.name),
                value: f64::from(device.syncs),
                unit: "syncs".into(),
            });
            self.metrics.push(Metric {
                name: format!("{} blocks scanned", device.name),
                value: device.scanned_blocks as f64,
                unit: "blocks".into(),
            });
            if device.bytes_received > 0 {
                self.metrics.push(Metric {
                    name: format!("{} directory bytes received", device.name),
                    value: device.bytes_received as f64,
                    unit: "bytes".into(),
                });
                self.metrics.push(Metric {
                    name: format!("{} directory bytes sent", device.name),
                    value: device.bytes_sent as f64,
                    unit: "bytes".into(),
                });
            }
            if device.row_files > 0 {
                self.metrics.push(Metric {
                    name: format!("{} row-file downloads", device.name),
                    value: device.row_files as f64,
                    unit: "files".into(),
                });
            }
        }
        self.metrics.push(Metric {
            name: "chain height".into(),
            value: f64::from(u32::from(self.chain.tip())),
            unit: "blocks".into(),
        });
        (self.timeline, payments, self.checks, self.metrics)
    }
}
