//! The world a scenario runs in: the chain, NEAR, the receiver directory, and the
//! wallets that observe payments, plus what the scenario expects of them.

pub mod chain;
pub mod device;
pub mod directory;
pub mod near;

use orchard::keys::FullViewingKey;
use zakura_one_time_ivk_scenarios::{Check, Class, Event, Metric, PaymentResult, zec};
use zcash_client_sqlite::wallet::one_time_ivk::swap::ReservationPolicy;
use zcash_protocol::consensus::BlockHeight;

use chain::{Chain, Mined, Payer, day_of};
use device::{Device, IncomingSwap, RefundSwap, SyncReport};
use near::Near;

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
        let report = self.devices[dev.0].sync(&self.chain, &self.near);
        self.log_sync(dev, &report);
        report
    }

    /// Runs "Check swap history" on `dev`, then keeps syncing a block at a time, as
    /// Vizor's polling would, until a sync scans nothing new, defers nothing and leaves
    /// nothing pending, at most six more syncs. Logs each.
    pub fn check_swap_history(&mut self, dev: Dev) {
        let (queued, mut report) = self.devices[dev.0].check_swap_history(&self.chain, &self.near);
        let name = self.name(dev);
        self.log(&name, format!("runs Check swap history: {queued} closed keys queued"));
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
        for i in 0..self.devices.len() {
            let dev = Dev(i);
            for round in 0..6 {
                let report = self.devices[i].sync(&self.chain, &self.near);
                let quiet = !report.pending && report.problems.is_empty() && report.scanned_blocks <= 1;
                if report.found_live + report.found_by_sweep > 0 || !report.problems.is_empty() || round == 0 && report.scanned_blocks > 1 {
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
            if report.pending { ", history pending" } else { "" }
        );
        let name = self.name(dev);
        self.log(&name, text);
        for problem in &report.problems {
            self.log(&name, problem.clone());
        }
    }

    /// Quotes an incoming swap on `dev` with a deposit deadline `deadline_in` seconds out.
    pub fn quote_incoming(
        &mut self,
        dev: Dev,
        deadline_in: i64,
    ) -> Result<IncomingSwap, ReservationPolicy> {
        let quoted = self.devices[dev.0].quote_incoming(&self.chain, &mut self.near, deadline_in);
        let name = self.name(dev);
        match &quoted {
            Ok(swap) => {
                let text = format!(
                    "quotes an incoming swap on {}, deadline in {} min",
                    swap.label(),
                    deadline_in / 60
                );
                self.log(&name, text);
            }
            Err(policy) => self.log(&name, format!("quote refused: {policy:?}")),
        }
        quoted
    }

    /// Quotes a ZEC-to-X swap on `dev`, reserving a refund key for it.
    pub fn quote_refund(&mut self, dev: Dev, deadline_in: i64) -> Result<RefundSwap, ReservationPolicy> {
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
    pub fn fund_refund(&mut self, dev: Dev, swap: &RefundSwap, amount: u64) -> BlockHeight {
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
        height
    }

    /// Records a NEAR status for a ZEC-to-X swap on `dev`.
    pub fn observe_refund(&mut self, dev: Dev, swap: &RefundSwap, status: &str, refunded: Option<u64>) {
        let matched = self.devices[dev.0].observe_refund(&self.chain, swap, status, refunded);
        let name = self.name(dev);
        let amount = refunded.map_or(String::new(), |v| format!(", refundedAmount {}", zec(v)));
        self.log(
            &name,
            format!("records NEAR status {status} for {}{amount}{}", swap.label(), if matched { "" } else { " (no match)" }),
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
        let matched =
            self.devices[dev.0].observe_incoming(&self.chain, swap, status, amount_out);
        let name = self.name(dev);
        let amount = amount_out.map_or(String::new(), |v| format!(", amountOut {}", zec(v)));
        self.log(
            &name,
            format!("records NEAR status {status} for {}{amount}{}", swap.label(), if matched { "" } else { " (no match)" }),
        );
    }

    /// Mines one block paying `value` to `fvk`'s address, from `payer`.
    pub fn pay(&mut self, label: &str, key: &str, fvk: &FullViewingKey, value: u64, payer: Payer) -> Mined {
        self.pay_many(label, &[(key, fvk, value)], payer).remove(0)
    }

    /// Mines one block with one transaction paying every output, from `payer`.
    pub fn pay_many(
        &mut self,
        label: &str,
        outputs: &[(&str, &FullViewingKey, u64)],
        payer: Payer,
    ) -> Vec<Mined> {
        let pairs: Vec<_> = outputs.iter().map(|(_, fvk, v)| ((*fvk).clone(), *v)).collect();
        let mined = self.chain.pay(&pairs, payer);
        let to = outputs
            .iter()
            .map(|(key, _, v)| format!("{} to {key}", zec(*v)))
            .collect::<Vec<_>>()
            .join(", ");
        self.log("chain", format!("{label}: {} pays {to}", payer.label()));
        mined
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

    /// Payment observations, checks, metrics and the timeline.
    pub fn finish(mut self) -> (Vec<Event>, Vec<PaymentResult>, Vec<Check>, Vec<Metric>) {
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
        for device in &self.devices {
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
        }
        self.metrics.push(Metric {
            name: "chain height".into(),
            value: f64::from(u32::from(self.chain.tip())),
            unit: "blocks".into(),
        });
        (self.timeline, payments, self.checks, self.metrics)
    }
}
