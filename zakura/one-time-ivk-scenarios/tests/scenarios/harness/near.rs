//! NEAR Intents as the receiver directory's feed sees it: every address it was given,
//! when, and in which role.

use receiver_directory::{ReceiverBytes, snapshot::ProviderSet};
use zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
use zakura_receiver_crypto::Receiver;
use zcash_client_sqlite::wallet::one_time_ivk::swap::ProviderSeen;

use super::chain::{DAY, MINUTE, T0};

/// What NEAR was given an address as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// An X-to-ZEC payout address (an incoming key).
    Payout,
    /// A ZEC-to-X refund address (a refund key).
    Refund,
}

/// NEAR's view of the addresses wallets gave it, and the feed the directory reads.
pub struct Near {
    given: Vec<([u8; 43], i64, Role)>,
    /// When the directory's feed started reading NEAR.
    pub feed_started: i64,
    /// How long ago the feed's last complete read began.
    pub read_lag: i64,
    deposits: u32,
}

impl Default for Near {
    fn default() -> Self {
        Self {
            given: Vec::new(),
            feed_started: T0 - 30 * DAY,
            read_lag: MINUTE,
            deposits: 0,
        }
    }
}

impl Near {
    /// Records that NEAR was given `receiver` at `at`.
    pub fn give(&mut self, receiver: [u8; 43], at: i64, role: Role) {
        self.given.push((receiver, at, role));
    }

    /// Whether NEAR was ever given `receiver`, whatever its feed has read.
    pub fn was_given(&self, receiver: &[u8; 43]) -> bool {
        self.given.iter().any(|(r, _, _)| r == receiver)
    }

    /// A fresh deposit address on the source chain, for an incoming quote.
    pub fn deposit_address(&mut self) -> String {
        self.deposits += 1;
        format!("near-deposit-{:04}", self.deposits)
    }

    /// A fresh ZEC deposit address for a ZEC-to-X quote: a P2PKH address, as 1Click
    /// deposits are, encoded for the simulated network.
    pub fn zec_deposit_address(&mut self) -> String {
        self.deposits += 1;
        let hash = [u8::try_from(self.deposits % 251).expect("fits"); 20];
        zcash_keys::address::Address::Transparent(
            transparent::address::TransparentAddress::PublicKeyHash(hash),
        )
        .encode(&super::chain::network())
    }

    /// When the feed's last complete read began, as of `now`.
    pub fn read_until(&self, now: i64) -> i64 {
        now - self.read_lag
    }

    /// Whether `receiver` is in the seen set as of `now`: an address given after the feed
    /// started and before its last read, as a payout or refund address.
    pub fn seen(&self, receiver: &[u8; 43], now: i64) -> bool {
        let until = self.read_until(now);
        self.given
            .iter()
            .any(|(r, at, _)| r == receiver && *at >= self.feed_started && *at <= until)
    }

    /// Runs `f` with NEAR's seen set as a wallet fetches it at `now`, the device's clock.
    pub fn with_seen<T>(&self, now: i64, f: impl FnOnce(&ProviderSeen<'_>) -> T) -> T {
        let contains =
            |receivers: &[[u8; 43]]| receivers.iter().map(|r| self.seen(r, now)).collect();
        f(&ProviderSeen {
            since: self.feed_started,
            until: self.read_until(now),
            contains: &contains,
        })
    }

    /// The provider sets a publication made at `now` carries: `near-intents/recent`
    /// (addresses given in the 24 hours before the last read) and `near-intents/seen`
    /// (addresses given since the feed started), each holding payout and refund
    /// addresses.
    pub fn sets(&self, now: i64) -> Vec<ProviderSet> {
        let until = self.read_until(now);
        let window = RESTORE_WATCH_SECS;
        let recent = self
            .given
            .iter()
            .filter(|(_, at, _)| *at <= until && *at > until - window)
            .map(|(r, _, _)| Receiver::from_bytes(*r).expect("a valid receiver"));
        let seen = self
            .given
            .iter()
            .filter(|(_, at, _)| *at >= self.feed_started && *at <= until)
            .map(|(r, _, _)| Receiver::from_bytes(*r).expect("a valid receiver"));
        vec![
            ProviderSet {
                label: "near-intents/recent".into(),
                window_secs: Some(u64::try_from(window).expect("a positive window")),
                since_unix: self.feed_started,
                until_unix: until,
                receivers: dedup(recent),
            },
            ProviderSet {
                label: "near-intents/seen".into(),
                window_secs: None,
                since_unix: self.feed_started,
                until_unix: until,
                receivers: dedup(seen),
            },
        ]
    }
}

/// `receivers` without repeats, in first-seen order.
fn dedup(receivers: impl Iterator<Item = Receiver>) -> Vec<ReceiverBytes> {
    let mut out: Vec<ReceiverBytes> = Vec::new();
    for receiver in receivers {
        if !out.contains(receiver.as_bytes()) {
            out.push(*receiver.as_bytes());
        }
    }
    out
}
