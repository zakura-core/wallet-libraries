//! Per-batch cost of one-time recovery bookkeeping for accounts that hold no one-time keys
//! beyond their completed seed walk. `scripts/bench-one-time-batch-overhead.py` runs it.
use std::time::Instant;

use zcash_client_backend::data_api::{AccountBirthday, chain::ChainState};

use super::discovery::{drain, publication_at};
use super::*;

/// Timed repetitions of each measurement.
const ROUNDS: usize = 25;

/// The median of `samples`, in milliseconds.
fn median_ms(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

/// A scanned Ironwood wallet with `accounts` seed accounts. With `enabled`, each has
/// recovery on and its seed walk completed against an empty history, the steady state of
/// an account that never swapped. Otherwise none ever enabled it.
fn overhead_wallet(accounts: u8, enabled: bool) -> State {
    let mut st = restored_wallet();
    let anchor = tip(&st);
    let birthday = AccountBirthday::from_parts(ChainState::empty(anchor.height, anchor.hash), None);
    let mut ids = vec![st.test_account().unwrap().id()];
    for seed in 1..accounts {
        let seed = SecretVec::new(vec![seed; 32]);
        let (id, _) = st
            .wallet_mut()
            .create_account("bench", &seed, &birthday, None)
            .unwrap();
        ids.push(id);
    }
    if enabled {
        let publication = publication_at(&st, anchor.height);
        for account in ids {
            let db = st.wallet_mut().db_mut();
            db.set_one_time_recovery_enabled(account, true).unwrap();
            assert!(db.begin_one_time_recovery(account, publication, true).unwrap());
            drain(&mut st, account, publication);
        }
    }
    st
}

/// Prints the median wall time of scanning 1, 5 and 10 empty blocks, and of the
/// `after_blocks_stored` hook alone, for 1, 3 and 10 accounts with recovery never enabled
/// and enabled.
#[test]
#[ignore = "timing experiment; run with scripts/bench-one-time-batch-overhead.py"]
fn one_time_batch_overhead() {
    for accounts in [1, 3, 10] {
        for enabled in [false, true] {
            let mut st = overhead_wallet(accounts, enabled);
            let mut hook = vec![];
            for _ in 0..=ROUNDS {
                let start = Instant::now();
                st.wallet_mut()
                    .db_mut()
                    .transactionally(|db| {
                        queue::after_blocks_stored(
                            db.conn.0,
                            db.params,
                            &db.one_time_sessions(),
                            clock_now(),
                        )
                    })
                    .unwrap();
                hook.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            println!(
                "BENCH accounts={accounts} enabled={enabled} step=hook ms={:.4}",
                median_ms(hook)
            );
            for batch in [1, 5, 10] {
                let mut scans = vec![];
                for _ in 0..=ROUNDS {
                    let (first, _) = st.generate_empty_block();
                    for _ in 1..batch {
                        st.generate_empty_block();
                    }
                    let start = Instant::now();
                    st.scan_cached_blocks(first, batch);
                    scans.push(start.elapsed().as_secs_f64() * 1000.0);
                }
                println!(
                    "BENCH accounts={accounts} enabled={enabled} step=scan{batch} ms={:.4}",
                    median_ms(scans)
                );
            }
        }
    }
}
