//! Per-batch one-time recovery bookkeeping: its cost for accounts that hold no one-time keys
//! beyond their completed seed walk, which `scripts/bench-one-time-batch-overhead.py`
//! measures, and the work it must still do on time.
use std::time::Instant;

use zcash_client_backend::data_api::{AccountBirthday, chain::ChainState};

use super::discovery::{
    drain, one_time_notes, pay_candidate, publication_at, queue_late, send_witness,
};
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
            assert!(
                db.begin_one_time_recovery(account, publication, true)
                    .unwrap()
            );
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

/// A batch with no witnessed candidate skips admission's monitoring fence, but the batch that
/// makes a waiting payment admissible still admits it, and widens the receive window past
/// the paid index in that same batch.
#[test]
fn quiet_batches_do_not_delay_admission_or_the_window() {
    let mut st = scanned_wallet();
    let receive_end = |st: &State| -> Vec<u8> {
        value(
            st.wallet().conn(),
            "SELECT receive_end FROM ironwood_one_time_recovery",
            [],
        )
    };
    st.generate_and_scan_empty_blocks(2);
    let key = KeyId::new(Purpose::Receive, 3);
    let candidate = pay_candidate(&mut st, key);
    queue_late(&mut st, key, &candidate);
    // Admission waits on spend coverage of the paying block until a rescan covers it.
    let tip = u32::from(candidate.height);
    for sql in [
        "UPDATE ironwood_journal_coverage SET end_height = ?1 WHERE end_height > ?1",
        "DELETE FROM ironwood_spend_journal_nullifiers WHERE block_height = ?1",
        "DELETE FROM ironwood_spend_journal WHERE block_height = ?1",
    ] {
        exec(st.wallet().conn(), sql, [tip]);
    }
    send_witness(&mut st, key, &candidate);
    assert!(one_time_notes(&st).is_empty(), "admission waits");
    assert_eq!(receive_end(&st), 4u64.to_be_bytes());
    st.scan_cached_blocks(candidate.height, 1);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(receive_end(&st), 8u64.to_be_bytes());
}
