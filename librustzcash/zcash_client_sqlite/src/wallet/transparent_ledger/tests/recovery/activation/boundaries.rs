//! Regressions at the candidate/trusted-transition and consumer-read boundaries.
use super::*;

fn active_and_candidate() -> (State, AccountUuid, AccountUuid, ReceiveEvent) {
    let (mut st, accounts) = recovery_wallet_with(1);
    let rev = revision(1, false);
    qualify(&mut st, &rev);
    let receive = recover_completely(&mut st, accounts[0], &rev, 51);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, accounts[0]).unwrap();
    (st, accounts[0], accounts[1], receive)
}

mod configuration;
mod financial;
mod revisions;

#[cfg(feature = "transparent-key-import")]
mod ownership;
