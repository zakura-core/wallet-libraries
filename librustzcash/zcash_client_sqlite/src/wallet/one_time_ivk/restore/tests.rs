//! Tests of discovery and recovery, on the shared one-time IVK fixtures.

use super::*;
use crate::wallet::one_time_ivk::tests::*;

mod coverage;
pub(in crate::wallet::one_time_ivk) mod discovery;
mod overhead;
