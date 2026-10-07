//! Records where Enhance PIR's transparent-output assertion was recovered, so that a transaction
//! re-mined elsewhere treats it as unknown and recovers it again.
use super::ironwood_transparent_output_shape;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Existing assertions carry no placement, so they become unknown and are queued again privately.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2d2e6409_78c1_48c5_9893_43b4d648e5d9);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_transparent_output_shape::MIGRATION_ID]
            .into_iter()
            .collect()
    }
    fn description(&self) -> &'static str {
        "Records the mined height of the transparent output shape from private Ironwood enhancement."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "UPDATE ironwood_enhance_routing SET has_transparent_outputs = NULL;
             ALTER TABLE ironwood_enhance_routing ADD COLUMN has_transparent_outputs_height INTEGER
                 CHECK (has_transparent_outputs_height >= 0
                        AND (has_transparent_outputs IS NULL)
                            = (has_transparent_outputs_height IS NULL));",
        )?;
        crate::wallet::ironwood_hooks::queue_ironwood_output_shape(conn, None)?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
