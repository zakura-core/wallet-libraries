//! The wallet schema.
//!
//! The wallet is split across two SQLite files, and that split is the whole
//! migration strategy.
//!
//! `wallet.db` holds what cannot be recovered from the chain: the account keys
//! and birthdays, the outgoing recipients and memos that only an outgoing
//! viewing key could recover, the raw transactions those were recovered from,
//! and anything the user typed. It is hand-migrated, and should need migrating
//! about twice in the product's life.
//!
//! `cache.db` holds what the chain and those keys can reproduce: blocks, notes,
//! nullifiers, the commitment trees and the scan queue. It is not migrated. On a
//! version mismatch it is deleted and rebuilt, which is why "rescan" is a file
//! deletion rather than a migration framework.
//!
//! Keeping them in one file would not work. Within six months somebody would
//! need to preserve one derived table across a version bump, would write a
//! migration to do it, and there would be migrations again.
//!
//! Three version numbers separate three costs:
//!
//! - [`DETECTION_VERSION`] — a bump means a true chain rescan. It changes only
//!   when trial decryption, tree parameters or position derivation change.
//! - [`LAYOUT_VERSION`] — a bump means a local reindex from `raw_transactions`
//!   and the retained shards, with no network access. Most schema changes are
//!   this.
//! - [`TREE_VERSION`] — a bump means refetching subtree roots. Separate because
//!   that is expensive and because a birthday frontier may not be reproducible.
//!
//! One structural consequence of the split: SQLite cannot enforce a foreign key
//! across attached databases, so `cache.received_notes.account_id` references
//! `main.accounts.id` by convention rather than by constraint. That is the price
//! of being able to drop the cache independently, and it is sound because
//! account identifiers in `wallet.db` are stable for the life of the wallet.

/// Bumping this invalidates detection itself, and requires a full chain rescan.
pub const DETECTION_VERSION: u32 = 1;

/// Bumping this invalidates the derived tables, which are rebuilt locally.
pub const LAYOUT_VERSION: u32 = 2;

/// Bumping this invalidates the stored commitment trees.
pub const TREE_VERSION: u32 = 1;

/// The name the derived database is attached under.
pub const CACHE_SCHEMA: &str = "cache";

/// Statements creating the durable schema, in `wallet.db`.
pub const DURABLE_DDL: &[&str] = &[
    // Arbitrary wallet-wide settings, including the three schema versions.
    "CREATE TABLE IF NOT EXISTS wallet_meta (
        key    TEXT NOT NULL PRIMARY KEY,
        value  BLOB NOT NULL
    )",
    // One row per account. The birthday frontiers are here because they are not
    // derivable from anything local and may not be re-fetchable if the server
    // has pruned; losing them would make the account's notes unwitnessable.
    "CREATE TABLE IF NOT EXISTS accounts (
        id                        INTEGER PRIMARY KEY,
        uuid                      BLOB NOT NULL UNIQUE,
        ufvk                      TEXT,
        uivk                      TEXT NOT NULL UNIQUE,
        seed_fingerprint          BLOB,
        hd_account_index          INTEGER,
        birthday_height           INTEGER NOT NULL,
        birthday_orchard_frontier  BLOB,
        birthday_ironwood_frontier BLOB,
        has_spend_key             INTEGER NOT NULL,
        CHECK (
            (seed_fingerprint IS NULL) = (hd_account_index IS NULL)
        )
    )",
    // Outgoing recipients, values and memos. Durable because they are recovered
    // by outgoing-key decryption of the raw transaction, and a rescan yields
    // only compact blocks: rebuilding these would mean re-enhancing all of
    // history, which under private enhancement may be impossible once the
    // service's snapshot has rotated.
    "CREATE TABLE IF NOT EXISTS sent_outputs (
        id              INTEGER PRIMARY KEY,
        txid            BLOB NOT NULL,
        output_pool     INTEGER NOT NULL,
        output_index    INTEGER NOT NULL,
        from_account_id INTEGER NOT NULL REFERENCES accounts(id),
        to_address      TEXT,
        to_account_id   INTEGER REFERENCES accounts(id),
        value           INTEGER NOT NULL,
        memo            BLOB,
        UNIQUE (txid, output_pool, output_index)
    )",
    // The raw transactions the above were recovered from. This is what makes a
    // layout-version reindex a local operation rather than a network one.
    "CREATE TABLE IF NOT EXISTS raw_transactions (
        txid  BLOB NOT NULL PRIMARY KEY,
        bytes BLOB NOT NULL
    )",
    // Anything the user typed. Never derived, never dropped.
    "CREATE TABLE IF NOT EXISTS user_metadata (
        txid  BLOB NOT NULL,
        key   TEXT NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (txid, key)
    )",
];

/// Statements creating the derived schema, in `cache.db`.
///
/// Every table here can be rebuilt from the chain plus the durable database.
pub const DERIVED_DDL: &[&str] = &[
    // Only fully scanned blocks get rows. `tree_sizes` are what the next
    // batch's position derivation starts from.
    "CREATE TABLE IF NOT EXISTS blocks (
        height                INTEGER PRIMARY KEY,
        hash                  BLOB NOT NULL,
        time                  INTEGER NOT NULL,
        orchard_tree_size     INTEGER NOT NULL,
        ironwood_tree_size    INTEGER NOT NULL,
        orchard_action_count  INTEGER NOT NULL,
        ironwood_action_count INTEGER NOT NULL
    )",
    // The scan planner's persistent state. Ranges are disjoint and gapless.
    "CREATE TABLE IF NOT EXISTS scan_queue (
        block_range_start INTEGER NOT NULL UNIQUE,
        block_range_end   INTEGER NOT NULL UNIQUE,
        priority          INTEGER NOT NULL,
        CONSTRAINT range_order CHECK (block_range_start < block_range_end)
    )",
    "CREATE TABLE IF NOT EXISTS transactions (
        id                 INTEGER PRIMARY KEY,
        txid               BLOB NOT NULL UNIQUE,
        block_height       INTEGER REFERENCES blocks(height),
        tx_index           INTEGER,
        expiry_height      INTEGER,
        mined_height       INTEGER,
        min_observed_height INTEGER,
        target_height      INTEGER,
        fee                INTEGER,
        -- The greatest height at which the wallet has positive proof this
        -- transaction is not mined: the chain tip when a server said it did not
        -- recognise it. Not an inference from the tip having passed the expiry
        -- height, which would only mean the wallet never asked. It is the sole
        -- basis on which a spend is released, so a wrong value here is a
        -- double spend.
        confirmed_unmined_at_height INTEGER,
        -- Unix seconds. The wallet's own clock when it built the transaction,
        -- or the block time once mined.
        created_time       INTEGER,
        CHECK (confirmed_unmined_at_height IS NULL OR mined_height IS NULL),
        CHECK (mined_height IS NULL
               OR min_observed_height IS NULL
               OR min_observed_height <= mined_height)
    )",
    // One table for both shielded pools, discriminated by `pool`. The reason
    // the fork needs two is that an Orchard action and an Ironwood action in
    // the same transaction can share an index and would collide on
    // `UNIQUE (transaction_id, action_index)`; adding `pool` to the key removes
    // the collision, and with it a whole parallel family of tables, views and
    // string-templated SQL.
    "CREATE TABLE IF NOT EXISTS received_notes (
        id                      INTEGER PRIMARY KEY,
        transaction_id          INTEGER NOT NULL REFERENCES transactions(id),
        pool                    INTEGER NOT NULL,
        action_index            INTEGER NOT NULL,
        account_id              INTEGER NOT NULL,
        diversifier             BLOB NOT NULL,
        value                   INTEGER NOT NULL,
        rho                     BLOB NOT NULL,
        rseed                   BLOB NOT NULL,
        note_version            INTEGER NOT NULL,
        nf                      BLOB,
        is_change               INTEGER NOT NULL,
        memo                    BLOB,
        key_scope               INTEGER NOT NULL,
        commitment_tree_position INTEGER,
        witness_stabilized      INTEGER NOT NULL DEFAULT 0,
        UNIQUE (transaction_id, pool, action_index),
        UNIQUE (pool, nf)
    )",
    "CREATE INDEX IF NOT EXISTS received_notes_account
        ON received_notes (account_id, pool)",
    // Stabilisation runs one UPDATE per applied batch over the notes that are
    // not yet stable. Partial, because the rows it must visit are exactly the
    // ones still to be marked, and that set shrinks to nothing on a settled
    // wallet — a full index would keep every stabilised note in it forever.
    "CREATE INDEX IF NOT EXISTS received_notes_unstabilized
        ON received_notes (witness_stabilized) WHERE witness_stabilized = 0",
    // A junction rather than a `spent` column, so that a spend which was
    // created and then expired is still recorded: the note is spendable again,
    // but the attempt is not forgotten.
    // A rewind filters transactions by mined height four times over, and it is
    // the one operation that must be quick while the user is waiting to find
    // out whether their funds are still there.
    "CREATE INDEX IF NOT EXISTS transactions_mined_height
        ON transactions (mined_height)",
    "CREATE TABLE IF NOT EXISTS received_note_spends (
        received_note_id INTEGER NOT NULL REFERENCES received_notes(id) ON DELETE CASCADE,
        transaction_id   INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
        PRIMARY KEY (received_note_id, transaction_id)
    )",
    // Nullifiers seen on chain that match no note we hold *yet*. Under
    // descending recovery a spend is scanned before the note it spends, so
    // discarding these would lose the spend permanently.
    // The txid is stored inline rather than behind a locator table. The fork
    // keeps a `(height, tx_index) -> txid` map to save 32 bytes a row; here the
    // map is bounded by the scan window, and one fewer table and one fewer join
    // is worth more than the bytes.
    "CREATE TABLE IF NOT EXISTS nullifier_map (
        pool         INTEGER NOT NULL,
        nf           BLOB NOT NULL,
        txid         BLOB NOT NULL,
        block_height INTEGER NOT NULL,
        tx_index     INTEGER NOT NULL,
        PRIMARY KEY (pool, nf)
    )",
    // `address_id` rather than an address string: the string form was written
    // one way here and another way in `addresses`, so the join between them
    // could never match. A foreign key also makes the rule structural — a
    // transparent output can only be received at an address the wallet already
    // derived, because unlike a shielded note there is no trial decryption to
    // discover one after the fact.
    //
    // `is_coinbase` is a tri-state, and NULL means *unknown*. Outputs found in
    // a compact block know the answer exactly, from the transaction's index;
    // outputs learned from a UTXO snapshot carry no index and cannot. Unknown
    // is treated as coinbase, because the cost of that is a mature output the
    // wallet declines to spend, where the opposite error builds a transaction
    // consensus rejects.
    "CREATE TABLE IF NOT EXISTS transparent_received_outputs (
        id                         INTEGER PRIMARY KEY,
        transaction_id             INTEGER NOT NULL REFERENCES transactions(id),
        output_index               INTEGER NOT NULL,
        account_id                 INTEGER NOT NULL,
        address_id                 INTEGER NOT NULL REFERENCES addresses(id),
        script                     BLOB NOT NULL,
        value                      INTEGER NOT NULL,
        is_coinbase                INTEGER,
        max_observed_unspent_height INTEGER,
        -- The height of a UTXO sweep that looked for this output and did not
        -- find it: the wallet's only evidence that a purely transparent spend
        -- happened somewhere it cannot see.
        observed_spent_at_height   INTEGER,
        UNIQUE (transaction_id, output_index)
    )",
    "CREATE INDEX IF NOT EXISTS transparent_outputs_account
        ON transparent_received_outputs (account_id)",
    "CREATE INDEX IF NOT EXISTS transparent_outputs_address
        ON transparent_received_outputs (address_id)",
    "CREATE TABLE IF NOT EXISTS transparent_received_output_spends (
        output_id      INTEGER NOT NULL REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
        transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
        PRIMARY KEY (output_id, transaction_id)
    )",
    // Lets a spend seen before its output be linked when the output arrives.
    "CREATE TABLE IF NOT EXISTS transparent_spend_map (
        spending_transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
        prevout_txid            BLOB NOT NULL,
        prevout_output_index    INTEGER NOT NULL,
        PRIMARY KEY (spending_transaction_id, prevout_txid, prevout_output_index)
    )",
    // `transparent_child_index` duplicates the diversifier index as an integer
    // because gap-limit queries need SQL arithmetic on it, which a big-endian
    // blob does not support.
    // One row per (account, scope, diversifier index), carrying both the
    // unified address and the transparent receiver derived at the same index.
    // They are the same address expressed two ways, and splitting them into
    // separate rows — which an earlier version did — leaves nothing able to
    // resolve a received transparent output back to the account that owns it.
    //
    // `key_scope`: 0 external, 1 internal, 2 RESERVED for ZIP 320 ephemeral
    // addresses, which this wallet does not issue. Deliberately not a CHECK
    // constraint: a wallet restored from a seed that used ephemeral addresses
    // elsewhere may hold funds at scope 2, and a schema that cannot even
    // represent such a row would have to change to admit one. Readers filter
    // explicitly and complain about anything unexpected, rather than skipping
    // it — treating a row as absent is how a balance comes out wrong.
    "CREATE TABLE IF NOT EXISTS addresses (
        id                      INTEGER PRIMARY KEY,
        account_id              INTEGER NOT NULL,
        key_scope               INTEGER NOT NULL,
        diversifier_index_be    BLOB NOT NULL,
        unified_address         TEXT,
        transparent_child_index INTEGER,
        transparent_address     TEXT,
        transparent_script      BLOB,
        exposed_at_height       INTEGER,
        UNIQUE (account_id, key_scope, diversifier_index_be),
        CHECK (length(diversifier_index_be) = 11),
        CHECK ((transparent_child_index IS NULL) = (transparent_address IS NULL)),
        CHECK ((transparent_address IS NULL) = (transparent_script IS NULL))
    )",
    // UNIQUE, not merely indexed. A transparent address is the hash of a public
    // key derived at one path, so two rows claiming the same one would mean
    // either a hash collision or a duplicated account, and both are errors the
    // wallet should refuse rather than absorb. It is also what lets a received
    // output resolve to exactly one address.
    "CREATE UNIQUE INDEX IF NOT EXISTS addresses_transparent
        ON addresses (transparent_address) WHERE transparent_address IS NOT NULL",
    // The four commitment-tree tables are shaped by `shardtree`'s store
    // interface rather than by choice; what is a choice is that `pool` is a
    // column, so there is one store parameterised by a runtime pool rather than
    // two instantiations over two table prefixes.
    "CREATE TABLE IF NOT EXISTS tree_shards (
        pool              INTEGER NOT NULL,
        shard_index       INTEGER NOT NULL,
        subtree_end_height INTEGER,
        root_hash         BLOB,
        shard_data        BLOB NOT NULL,
        contains_marked   INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (pool, shard_index)
    )",
    "CREATE TABLE IF NOT EXISTS tree_cap (
        pool     INTEGER NOT NULL PRIMARY KEY,
        cap_data BLOB NOT NULL
    )",
    // `retained_for` non-null marks a checkpoint on the ZIP 318 anchor grid,
    // which must survive ordinary pruning: a pool-crossing transfer proves
    // against the tree state at a boundary block long after that block has
    // passed, and a pruned boundary makes the transfer permanently unprovable.
    "CREATE TABLE IF NOT EXISTS tree_checkpoints (
        pool          INTEGER NOT NULL,
        checkpoint_id INTEGER NOT NULL,
        position      INTEGER,
        retained_for  INTEGER,
        PRIMARY KEY (pool, checkpoint_id)
    )",
    "CREATE TABLE IF NOT EXISTS tree_checkpoint_marks_removed (
        pool                  INTEGER NOT NULL,
        checkpoint_id         INTEGER NOT NULL,
        mark_removed_position INTEGER NOT NULL,
        PRIMARY KEY (pool, checkpoint_id, mark_removed_position),
        FOREIGN KEY (pool, checkpoint_id)
            REFERENCES tree_checkpoints(pool, checkpoint_id) ON DELETE CASCADE
    )",
    // Ironwood actions of wallet-funded transactions that the wallet did not
    // itself receive. Recorded during scanning because they cannot be
    // reconstructed later without the raw transaction, which is precisely what
    // private enhancement exists to avoid fetching.
    "CREATE TABLE IF NOT EXISTS enhance_candidates (
        commitment_tree_position INTEGER NOT NULL PRIMARY KEY,
        transaction_id     INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
        action_index       INTEGER NOT NULL,
        nullifier          BLOB NOT NULL,
        cmx                BLOB NOT NULL,
        ephemeral_key      BLOB NOT NULL,
        compact_ciphertext BLOB NOT NULL,
        CHECK (length(nullifier) = 32),
        CHECK (length(cmx) = 32),
        CHECK (length(ephemeral_key) = 32),
        CHECK (length(compact_ciphertext) = 52)
    )",
    "CREATE TABLE IF NOT EXISTS enhance_candidate_accounts (
        commitment_tree_position INTEGER NOT NULL
            REFERENCES enhance_candidates(commitment_tree_position) ON DELETE CASCADE,
        account_id INTEGER NOT NULL,
        PRIMARY KEY (commitment_tree_position, account_id)
    )",
    // `routing` is the column private enhancement grows into: NULL, or a
    // sticky decision to fall back to fetching the whole transaction.
    // Outstanding questions about a transaction, keyed by the *pair*, because
    // one transaction can carry two intents with different lifetimes: an
    // enhancement request is satisfied once and deleted, while a status request
    // is durable — dormant while the transaction is mined, and reactivating by
    // itself if a rewind un-mines it. One row per txid cannot express that.
    //
    // There is deliberately no routing column. The seam a private transport
    // would replace is `ChainSource::transaction`, not storage.
    //
    // `last_polled_height` is not in the fork, which does not need it because
    // its request driver lives in the consuming application. This one runs
    // inside the sync loop and would otherwise re-ask the same question of the
    // same server on every step.
    "CREATE TABLE IF NOT EXISTS tx_requests (
        txid                    BLOB NOT NULL,
        query_type              INTEGER NOT NULL,
        dependent_transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE,
        last_polled_height      INTEGER,
        PRIMARY KEY (txid, query_type)
    )",
];

/// The names of every table in the derived database.
///
/// Kept explicit so a test can assert the created schema is exactly this, and
/// so that dropping the cache does not depend on guessing.
pub const DERIVED_TABLES: &[&str] = &[
    "addresses",
    "blocks",
    "enhance_candidate_accounts",
    "enhance_candidates",
    "nullifier_map",
    "received_note_spends",
    "received_notes",
    "scan_queue",
    "transactions",
    "transparent_received_output_spends",
    "transparent_received_outputs",
    "transparent_spend_map",
    "tree_cap",
    "tree_checkpoint_marks_removed",
    "tree_checkpoints",
    "tree_shards",
    "tx_requests",
];

/// The names of every table in the durable database.
pub const DURABLE_TABLES: &[&str] = &[
    "accounts",
    "raw_transactions",
    "sent_outputs",
    "user_metadata",
    "wallet_meta",
];
