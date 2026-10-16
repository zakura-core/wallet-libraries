PRAGMA user_version = 8;
CREATE TABLE schemer_migrations (
                        id blob PRIMARY KEY
                    );
CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL
            , sapling_commitment_tree_size INTEGER, orchard_commitment_tree_size INTEGER, sapling_output_count INTEGER, orchard_action_count INTEGER, ironwood_commitment_tree_size INTEGER, ironwood_action_count INTEGER);
CREATE TABLE sapling_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
CREATE TABLE sapling_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );
CREATE TABLE sapling_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
CREATE TABLE sapling_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );
CREATE TABLE scan_queue (
                block_range_start INTEGER NOT NULL,
                block_range_end INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                CONSTRAINT range_start_uniq UNIQUE (block_range_start),
                CONSTRAINT range_end_uniq UNIQUE (block_range_end),
                CONSTRAINT range_bounds_order CHECK (
                    block_range_start < block_range_end
                )
            );
CREATE TABLE orchard_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
CREATE TABLE orchard_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );
CREATE TABLE orchard_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
CREATE TABLE orchard_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES orchard_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );
CREATE TABLE tx_locator_map (
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                txid BLOB NOT NULL UNIQUE,
                PRIMARY KEY (block_height, tx_index)
            );
CREATE TABLE nullifier_map (
                spend_pool INTEGER NOT NULL,
                nf BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                CONSTRAINT tx_locator
                    FOREIGN KEY (block_height, tx_index)
                    REFERENCES tx_locator_map(block_height, tx_index)
                    ON DELETE CASCADE
                    ON UPDATE RESTRICT,
                CONSTRAINT nf_uniq UNIQUE (spend_pool, nf)
            );
CREATE TABLE "transactions" (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                mined_height INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                fee INTEGER,
                target_height INTEGER,
                min_observed_height INTEGER NOT NULL,
                confirmed_unmined_at_height INTEGER, trust_status INTEGER, zip318_kind INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT height_consistency CHECK (
                    block IS NULL OR mined_height = block
                ),
                CONSTRAINT min_observed_consistency CHECK (
                    mined_height IS NULL OR min_observed_height <= mined_height
                ),
                CONSTRAINT confirmed_unmined_consistency CHECK (
                    confirmed_unmined_at_height IS NULL OR mined_height IS NULL
                )
            );
CREATE TABLE "sapling_received_notes" (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                address_id INTEGER
                    REFERENCES addresses(id) ON DELETE CASCADE, witness_stabilized INTEGER NOT NULL DEFAULT 0, lock_expiry_height INTEGER, lock_owner BLOB,
                UNIQUE (transaction_id, output_index)
            );
CREATE TABLE "sapling_received_note_spends" (
                sapling_received_note_id INTEGER NOT NULL
                    REFERENCES sapling_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (sapling_received_note_id, transaction_id)
            );
CREATE TABLE "orchard_received_notes" (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                action_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rho BLOB NOT NULL,
                rseed BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                address_id INTEGER
                    REFERENCES addresses(id) ON DELETE CASCADE, witness_stabilized INTEGER NOT NULL DEFAULT 0, note_version INTEGER NOT NULL DEFAULT 2, lock_expiry_height INTEGER, lock_owner BLOB,
                UNIQUE (transaction_id, action_index)
            );
CREATE TABLE "orchard_received_note_spends" (
                orchard_received_note_id INTEGER NOT NULL
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (orchard_received_note_id, transaction_id)
            );
CREATE TABLE "transparent_received_outputs" (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                address TEXT NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                max_observed_unspent_height INTEGER,
                address_id INTEGER NOT NULL
                    REFERENCES addresses(id) ON DELETE CASCADE, lock_expiry_height INTEGER, lock_owner BLOB,
                UNIQUE (transaction_id, output_index)
            );
CREATE TABLE "transparent_received_output_spends" (
                transparent_received_output_id INTEGER NOT NULL
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (transparent_received_output_id, transaction_id)
            );
CREATE TABLE "transparent_spend_map" (
                spending_transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                -- NOTE: We can't create a unique constraint on just (prevout_txid, prevout_output_index)
                -- because the same output may be attempted to be spent in multiple transactions, even
                -- though only one will ever be mined.
                UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index)
            );
CREATE TABLE "sent_notes" (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                to_address TEXT,
                to_account_id INTEGER
                    REFERENCES accounts(id) ON DELETE SET NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                UNIQUE (transaction_id, output_pool, output_index)
            );
CREATE TABLE "transparent_spend_search_queue" (
                address TEXT NOT NULL,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                UNIQUE (transaction_id, output_index)
            );
CREATE TABLE "addresses" (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                key_scope INTEGER NOT NULL,
                diversifier_index_be BLOB,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                receiver_flags INTEGER NOT NULL,
                transparent_receiver_next_check_time INTEGER,
                imported_transparent_receiver_pubkey BLOB,
                imported_transparent_receiver_script BLOB,
                UNIQUE (account_id, key_scope, diversifier_index_be),
                UNIQUE (imported_transparent_receiver_pubkey),
                UNIQUE (imported_transparent_receiver_script),
                CONSTRAINT ck_addr_transparent_index_consistency CHECK (
                    (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
                    AND (
                        (
                            cached_transparent_receiver_address IS NULL
                            AND transparent_child_index IS NULL
                            AND imported_transparent_receiver_pubkey IS NULL
                            AND imported_transparent_receiver_script IS NULL
                        )
                        OR (
                            cached_transparent_receiver_address IS NOT NULL
                            AND (
                                (transparent_child_index IS NULL) == (
                                    key_scope = -1 AND (
                                        (imported_transparent_receiver_pubkey IS NULL) !=
                                          (imported_transparent_receiver_script IS NULL)
                                    )
                                )
                            )
                        )
                    )
                ),
                CONSTRAINT ck_addr_foreign_or_diversified CHECK (
                    (diversifier_index_be IS NULL) == (key_scope = -1)
                )
            );
CREATE TABLE ironwood_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
CREATE TABLE ironwood_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );
CREATE TABLE ironwood_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
CREATE TABLE ironwood_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES ironwood_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );
CREATE TABLE ironwood_tree_retained_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY
            );
CREATE TABLE ironwood_received_notes (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                action_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rho BLOB NOT NULL,
                rseed BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                address_id INTEGER
                    REFERENCES addresses(id) ON DELETE CASCADE,
                witness_stabilized INTEGER NOT NULL DEFAULT 0,
                note_version INTEGER NOT NULL, lock_expiry_height INTEGER, lock_owner BLOB, ephemeral_key BLOB, compact_ciphertext BLOB
                CHECK ((ephemeral_key IS NULL AND compact_ciphertext IS NULL) OR
                       (ephemeral_key IS NOT NULL AND compact_ciphertext IS NOT NULL AND
                        length(ephemeral_key) = 32 AND length(compact_ciphertext) = 52)), one_time_key_id INTEGER
                REFERENCES ironwood_one_time_keys(id),
                UNIQUE (transaction_id, action_index)
            );
CREATE TABLE ironwood_received_note_spends (
                ironwood_received_note_id INTEGER NOT NULL
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (ironwood_received_note_id, transaction_id)
            );
CREATE TABLE "tx_retrieval_queue" (
                txid BLOB NOT NULL,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER
                    REFERENCES transactions(id_tx) ON DELETE CASCADE, policy_generation INTEGER NOT NULL DEFAULT 0, reconfirm_mined INTEGER NOT NULL DEFAULT 0,
                CONSTRAINT tx_retrieval_intent UNIQUE (txid, query_type)
            );
CREATE TABLE ironwood_memo_retrieval_queue (
                received_note_id INTEGER PRIMARY KEY
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                commitment_tree_position INTEGER NOT NULL UNIQUE
                    CHECK (commitment_tree_position >= 0)
            );
CREATE TABLE ironwood_enhance_outgoing_queue (
                commitment_tree_position INTEGER PRIMARY KEY
                    CHECK (commitment_tree_position >= 0),
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL CHECK (output_index >= 0),
                nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
                cmx BLOB NOT NULL CHECK (length(cmx) = 32),
                ephemeral_key BLOB NOT NULL CHECK (length(ephemeral_key) = 32),
                compact_ciphertext BLOB NOT NULL CHECK (length(compact_ciphertext) = 52),
                not_recoverable INTEGER NOT NULL DEFAULT 0 CHECK (not_recoverable IN (0, 1)),
                UNIQUE(transaction_id, output_index)
            );
CREATE TABLE ironwood_enhance_outgoing_accounts (
                commitment_tree_position INTEGER NOT NULL
                    REFERENCES ironwood_enhance_outgoing_queue(commitment_tree_position)
                    ON DELETE CASCADE,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                PRIMARY KEY(commitment_tree_position, account_id)
            );
CREATE TABLE ironwood_enhance_discovery_queue (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                suspended INTEGER NOT NULL DEFAULT 0 CHECK (suspended IN (0, 1))
            );
CREATE TABLE ironwood_enhance_metadata_queue (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                commitment_tree_position INTEGER UNIQUE CHECK (commitment_tree_position >= 0),
                output_index INTEGER CHECK (output_index >= 0),
                compact_bound INTEGER NOT NULL DEFAULT 0 CHECK (compact_bound IN (0, 1)),
                CHECK ((commitment_tree_position IS NULL) = (output_index IS NULL)),
                CHECK (compact_bound = 0 OR commitment_tree_position IS NOT NULL)
            );
CREATE TABLE sapling_tree_retained_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY
            );
CREATE TABLE orchard_tree_retained_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY
            );
CREATE TABLE "accounts" (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                uuid BLOB NOT NULL,
                account_kind INTEGER NOT NULL DEFAULT 0,
                key_source TEXT,
                hd_seed_fingerprint BLOB,
                hd_account_index INTEGER,
                ufvk TEXT,
                uivk TEXT NOT NULL,
                orchard_ivk_item_cache BLOB,
                sapling_ivk_item_cache BLOB,
                p2pkh_ivk_item_cache BLOB,
                p2sh_ivk_item_cache BLOB,
                birthday_height INTEGER NOT NULL,
                birthday_sapling_tree_size INTEGER,
                birthday_orchard_tree_size INTEGER,
                recover_until_height INTEGER,
                has_spend_key INTEGER NOT NULL DEFAULT 1,
                zcashd_legacy_address_index INTEGER NOT NULL DEFAULT -1,
                CHECK (
                  (
                    account_kind = 0
                    AND hd_seed_fingerprint IS NOT NULL
                    AND hd_account_index IS NOT NULL
                    AND ufvk IS NOT NULL
                  )
                  OR
                  (
                    account_kind = 1
                    AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL)
                  )
                ),
                CHECK (
                  NOT (p2pkh_ivk_item_cache IS NOT NULL AND p2sh_ivk_item_cache IS NOT NULL)
                )
            );
CREATE TABLE tpir_meta (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                applied_mode INTEGER NOT NULL CHECK (applied_mode IN (0, 2)),
                policy_generation INTEGER NOT NULL CHECK (policy_generation >= 0),
                min_reader_version INTEGER NOT NULL CHECK (min_reader_version >= 1)
            );
CREATE TABLE tpir_output_origins (
                output_id INTEGER NOT NULL
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                origin INTEGER NOT NULL CHECK (origin IN (0, 1, 2, 3)),
                UNIQUE (output_id, origin)
            );
CREATE TABLE tpir_spend_origins (
                spending_transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                origin INTEGER NOT NULL CHECK (origin IN (0, 1, 2, 3)),
                UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index, origin)
            );
CREATE TABLE "ironwood_enhance_routing" (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                route INTEGER NOT NULL CHECK (route IN (0, 1, 2)),
                history_expiry_height INTEGER
                    CHECK (history_expiry_height >= 0 AND history_expiry_height < 500000000)
            , has_transparent_outputs INTEGER
                 CHECK (has_transparent_outputs IN (0, 1)));
CREATE TABLE tpir_candidate_windows (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                key_scope INTEGER NOT NULL CHECK (key_scope IN (0, 1, 2)),
                end_index INTEGER NOT NULL CHECK (end_index >= 0 AND end_index <= 2147483648),
                PRIMARY KEY (account_id, key_scope)
            );
CREATE TABLE tpir_revisions (
                id INTEGER PRIMARY KEY,
                source BLOB NOT NULL,
                revision BLOB NOT NULL,
                lineage INTEGER NOT NULL CHECK (lineage >= 0),
                sealed INTEGER NOT NULL CHECK (sealed IN (0, 1)),
                publication_height INTEGER NOT NULL CHECK (publication_height >= 0),
                publication_hash BLOB NOT NULL,
                UNIQUE (source, revision),
                UNIQUE (source, lineage)
            );
CREATE TABLE tpir_receive_events (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                txid BLOB NOT NULL,
                output_index INTEGER NOT NULL CHECK (output_index >= 0),
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL CHECK (value_zat >= 0),
                coinbase INTEGER NOT NULL CHECK (coinbase IN (0, 1)),
                mined_height INTEGER CHECK (mined_height >= 0),
                UNIQUE (txid, output_index)
            );
CREATE TABLE tpir_receive_observations (
                receive_id INTEGER NOT NULL REFERENCES tpir_receive_events(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                PRIMARY KEY (receive_id, revision_id)
            );
CREATE TABLE tpir_spend_events (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                spending_txid BLOB NOT NULL,
                input_index INTEGER NOT NULL CHECK (input_index >= 0),
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL CHECK (prevout_output_index >= 0),
                prevout_script BLOB NOT NULL,
                mined_height INTEGER CHECK (mined_height >= 0),
                UNIQUE (spending_txid, input_index)
            );
CREATE TABLE tpir_spend_observations (
                spend_id INTEGER NOT NULL REFERENCES tpir_spend_events(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                PRIMARY KEY (spend_id, revision_id)
            );
CREATE TABLE tpir_coverage (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                script BLOB NOT NULL,
                from_height INTEGER NOT NULL CHECK (from_height >= 0),
                through_height INTEGER NOT NULL,
                anchor_height INTEGER NOT NULL,
                anchor_hash BLOB NOT NULL,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                supported INTEGER NOT NULL CHECK (supported IN (0, 1)),
                CHECK (from_height <= through_height AND through_height <= anchor_height)
            );
CREATE TABLE tpir_pending_pages (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                page BLOB NOT NULL,
                from_height INTEGER NOT NULL CHECK (from_height >= 0),
                through_height INTEGER NOT NULL,
                target_height INTEGER NOT NULL,
                target_hash BLOB NOT NULL,
                UNIQUE (account_id, revision_id, page),
                CHECK (from_height <= through_height AND through_height <= target_height)
            );
CREATE TABLE tpir_pending_page_scripts (
                page_id INTEGER NOT NULL REFERENCES tpir_pending_pages(id) ON DELETE CASCADE,
                script BLOB NOT NULL,
                PRIMARY KEY (page_id, script)
            );
CREATE TABLE tpir_active_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
CREATE TABLE tpir_qualified_revisions (
                revision_id INTEGER PRIMARY KEY REFERENCES tpir_revisions(id)
            );
CREATE TABLE tpir_quarantined_sources (
                source BLOB PRIMARY KEY
            );
CREATE TABLE tpir_quarantined_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
CREATE TABLE tpir_transaction_metadata (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    txid BLOB NOT NULL CHECK (length(txid) = 32),
    revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id) ON DELETE CASCADE,
    mined_height INTEGER NOT NULL CHECK (mined_height >= 0),
    fee_state INTEGER NOT NULL CHECK (fee_state IN (0, 1, 2)),
    fee_zat INTEGER CHECK (fee_zat >= 0 AND fee_zat <= 2100000000000000),
    input_count INTEGER NOT NULL CHECK (input_count >= 0 AND input_count <= 4294967295),
    shielded INTEGER NOT NULL CHECK (shielded IN (0, 1)),
    CHECK ((fee_state = 0 AND fee_zat IS NOT NULL) OR (fee_state != 0 AND fee_zat IS NULL)),
    CHECK (fee_state != 2 OR input_count = 0),
    PRIMARY KEY (account_id, txid, revision_id)
);
CREATE TABLE tpir_shared_derivations (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_scope INTEGER NOT NULL CHECK (key_scope IN (0, 1, 2)),
    child_index INTEGER NOT NULL CHECK (child_index >= 0 AND child_index < 2147483648),
    PRIMARY KEY (account_id, key_scope, child_index)
);
CREATE TABLE tx_reconfirmation_receipts (
        transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
        mined_height INTEGER NOT NULL CHECK (typeof(mined_height) = 'integer' AND mined_height BETWEEN 0 AND 4294967295),
        block_hash BLOB NOT NULL CHECK (typeof(block_hash) = 'blob' AND length(block_hash) = 32),
        tx_index INTEGER CHECK (tx_index IS NULL OR (typeof(tx_index) = 'integer' AND tx_index BETWEEN 0 AND 65535)),
        replacement_observed INTEGER NOT NULL DEFAULT 0 CHECK (replacement_observed IN (0, 1))
    );
CREATE TABLE transparent_detail_work (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                reasons INTEGER NOT NULL CHECK (reasons > 0 AND reasons < 8),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                attempted_at INTEGER,
                attempted_height INTEGER CHECK (attempted_height >= 0),
                last_outcome INTEGER CHECK (last_outcome BETWEEN 0 AND 6),
                last_map_sha256 BLOB CHECK (length(last_map_sha256) = 32)
            , content_failures INTEGER NOT NULL
                DEFAULT 0 CHECK (content_failures >= 0));
CREATE TABLE transparent_tx_display (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                coinbase INTEGER NOT NULL CHECK (coinbase IN (0, 1)),
                fee_zat INTEGER NOT NULL CHECK (fee_zat >= 0 AND fee_zat <= 2100000000000000),
                input_count INTEGER NOT NULL CHECK (input_count >= 0 AND input_count <= 4294967295),
                output_count INTEGER NOT NULL CHECK (output_count >= 0 AND output_count <= 4294967295),
                shielded INTEGER NOT NULL CHECK (shielded IN (0, 1)),
                sender_kind INTEGER NOT NULL CHECK (sender_kind IN (0, 1, 2, 3)),
                sender_hash BLOB CHECK (length(sender_hash) = 20),
                multiple_source_scripts INTEGER NOT NULL CHECK (multiple_source_scripts IN (0, 1)),
                shielded_and_transparent_funding INTEGER NOT NULL
                    CHECK (shielded_and_transparent_funding IN (0, 1)),
                shard_id INTEGER NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 0),
                map_sha256 BLOB NOT NULL CHECK (length(map_sha256) = 32),
                looked_up_height INTEGER NOT NULL CHECK (looked_up_height >= 0),
                stored_at INTEGER NOT NULL,
                CHECK ((sender_kind IN (1, 2)) = (sender_hash IS NOT NULL)),
                CHECK ((sender_kind = 0) = (input_count = 0)),
                CHECK (coinbase = 0 OR (fee_zat = 0 AND input_count = 0)),
                CHECK (coinbase = 1 OR input_count > 0 OR shielded = 1),
                CHECK (multiple_source_scripts = 0 OR input_count >= 2),
                CHECK (shielded_and_transparent_funding = 0 OR (input_count > 0 AND shielded = 1))
            );
CREATE TABLE transparent_tx_display_outputs (
                transaction_id INTEGER NOT NULL
                    REFERENCES transparent_tx_display(transaction_id) ON DELETE CASCADE,
                output_index INTEGER NOT NULL CHECK (output_index IN (0, 1)),
                value_zat INTEGER NOT NULL CHECK (value_zat >= 0 AND value_zat <= 2100000000000000),
                address_kind INTEGER NOT NULL CHECK (address_kind IN (1, 2, 3)),
                address_hash BLOB CHECK (length(address_hash) = 20),
                CHECK ((address_kind = 3) = (address_hash IS NULL)),
                PRIMARY KEY (transaction_id, output_index)
            );
CREATE TABLE ironwood_one_time_keys (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose INTEGER NOT NULL CHECK (purpose BETWEEN 0 AND 255),
                key_index BLOB NOT NULL CHECK (typeof(key_index) = 'blob' AND length(key_index) = 8),
                receiver BLOB NOT NULL CHECK (typeof(receiver) = 'blob' AND length(receiver) = 43),
                scan_from INTEGER NOT NULL CHECK (scan_from BETWEEN 0 AND 4294967295),
                advances_allocation INTEGER NOT NULL CHECK (advances_allocation IN (0, 1)),
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
                paid_before_birthday INTEGER NOT NULL DEFAULT 0
                    CHECK (paid_before_birthday IN (0, 1)),
                provider_seen INTEGER NOT NULL DEFAULT 0 CHECK (provider_seen IN (0, 1)),
                registered_at INTEGER NOT NULL DEFAULT 0,
                reserved_at INTEGER,
                released_at INTEGER,
                active_from INTEGER CHECK (active_from BETWEEN 0 AND 4294967295),
                closed_at INTEGER,
                UNIQUE (account_id, purpose, key_index)
            );
CREATE TABLE ironwood_one_time_operations (
                id INTEGER PRIMARY KEY,
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                request TEXT UNIQUE,
                reference TEXT,
                memo TEXT,
                deadline INTEGER NOT NULL,
                begun_at INTEGER NOT NULL,
                started INTEGER NOT NULL DEFAULT 0 CHECK (started IN (0, 1)),
                funded INTEGER NOT NULL DEFAULT 0 CHECK (funded IN (0, 1)),
                rejected INTEGER NOT NULL DEFAULT 0 CHECK (rejected IN (0, 1)),
                observed_at INTEGER NOT NULL DEFAULT 0,
                expectation INTEGER NOT NULL DEFAULT 0 CHECK (expectation BETWEEN 0 AND 255),
                expected_value INTEGER CHECK (expected_value > 0),
                CHECK (request IS NOT NULL OR reference IS NOT NULL)
            );
CREATE TABLE ironwood_one_time_sweeps (
                one_time_key_id INTEGER PRIMARY KEY REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                lookup_height INTEGER CHECK (lookup_height BETWEEN 0 AND 4294967295),
                lookup_hash BLOB CHECK (length(lookup_hash) = 32),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                done_height INTEGER CHECK (done_height BETWEEN 0 AND 4294967295),
                content_failures INTEGER NOT NULL DEFAULT 0 CHECK (content_failures >= 0)
            , provisional INTEGER NOT NULL DEFAULT 0 CHECK (provisional IN (0, 1)));
CREATE TABLE ironwood_one_time_payment_recovery (
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                action_index INTEGER NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
                height INTEGER NOT NULL CHECK (height BETWEEN 0 AND 4294967295),
                block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 4294967295),
                encrypted_note BLOB NOT NULL CHECK (length(encrypted_note) = 148), witness BLOB CHECK (length(witness) = 1024), scan_hint INTEGER NOT NULL DEFAULT 0 CHECK (scan_hint IN (0, 1)),
                PRIMARY KEY (txid, action_index)
            );
CREATE TABLE ironwood_nullifier_scan_blocks (
                height INTEGER PRIMARY KEY CHECK (height BETWEEN 0 AND 4294967295)
            );
CREATE TABLE ironwood_one_time_fresh_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
CREATE TABLE ironwood_one_time_spend_retention (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                nullifier_retention_height INTEGER NOT NULL DEFAULT 0
                    CHECK (nullifier_retention_height BETWEEN 0 AND 4294967295),
                replay_through INTEGER CHECK (replay_through BETWEEN 0 AND 4294967295)
            );
CREATE TABLE ironwood_one_time_restores (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                restore_from INTEGER NOT NULL CHECK (restore_from BETWEEN 0 AND 4294967295),
                anchor_height INTEGER NOT NULL CHECK (anchor_height BETWEEN 0 AND 4294967295),
                anchor_hash BLOB NOT NULL CHECK (length(anchor_hash) = 32),
                anchor_tree_size INTEGER NOT NULL CHECK (anchor_tree_size >= 0),
                state INTEGER NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2))
            );
INSERT INTO "accounts" VALUES (1, CAST(X'' AS TEXT), X'5c040ca742fc472cbd0e5e751a724892', 0, NULL, X'1e28a65f5a61af5b7f0d52928d9be249b1c5b5238d51dbe69bb418a41d5bc665', 0, CAST(X'7576696577726567746573743173377a786b7435373971663937636a783776383275773465357567633974727a6a33676e76377a64333677376379667375387968636b766e717a6636723239753073756875326c356d70306a7672676739737a746634647730713830797770653763763971786474633967766333747a6a74323938793630716d737564726a76636b677265643235746e7134326530386e39787a6a6430797767337a74706c76776168616678637576383035687a767a6476716174357970646b6b3372726b3338756e72397363767a37676e6d686b39727637646a3978617735646a386834636c337776637930757939796d6639327170783975666c67387a736367336b686477387532396a3837766e38393871647279756174767135646b72336d686437363663796e6a7a786d34367a6d6a3235356e6b647374726670386d773264706d376b3236336d6b3967336d3463726a736c64306d656c37347033346d333375326675727970723772743635397376647a74736a753738723563686b6877396872346c717a6d7a30787467736168687336633078726534736c776a70757368376b33636833323034377030326b3936746c36386e6d30347a3275636d6d70616132787774356e66683275666b3965787030396c7638706e777530793461326e7871777a756a6a6c716c74657a67733334617663633771326d3934' AS TEXT), CAST(X'7569766b7265677465737431776d61736c6d667374756e77706761366d687a6b376a737270767472767a36717535776b743478326c68786a39757371797a65336639306c3534756375326b326735713777367a6e676464346639773466733435386432336c38363633703373753033656a3532397471793474676c743335766d6b78753734377832306a38777976306375377834687a72656761687161666e6e677961776d3965723974356461306a706d776733686e776b78306b79676c647a7a6570373565347175746d6e6e376c616b68706168367a7561706138636a6e743239736737656b3730326d6e717776736375356679663461617577327438373278326c33796e78657a683565357a373274617a646170746863726561376e65686a6d346b34357534656367777361636b676835786c33716b63723275737a6e64716463796c736e3071797771356d6c743834676139756d6436383377616c646d666e6370307a78736874' AS TEXT), X'c3aecd8aca5bbf592ef7f6e10940a7eba55a49ee6cd504f96433c2f8e892b3cc7e99b7c85adddd37806dbc2d49ba237fbaaa87d68cf6d20e2144155d951df010', X'6d7b568952acc3ec20772d14bc0edb431cf3519278c043538426bcde6f5b39d33a98ad8a2329c4fbc8fe4384d436d5a9771b3d40d62b62da536d23d22dc1d402', X'3b5d9cb0caec849ed9742aae3a58fb2e7507f99998e0722f8431b6977b0a29e903f7d44ba06f161a4ef41a2d0e7edc21e27a216ebfc214270da4a18507601a7e80', NULL, 3428393, 0, 0, NULL, 1, -1);
INSERT INTO "addresses" VALUES (1, 1, 0, X'0000000000000000000001', CAST(X'75726567746573743132726e6b7139656165667665633238323277756b65326d7a397337776d64686e337974646d7a307338706d7a6c71796e663273727875706e786b3661777939776737613564677238363637796670717a6130326d37386d646a7a6d6432796e6d646e786b78656a33347630687636327270677a736c6770376a656178737676393935653836773661723571377366396e6a39323761726b6e3377336b746b7972647165333766617a6639717166776c796772303974687333617339367336656837646338366e383666736132636d7932777933' AS TEXT), 1, CAST(X'746d50386264564d6a393357326774713851516d4a667a774244436b667142376b3753' AS TEXT), 3428393, 13, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (10, 1, 0, X'0000000000000000000009', CAST(X'7572656774657374317363666c6b6e7568386637366d6d6d66377670377665356d37737267387061787663786335656b6a6679763461767177746b74377066326c74726c6d356a6178356a6b353737366c61677573376d3939686673376564636a6832356a6d73756736307372676c7167666167647577346d3071757067736567617068377a6c38683768746a346538393268666e30747668323832766e7a373664657a657632637873347376707767713976347135343965347a656733656e37786a3767766a3264767473796171717a78396d686b6b64346e7061' AS TEXT), 9, CAST(X'746d45626378314175737842366d554e6d727657614a554837487351746d4339797448' AS TEXT), NULL, 13, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (11, 1, 1, X'0000000000000000000000', CAST(X'746d567a667537454e3471597071464c636a7a4d6d364a544b78744d44686863476a69' AS TEXT), 0, CAST(X'746d567a667537454e3471597071464c636a7a4d6d364a544b78744d44686863476a69' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (12, 1, 1, X'0000000000000000000001', CAST(X'746d576f4e376d363667343667574e504d53336b44715a437539514d48335076386976' AS TEXT), 1, CAST(X'746d576f4e376d363667343667574e504d53336b44715a437539514d48335076386976' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (13, 1, 1, X'0000000000000000000002', CAST(X'746d453576744a716d54616239783375365a52516a65574462357670334d685954544b' AS TEXT), 2, CAST(X'746d453576744a716d54616239783375365a52516a65574462357670334d685954544b' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (14, 1, 1, X'0000000000000000000003', CAST(X'746d5272656a4e593965593533586339486b684e58664c7273514c414250764766435a' AS TEXT), 3, CAST(X'746d5272656a4e593965593533586339486b684e58664c7273514c414250764766435a' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (15, 1, 1, X'0000000000000000000004', CAST(X'746d397331774474424a3750636b56353641536d6b554e714b4261646852725a454752' AS TEXT), 4, CAST(X'746d397331774474424a3750636b56353641536d6b554e714b4261646852725a454752' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (16, 1, 2, X'0000000000000000000000', CAST(X'746d4c4e3273484e796f7344636e5978426d674c333942743473577a33426a4243486e' AS TEXT), 0, CAST(X'746d4c4e3273484e796f7344636e5978426d674c333942743473577a33426a4243486e' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (17, 1, 2, X'0000000000000000000001', CAST(X'746d475a4b4b686d69433550546e553672746a5173376b6a6e524d666f535464433848' AS TEXT), 1, CAST(X'746d475a4b4b686d69433550546e553672746a5173376b6a6e524d666f535464433848' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (18, 1, 2, X'0000000000000000000002', CAST(X'746d5048566873656933646b475468773155514155637132756d6f62634e3576763753' AS TEXT), 2, CAST(X'746d5048566873656933646b475468773155514155637132756d6f62634e3576763753' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (19, 1, 2, X'0000000000000000000003', CAST(X'746d4b334263645751336276467831424d6a414c6f6e31694653727a57544a6a614357' AS TEXT), 3, CAST(X'746d4b334263645751336276467831424d6a414c6f6e31694653727a57544a6a614357' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (2, 1, 0, X'0000000000000000000000', CAST(X'7572656774657374316a7a6571736d7568386d33776c3036707777707165746a6a616a787875386766397173686767776737686b616b3832796a7a683077767373667378636568753875757435636e7a366470306667686e6530346b6b3937643639376363793935636b746673656634307634397974666c773232393038723966777a66656b6e787039746b757765787075706a' AS TEXT), 0, CAST(X'746d43554168646579467756784554743378545a727251335a383765314772616b6331' AS TEXT), NULL, 9, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (20, 1, 2, X'0000000000000000000004', CAST(X'746d414e383974697931596b636b435a38514863375542755031643138647470653841' AS TEXT), 4, CAST(X'746d414e383974697931596b636b435a38514863375542755031643138647470653841' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (21, 1, 2, X'0000000000000000000005', CAST(X'746d45656d484c3148773557723478437833557550644d6e583843684b774c4b746353' AS TEXT), 5, CAST(X'746d45656d484c3148773557723478437833557550644d6e583843684b774c4b746353' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (22, 1, 2, X'0000000000000000000006', CAST(X'746d514b63664d71794846766b6b3150567a455169336d58326f784a71526544614a57' AS TEXT), 6, CAST(X'746d514b63664d71794846766b6b3150567a455169336d58326f784a71526544614a57' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (23, 1, 2, X'0000000000000000000007', CAST(X'746d4d43754c546659454c723269446d4b5843766d4e4b39366850436571636a656372' AS TEXT), 7, CAST(X'746d4d43754c546659454c723269446d4b5843766d4e4b39366850436571636a656372' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (24, 1, 2, X'0000000000000000000008', CAST(X'746d42596a5255394168564845797a4356717439565735527947384e48487748725833' AS TEXT), 8, CAST(X'746d42596a5255394168564845797a4356717439565735527947384e48487748725833' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (25, 1, 2, X'0000000000000000000009', CAST(X'746d4778354c4151715368597a4e6b6273614e39646f55667961704a7569654a37384a' AS TEXT), 9, CAST(X'746d4778354c4151715368597a4e6b6273614e39646f55667961704a7569654a37384a' AS TEXT), NULL, 1, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (3, 1, 0, X'0000000000000000000002', CAST(X'7572656774657374316435776e63746e79396a6d75327a6d656572646c366d306c30777564746e6639397663747537387167356c3479376c6b6635636136636c767071676a38703868356370677136616b37786c7730637432757164307266393434787361396a376b396d73396161356e726771757638616b747374776e74746c7a6e6e337536776b7a7937676a706a66647579' AS TEXT), 2, CAST(X'746d4753523277516a786e7839416b673559704d663878687a67704146366d484b3572' AS TEXT), NULL, 9, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (4, 1, 0, X'0000000000000000000003', CAST(X'7572656774657374316a357132636e6d64746d306c796d6d327272353035796832677665616b3934646370727a676e66346564676c656878647073393264657877786165683339307061786d7a653661357a3264776c67336a3670636b376a68376c3938673537367a6a6172387633646477757776396174677478376e77307277687a746863646d37703532766a6e72797130717a6b35787a7466636375636666757968683470397670306d676872786e6e676c356e636e6a746864706e366c6d65616b6373357975396b686b357a7271666e327078666835376578' AS TEXT), 3, CAST(X'746d4552345676637961447165555546565732657244644a386b533264613361396342' AS TEXT), NULL, 13, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (5, 1, 0, X'0000000000000000000004', CAST(X'7572656774657374313973646366307175727a34736b3235357273636777356d79797a61636a7a75676b6d32656865333879656374726468636765327a346564773238677872613832657073346e34386365643733387665386d65677735646839766d7a70646d616b7230337a7370336c347977656832673335647a77766b763734686671733375397061356363737a34356e72676b7a32657a61386475367875677730353671663864773065636a6b356671616838717930353976706e39326170776e32706d79326675396175736e36736665746a686d6c796c6b' AS TEXT), 4, CAST(X'746d43337a54474e7843354e564865316577634b696b79327547644d69437156336557' AS TEXT), NULL, 13, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (6, 1, 0, X'0000000000000000000005', CAST(X'757265677465737431383674377063326b6e3532366e777270756b6d3276323734377a39686d746b777266363039767a7674347766336861346d33616175367a326e796639756c6c767671726a733467326373636a7968716170767677673866386a67347333777a67673677667771666a7279707970336e79336b6d6a73387061736364766a7932657030667a366d7a79376a6c' AS TEXT), 5, CAST(X'746d544b5065693655476d46396841474248527353644e726d6a4b6b7738634d6d7063' AS TEXT), NULL, 9, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (7, 1, 0, X'0000000000000000000006', CAST(X'757265677465737431326e6a6a7075796d636e757472786666727866707967707576736373367464303939716c73376b356a7a67646e766b676a6179336636777a753039397368366c6c75636b38636b6e393963386a307079663667397166713574797a6838346a307866666372636870346a70306e6a6c6c6b753630726830703266366e6b63703332783465346b3078716d61617265617367716c3477373074376d776865376876767a67326a39376337673330686332386b6c7435387438793633347973656a71777a7a7a78686b343238647a3270766d6a6e37' AS TEXT), 6, CAST(X'746d535a6d6258596f354a7669796d71544778774b72376e685a76775338644b773836' AS TEXT), NULL, 13, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (8, 1, 0, X'0000000000000000000007', CAST(X'757265677465737431306475706a6b6478636372636a3835793830326a786d7073716c776d616a6d396d6574757577367037656877326877713935787563776a636e72786d353379326c76746d6876346d333672336b307736737563676563307061733872387932343971336767726d343074353078366d7678356b686a303077323430733473796d6a78643863647a6d633768' AS TEXT), 7, CAST(X'746d486b55677357446d4d37463665324b54637a696e5a666d773651584d585a6d6e34' AS TEXT), NULL, 9, NULL, NULL, NULL);
INSERT INTO "addresses" VALUES (9, 1, 0, X'0000000000000000000008', CAST(X'75726567746573743173726537723674776d6b39367878786d6d3637656e7a76746635397174616133617136716a38656d786e3961776676386c6e726c6835357561346d646d776e3270383572686a347630716738773471616776773379323263777461373074756176366a396830687372776c67706c7075376d37386777353079333366726e7538347a3038786c7563646674' AS TEXT), 8, CAST(X'746d5a3175666f57395375356a5039466f33585852576f4642486434376d3436685256' AS TEXT), NULL, 9, NULL, NULL, NULL);
INSERT INTO "blocks" VALUES (3428393, X'b2f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428394, X'58a28c18576b71e5e61c32867855a03cd0a8c91e731f9a1c00a6c0870d9d2e40', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428395, X'e4dc580e2f621a7ffa4541a7dffa5cc5a3c78dacf4a7c74364b12384f8d6ca16', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428396, X'e9e9a8532b0c9725bc870859c7b40191bcdf63d48d9342bd22498549ee3a1dba', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428397, X'e3302d928ad0cd0e2d23696a8bce0c53b7eda63b5167480a0003941935b909ee', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428398, X'6dff97d6447ea48052db6f5fcd7668cee86b48ed21b4e5d03a01f7aba7a9dcd9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428399, X'5803491d49c5ae30f1965b5825c46ae907147e8db39ae377e11547875f18d0f6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428400, X'7ff43dfc9b35f16e322f2a316e21570f725c4f4ac2900ddcedb86b8e3b2785ea', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428401, X'1aaede1f1a5f95723b160c9822e98723796f9abddcd68958b19cf938cbd6d43e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428402, X'872eaed8b393567a60257d9ed482f2892e49937a9bbc1e0350a6b1a5c7f6d8ee', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428403, X'344a1eb303a9f9cc5ec52125817f15de746a95b3c5f5f65680203f8c5de1969d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428404, X'f7d277ab137de8bc6040d010e0eba8cdb64488ae3dd935485ac9ac26724a0169', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428405, X'cfe412c06cd237a4e5871141bfcebbc54283271824ae34d3c67693905030d659', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428406, X'f5a94a5287ff92eea10b28b9720d3b96edcaf2971c389cb3e58592d252d2406d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428407, X'b43b818520435c4aae469c936b39499176b0cf1c31f2891e61f284710eae0b26', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428408, X'818269030fb4157c737c278379f7bb3314e24a61e668aa7199e807337b778fe7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428409, X'6870074e651127e658148a52fd8e84847146376408d2beee9db3da0dddd86cd0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428410, X'465651143b8417424e2e3aca54f72b2c832d5db18fda55ec0b861a643935caa9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428411, X'2ec85d98f12eb00c284f70b62f321b9865facfedc731b8606eb5e653045f18dd', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428412, X'6b5a9cfc3632e8cae4dd5a6e096102b09e7a3640e011e6018ec5b7185da59180', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428413, X'7ce067b2a0ff4ffb864095aa4a0a509b637fd167a051b32f0170a5b6857135d7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428414, X'57e527630154ee4d5c1580230eeab47d443f18b43d014c7e03f6a09b6b461029', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428415, X'dafe330f3967681dcf55e4e8c8a80a15b323f1bd26a73afad19deac396e79deb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428416, X'ddd4a167649a2a7a70d69a53a13283e8b1b4244eb61fc01a71f85ceaba07185c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428417, X'd9bd0a38dc1ff2faedc2ea567414b215562df60aca198d5e8dc151eaf109d5be', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428418, X'cb6d242959491d435338b06a2fd69d3755668efb72b2b58e46f7e943aad57d51', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428419, X'8b20f6a66c9555759983b292feb27588cdc67ed3b69a3c20ebdb117595c535d7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428420, X'04c52e136c4f6357671d49de5253236d486d0c540a4fcc4ad9a0ba6fd28d8009', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428421, X'2911e5430fc953009cb010aaf5cd4a4e9cae9b5624dc2e7d44d5ad387d8f79a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428422, X'f8eb2884713d9038420bc44daabc46557970889a184ec366be37ec3fdad96685', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428423, X'bb7a37c319464701a15990980cacd26403d467778ebad72dcd5e2902b47da297', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428424, X'e0bf339be49e61ef35a5dc705d6e95341c0cab3ef64eb894a4c9baaf1089f37f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428425, X'fd36fb0500f07e69c7dd734daa0e87aa2b84f843842c72469f8697bf75b8e6a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428426, X'ee3bc89ad8b6accd564dba902de516af09f509141490b0dd012f481b7085db88', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428427, X'c29cfcc5c1a93a35b02d18a68c08469bc9376f17859d3494f61adfb9a520d1f1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428428, X'6c11b0ec99e4c893eabbf355793e3cbb1773e74e5ae480b0d1e35f88bbdc9608', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428429, X'157d701079eb887b08377970755e75e76852292494b88dd18de41bc38514bf4a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428430, X'58e0e44e4d4b78dd12706108827500c6d4761e62b166316b88f02cb34252fe22', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428431, X'711d2389fb76bd9d6840befbcfeb20c3c7a3b7cafe3ed0d77b6eb27d1fd667ea', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428432, X'2fccfbc156f8315c356bb09b448c33c88ecf88ce8364aec6626c4a9913cb7230', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428433, X'309e2a767dbbad6ebc3ca3f15beb1b7718051fd9e7e342db0dd1ae1b2ce70612', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428434, X'14e8cdbab31808aa54cd655002427628f9657773838ae90011724af40445b270', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428435, X'9b6f7c23db69429fc9da6d1fbfeee0c2db04ebe8a8352deffb66c2669daa3e2f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428436, X'40bfc15fe7ddbae21077b0ce8962e2b102d5285674e4be5c326f8a4e885ff7d8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428437, X'95fa00eb361b25fade841a6d8fb8e57a0cbe3a6dd7ffc1b351cef0f384b8a79f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428438, X'7f454d2281a1f17ec68db0531d348c53fd6d6c5ccd5da58347947299af410312', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428439, X'ec205f8dd055f1db1e0b729727eb4f4c1068559a9d23276059051c5e8f4d4f0c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428440, X'6d0a11deeeb2e6d9b7d0ee5e591f6e872f4a865b1f4aa13bd84e202c661759b3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428441, X'2ad42bbd50a74778043a480464544bf4b3e74d963884809c31ab51b11c9c993b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428442, X'1f6a217254bb4851a49658c5ac086006c820699f8ac8d6621ecd1bb00bd21a4e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428443, X'c727454490abcfdaf7246c2895284fdce01e11c46d286c440723d87d82828019', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428444, X'9199b7d5f7f514dc8241c312064f2de290ebac729ab84812c05ae229ca31c7b5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428445, X'52cb20735b13dfc0a418cd08c21cbeeadbd164bd23d8f7420a0e9499d284ce01', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428446, X'6acbe9d5279f8c0c431131ceb89e83f2be5a9747c6027f41599145db88967fbe', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428447, X'9d145156228b2a7211497045d3ee5fe839721f551b261c917d75f0b5ea713a51', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428448, X'f5aef4a28fddd2bcb97872e67040c272eb616f8770888baec4b7a56a2df7e3a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428449, X'fcdd4aa0c6c636b2e799f4efee3815e6af164b32401c5003c43161fbef24eff5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428450, X'1c7677ed0854bcd04352223ddf1b4d32b618328de7fc2c534a87268c684ffded', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428451, X'6b3f34da02ed97dac55d2dca3442ff3157113e6d3f7ecfa4a1f3d788d3811021', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428452, X'55d1cf2acd7bc84d55f29e25874b62b0eff14b3b743788eec68559d6f96cb197', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428453, X'3c331877f39aa29def0ee300cb2e141dc98f780cf40a15295b0dbf83b49537af', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428454, X'586f48b4af816b8e5b804ecc55db1738ffcd89f0c9a86b32cd46d1000792beb9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428455, X'ab260494c1c2280cebe99456648b958d8d41ad7a7dc198562039eb068c708e6a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428456, X'e881b22a68cb32696dd269678858cb8c418a9724a030d62f5b63099e9ad81474', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428457, X'6ec548cb385b2b7315ac26e9a12018bcf33c056e2feb321be5077d2ad946f8e3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428458, X'bdfcd049604c4cf14d92632e2c6bb4b1f56b7b9b98242b62f25fdee6d88a25e5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428459, X'3f0383a83c046f0dfe807aee4b44f3c86ffe8161d50bbca260b68356cce3312b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428460, X'9dbea98a73a9cec02a2ef551fba78b5bb34eaf8ebf6349df2e93ffb915deaddf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428461, X'cd0a8bf71b827613079b3b4144d63f4348c06a56c0ae90d88d49cf82a9033ed8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428462, X'f575051d50c60a809ce3e8f526dfe1803f17b40f7cb4ba243b1c14b44c8810ba', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428463, X'93d261cbad61f677fd1dfd477485aab8807585794b68d1e84cbd02af6e924733', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428464, X'8926c1802277fb98348c28ec0a018fcada269252fdd3c0571faa18cef5d9366e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428465, X'bca0e84227e465ecc4454719fb8e3b94a9e2787e9c53e8e9cf7d963a9047ad17', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428466, X'3dc9fb3033384512c18f02f2e876d0064d20215651f330a83993a78d1f56becf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428467, X'6baeb86248a4973ff61c863925ab7f0d54efba9bc70a1eda776753e741d6399d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428468, X'277d7a8fcad0a06d20200202f787367b29864ab39f94815dbf66d00c2f760e0f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428469, X'76ed18294add65e4e3c1926482acfa21b1f3ae3d585b702049cd158cebd49169', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428470, X'e9e7daad9faf3dace284a5ec9d20f5e79a6ad6b1b5e3618d38cdc86985fc5cb8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428471, X'43bb65ed2eceeaa03c30d03fc51ed30a451441c496b2447809728a87d01313a6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428472, X'3a1cd0b42bd8a6325a1de6a3bc9367d338f839d7e75d3ed7cd49bd42564bf33e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428473, X'fa7e212dbd89fd9cc81361c53aa9894e4f25e3f69ebc6aa1d553cd7ed18ca611', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428474, X'84fa8393ea25ef152d05068c5de10d99b95d572238a6558bae3da61ac67a1254', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428475, X'1272308122956a0364b7e89c7123e47fcac9133463e9c659c22ccb8276fe3702', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428476, X'2677287fb5e9e5cbba36dfb7111a11ebfc10263a0d1c3a909c4475e3489a1708', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428477, X'a64c8ab158aa747e5a5cb0cd14a6cade48d850876b55edc7c931919e5265d02a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428478, X'034ac0adab497ada6fbd82d12a9fdee02133039dd9a36daf250e4fbaaefe306a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428479, X'041083e3031118efe7b62a18ab17ef842c9d443d0661a9392407dbde57a68ece', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428480, X'452e996d00eb2e10ee32d7463674a640cddc0df27971002fd7166ef7143645c4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428481, X'e756792291452f4184873cec7c9760351e980a7bd027c767d20d04fac36fce69', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428482, X'ee5199a0efe9b90538d985da358d3365c62184031357e662e3f336bc57d17a49', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428483, X'17f93a341f44a6ebe933cbe79b8f901568ef334d028eb3da65cbc58103e6bda2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428484, X'280cefbec0cf82244c5575db6c8fbf4faf9b1ff8bd243b4f5f97f009a191c08f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428485, X'd2a125d7ea1aef5261392cb8e4fe4729c48f67671dcc69ec621f9aa69150b05a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428486, X'5946fc521e9096fcd272dd394daeba540d7761d5c853c34c461adf30591065a4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428487, X'7cf0b3dcdde48a4c4dac9ae7c962836a9ddc4c4636e47df0233263f80a82e8e3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428488, X'5a705f2ec5de82b2f15b07c1684166103167188c96ca33816791cd9520d90fdf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428489, X'eded694851d1e9e6e754517aa8757a8ea2f1825c2c56c95f2d7be69d0d103574', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428490, X'66c1e4830a7d4dacf9c219ce53589f3665b03e19b2b5dcc00fa8244d98c7e103', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428491, X'b6c1f1db63a48c4ea9821201309ecce8e34932edba5013acfb7e68db35472d13', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428492, X'3be24707c61986e9859ca2d5e8a065155d447dcafd5df4791eeee5c02f530fb7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428493, X'248271ebc012dd2be67deaffebaba3485fc40a9a059d93d6a5eb6480e75ad5b3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428494, X'3fd74a8f9d43e46c5a840d471c7b69560bf18915355f7fb1bc6c0e25392432a1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428495, X'eb6e47817ebb621a3cd04a73fdd08fa19a6e5f26081522e459b3f0ed4e7a517e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428496, X'75376cd982ff23d8661ddd32df1993daff54ae2f552784184c187011117b67f3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428497, X'532929b8432ee86b71648ff5f9abd50bee7e7e1f52c7f65920e2bb062cce83d2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428498, X'0e125f9b7aa7320ae4d8e53ee1852ee86cfc4c6372ef39a97a5c735d99f3b264', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428499, X'664da22b288b5fdace4d1fd546c7a5f5832fd7c137480e8b758ae45abb462024', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428500, X'9d9117ef454c728162e32c73fd5bd100123fdb8f023950c12e9c496ef44ce7e5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428501, X'ada4ea6082e6d066fa2571583559d9a86c222e000d304050457f246dd2c3d9a5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428502, X'8f39b8377de1a6b84ad942e5c8338c99117a711a4b9a24a7e6cfd2ac9261c353', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428503, X'eb46f56489b1d73a1d275c753a902ca5de52cdbc265bb20332c70587653ebcc3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428504, X'c2e19031d44ba7ba210e0c4fbe1d6419a6e4fefea835d7ba62d977954cbdd50a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428505, X'0ec4df0330e63c7e8910dcf330e93f34d14747d2ed1e1a5de1ec9f286e72885c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428506, X'90f11677e7e32e12c5642496ea5be2ad68caaf02f79ab84b3c6dd1c6be81db16', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428507, X'f3df3db531fc2ea173079cf1b2eed9044261d59921770e205c73974d602d3196', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428508, X'8ce609297226d85bddf324a5e476b6a855fa385d109eb2a8190671790ae87450', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428509, X'450b1c8e93b80f1b24e8b0930aced49152958fcb099ca5cfcbbd297cea4cf3f4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428510, X'1d6d804314dd0f71624b896f3cd6cbabed548eb560a90cb22ab420f648b50b97', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428511, X'6649092918deddad58e9ce4042201eade1e6b025a6dfedacadede643b1846aa3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428512, X'be65abd8a53dd8edb3e49832959dc40f4ecf183c914c88679227074c14662bc0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428513, X'bc9e2275ff1281ce8253052d9d01e8bb2d24090271f0c10f05112ff28d6af687', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428514, X'a099369c55e3db3e082ae42d5cf61a0d89f6843b0d5070c4c688649428d19af9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428515, X'a1f0fb2e47c19198add24c97e722900acfcb941c9cc35b99be1ee4fd8e1b8971', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428516, X'7e36a717980b55a29ee3eb9f4de739fd5d69ac1d4152e55d4f990af3a0ef266b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428517, X'a9e0d4d90bed55c945f9c305b198ffeb110b79350c0953b6a4d0368b1ee04b27', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428518, X'404150f73de230786a6d4ede00a6ef96ffc6ac0ee36cb7c87bddaa0c1670c088', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428519, X'610d5dc352f225b417801c886dbb901babd0bafc2aa1fb63e943ebeb1d771ee9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428520, X'23a7f1ba587ff5d95e7c41d3095222e5896e16a2e6be202af37b0b4610169716', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428521, X'6d5e261841ed0f84a7132b1b478fc30c4122b684bc2e76a43c993088acd42fdc', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428522, X'b3b7bd6409cf87535d0747c7a99daa8244b520ce93c5e4b8ed55feb11c3d6ec0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428523, X'd9e7581fe1542cd7560e554f936f229e546e5539c61830bdb502879d55ff2cdb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428524, X'717937e3651cd569401d921e770215fe82feeb9a070debd5779db14b31efb863', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428525, X'd1d1774c4ec8fdd6814652f9471551967cb8769989860a98e2613d041010b621', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428526, X'f5cf7587b6b1deef991b52933f1ef5df94795dfe0d956ba63d04ca4da9ad274a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428527, X'00c15bfdf98f86c5ad599debaa8d07eab18624d8e14bce2202841d00860f335a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428528, X'd58336f1e8a2521bb490ea8aa3616622ce13674b54e862185308f23cba66cae0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428529, X'597287996ab569fe05ab5d8a4d8256ae15271c592f77f689efdfb1ec859089d8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428530, X'd80f65611d444c6dbdd3dad3ae4ac06a0394bfd3772af256a52cbd833ab1edf9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428531, X'362dc35b92dc5d927768592741ac547eebae7f2332cc653d553ef0175d74e7b7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428532, X'a05adcf6b544df2dcb4c4f93690179e321eeb3b2949a2f7b3e2dfa7d96717dda', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428533, X'8d41c781e9138c7d2dce60222b295794bd17cf3de4f015d750ae2073e26e9443', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428534, X'8b127030be908c058ccf3ffe54775d94da0d533cee14e457e9730c65eb204209', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428535, X'ebcfaab45a5fa2eca9997b1c746eaf8ac77b2505636a06ce8b24cf9e2d1df11e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428536, X'07b1955128db35345090d776b42c005ac636b806e9dbc69b1b309b61ac40b635', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428537, X'd040753d21b613b0951c89569850c36a4ef94a8b4e408bbf56ec2304ec2bc622', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428538, X'd347e005538e4d21ba087363754ec50d152aef23863834717d3899a62a891a34', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428539, X'a700a81a43f3c0af70a501b89c53b4c567a7d0717cd0c59aa9a4664f53b8b4e7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428540, X'6a86ddc39ff98fa968d5dabea92402a4587721ce256f6a6d79ad0d377ca5870a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428541, X'12216a210757bcb13f64c225a1e329c646b0c5caf70654c0239b52a55c96e91b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428543, X'2ac84e3b7c0086462806117489faf986ae4524ab7457704c3d2dacf2619e263e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428544, X'd75aad37ab44f472e60037305ce66df76d6957ec9e8889b11e855635d7b6acf2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428545, X'5fe89ffec59165d19cf2c86103d3d60729f688b0db5275fddb3b68d83e8c2c5a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428546, X'1eb7f0d0971809586827f1aaa51fe3cda1d8de666de2fd373e3cbf5edb067e65', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428547, X'92a98c159205043da8583e6be1bdd15e1c240a87bc611b3fabed5859d156c19f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428548, X'53fd82dc22f8309e314ba77ed81095812a9383054d47afb57b383464200efc2e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428549, X'158304ccc2d6c7bee25a879c621d6c424ca0e76ee97045ba5912ce555c7a5f48', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428550, X'26d8ca2270d9e30f6a21b024b87accbb91c40f73004d92c7ab1512295c06c427', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428551, X'024563c9fb3a9c15041286e2484859ad400847c5e5c7f47a57378a588de33dd5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428552, X'37e5bed0a13503998eb52603dcdf3855427174c804160b951033b954806bb810', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428553, X'6a7598b8bdc8d8db0bd03397573ea16e57b6fe3786f6eb42606af0d6808e90be', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428554, X'6b78fa1525854086c59c8196075d62c5e69f387e23d3179fd29c57300c541e57', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428555, X'a4fe6faff47b3f5b67edff51b3d93be78db9dc7625538a9598807225a1818bf7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428556, X'32bf49e1e25b1c7ab69ab0a5507cac0d4ff79c1c3087c20d0a91df3ddd030744', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428557, X'af17d2e4dcdb2dc19eae9d9561ef85368ceec549192e0ba7e05fe40e1b678f22', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428558, X'26a25f9abc32bc0c7e82ca24aa69f03f0023b10441811afba793d7f6b4787009', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428559, X'c69a7cea96ce8465be889e02289906496a856941918da8dc51c405830fce0999', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428560, X'b1d763f165d290de2395f03e8df5abd69a895101be3dad0001ecb3bd5e718296', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428561, X'cb8d103a011d189be601588e8116edbebfa9ad5a6eb9f4823c169ef17340ab92', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428562, X'435853dc16f2100a616bb95e3d9fc7bc8bd1547279a939825264d3b80f89bfb1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428563, X'af8f9c88654f904cc031921304c08f8016c3cb0877c0d70d719b055e29f96078', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428564, X'e9eb27849d7b4dea196d9fee8643c4e2d9e9851627b06d02629855133636ea1f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428565, X'426168cdfe94f3162de3f86017e5997c4eff104c2c442d45d2467ebb3b18af13', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428566, X'7e464ff684513599434763e428b52c9a29027a7b1c51214a5c00b3e288cd0465', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428567, X'b24ac1e72ea62973d598a39d887fa8994c445ebde2a72d1861f48741d9d6998d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428568, X'1fd8cf5690ffe18cc4033f125acda674b86a51df3a3ecb350a75e8e6f9b3af25', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428569, X'715a838bd5db38b37dc927cd21d3c3695026ddff634a7af0d94de65414b5a5f4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428570, X'333dbd200941642f89f54c86cafa09f55c9d31e9ea8ee022389eb24586174a4c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428571, X'ec11afbc7d9ff675d00ece0294e00c3c03edd173a7509f99c15841954783c3ab', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428572, X'9a3995af074e81e31daa69b7e8b19d1a3c5f327e696e0fa5cc14ff8c0ea4d58c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428573, X'b0f87e67a2c7825c7180dd2b243f5cd8f058f5fa4db2a0ee3e644db7c044354c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428574, X'9755827f988dbb2b6762b1e9eaeb4901b0b4709605078509c2b66b42cf09c4ad', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428575, X'07e59c7e4a7d02d749530abec837ffd088222c8f3979949732b144d1298d4570', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428576, X'aa6e80188a54cbd9bcd22d9cfcc89ac9773631de94f667d161e3b00b185cfa18', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428577, X'54639999ebb2209839c80c4eff16f3e97ba27c6ac1386fcb25fd364555911e31', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428578, X'cfc150242ee7b5928f0e72afc4548c141c765309e0fe20fdba1a75da77469afb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428579, X'd71f13cc34ea5078782d684f7c21c4f54798b8ca6af24f7647b42619496b0040', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428580, X'c32b396fdc66654ac7970fdc49d5108c623130bc6700b081e96f69e08b0c798b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428581, X'd4f928a984e6554a9248e2f99b4ec5e4246e249ae4585937d955535c59a4cd38', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428582, X'e744ec6d3e8c63eb8d998d3924da0a98878a53b5c75ce77f0080cbda72819eab', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428583, X'7a188ba87b8bd0c5771009b88c8bb6c2b5e418780264efda75bd4deae5de526c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428584, X'5d5e82d873626a02e8e852197fa543f6f5f93101ddc6be6ae4cfb7ee98854c88', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428585, X'0a51358b25ee01c335b767183e9c9f6630ba00cc82b6186c2ed5e72a3f048c94', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428586, X'b228a9dc376720442def2c10e607929297bdc658a7dd40c6b284bfd0a9cfdbfc', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428587, X'6d8bab645f641e176939c3da3830065d814be72eee7bc04b1165f3b55f7c50de', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428588, X'0636ce0a2d12b2f371edf9670e42f644d75e563607aec30890e5237e8a243fc4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428589, X'a9db1b25189d3cc11964e5cb4c04d6653a8e8b9f634f075446fffb11f177451e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428590, X'4056898f073ac114567fce30ab4f35ccc4e209e933e8165436fa4d7151ccdd2b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428591, X'68fbd334ff4345ff4d206015f5bb45794951785d58f761cab96f6252cbfd7968', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428592, X'ab1ab8e05d8faff42a2bdde63ed3c06c2e7b055484d5fb37e175e526852402fd', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428593, X'05dbaf799fcb40a41ce4e7153916ed0b0725ffa73acfa14f945db690a150c01a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428594, X'99bb403a6ee2ea11f30dda39bbaeeb17429cab1bbf5d75c1c25fd7666d394aac', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428595, X'77758a6ec3730ec601a6102299a4827e25fd475e612b73df468ea0c60dc1b24a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428596, X'f745e69a75e4b4ae7d8ece2e9f36d3f829351693acc18bbf663fcd21a2f2916a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428597, X'af2390164e1ac28cfdbd97bac1023679a8d22550cd3ba6a1bd7b6cf44f81580d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428598, X'788325dc6ddc362bf264b9342db8cdd69b340296adcbc1a57822ead2badf2ea6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428599, X'871a7be57b04f838d53ff5ad2e65c7dddc1d3cad7d9bc1f23f0d515aaa01ad03', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428600, X'53dea87395d7bd6be220eb38f5eed5e4b26e1d7cd5b1f15b6b48246cd65f223c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428601, X'8466e3ed6e8def9cba88a176dd834763cbafd21e0b3f79304bf8a9bf4c59b944', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428602, X'afe3aab89ac295e1f41a7ed56f3a2366319f55b822b8ba05b51a065e83c9be05', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428603, X'75d3d0e57cb712b49142b1876b2874a831cbe0fc15ea4fc8f437ffc3cd017db9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428604, X'9a1b057fc14b26ee587ecddbbfb0a64b744ef01260062b80302aede80687591f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428605, X'88dcb26342904249e6da6fd8a9639d340a3d29f3e13b498403a9e0cbbc0fe230', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428606, X'6fec0424592add199314305c849b6ff2ad9de9ce4cb7b3647f92b1303806dde8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428607, X'fa59045162e8838fd2f10920a8af1a410e556570e825099fb25d5261e4d64da3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428608, X'97749484ae4f59c9acc4bc3ce0975845f7ac2f7b6d23bdba0fee0f581abcfbff', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428609, X'20e2af26405e0b9bb06b783e924a2428eab9e112f06a4182445de5456cb1c508', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428610, X'432f9eb387e0f561360dee825262f1cd2714674ee8cf3efda7c33ad621e0bdc1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428611, X'3f44dede55a53323861324d08e479f4dd836ca9a41f1d11a6c88dbec2053e026', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428612, X'e87da6dd935e5d65dd549740ba8e873b55e29810e5f36e02b6ab1f71509afaa3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428613, X'fbc551a6bcd43400c3ced1bf169bfc717423b3eab54e0ad91accd68377dc199f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428614, X'89c321cd26572d384967b28c8495f7290312741e620d52c84d96f754d9febd84', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428615, X'bcab93159b9889a4c16bcf0abe1a7924f9cbf25f7f341e8d0bb585bd75a5dc1c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428616, X'9658e502c7252732481d12046e168ed79ce7541af13258cabf8b32a87379aee3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428617, X'02cfda33c1ae835ee03a705c5d0ca6cf1837bb4efc3521de5bac6e7a0e26c19d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428618, X'c1f2836d869d045842c81018c74fe29baae503b5094bb656eefa7e7e3afdcd38', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428619, X'5df6704cd04be2dd1570d6a3f35e7cce60cd6d2c5753338b71e48292a81d4121', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428620, X'f224ab18859e6f9545995c2afff7e5161932c93462834a74d09e19d66daa775f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428621, X'f6ea0ee62cf6a4ba70a87103d84248e96a7dfd0e9bf58d1ae0fc592c1857e287', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428622, X'715bc582156504e807d618b984920e4319def0767f1ce1a4f56d9013cd26f03b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428623, X'9d8e053ed23f25e9c374546f3af097f9b52a90130c52e3b8a90e5ec4b05113d4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428624, X'e502fc9cf91380e3e299a089bf69cc782cf9b96dd4cde50189343bf997a14662', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428625, X'1dde6b9ab37b8a946844f2a30e848b03cca77c9804fc486bac0242a02b40bff8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428626, X'e75368302a62d8e0bb9d246448f2b26e367123aac080f2594f8407bcc441d3e6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428627, X'01d881f444a3165ff2f5c0d591cc0407d7a9fabc1611e6bd9a7b35eb478dc7bf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428628, X'36bc66078e0b6c19460e67272a504e423dfa26ddbfaa303f192729dbfc3d3959', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428629, X'64d4cd32be14efc00909488b68aa8b829922608b9d99912b6cdb2dedf86a57fd', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428630, X'3d733df726412c63c2b793be96b5b7de74a0d6171b4812a224330e17b989410c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428631, X'1d82bd04496dd70e316e410cfd1e9bc309f4a51f8492297325de511d57ae5985', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428632, X'e6d2d30fab9af2f7b642caf07c548466c6a9b22cf46078d14c8ee131416021ab', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428633, X'f9194c92eda11ded76d24dd8e3f9307dd0b9069fb95ed23d33c8ddbf52482e63', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428634, X'd9ee6556f9a5e86b1532775e4389f327d4364eb4622dfbd550fc8d890dbe844d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428635, X'bd26ecf1ef4f12732193c6a3b654267ad86e8baa52645c5e8cb9ac0a9750389e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428636, X'ef1cba23ff7d90b4ff6219738bfb32e575ac67c4f1fa99844b51fe82e44e47a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428637, X'bdaa34c19baa0b08de8992c91d08c8a1928554d5f98fda750a703fcce6acf17e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428638, X'463baa3751355157d84f6242f0fbbf390ff003b7d3df136068953992becdee63', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428639, X'c6d615ff8da3c134a7ffdb4eb3c0afd7fef046c78001b8166b7efa52db28b9db', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428640, X'7be867dc6d47894d79dd221d9536a3636a7f726b120f0113125d215c5659f0f2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428641, X'964e1a66f8995e514e2e4969c8d429133207dd6c7beca1053767288b4e1a02c0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428642, X'6668db51b9c5be320ec2593b8a8660b3ad1eebcaed4b8aa62df9812f7f2390ac', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428643, X'b51faf16df6d46fbcc92b6b61d50d9c27289a8fdd55d0bf8b9340a636ca0e659', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428644, X'd00feaa9f81c9ab32f4d62ce3d81f3c5bf5d9571b9b802bd19a58df044cd8fab', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428645, X'b4c92419e8b498d111e5670621a1e61003763e9fbeedd6c4fb3eb69a67a8fbe8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428646, X'ca6bcad8d5b762b15ec4e6a3809824ca6af936741a2d3787a5fb95c108a53de9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428647, X'72d76ba2f204259ca9ab745e4eb52475aeeb0f0b07f6a86a2db2867c8618ed8b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428648, X'fe844f91f2e6dff3396d3058ebfa93ae3ccdf8ba9ec4a834338169d94d755817', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428649, X'da1140143ddc4258539fd4d3bc33839f7348b3a07ccb530965ef5156d5174012', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428650, X'a81a4ca9d70d59be901ab4e1539e5069477862bbdb8732a0838f11bb72afe09b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428651, X'5e9283ac90ecfd461a19bdb6bd179265757715611294cbbc211617b945089828', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428652, X'216cb38a373c743f32b8dcbe9c284605ce4a6ee0e03162b97000e8fcb7e34145', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428653, X'5271368515037961051e3930d7c20632226d1f37836556630325915740187cb0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428654, X'f2c053256afbbd2b64607c69c6afd52ef08f3c7d236e03eec9836e016aaa21fb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428655, X'7572db055b2a9030c0cc9e4f7f234c338d5f6a7eee62413d70a7a7fa56e4dd8c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428656, X'849ed5d3cf6fcc5a14117b090af595fcc239f161dc9b58ab6fc74b147d4fa371', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428657, X'054786d2e66c2a454f622ead3ef4366ba41d9895cc64ab31c287aed38cfd14d2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428658, X'c8907a8c67c433e87a4b209f519ea4d111509b3ed71472df39e7856d1f200e8a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428659, X'82b48408994fadee91047364502580e9a58d5a8d4907b9a219af7b6c223591d3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428660, X'cf010bf3b28c157b9594f5624b444417eb74d5d91f76c6eb30cb3b9d6dcf6e5c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428661, X'e8170dea0cf78890bf6695041f7c6547a2743cae87949ebe53c47e6e31d2b558', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428662, X'6b31cedd475cedb3cb8a351e0ece21d8c4b472d91f9fdfe54aa7b6523528f078', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428663, X'1beeb3becf903d5427a035519262157b4d651cb553784cb225cf694d0cd8e4a8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428664, X'b1b611552dae07562a5e8a1f08ff01702d2152ddb4497ea7d51533f60f48de62', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428665, X'68d806436d8e6b3a133691be116f07e88e866b8b397eb955644fb16a0556fd1e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428666, X'd4ffa286d8544802d8f205eb8798ab537bf090fc1e4b2684dff155c6695602af', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428667, X'48e028ea6e1a4e65439bc270e03ca914a32123fe91bb2278609e48bd29959b00', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428668, X'2a1e203103a464e16093500506d3ab16890898746f0ea0383e4bc04ace865ba3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428669, X'4bc230b3c2e82d419682f4084d3a06281a57b30551d6980e6d414fb1a3c25a56', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428670, X'ec90a9f2538e0d009a8f96aa9c1273f9e6b92463f8ee676c5ed745e7236c6448', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428671, X'260609097bfc49eca069a33acd50cf9799928265cb5a00d517438c08c57c8656', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428672, X'60968e6ea6ed5551222268fdbc0613fb3b7d0fabd9f71fe82fbe9ee03f215096', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428673, X'5242bfef26a908052401854600a339189a6a9752d0e7d7bd7ad1caec98fbac09', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428674, X'72c971bc1ed3737156889960f5d0ad05655a9ebd285bbec1543304af2fe0296c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428675, X'04c960ef2430f2569e17b712317290d56e94e08c3531c078cc6d97b61a2aa87d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428676, X'd6f420a6dcf5f30609df1b8defa1bbdbc97bf4ef818c5d7bb3d840ed209b1e74', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428677, X'1646c2a80a856f152a61f07c08ad946301a6cc32fbd8d9f18b149a986e1b4b74', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428678, X'edda572cdab97071c360ab73cf5e65a2845080ec465e51932d6714ed71ff5dfb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428679, X'aa73063f20b4de4f756f36b9fd88a8a9e3f65f70d2c3ca97500d5cd5336754ef', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428680, X'cc9d7da1052d79b133009c369349daef55ab35d41acaad12667de0dcdd90182b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428681, X'b52acad0101d1389a92e66a242461ed83514539cc1d254d6aa66ab1651ac5961', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428682, X'42424c30ad6cf22afab0c8081725618956c63317aea45c5de3350723c615ebee', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428683, X'998437391790320bdde462d56b951476490d4bf399a41f34ebc15cdf6889004e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428684, X'a2de192a1901e68e4775f57b926007a4605cc7cee419f08a10fa22a80523a3f3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428685, X'5cf2da70be25b1aaa6a4d9a813ea13f339f90a83bb4bc73eca4ea12c67da2fff', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428686, X'092cfdcda9aa719ca303bd55656604bea900d82936b9446cd425e95277a6e8fb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428687, X'c6f84f6da768f429c39481880ae7e12dd6add5f73ce279a253c583f96711a8f3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428688, X'3f9f6dd10ec823fda1572a64c05331ef1c7eff8c31a00a94d1ab17b190416cdb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428689, X'dfc37abdd048766a3ddb21301c9742880bbb029cf8797502a7595ca17deceddb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428690, X'e7ef67bb5f2555606e0bf7b9be0f548b0fcad9ebc241b148a6551f6058bc1db3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428691, X'd44ccf19325c8aedcd3d434e3a4ceba636ba8ad9a35909a2247e38c007f44d72', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428692, X'066dff4a666bc9bebaf0e7a5bf8bf7c3805f71b5043ae5acd7b897e983c81f76', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428693, X'e58ad532f7cad4164f97aea4f0aa36e632ccda933d497914fc85f219ce3ea735', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428694, X'0a7c01c1c04fa96fc43b37d32cee968ad8b46c2ea95ffbea29b14b2a89137a27', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428695, X'7eb6e8c8b8c4a4a44b86dcc29095eacbfa7682e94e95ee302a9719a05b433de8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428696, X'ff48169026ccec0f02985326a4dc641873e750205d08807ce19548194005231e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428697, X'da36e098c9b876516e5f78c8280bfc12274aefcdf45b2a7c4a5c4fe428c6dcc9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428698, X'067a7ee1bf8099bfa9074f75f08d30dee66853e04dc2ed2a27a8aaa25f47892e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428699, X'e1ab61d9cb072306222222bcc03f79ca96c4807f098e963d02499d8a6b76708c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428700, X'8d621994239c554fcdbf32da1cd8c4b4b27a0c412dd63a7672109c15e7d3c1c3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428701, X'4eda4850d54e34ee878ec197031ca0c62b3fce73c0eb0727292c063a0dad8bdf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428702, X'5cfd41a934028fdc5c1a57cee08c783ae0f592063425a043eccca7358d5974de', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428703, X'9d17c9e7ba2925417de214dc707e00d7d1e3ba576ec40494e2e1568208343866', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428704, X'9a63f128673ba7c36501aa187e93ec1840acb1da7a1eef79aefa7fc50de08fec', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428705, X'310be539be93b71321b990f5febc9efbf3d1dc8b0e8dec79da8e96d0147478ef', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428706, X'228b20c898c168e46e3b597904f83678a00f7eaab0aee5a9aef64ca262e04b2d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428707, X'9ba293f7c5aa359c11770ec537f42dfc8f73d3af791ef333c660ee8274706270', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428708, X'a13b8b49ecd2d0c9694a02664a622ee791ae67045380ec92e0d7587b7e7321a2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428709, X'530b7d42982b20b08079a6c454924b44cf6ff61c19ee5dab1044ea9b99cd450b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428710, X'2fa506e75559126b1f17dba35570c1b8a52a131057d336d8a6f847a27dc746de', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428711, X'19d3283e2f8241e946ca82224bd1ac80404f8cfff244ef839e93b609ee3d050b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428712, X'567a5cf0ceca16fd675528189e5b3c3e1f3844708581f2f740318c43d9b52f7b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428713, X'e51aad81d2dc04711362bb4672a122194726f1117b12d6497f3d7f7f8c1e0d74', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428714, X'ad94eb8f6518427c272d866cf95da413c5855b99da171559aa3163ac75daf2fe', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428715, X'c0914cd0b1d86ce0a6eaf21967471cd6c5ecea411afdf0a318a4e42337bdffa1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428716, X'0542d1c91f20911bb27f1052a455a80f081e5ebd0f97fb20f051c4a89d5e1785', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428717, X'37438ff291fb4f8906d6a4e38657d3e8821c6528c0c7189090149939f4d357c5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428718, X'd27cc7860ba726fa293847ac4fdcf617c0c6ec5ae38ee5f5b597dc06c92465eb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428719, X'0e9175f3e42c82bdb158a1225f697accae90d51213fe3231d465854028b0b834', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428720, X'04aa5a010572d8578f41b9deb94d31dd68f000dde5bea8015b3ea27cb8a60a70', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428721, X'19f6009c21a7cd657f036b719d607b70cc4fa07396e4765a02adb60f11a33dd8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428722, X'0c9d88dcfcc04f5cdb8869d7a912121069e6de1bf6c2efa584c0938822b5a693', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428723, X'addef432901ed74acbaf7ce4d462eb9ec6fe387277c0d49c1e85bc829c4fc2a4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428724, X'd3a8a23b1c134fb86d95150a3bd68d6d6b04a124eae206c58946725226da8a89', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428725, X'40084beddd5a48f70a03790808d5c8e0444269c250ce7bb8c7ed7fe8ad36ed3f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428726, X'65cf6ccb268629f9681df50df5b2144747f41dc8c193299c931cf9dd7cf45aaf', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428727, X'aed4951a75f2a13dad1e2e8574ed93988569394ba08a55d614d532f993cfafd3', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428728, X'8201988ab1ed31a8d443ca7403d3044cb5d17a95df30959678b8893a90c47a5b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428729, X'b656f147ef668249cc2c39c82fae935516b0d3b3fe7166845950b2741348a044', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428730, X'2f18f255ff2eb2076f865c9118667b0123995eab1b3d09e31cfa3cf1312653f7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428731, X'4b9817b03a14d868ad3470124972f4568c7449d09c663332f01ad99df58a4abe', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428732, X'f7ec2c66e4e923af0b793dd60042c6cdb20bc48a1ed6074cc569502ac44159f0', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428733, X'19e07ad944434926d0b7f89e79ab91b5e815dc766b807ee18ed1adb728cf5d36', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428734, X'bee6fc15f9f5a8a7f85519325b1db87b9c84c9d4be4b7927648563d42a95cec8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428735, X'8254002251ddc87bcf7c60e5d103ac5c72c4def3de8424ecea00ae97e482db7d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428736, X'36b549e5ca025f07c78380761a7298b474392980b1564113fc859549021682b7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428737, X'b1cdac5b228d6e84230803fc83b78fbd3d4841c5a4cb73ce98ae86a2c0fb383b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428738, X'77088d8a5287f8fcb9f6a0177fd5887a1a9230fad85f85dd0d7e90f56faff284', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428739, X'05f6cb06a51b1ab2012b6193ff6e995db3edf011991d37fad9dca703a16ddaa1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428740, X'be75753728816bdfc4656d6965bf26f4e9215a0217bc13247535b1a99898d1ac', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428741, X'd12784dcea4c6b4e0d97c6d45b5778ab0a70e8c87982c053feb0cd436e626a1c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428743, X'fb9a70c320a48889288217921eb55ed8fdd96d2b7ebb555154910e2590c928f6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428744, X'a10f911a54e972c42a4ec0b8200c8ffe5025c9079288a3b48efb20dd8a961c9b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428745, X'bd9f1954a73f2f8e161f2f801adf331c4fe0c44b5fb8aed8018af319270922e1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428746, X'211781b6e567c2383daaee5baadcc618cc59d3a9fb949594cd9295730c47f37f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428747, X'6eed734f3fb43308dd34950cf4f5068a6ce3ed4330cf3fabd521908808a90bb4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428748, X'7ee5a72658fd633eeadd62b244e9bec85daf79658fc8a8f129fa75fc716ac97f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428749, X'029cb1277c7b7070a312c367d5721a7e5ad946aadd4a7aa7b2c00f4e4168be76', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428750, X'2cd68043f034cf9a06ca01b3648d9435727ccdc564aeb095b7eff5ea6d4f15c5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428751, X'c35736cadcbe99133b8cd12e0061c2ab8d8e22c0ca9301d2de4eaea7d159f1a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428752, X'1ef5bda272c1f909e84658d6d8c0710a53966f8838c1d2c4ac81ca9a45fe2706', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428753, X'0f21f9e11070e50315c41b1072ddbec3ae58454d522198137f0f8aafe8b1fe49', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428754, X'9800b4ec0dbdeeddbecfb9b32d76f7ad60d47d7d457a7b33dfd78b025106fedd', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428755, X'd6fda1e8c702537c52c7113fbb2f933f1f7bac7ffb1a2cddc3acd205547fc3a7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428756, X'c4986047886bf7b8518f4658d1dba63dbf47df6aebf0e2994d0ff160a047c926', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428757, X'9cb932f88f4624cd2417ef3efdd5ef716bd1076bc2b6d56bfdee5065cea7a167', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428758, X'4a18dc97b8da2f0a1485bc9ce57696933bb8e45a896588d2b1fc8d9b25af9e2c', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428759, X'4965cf958a23feab08c85706c8a4de23be517fdd986c52014e7ee77dd1e991bc', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428760, X'8a468a2852d50745e45b5c94027a07e7d23b87a1e72a560994548416b67b8ebd', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428761, X'8ab6303e406e61d86edc8ecd1aeb9867b42c655eb91eb25a5048af257a89edf8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428762, X'361f13714488df587ace319da060ad9454b25c7631620b6614fe2a6521b08ae2', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428763, X'019d24a6a8974d71da0557b37508fa82967ce2c991d1d2df6bdf46eeccd958ce', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428764, X'4966ec1ddd2e779a995ff970b9f37f07189b01d232c6f70d5223c78c66e164d7', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428765, X'5376ceb9259bdb75d78f3e6c50b837d44eee914aad5e8d20cbaa7b1e814a608f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428766, X'ffb55face10d4186fe673a249f3bd27658cd934fc64ac7290f6624e203a4c4c4', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428767, X'ad2354d61fee4db6cbb03288be45a3351288d0dca65e8a8dcbcc99fcd035e822', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428768, X'3f255f0a7c193c6355a40e684b635a198cac7907cbe6d65cc5bbb87c4469fa9a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428769, X'7529e084eb70b452a10def2a9d2d77ce3b60bb2d93b4ff515196227eb6aec750', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428770, X'acf6ac3181b398e3ae1e34754fd4d3528619774886f7918bd8cc12af0440cf11', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428771, X'd343248afd8d4ce721015e73c4f6947a948ff8e9cda6a83a26e1f81828c780c6', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428772, X'8a94846bf54aa23285eddf0598a9e0fab67ed465f1cdfd2b2a3c14efc9cc3938', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428773, X'c20bba21f5d180256f4df0b5eafc52d50752b70e38121d5ce8888ba062b35af5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428774, X'049413cee9f4da26e070f28182a6386f520c1b1db16eecb8f8ae727eee3de29d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428775, X'c5c88c1f2947fe96746844284ac39f3c2ccb9e384964bdafc6605becb0b4320f', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428776, X'258ff0786579614bd66d7fbf81a70689a1208ee3fd8f5303178c79e4f0002c72', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428777, X'a8761d4d816d64a1d3b08752a4e1737bb9f57e3ab463b20bf3474d42979a4659', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428778, X'6ba4301f32caf6fea0448423cc025738a4a6c35c48e9739d77844aee4f44575a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428779, X'987edbbd2b444a4450d9dbc985934db52615487c968a2ac7a1670434d4bae32a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428780, X'40dafbed8544a5bb458f174fdc67faf4507700273ec208de79bd4013f25bb725', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428781, X'c07254c2c77c528bba9460f624c55ad22b0a2fd9e9f7cfb3d77eeff32ddfb64a', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428782, X'80a90bb1747af73b8099ac0202353898f1e23a41f3f638b2045a17e460a3916b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428783, X'713a365010ce48fdfa32c7131c87cc50b1e108170d5358e6ee76d73b33936aea', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428784, X'ad1fcfe47d7459dbd7ccab151f8acf9abaa45b70ad1a3a3a44ef663c2a1c3c06', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428785, X'c9bc31fe0f6ec07eb29e5ef6cf7f202935d9b7db40ff71f7ef06a275eb5015c8', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428786, X'f558443f0a4e8520b32b7bb52fd47fc95cc1c361e8ef075df890dedd452ce3b5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428787, X'2a67dbbaa508f73e27681277c216d48c9f9b5368dd03d92ddcb216e497f67d3d', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428788, X'1af685a54f017a96f99016e8596d13def4f4898278e2de937750d47b062e1c6e', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428789, X'cdcc4fd3e39280303c8fc68dbb9e614fa266360fb92c445673da9cd8ed276c67', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428790, X'2a05e64f350bc8bc47a00987a81f783f7f0933176f27f60e906645c0c2ba4edb', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428791, X'4bed0e387b67aad67c39f8c3118af66048b62fbd41cdc28dff236f0a896144c1', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428792, X'61691a5a00ee9f9d4276c65c641367da4d6ef3b9d777d3d48c49fdc253ef2e60', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428793, X'8695d8e7a4ba27514d5086c837bf43da8a8c864ebb7a5708a9e5617e055f91d9', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428794, X'116b35083be7774fc915fcefb77cdb9fa40dc9cd5e41a42da9819affd34cb00b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428795, X'fc38d191f2d7a16a732f5aaf29a27398633639197a7f4aead9e46b06686851f5', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428796, X'37991e45383a09960d8f69e32eb5cdc88b0fceede723e0fe2c0bfa7cb9d11892', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428797, X'7e446871af420377d617ac77cc9820f6952a4c79f2cde94c97d13bf0cd308142', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428798, X'3fd661cd02712c54bab9a2e4410b70d03b6d200ac9e754fde54903d0e694365b', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428799, X'8ec7333be2b1f19e8d41dbdc7847c8e444bb2157ce93f39d982abbc8bb28a890', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428800, X'a000462b5a0bd219346c976540b8cf11255df82c7461b0ab1329c0cc8274a962', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428801, X'f028cb929347dfa2b2c71206a4b4b0ad54dd6480ff675342bdc5cc8053038003', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428802, X'e523eea08fea4c43453f31eb82a087257e722473e19ce199cf5452f5972fd024', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "blocks" VALUES (3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 0, X'00', 0, 0, 0, 0, 0, 0);
INSERT INTO "ironwood_tree_checkpoints" VALUES (3428392, NULL);
INSERT INTO "ironwood_tree_checkpoints" VALUES (3428496, NULL);
INSERT INTO "ironwood_tree_checkpoints" VALUES (3428640, NULL);
INSERT INTO "ironwood_tree_checkpoints" VALUES (3428784, NULL);
INSERT INTO "ironwood_tree_checkpoints" VALUES (3428792, NULL);
INSERT INTO "ironwood_tree_retained_checkpoints" VALUES (3428496);
INSERT INTO "ironwood_tree_retained_checkpoints" VALUES (3428640);
INSERT INTO "ironwood_tree_retained_checkpoints" VALUES (3428784);
INSERT INTO "orchard_tree_checkpoints" VALUES (3428392, NULL);
INSERT INTO "orchard_tree_checkpoints" VALUES (3428496, NULL);
INSERT INTO "orchard_tree_checkpoints" VALUES (3428640, NULL);
INSERT INTO "orchard_tree_checkpoints" VALUES (3428784, NULL);
INSERT INTO "orchard_tree_checkpoints" VALUES (3428792, NULL);
INSERT INTO "orchard_tree_retained_checkpoints" VALUES (3428496);
INSERT INTO "orchard_tree_retained_checkpoints" VALUES (3428640);
INSERT INTO "orchard_tree_retained_checkpoints" VALUES (3428784);
INSERT INTO "sapling_tree_cap" VALUES (0, X'0100');
INSERT INTO "sapling_tree_checkpoints" VALUES (3428392, NULL);
INSERT INTO "sapling_tree_checkpoints" VALUES (3428496, NULL);
INSERT INTO "sapling_tree_checkpoints" VALUES (3428640, NULL);
INSERT INTO "sapling_tree_checkpoints" VALUES (3428784, NULL);
INSERT INTO "sapling_tree_checkpoints" VALUES (3428792, NULL);
INSERT INTO "sapling_tree_retained_checkpoints" VALUES (3428496);
INSERT INTO "sapling_tree_retained_checkpoints" VALUES (3428640);
INSERT INTO "sapling_tree_retained_checkpoints" VALUES (3428784);
INSERT INTO "scan_queue" VALUES (100000, 3428393, 0);
INSERT INTO "scan_queue" VALUES (3428393, 3428804, 10);
INSERT INTO "schemer_migrations" VALUES (X'07610aacb0e34ba8aaa6cda606f0fd7b');
INSERT INTO "schemer_migrations" VALUES (X'07770bfdc54940699e05822458f81cc4');
INSERT INTO "schemer_migrations" VALUES (X'0a35a9e46c1d4f7a9c0251b8de4f7c33');
INSERT INTO "schemer_migrations" VALUES (X'0ddbe561825942129ab766fdc4a74e1d');
INSERT INTO "schemer_migrations" VALUES (X'0e1d42741f8e44e2909d689a4bc2967b');
INSERT INTO "schemer_migrations" VALUES (X'0eaf99b94db74d0bb0bd00a9a6bbd8cf');
INSERT INTO "schemer_migrations" VALUES (X'156d8c8f21734b5989b675697d5a2103');
INSERT INTO "schemer_migrations" VALUES (X'1ab3caf9ef1e482c93a3a3f1080038df');
INSERT INTO "schemer_migrations" VALUES (X'1f5420e3f8a04afda9e5e20fc6fae271');
INSERT INTO "schemer_migrations" VALUES (X'254d4f20f0f6463580ed9d52c536d5df');
INSERT INTO "schemer_migrations" VALUES (X'282fad2e83724ca08bed71821320909f');
INSERT INTO "schemer_migrations" VALUES (X'2aa44e8ee8a747608de4501956c969ac');
INSERT INTO "schemer_migrations" VALUES (X'2aa4d24f51aa4a4c8d9be5b8a762865f');
INSERT INTO "schemer_migrations" VALUES (X'31eeaa720c174e22b8023f8161d6accd');
INSERT INTO "schemer_migrations" VALUES (X'3a2562b3f17446a1aa8c1d122ca2e884');
INSERT INTO "schemer_migrations" VALUES (X'3a6487f7e06842bb9d126bb8dbe6da00');
INSERT INTO "schemer_migrations" VALUES (X'3d1c7a528e0b4f6d9a475be2c0f19e84');
INSERT INTO "schemer_migrations" VALUES (X'3d4f12d63da94aceac65a0dd0a7adc32');
INSERT INTO "schemer_migrations" VALUES (X'47c0e9c22eda4b9cbe1563c636c0e1c7');
INSERT INTO "schemer_migrations" VALUES (X'4e68277f6269467e9437f3853cc4a41f');
INSERT INTO "schemer_migrations" VALUES (X'50fd092d97b944cfade986b526e4cd50');
INSERT INTO "schemer_migrations" VALUES (X'51d7a273aa194109932580e4a5545048');
INSERT INTO "schemer_migrations" VALUES (X'547331735f3c4870831ea48a4a93b1d7');
INSERT INTO "schemer_migrations" VALUES (X'5775610295834af5b4115eead49fc9f0');
INSERT INTO "schemer_migrations" VALUES (X'604349c75ce54768bea612d106ccda93');
INSERT INTO "schemer_migrations" VALUES (X'62032f4a88b5454da59110f3d4c4d2b7');
INSERT INTO "schemer_migrations" VALUES (X'6492556765ae495eb6cfd5f56e99e422');
INSERT INTO "schemer_migrations" VALUES (X'6ad71499aa45439d8b4b3f7cff9c0017');
INSERT INTO "schemer_migrations" VALUES (X'6d02ec7687204cc6b646c4e2ce69221c');
INSERT INTO "schemer_migrations" VALUES (X'6d36656d533b4b65ae91dcb95c4ad289');
INSERT INTO "schemer_migrations" VALUES (X'6f2b1c849a3d4e50b7c62d9f1a4e83b7');
INSERT INTO "schemer_migrations" VALUES (X'7029b90465574aa19da56904b65d2ba5');
INSERT INTO "schemer_migrations" VALUES (X'702cf97b83954edcb5845c9f87f0ef35');
INSERT INTO "schemer_migrations" VALUES (X'73d751a3dbdc461a9154e061903aae4f');
INSERT INTO "schemer_migrations" VALUES (X'761884d630d844efb2040b82551c4ca1');
INSERT INTO "schemer_migrations" VALUES (X'772a06323d0e4dffb1f8c64863eefaaa');
INSERT INTO "schemer_migrations" VALUES (X'7b2f6a419c3d4e588a172f6b9d0c4e11');
INSERT INTO "schemer_migrations" VALUES (X'7da6489de83546578be5f512bcce6cbf');
INSERT INTO "schemer_migrations" VALUES (X'7f2fd1b318724b9088ba7d02b470090f');
INSERT INTO "schemer_migrations" VALUES (X'835d61e15b884f4492b3746fb9173360');
INSERT INTO "schemer_migrations" VALUES (X'856ecde7c67047c19345b80ba5b12c4f');
INSERT INTO "schemer_migrations" VALUES (X'88cad11149144382a78fd85bb3507c5c');
INSERT INTO "schemer_migrations" VALUES (X'894574e0663e401a8426820b1f75149a');
INSERT INTO "schemer_migrations" VALUES (X'8f290af0eb5a4f1e88d43550fc0ff911');
INSERT INTO "schemer_migrations" VALUES (X'8f4c321004e149eb9de2d713ee0a8426');
INSERT INTO "schemer_migrations" VALUES (X'9302bbcf425a426b9074084d626e45bd');
INSERT INTO "schemer_migrations" VALUES (X'93278b0f77fe473cb88e7f285da38dd3');
INSERT INTO "schemer_migrations" VALUES (X'935cd43609fd4f4fa808260ee399cb21');
INSERT INTO "schemer_migrations" VALUES (X'944f8a1ebdfa4d5290ca663dee8efc62');
INSERT INTO "schemer_migrations" VALUES (X'96bc0e7251cf4cdbb11f85a460db37ab');
INSERT INTO "schemer_migrations" VALUES (X'97ac36a9196f4dd9993d722bde95bebc');
INSERT INTO "schemer_migrations" VALUES (X'9fa43ce0a38745d1be0357a3edc76d01');
INSERT INTO "schemer_migrations" VALUES (X'9ffe82d43bf5459a9a217affd9e88e95');
INSERT INTO "schemer_migrations" VALUES (X'a03b0d6a60854859ae77bce948345214');
INSERT INTO "schemer_migrations" VALUES (X'a1d4a28c75824457b0f4d3f297b62a71');
INSERT INTO "schemer_migrations" VALUES (X'a2e0ed2e8852475eb0a4f154b15b9dbe');
INSERT INTO "schemer_migrations" VALUES (X'a6ef40c7050a43c6a4e22f034168c979');
INSERT INTO "schemer_migrations" VALUES (X'aa0a4168b41b44c5a47dc4c66603cfab');
INSERT INTO "schemer_migrations" VALUES (X'ab1be47edbfd439a876a55a7e4a0ea0b');
INSERT INTO "schemer_migrations" VALUES (X'b3e21434286f41f38d7144cce968ab2b');
INSERT INTO "schemer_migrations" VALUES (X'b6f3d060803a4b17aecd6a02d9cb2249');
INSERT INTO "schemer_migrations" VALUES (X'b7c4e2a19d3f4e8ba6c51f0e8d7c6b5a');
INSERT INTO "schemer_migrations" VALUES (X'b8fe51124365473c8b422b07c0f0adaf');
INSERT INTO "schemer_migrations" VALUES (X'b951587c34fd4f02a31305ff7adb6268');
INSERT INTO "schemer_migrations" VALUES (X'bc4f5e57d6004b6c990fb3538f0bfce1');
INSERT INTO "schemer_migrations" VALUES (X'bdcdcedc7b294f1c830735f937f0d32a');
INSERT INTO "schemer_migrations" VALUES (X'be57ef3b388e42ea97e2678dafcf9754');
INSERT INTO "schemer_migrations" VALUES (X'c41dfc0ee8704859be47d2f572f5ca73');
INSERT INTO "schemer_migrations" VALUES (X'c5b63b3b81904d0fb2173921d7aac225');
INSERT INTO "schemer_migrations" VALUES (X'c5bf7f71229741ff89e175e07c4e8838');
INSERT INTO "schemer_migrations" VALUES (X'cbf88891ba834329a798c986649d77e8');
INSERT INTO "schemer_migrations" VALUES (X'cc104d0d54d64e079404202676561d94');
INSERT INTO "schemer_migrations" VALUES (X'cccc623f324343c7b884ceef25149e04');
INSERT INTO "schemer_migrations" VALUES (X'cf147152694f47e88c05c6dd853ac329');
INSERT INTO "schemer_migrations" VALUES (X'd334a9fab9dc46bd9b311fba6aa47f55');
INSERT INTO "schemer_migrations" VALUES (X'd7ab0ab214874cb7ba7472ece5fdba2f');
INSERT INTO "schemer_migrations" VALUES (X'd956978c9c874d6e815dfb8f088d094c');
INSERT INTO "schemer_migrations" VALUES (X'dab89587cd0543b0a5b58cb64a702791');
INSERT INTO "schemer_migrations" VALUES (X'dba47c8613b5460194b20cde0abe1e45');
INSERT INTO "schemer_migrations" VALUES (X'dc0d6c91b3db429e9a7bd671cc19656e');
INSERT INTO "schemer_migrations" VALUES (X'e2d71ac56a444c6ba9a06d0a79d355f1');
INSERT INTO "schemer_migrations" VALUES (X'e5339f96a98a4047827428efdb9107ce');
INSERT INTO "schemer_migrations" VALUES (X'ee89ed2bc1c2421e9e98c1e3e54a7fc2');
INSERT INTO "schemer_migrations" VALUES (X'eeec0d0dfee042318c685f3a7c7c2245');
INSERT INTO "schemer_migrations" VALUES (X'fa934bdc97b649808a83b2cb1ac465fd');
INSERT INTO "schemer_migrations" VALUES (X'fec02b6139884b4f969998977fac9e7f');
INSERT INTO "sqlite_sequence" VALUES (CAST(X'6163636f756e7473' AS TEXT), 1);
INSERT INTO "tpir_candidate_windows" VALUES (1, 0, 60);
INSERT INTO "tpir_coverage" VALUES (1, 1, X'76a91401a38d8f5ba691b969f4933353d9650d99c7d1e088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (10, 1, X'76a9142490f016f2d18afad0869e669d846105b5cda39188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (100, 1, X'76a9142ff53f7471ccb74fd481799f3b3cf1e4ff43a0fa88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (101, 1, X'76a914339381ced0df2438b46e31973d76949edf88b05188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (102, 1, X'76a9143592c1178f416c9dfea05acfd7f3d1f616a3e71288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (103, 1, X'76a914362af5560158cc127e8b9cfc5fb3f22eeaee1f7988ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (104, 1, X'76a9143f367a3ea203e089c98e96b637775061658c319c88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (105, 1, X'76a91443da156a65f01eecdf28eaa146472c99b7a2f9ed88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (106, 1, X'76a91449c550ec97f2455882249263f6b129339563310d88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (107, 1, X'76a9144b1375e8a32815416a58be1c39ac837f5b25bbcf88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (108, 1, X'76a9144c8eb8685b443da6b6278c45f3adae852857eff988ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (109, 1, X'76a9144d33c113c3358640df7f49d69890a1fef9428eb488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (11, 1, X'76a914256b5ddc95bc330696e5a34e3e206ca58ba78d9788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (110, 1, X'76a9144f615902f3a86cf8eccc3aff5c991aee1c0d588f88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (111, 1, X'76a9144ff31ef9d90d53a9d51663b64cff7f23acb355d588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (112, 1, X'76a91451907d21de12bcb89ddb70c31685f9cc87f6621288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (113, 1, X'76a91451c363c60d721d1d5ec2ed4cae30f461b39f569888ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (114, 1, X'76a9145219459f5cf88fdb60393379bfe6016a48c21d9488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (115, 1, X'76a914543db4565f675d677a05ff5359864d624aed168388ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (116, 1, X'76a9145827fabb59f1b7e624bd1f9e1a52b593eacc03a488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (117, 1, X'76a91458cb9fc34e426630a4dc277b34912e12b3d14cdc88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (118, 1, X'76a9145afeb4c3e13653a53a0d6c0e64464b67d62f397688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (119, 1, X'76a9145ceb497978d8c20206c066310cad05c763e0993688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (12, 1, X'76a9142a224ebe6d91e66240fe49eea837f3d4ffc632c588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (120, 1, X'76a9145d78d48fb921730aad494e6e6458300b02c6355c88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (121, 1, X'76a9145f07d8c4b118d3493a354666cff42ff3375d710788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (122, 1, X'76a914608d6c0d55e6f02c9e62f81dadfa3e291eed102088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (123, 1, X'76a9146341413871fa17255332be5750548eeb956d18c588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (124, 1, X'76a914651f6fd74aeb850f5193a3831d6b9d852242156388ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (125, 1, X'76a9146648ecb460407ca426dc9f74ab5bc954ea6d8b3288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (126, 1, X'76a9146bec4fe4ffe2316f12fd8edfba57fc5d744025f988ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (127, 1, X'76a9146f52d8e94a4dce5d6a652e145a8f4db7d7c991e088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (128, 1, X'76a9146fb9c8dc87f1e371a75d5e9f6cfaa3627aaaffe888ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (129, 1, X'76a914715df7dea6dd8fb86c8a5ad145dd1fe3dd1e0f2388ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (13, 1, X'76a9142a45320c87e003f50a7080b84e04005c851679cc88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (130, 1, X'76a91472d5dbc2bae9c92965270b97555e5c3351d7d6f088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (131, 1, X'76a91474d1a6d961dc5f43f26e9acf331c7363d06e7e6b88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (132, 1, X'76a914756a5bbcb7ed38da40a11b7273243328adcf513788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (133, 1, X'76a9147d7c09623db1cdeeeeb6ad537dadfbfe8a8b5da088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (134, 1, X'76a9147e0fbf3918dc5167199708839883759b50f2a7b488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (135, 1, X'76a91481d1d50a234c88d6385267a0aa3a86f74eddfadf88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (136, 1, X'76a91485b9b9c46f230eb1db32d45a0357250efc3566d688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (137, 1, X'76a914889b67a8d5bf3499a3767814bd4f4b01bed4cb6a88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (138, 1, X'76a9148ae4db39f786dfdd3e97c13de078cbd2ebf60b5488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (139, 1, X'76a9148b3e08a16104d16d3c3142ea8f81cade8f3605ff88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (14, 1, X'76a9142dbc35218aab094fca18927b7adaf9d7be59b94388ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (140, 1, X'76a9148bfb0cb17692970da70f977caafebf91c9c407fc88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (141, 1, X'76a914900a44ba8413b27eafe7d3cc2bdae17d5683a47288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (142, 1, X'76a91490c2744262846d6a26ab0c3371b29127a710deed88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (143, 1, X'76a914932f8ddba21c722540844e06d8063a7214a090e488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (144, 1, X'76a91494de5a331a430d63ed0c7da9b742e5ba3de6cbf188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (145, 1, X'76a91496ec1be22bb2f10af3e14c579d69cae957e5d0de88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (146, 1, X'76a9149c96f529d7fd79579278947fce329e5a968c700188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (147, 1, X'76a914a03d1dff2503f62088eceb484fba9d0dcb0f706488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (148, 1, X'76a914a55e182cf62838ca1be2348bad2d73ec5472c3d188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (149, 1, X'76a914a95530343036ae1236c86793153ba7948a4d9ee488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (15, 1, X'76a9142ff53f7471ccb74fd481799f3b3cf1e4ff43a0fa88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (150, 1, X'76a914aaaacaf26dda4f54b681de92b03a49affd82e2fe88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (151, 1, X'76a914b113dd72ac6e770940f889edbc2539d2fcecd30a88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (152, 1, X'76a914b4482f1f3f94c16e457ef0ae72a461ea6325d4e688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (153, 1, X'76a914b8daa65db19fcd424e6e5c0ca84f2cf84563371988ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (154, 1, X'76a914b95462180e827446f86142882373497238eeea3288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (155, 1, X'76a914bbe919c4ad9c246a4b590c5105a48231f4917e7188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (156, 1, X'76a914c11aa22043ca6f243d999ed3c1703b6d380fa7e788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (157, 1, X'76a914cc1f2d8c2d1ca51fcc9488c45b4d60af9ff7e92288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (158, 1, X'76a914ce6ebcc4c968b49d78ecd1c5d773d5016f3946b188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (159, 1, X'76a914d56eba05f18cd36f6481cc353adf8f2e0bfd6f0488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (16, 1, X'76a914339381ced0df2438b46e31973d76949edf88b05188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (160, 1, X'76a914d5847311f212b716a2e2104a76024fb41195d85088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (161, 1, X'76a914de78abb5dffcfb307a2a202379aaf210d44ce72788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (162, 1, X'76a914e4af5bf4f39f041491af382412339b3561480f4088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (163, 1, X'76a914e74d609dc55ff00358e937e53e4dbf5604e177a288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (164, 1, X'76a914e79a88ef2be27329d24142e3bc6bf448b020167688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (165, 1, X'76a914f040edb782c97261f4bcecc56eea92f15e89c4c188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (166, 1, X'76a914f4be28de88d3ac40b3a7cc9c5295faf164676d1288ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (167, 1, X'76a914f63ecbb1b2e466515fa4ba769de65a4eee06aa8b88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (168, 1, X'76a914fd4136fb759f7fcc146ca9eabd6f96ae0b58c39a88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (169, 1, X'76a914ff9cf58c119bf1ea64b9be52c1c72206e1fa18d188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (17, 1, X'76a9143592c1178f416c9dfea05acfd7f3d1f616a3e71288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (18, 1, X'76a914362af5560158cc127e8b9cfc5fb3f22eeaee1f7988ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (19, 1, X'76a9143f367a3ea203e089c98e96b637775061658c319c88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (2, 1, X'76a91403c1dc78037cd43a7588fe8d488a5c48daf3046e88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (20, 1, X'76a91443da156a65f01eecdf28eaa146472c99b7a2f9ed88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (21, 1, X'76a91449c550ec97f2455882249263f6b129339563310d88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (22, 1, X'76a9144b1375e8a32815416a58be1c39ac837f5b25bbcf88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (23, 1, X'76a9144c8eb8685b443da6b6278c45f3adae852857eff988ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (24, 1, X'76a9144d33c113c3358640df7f49d69890a1fef9428eb488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (25, 1, X'76a9144f615902f3a86cf8eccc3aff5c991aee1c0d588f88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (255, 1, X'76a91452aa25170c8c54c115208ea34efa86a1734dff8d88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (256, 1, X'76a914589b70bcef5b558484df0bdf1e6c24817866484e88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (257, 1, X'76a9145c177980b8917f158ee8705106060219f877ed8b88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (258, 1, X'76a914699eee5d970f850c9a56e72678b959ded03eed0588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (259, 1, X'76a9147e887cd51d4bcb13859a638e02c45bf499d9e51688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (26, 1, X'76a9144ff31ef9d90d53a9d51663b64cff7f23acb355d588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (260, 1, X'76a9148d29e5eea0cf9e61687e77a1851b49bc71736d0e88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (261, 1, X'76a914ca6c120e684b3afad09c85bfe83a12ea2246deec88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (262, 1, X'76a914d1660b64b43fad46f678f766bf48ae1bfb92aac488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (263, 1, X'76a914ec9e2a09045ff885ad3c8515fbbe1b5d519492fd88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (264, 1, X'76a914f2149f50356eaf6331da4da2178b097be2a5863a88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (265, 1, X'76a91452aa25170c8c54c115208ea34efa86a1734dff8d88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (266, 1, X'76a914589b70bcef5b558484df0bdf1e6c24817866484e88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (267, 1, X'76a9145c177980b8917f158ee8705106060219f877ed8b88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (268, 1, X'76a914699eee5d970f850c9a56e72678b959ded03eed0588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (269, 1, X'76a9147e887cd51d4bcb13859a638e02c45bf499d9e51688ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (27, 1, X'76a91451907d21de12bcb89ddb70c31685f9cc87f6621288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (270, 1, X'76a9148d29e5eea0cf9e61687e77a1851b49bc71736d0e88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (271, 1, X'76a914ca6c120e684b3afad09c85bfe83a12ea2246deec88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (272, 1, X'76a914d1660b64b43fad46f678f766bf48ae1bfb92aac488ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (273, 1, X'76a914ec9e2a09045ff885ad3c8515fbbe1b5d519492fd88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (274, 1, X'76a914f2149f50356eaf6331da4da2178b097be2a5863a88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (275, 1, X'76a91401a38d8f5ba691b969f4933353d9650d99c7d1e088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (276, 1, X'76a91403c1dc78037cd43a7588fe8d488a5c48daf3046e88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (277, 1, X'76a9140724ce8781585f6cb5b112fd2e9a6c635bc1737788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (278, 1, X'76a9140bde98e398402835adb8812738a870cad019b92f88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (279, 1, X'76a914141e8869bd91686fb4a4ab974739cbcde774797588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (28, 1, X'76a91451c363c60d721d1d5ec2ed4cae30f461b39f569888ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (280, 1, X'76a9141609a1a461988de5745b337b472132512d6414a088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (281, 1, X'76a91419a7249b0b52a84cf0891e5f3b98424edf131deb88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (282, 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (283, 1, X'76a9141e39ae3069976f7cfb10d0124b57fe79fbbf426c88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (284, 1, X'76a9141e7cb4eb52728f403e60b616c57ff672df79023588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (285, 1, X'76a9142490f016f2d18afad0869e669d846105b5cda39188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (286, 1, X'76a914256b5ddc95bc330696e5a34e3e206ca58ba78d9788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (287, 1, X'76a9142a224ebe6d91e66240fe49eea837f3d4ffc632c588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (288, 1, X'76a9142a45320c87e003f50a7080b84e04005c851679cc88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (289, 1, X'76a9142dbc35218aab094fca18927b7adaf9d7be59b94388ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (29, 1, X'76a9145219459f5cf88fdb60393379bfe6016a48c21d9488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (290, 1, X'76a9142ff53f7471ccb74fd481799f3b3cf1e4ff43a0fa88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (291, 1, X'76a914339381ced0df2438b46e31973d76949edf88b05188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (292, 1, X'76a9143592c1178f416c9dfea05acfd7f3d1f616a3e71288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (293, 1, X'76a914362af5560158cc127e8b9cfc5fb3f22eeaee1f7988ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (294, 1, X'76a9143f367a3ea203e089c98e96b637775061658c319c88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (295, 1, X'76a91443da156a65f01eecdf28eaa146472c99b7a2f9ed88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (296, 1, X'76a91449c550ec97f2455882249263f6b129339563310d88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (297, 1, X'76a9144b1375e8a32815416a58be1c39ac837f5b25bbcf88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (298, 1, X'76a9144c8eb8685b443da6b6278c45f3adae852857eff988ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (299, 1, X'76a9144d33c113c3358640df7f49d69890a1fef9428eb488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (3, 1, X'76a9140724ce8781585f6cb5b112fd2e9a6c635bc1737788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (30, 1, X'76a914543db4565f675d677a05ff5359864d624aed168388ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (300, 1, X'76a9144f615902f3a86cf8eccc3aff5c991aee1c0d588f88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (301, 1, X'76a9144ff31ef9d90d53a9d51663b64cff7f23acb355d588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (302, 1, X'76a91451907d21de12bcb89ddb70c31685f9cc87f6621288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (303, 1, X'76a91451c363c60d721d1d5ec2ed4cae30f461b39f569888ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (304, 1, X'76a9145219459f5cf88fdb60393379bfe6016a48c21d9488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (305, 1, X'76a91452aa25170c8c54c115208ea34efa86a1734dff8d88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (306, 1, X'76a914543db4565f675d677a05ff5359864d624aed168388ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (307, 1, X'76a9145827fabb59f1b7e624bd1f9e1a52b593eacc03a488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (308, 1, X'76a914589b70bcef5b558484df0bdf1e6c24817866484e88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (309, 1, X'76a91458cb9fc34e426630a4dc277b34912e12b3d14cdc88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (31, 1, X'76a9145827fabb59f1b7e624bd1f9e1a52b593eacc03a488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (310, 1, X'76a9145afeb4c3e13653a53a0d6c0e64464b67d62f397688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (311, 1, X'76a9145c177980b8917f158ee8705106060219f877ed8b88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (312, 1, X'76a9145ceb497978d8c20206c066310cad05c763e0993688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (313, 1, X'76a9145d78d48fb921730aad494e6e6458300b02c6355c88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (314, 1, X'76a9145f07d8c4b118d3493a354666cff42ff3375d710788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (315, 1, X'76a914608d6c0d55e6f02c9e62f81dadfa3e291eed102088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (316, 1, X'76a9146341413871fa17255332be5750548eeb956d18c588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (317, 1, X'76a914651f6fd74aeb850f5193a3831d6b9d852242156388ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (318, 1, X'76a9146648ecb460407ca426dc9f74ab5bc954ea6d8b3288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (319, 1, X'76a914699eee5d970f850c9a56e72678b959ded03eed0588ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (32, 1, X'76a91458cb9fc34e426630a4dc277b34912e12b3d14cdc88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (320, 1, X'76a9146bec4fe4ffe2316f12fd8edfba57fc5d744025f988ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (321, 1, X'76a9146f52d8e94a4dce5d6a652e145a8f4db7d7c991e088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (322, 1, X'76a9146fb9c8dc87f1e371a75d5e9f6cfaa3627aaaffe888ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (323, 1, X'76a914715df7dea6dd8fb86c8a5ad145dd1fe3dd1e0f2388ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (324, 1, X'76a91472d5dbc2bae9c92965270b97555e5c3351d7d6f088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (325, 1, X'76a91474d1a6d961dc5f43f26e9acf331c7363d06e7e6b88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (326, 1, X'76a914756a5bbcb7ed38da40a11b7273243328adcf513788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (327, 1, X'76a9147d7c09623db1cdeeeeb6ad537dadfbfe8a8b5da088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (328, 1, X'76a9147e0fbf3918dc5167199708839883759b50f2a7b488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (329, 1, X'76a9147e887cd51d4bcb13859a638e02c45bf499d9e51688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (33, 1, X'76a9145afeb4c3e13653a53a0d6c0e64464b67d62f397688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (330, 1, X'76a91481d1d50a234c88d6385267a0aa3a86f74eddfadf88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (331, 1, X'76a91485b9b9c46f230eb1db32d45a0357250efc3566d688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (332, 1, X'76a914889b67a8d5bf3499a3767814bd4f4b01bed4cb6a88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (333, 1, X'76a9148ae4db39f786dfdd3e97c13de078cbd2ebf60b5488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (334, 1, X'76a9148b3e08a16104d16d3c3142ea8f81cade8f3605ff88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (335, 1, X'76a9148bfb0cb17692970da70f977caafebf91c9c407fc88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (336, 1, X'76a9148d29e5eea0cf9e61687e77a1851b49bc71736d0e88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (337, 1, X'76a914900a44ba8413b27eafe7d3cc2bdae17d5683a47288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (338, 1, X'76a91490c2744262846d6a26ab0c3371b29127a710deed88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (339, 1, X'76a91494de5a331a430d63ed0c7da9b742e5ba3de6cbf188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (34, 1, X'76a9145ceb497978d8c20206c066310cad05c763e0993688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (340, 1, X'76a91496ec1be22bb2f10af3e14c579d69cae957e5d0de88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (341, 1, X'76a9149c96f529d7fd79579278947fce329e5a968c700188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (342, 1, X'76a914a03d1dff2503f62088eceb484fba9d0dcb0f706488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (343, 1, X'76a914a55e182cf62838ca1be2348bad2d73ec5472c3d188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (344, 1, X'76a914a95530343036ae1236c86793153ba7948a4d9ee488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (345, 1, X'76a914aaaacaf26dda4f54b681de92b03a49affd82e2fe88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (346, 1, X'76a914b113dd72ac6e770940f889edbc2539d2fcecd30a88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (347, 1, X'76a914b4482f1f3f94c16e457ef0ae72a461ea6325d4e688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (348, 1, X'76a914b8daa65db19fcd424e6e5c0ca84f2cf84563371988ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (349, 1, X'76a914b95462180e827446f86142882373497238eeea3288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (35, 1, X'76a9145d78d48fb921730aad494e6e6458300b02c6355c88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (350, 1, X'76a914bbe919c4ad9c246a4b590c5105a48231f4917e7188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (351, 1, X'76a914c11aa22043ca6f243d999ed3c1703b6d380fa7e788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (352, 1, X'76a914ca6c120e684b3afad09c85bfe83a12ea2246deec88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (353, 1, X'76a914cc1f2d8c2d1ca51fcc9488c45b4d60af9ff7e92288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (354, 1, X'76a914ce6ebcc4c968b49d78ecd1c5d773d5016f3946b188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (355, 1, X'76a914d1660b64b43fad46f678f766bf48ae1bfb92aac488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (356, 1, X'76a914d56eba05f18cd36f6481cc353adf8f2e0bfd6f0488ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (357, 1, X'76a914d5847311f212b716a2e2104a76024fb41195d85088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (358, 1, X'76a914de78abb5dffcfb307a2a202379aaf210d44ce72788ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (359, 1, X'76a914e4af5bf4f39f041491af382412339b3561480f4088ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (36, 1, X'76a9145f07d8c4b118d3493a354666cff42ff3375d710788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (360, 1, X'76a914e74d609dc55ff00358e937e53e4dbf5604e177a288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (361, 1, X'76a914e79a88ef2be27329d24142e3bc6bf448b020167688ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (362, 1, X'76a914ec9e2a09045ff885ad3c8515fbbe1b5d519492fd88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (363, 1, X'76a914f040edb782c97261f4bcecc56eea92f15e89c4c188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (364, 1, X'76a914f2149f50356eaf6331da4da2178b097be2a5863a88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (365, 1, X'76a914f4be28de88d3ac40b3a7cc9c5295faf164676d1288ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (366, 1, X'76a914f63ecbb1b2e466515fa4ba769de65a4eee06aa8b88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (367, 1, X'76a914fd4136fb759f7fcc146ca9eabd6f96ae0b58c39a88ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (368, 1, X'76a914ff9cf58c119bf1ea64b9be52c1c72206e1fa18d188ac', 3428743, 3428803, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86', 4, 1);
INSERT INTO "tpir_coverage" VALUES (37, 1, X'76a914608d6c0d55e6f02c9e62f81dadfa3e291eed102088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (38, 1, X'76a9146341413871fa17255332be5750548eeb956d18c588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (39, 1, X'76a914651f6fd74aeb850f5193a3831d6b9d852242156388ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (4, 1, X'76a9140bde98e398402835adb8812738a870cad019b92f88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (40, 1, X'76a9146648ecb460407ca426dc9f74ab5bc954ea6d8b3288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (41, 1, X'76a9146bec4fe4ffe2316f12fd8edfba57fc5d744025f988ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (42, 1, X'76a9146f52d8e94a4dce5d6a652e145a8f4db7d7c991e088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (43, 1, X'76a9146fb9c8dc87f1e371a75d5e9f6cfaa3627aaaffe888ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (44, 1, X'76a914715df7dea6dd8fb86c8a5ad145dd1fe3dd1e0f2388ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (45, 1, X'76a91472d5dbc2bae9c92965270b97555e5c3351d7d6f088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (46, 1, X'76a91474d1a6d961dc5f43f26e9acf331c7363d06e7e6b88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (47, 1, X'76a914756a5bbcb7ed38da40a11b7273243328adcf513788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (48, 1, X'76a9147d7c09623db1cdeeeeb6ad537dadfbfe8a8b5da088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (49, 1, X'76a9147e0fbf3918dc5167199708839883759b50f2a7b488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (5, 1, X'76a914141e8869bd91686fb4a4ab974739cbcde774797588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (50, 1, X'76a91481d1d50a234c88d6385267a0aa3a86f74eddfadf88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (51, 1, X'76a91485b9b9c46f230eb1db32d45a0357250efc3566d688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (52, 1, X'76a914889b67a8d5bf3499a3767814bd4f4b01bed4cb6a88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (53, 1, X'76a9148ae4db39f786dfdd3e97c13de078cbd2ebf60b5488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (54, 1, X'76a9148b3e08a16104d16d3c3142ea8f81cade8f3605ff88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (55, 1, X'76a9148bfb0cb17692970da70f977caafebf91c9c407fc88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (56, 1, X'76a914900a44ba8413b27eafe7d3cc2bdae17d5683a47288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (57, 1, X'76a91490c2744262846d6a26ab0c3371b29127a710deed88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (58, 1, X'76a914932f8ddba21c722540844e06d8063a7214a090e488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (59, 1, X'76a91494de5a331a430d63ed0c7da9b742e5ba3de6cbf188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (6, 1, X'76a9141609a1a461988de5745b337b472132512d6414a088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (60, 1, X'76a91496ec1be22bb2f10af3e14c579d69cae957e5d0de88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (61, 1, X'76a9149c96f529d7fd79579278947fce329e5a968c700188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (62, 1, X'76a914a03d1dff2503f62088eceb484fba9d0dcb0f706488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (63, 1, X'76a914a55e182cf62838ca1be2348bad2d73ec5472c3d188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (64, 1, X'76a914a95530343036ae1236c86793153ba7948a4d9ee488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (65, 1, X'76a914aaaacaf26dda4f54b681de92b03a49affd82e2fe88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (66, 1, X'76a914b113dd72ac6e770940f889edbc2539d2fcecd30a88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (67, 1, X'76a914b4482f1f3f94c16e457ef0ae72a461ea6325d4e688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (68, 1, X'76a914b8daa65db19fcd424e6e5c0ca84f2cf84563371988ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (69, 1, X'76a914b95462180e827446f86142882373497238eeea3288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (7, 1, X'76a91419a7249b0b52a84cf0891e5f3b98424edf131deb88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (70, 1, X'76a914bbe919c4ad9c246a4b590c5105a48231f4917e7188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (71, 1, X'76a914c11aa22043ca6f243d999ed3c1703b6d380fa7e788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (72, 1, X'76a914cc1f2d8c2d1ca51fcc9488c45b4d60af9ff7e92288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (73, 1, X'76a914ce6ebcc4c968b49d78ecd1c5d773d5016f3946b188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (74, 1, X'76a914d56eba05f18cd36f6481cc353adf8f2e0bfd6f0488ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (75, 1, X'76a914d5847311f212b716a2e2104a76024fb41195d85088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (76, 1, X'76a914de78abb5dffcfb307a2a202379aaf210d44ce72788ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (77, 1, X'76a914e4af5bf4f39f041491af382412339b3561480f4088ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (78, 1, X'76a914e74d609dc55ff00358e937e53e4dbf5604e177a288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (79, 1, X'76a914e79a88ef2be27329d24142e3bc6bf448b020167688ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (8, 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (80, 1, X'76a914f040edb782c97261f4bcecc56eea92f15e89c4c188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (81, 1, X'76a914f4be28de88d3ac40b3a7cc9c5295faf164676d1288ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (82, 1, X'76a914f63ecbb1b2e466515fa4ba769de65a4eee06aa8b88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (83, 1, X'76a914fd4136fb759f7fcc146ca9eabd6f96ae0b58c39a88ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (84, 1, X'76a914ff9cf58c119bf1ea64b9be52c1c72206e1fa18d188ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (85, 1, X'76a91401a38d8f5ba691b969f4933353d9650d99c7d1e088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (86, 1, X'76a91403c1dc78037cd43a7588fe8d488a5c48daf3046e88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (87, 1, X'76a9140724ce8781585f6cb5b112fd2e9a6c635bc1737788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (88, 1, X'76a9140bde98e398402835adb8812738a870cad019b92f88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (89, 1, X'76a914141e8869bd91686fb4a4ab974739cbcde774797588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (9, 1, X'76a9141e7cb4eb52728f403e60b616c57ff672df79023588ac', 3428393, 3428542, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8', 1, 1);
INSERT INTO "tpir_coverage" VALUES (90, 1, X'76a9141609a1a461988de5745b337b472132512d6414a088ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (91, 1, X'76a91419a7249b0b52a84cf0891e5f3b98424edf131deb88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (92, 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (93, 1, X'76a9141e39ae3069976f7cfb10d0124b57fe79fbbf426c88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (94, 1, X'76a9141e7cb4eb52728f403e60b616c57ff672df79023588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (95, 1, X'76a9142490f016f2d18afad0869e669d846105b5cda39188ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (96, 1, X'76a914256b5ddc95bc330696e5a34e3e206ca58ba78d9788ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (97, 1, X'76a9142a224ebe6d91e66240fe49eea837f3d4ffc632c588ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (98, 1, X'76a9142a45320c87e003f50a7080b84e04005c851679cc88ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_coverage" VALUES (99, 1, X'76a9142dbc35218aab094fca18927b7adaf9d7be59b94388ac', 3428543, 3428742, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165', 2, 1);
INSERT INTO "tpir_meta" VALUES (0, 2, 1, 6);
INSERT INTO "tpir_qualified_revisions" VALUES (1);
INSERT INTO "tpir_qualified_revisions" VALUES (2);
INSERT INTO "tpir_qualified_revisions" VALUES (3);
INSERT INTO "tpir_qualified_revisions" VALUES (4);
INSERT INTO "tpir_receive_events" VALUES (1, 1, X'0a00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7000, 0, 3428553);
INSERT INTO "tpir_receive_events" VALUES (2, 1, X'0b00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7001, 0, 3428573);
INSERT INTO "tpir_receive_events" VALUES (3, 1, X'0c00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7002, 0, 3428593);
INSERT INTO "tpir_receive_events" VALUES (4, 1, X'0d00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7003, 0, 3428613);
INSERT INTO "tpir_receive_events" VALUES (5, 1, X'0e00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7004, 0, 3428633);
INSERT INTO "tpir_receive_events" VALUES (6, 1, X'0f00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 7005, 0, 3428653);
INSERT INTO "tpir_receive_observations" VALUES (1, 2);
INSERT INTO "tpir_receive_observations" VALUES (2, 2);
INSERT INTO "tpir_receive_observations" VALUES (3, 2);
INSERT INTO "tpir_receive_observations" VALUES (4, 2);
INSERT INTO "tpir_receive_observations" VALUES (5, 2);
INSERT INTO "tpir_receive_observations" VALUES (6, 2);
INSERT INTO "tpir_revisions" VALUES (1, X'118925d65e783884d8198c0cd0ccf6169392e1d109f84b172757d56b7526312d', X'be8651c9d405bdd3b54219d75115c1b876a7165aa93702e45b654438972120e9', 1, 1, 3428542, X'539106b300c1ca0d7192a074f4539186e2c30fcd133a621ba92109e70af5c7c8');
INSERT INTO "tpir_revisions" VALUES (2, X'0b316c4c6fac960e91d5618c3783479473e17781ad5b7eba8e6dd8117bd2c85f', X'83a819c054947ec43214138cb495ea1f71dd8b7b873f31020158d8b5c0754967', 1, 1, 3428742, X'4989de9ae9cd7d0a15a90f9449ab2825573239ba0888f00a6feb0d831ca7e165');
INSERT INTO "tpir_revisions" VALUES (3, X'13d49be1c853e39a3fd7da6262bcca6e67d428a37d0e0fd778f6d8f18b55cc0d', X'cb498a01f95ad3f99d5fcdd590eedb3d7c9387d6875f6c0d2537774e2943a765', 1, 0, 3428792, X'61691a5a00ee9f9d4276c65c641367da4d6ef3b9d777d3d48c49fdc253ef2e60');
INSERT INTO "tpir_revisions" VALUES (4, X'13d49be1c853e39a3fd7da6262bcca6e67d428a37d0e0fd778f6d8f18b55cc0d', X'1ffb22892cdd207670877ea4ccc1f7c0ddb3054acb29d8385e4be3791a703a4d', 2, 0, 3428803, X'15f6aef7a9c1a6501ffecb3feedad4561fcc5e008630bc97bd7cd053b4706e86');
INSERT INTO "tpir_spend_events" VALUES (1, 1, X'0400000000000000000000000000000000000000000000000000000000000077', 0, X'0a00000000000000000000000000000000000000000000000000000000000077', 1, X'76a9141d3d64a95644421a538750589e7f1346a9d67f7388ac', 3428763);
INSERT INTO "tpir_spend_observations" VALUES (1, 4);
CREATE VIEW v_sapling_shard_scan_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << 16 AS start_position,
                    (shard.shard_index + 1) << 16 AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, 100000) AS subtree_start_height,
                    shard.subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM sapling_tree_shards shard
                LEFT OUTER JOIN sapling_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                );
CREATE VIEW v_sapling_shard_unscanned_ranges AS
                WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
                SELECT
                    shard_index,
                    start_position,
                    end_position_exclusive,
                    subtree_start_height,
                    subtree_end_height,
                    contains_marked,
                    block_range_start,
                    block_range_end,
                    priority
                FROM v_sapling_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > 10
                AND block_range_end > wallet_birthday.height;
CREATE VIEW v_sapling_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_sapling_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;
CREATE VIEW v_orchard_shard_scan_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << 16 AS start_position,
                    (shard.shard_index + 1) << 16 AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, 100000) AS subtree_start_height,
                    shard.subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM orchard_tree_shards shard
                LEFT OUTER JOIN orchard_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                );
CREATE VIEW v_orchard_shard_unscanned_ranges AS
                WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
                SELECT
                    shard_index,
                    start_position,
                    end_position_exclusive,
                    subtree_start_height,
                    subtree_end_height,
                    contains_marked,
                    block_range_start,
                    block_range_end,
                    priority
                FROM v_orchard_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > 10
                AND block_range_end > wallet_birthday.height;
CREATE VIEW v_orchard_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_orchard_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;
CREATE INDEX nf_map_locator_idx ON nullifier_map(block_height, tx_index);
CREATE VIEW v_address_first_use AS
            SELECT
                address_id,
                account_id,
                key_scope,
                diversifier_index_be,
                transparent_child_index,
                MIN(mined_height) AS first_use_height
            FROM v_address_uses
            GROUP BY
                address_id, account_id, key_scope,
                diversifier_index_be, transparent_child_index;
CREATE INDEX idx_sapling_received_notes_account ON sapling_received_notes (account_id ASC);
CREATE INDEX idx_sapling_received_notes_address ON sapling_received_notes (address_id ASC);
CREATE INDEX idx_sapling_received_notes_tx ON sapling_received_notes (transaction_id ASC);
CREATE INDEX idx_sapling_received_note_spends_note_id ON sapling_received_note_spends (sapling_received_note_id ASC);
CREATE INDEX idx_sapling_received_note_spends_transaction_id ON sapling_received_note_spends (transaction_id ASC);
CREATE INDEX idx_orchard_received_notes_account ON orchard_received_notes (account_id ASC);
CREATE INDEX idx_orchard_received_notes_address ON orchard_received_notes (address_id ASC);
CREATE INDEX idx_orchard_received_notes_tx ON orchard_received_notes (transaction_id ASC);
CREATE INDEX idx_orchard_received_note_spends_note_id ON orchard_received_note_spends (orchard_received_note_id ASC);
CREATE INDEX idx_orchard_received_note_spends_transaction_id ON orchard_received_note_spends (transaction_id ASC);
CREATE INDEX idx_transparent_received_outputs_account ON transparent_received_outputs (account_id);
CREATE INDEX idx_transparent_received_outputs_address ON transparent_received_outputs (address_id);
CREATE INDEX idx_transparent_received_outputs_tx ON transparent_received_outputs (transaction_id);
CREATE INDEX idx_transparent_received_output_spends_output_id ON transparent_received_output_spends (transparent_received_output_id ASC);
CREATE INDEX idx_transparent_received_output_spends_transaction_id ON transparent_received_output_spends (transaction_id ASC);
CREATE INDEX idx_transparent_spend_map_transaction_id ON transparent_spend_map (spending_transaction_id ASC);
CREATE INDEX idx_sent_notes_from_account ON sent_notes (from_account_id);
CREATE INDEX idx_sent_notes_to_account ON sent_notes (to_account_id);
CREATE INDEX idx_sent_notes_transaction_id ON sent_notes (transaction_id);
CREATE INDEX idx_tssq_transaction_id ON transparent_spend_search_queue (transaction_id);
CREATE INDEX idx_addresses_accounts ON addresses (
                account_id ASC
            );
CREATE INDEX idx_addresses_indices ON addresses (
                diversifier_index_be ASC
            );
CREATE INDEX idx_addresses_pubkeys ON addresses (
                imported_transparent_receiver_pubkey ASC
            );
CREATE INDEX idx_addresses_t_indices ON addresses (
                transparent_child_index ASC
            );
CREATE UNIQUE INDEX idx_addresses_cached_transparent_receiver_address
                 ON addresses (cached_transparent_receiver_address ASC);
CREATE VIEW v_ironwood_shard_scan_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << 16 AS start_position,
                    (shard.shard_index + 1) << 16 AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, 100000) AS subtree_start_height,
                    shard.subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM ironwood_tree_shards shard
                LEFT OUTER JOIN ironwood_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                );
CREATE VIEW v_ironwood_shard_unscanned_ranges AS
                WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
                SELECT
                    shard_index,
                    start_position,
                    end_position_exclusive,
                    subtree_start_height,
                    subtree_end_height,
                    contains_marked,
                    block_range_start,
                    block_range_end,
                    priority
                FROM v_ironwood_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > 10
                AND block_range_end > wallet_birthday.height;
CREATE VIEW v_ironwood_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_ironwood_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;
CREATE INDEX idx_sapling_received_notes_witness_stabilized
                 ON sapling_received_notes (witness_stabilized);
CREATE INDEX idx_orchard_received_notes_witness_stabilized
                 ON orchard_received_notes (witness_stabilized);
CREATE INDEX idx_ironwood_received_notes_account ON ironwood_received_notes (
                account_id ASC
            );
CREATE INDEX idx_ironwood_received_notes_address ON ironwood_received_notes (
                address_id ASC
            );
CREATE INDEX idx_ironwood_received_notes_tx ON ironwood_received_notes (
                transaction_id ASC
            );
CREATE INDEX idx_ironwood_received_notes_witness_stabilized ON ironwood_received_notes (
                witness_stabilized
            );
CREATE INDEX idx_ironwood_received_note_spends_note_id ON ironwood_received_note_spends (
                ironwood_received_note_id ASC
            );
CREATE INDEX idx_ironwood_received_note_spends_transaction_id ON ironwood_received_note_spends (
                transaction_id ASC
            );
CREATE VIEW v_received_outputs AS
                SELECT
                    sapling_received_notes.id AS id_within_pool_table,
                    sapling_received_notes.transaction_id,
                    2 AS pool,
                    sapling_received_notes.output_index,
                    account_id,
                    sapling_received_notes.value,
                    is_change,
                    sapling_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    sapling_received_notes.address_id
                FROM sapling_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (sapling_received_notes.transaction_id, 2, sapling_received_notes.output_index)
            UNION
                SELECT
                    orchard_received_notes.id AS id_within_pool_table,
                    orchard_received_notes.transaction_id,
                    3 AS pool,
                    orchard_received_notes.action_index AS output_index,
                    account_id,
                    orchard_received_notes.value,
                    is_change,
                    orchard_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    orchard_received_notes.address_id
                FROM orchard_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (orchard_received_notes.transaction_id, 3, orchard_received_notes.action_index)
            UNION
                SELECT
                    ironwood_received_notes.id AS id_within_pool_table,
                    ironwood_received_notes.transaction_id,
                    4 AS pool,
                    ironwood_received_notes.action_index AS output_index,
                    account_id,
                    ironwood_received_notes.value,
                    is_change,
                    ironwood_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    ironwood_received_notes.address_id
                FROM ironwood_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (ironwood_received_notes.transaction_id, 4, ironwood_received_notes.action_index)
            UNION
                SELECT
                    u.id AS id_within_pool_table,
                    u.transaction_id,
                    0 AS pool,
                    u.output_index,
                    u.account_id,
                    u.value_zat AS value,
                    0 AS is_change,
                    NULL AS memo,
                    sent_notes.id AS sent_note_id,
                    u.address_id
                FROM transparent_received_outputs u
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (u.transaction_id, 0, u.output_index);
CREATE VIEW v_received_output_spends AS
            SELECT
                2 AS pool,
                s.sapling_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM sapling_received_note_spends s
            JOIN sapling_received_notes rn ON rn.id = s.sapling_received_note_id
            UNION
            SELECT
                3 AS pool,
                s.orchard_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM orchard_received_note_spends s
            JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
            UNION
            SELECT
                4 AS pool,
                s.ironwood_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM ironwood_received_note_spends s
            JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
            UNION
            SELECT
                0 AS pool,
                s.transparent_received_output_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM transparent_received_output_spends s
            JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id;
CREATE VIEW v_tx_outputs AS
            WITH unioned AS (
                -- select all outputs received by the wallet
                SELECT t.id_tx                      AS transaction_id,
                       t.txid                       AS txid,
                       t.mined_height               AS mined_height,
                       IFNULL(t.trust_status, 0)    AS trust_status,
                       ro.pool                      AS output_pool,
                       ro.output_index              AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       to_account.uuid              AS to_account_uuid,
                       -- for a transparent output, the address at which it was received is
                       -- the transparent receiver itself, not a unified address containing it
                       CASE ro.pool
                            WHEN 0 THEN a.cached_transparent_receiver_address
                            ELSE a.address
                       END                          AS to_address,
                       0                            AS is_sent_row,
                       a.diversifier_index_be       AS diversifier_index_be,
                       ro.value                     AS value,
                       ro.is_change                 AS is_change,
                       ro.memo                      AS memo,
                       a.key_scope                  AS recipient_key_scope
                FROM v_received_outputs ro
                JOIN transactions t
                    ON t.id_tx = ro.transaction_id
                LEFT JOIN addresses a ON a.id = ro.address_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                UNION ALL
                -- select all outputs sent by the wallet
                SELECT t.id_tx                      AS transaction_id,
                       t.txid                       AS txid,
                       t.mined_height               AS mined_height,
                       IFNULL(t.trust_status, 0)    AS trust_status,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       NULL                         AS to_account_uuid,
                       sent_notes.to_address        AS to_address,
                       1                            AS is_sent_row,
                       NULL                         AS diversifier_index_be,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo,
                       NULL                         AS recipient_key_scope
                FROM sent_notes
                JOIN transactions t
                    ON t.id_tx = sent_notes.transaction_id
                LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
            )
            -- merge duplicate rows while retaining maximum information
            SELECT
                transaction_id,
                MAX(txid)                   AS txid,
                MAX(mined_height)           AS tx_mined_height,
                MIN(trust_status)           AS tx_trust_status,
                output_pool,
                output_index,
                MAX(from_account_uuid)      AS from_account_uuid,
                MAX(to_account_uuid)        AS to_account_uuid,
                -- the recipient address recorded when the wallet created the output is
                -- authoritative; the receiving address is reported only for outputs the
                -- wallet did not create
                COALESCE(
                    MAX(CASE WHEN is_sent_row THEN to_address END),
                    MAX(CASE WHEN NOT is_sent_row THEN to_address END)
                )                           AS to_address,
                MAX(value)                  AS value,
                MAX(is_change)              AS is_change,
                MAX(memo)                   AS memo,
                MAX(recipient_key_scope)    AS recipient_key_scope
            FROM unioned
            GROUP BY transaction_id, output_pool, output_index;
CREATE INDEX idx_transparent_received_outputs_value_zat
                 ON transparent_received_outputs (value_zat DESC);
CREATE INDEX idx_tx_retrieval_queue_dependent_tx
            ON tx_retrieval_queue (dependent_transaction_id);
CREATE VIEW v_address_uses AS
                SELECT orn.address_id, orn.account_id, orn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM orchard_received_notes orn
                JOIN addresses a ON a.id = orn.address_id
                JOIN transactions t ON t.id_tx = orn.transaction_id
            UNION
                SELECT irn.address_id, irn.account_id, irn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM ironwood_received_notes irn
                JOIN addresses a ON a.id = irn.address_id
                JOIN transactions t ON t.id_tx = irn.transaction_id
            UNION
                SELECT srn.address_id, srn.account_id, srn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM sapling_received_notes srn
                JOIN addresses a ON a.id = srn.address_id
                JOIN transactions t ON t.id_tx = srn.transaction_id
            UNION
                SELECT tro.address_id, tro.account_id, tro.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM transparent_received_outputs tro
                JOIN addresses a ON a.id = tro.address_id
                JOIN transactions t ON t.id_tx = tro.transaction_id;
CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
CREATE UNIQUE INDEX accounts_ufvk ON accounts (ufvk);
CREATE UNIQUE INDEX accounts_uivk ON accounts (uivk);
CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index);
CREATE UNIQUE INDEX accounts_orchard_ivk ON accounts (orchard_ivk_item_cache);
CREATE UNIQUE INDEX accounts_sapling_ivk ON accounts (sapling_ivk_item_cache);
CREATE UNIQUE INDEX accounts_p2pkh_ivk ON accounts (p2pkh_ivk_item_cache);
CREATE UNIQUE INDEX accounts_p2sh_ivk ON accounts (p2sh_ivk_item_cache);
CREATE INDEX idx_tpir_coverage_script ON tpir_coverage (account_id, script);
CREATE INDEX idx_tpir_receive_events_account ON tpir_receive_events (account_id);
CREATE INDEX idx_tpir_spend_events_account ON tpir_spend_events (account_id);
CREATE INDEX idx_tpir_spend_events_prevout ON tpir_spend_events (prevout_txid, prevout_output_index);
CREATE INDEX idx_tx_reconfirmation_receipts_height ON tx_reconfirmation_receipts(mined_height);
CREATE VIEW v_transactions AS
WITH
notes AS (
    -- Outputs received in this transaction
    SELECT ro.account_id              AS account_id,
           ro.transaction_id          AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           ro.value                   AS value,
           ro.value                   AS received_value,
           0                          AS spent_value,
           0                          AS spent_note_count,
           CASE
                WHEN ro.is_change THEN 1
                ELSE 0
           END AS change_note_count,
           CASE
                WHEN ro.is_change THEN 0
                ELSE 1
           END AS received_count,
           CASE
             WHEN (ro.memo IS NULL OR ro.memo = X'F6')
               THEN 0
             ELSE 1
           END AS memo_present,
           -- The wallet cannot receive transparent outputs in shielding transactions.
           CASE
             WHEN ro.pool = 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    FROM v_received_outputs ro
    UNION
    -- Outputs spent in this transaction
    SELECT ro.account_id              AS account_id,
           ros.transaction_id         AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           -ro.value                  AS value,
           0                          AS received_value,
           ro.value                   AS spent_value,
           1                          AS spent_note_count,
           0                          AS change_note_count,
           0                          AS received_count,
           0                          AS memo_present,
           -- The wallet cannot spend shielded outputs in shielding transactions.
           CASE
             WHEN ro.pool != 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    FROM v_received_outputs ro
    JOIN v_received_output_spends ros
         ON ros.pool = ro.pool
         AND ros.received_output_id = ro.id_within_pool_table
),
-- What each account spent and received in each pool, per transaction. A pool the account
-- received value in but spent nothing from is a pool that value crossed into from
-- elsewhere, which is what `pool_crossings` below is built on.
notes_by_pool AS (
    SELECT account_id, transaction_id, pool,
           SUM(spent_note_count)                   AS spent_note_count,
           SUM(received_count + change_note_count) AS received_note_count,
           SUM(received_value)                     AS received_value
    FROM notes
    GROUP BY account_id, transaction_id, pool
),
-- Obtain a count of the notes that the wallet created in each transaction,
-- not counting change notes.
sent_note_counts AS (
    SELECT sent_notes.from_account_id     AS account_id,
           sent_notes.transaction_id      AS transaction_id,
           COUNT(DISTINCT sent_notes.id)  AS sent_notes,
           SUM(
             CASE
               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                 THEN 0
               ELSE 1
             END
           ) AS memo_count
    FROM sent_notes
    LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
    WHERE COALESCE(ro.is_change, 0) = 0
    -- Group by the sending account. A bare `account_id` here would resolve to the joined
    -- `ro.account_id`, splitting one sender's notes into a group per receiving account.
    GROUP BY sent_notes.from_account_id, sent_notes.transaction_id
),
-- Identifies the transactions that are wallet-internal transfers moving an account's own
-- funds between shielded pools, and reports the value that crossed. `crossing_value` is
-- non-NULL exactly for such a transaction, so it carries both the classification and the
-- amount; see the `pool_crossing_value` column below.
pool_crossings AS (
    SELECT notes_by_pool.account_id     AS account_id,
           notes_by_pool.transaction_id AS transaction_id,
           CASE WHEN (
                -- Every note spent and every output received by the wallet is shielded.
                SUM(CASE WHEN notes_by_pool.pool = 0 THEN notes_by_pool.spent_note_count + notes_by_pool.received_note_count ELSE 0 END) = 0
                -- The transaction spends at least one of the account's notes.
                AND SUM(notes_by_pool.spent_note_count) > 0
                -- At least one output was received in a pool the account spent nothing
                -- from, so value crossed between pools.
                AND SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_note_count ELSE 0 END) > 0
                -- We do not know about any external outputs of the transaction.
                AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
           )
           -- The total value received in the pools the account did not spend from. The
           -- condition above guarantees at least one such output, so when this branch is
           -- taken the sum is never NULL.
           THEN SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_value ELSE 0 END)
           END AS crossing_value
    FROM notes_by_pool
    LEFT JOIN sent_note_counts
         ON sent_note_counts.account_id = notes_by_pool.account_id
         AND sent_note_counts.transaction_id = notes_by_pool.transaction_id
    GROUP BY notes_by_pool.account_id, notes_by_pool.transaction_id
),
blocks_max_height AS (
    SELECT MAX(blocks.height) AS max_height FROM blocks
)
SELECT accounts.uuid                AS account_uuid,
       transactions.mined_height    AS mined_height,
       transactions.txid            AS txid,
       transactions.tx_index        AS tx_index,
       COALESCE(transactions.expiry_height, (SELECT history_expiry_height
        FROM ironwood_enhance_routing WHERE transaction_id = transactions.id_tx AND route = 0))
           AS expiry_height,
       transactions.raw             AS raw,
       SUM(notes.value)             AS account_balance_delta,
       SUM(notes.spent_value)       AS total_spent,
       SUM(notes.received_value)    AS total_received,
       transactions.fee             AS fee_paid,
       SUM(notes.change_note_count) > 0  AS has_change,
       MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
       SUM(notes.received_count)         AS received_note_count,
       SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
       blocks.time                       AS block_time,
       (
            transactions.mined_height IS NULL
            AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
       ) AS expired_unmined,
       SUM(notes.spent_note_count) AS spent_note_count,
       (
            -- All of the wallet-spent and wallet-received notes are consistent with a
            -- shielding transaction.
            SUM(notes.does_not_match_shielding) = 0
            -- The transaction contains at least one wallet-spent output.
            AND SUM(notes.spent_note_count) > 0
            -- The transaction contains at least one wallet-received note.
            AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
            -- We do not know about any external outputs of the transaction.
            AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
       ) AS is_shielding,
       -- The value that crossed pools, when this transaction is a wallet-internal transfer
       -- between shielded pools; NULL when it is not such a transfer. A transaction is one
       -- exactly when this column is non-NULL.
       pool_crossings.crossing_value AS pool_crossing_value,
       transactions.trust_status,
       transactions.zip318_kind
FROM notes
JOIN accounts ON accounts.id = notes.account_id
JOIN transactions ON transactions.id_tx = notes.transaction_id
LEFT JOIN blocks_max_height
LEFT JOIN blocks ON blocks.height = transactions.mined_height
LEFT JOIN sent_note_counts
     ON sent_note_counts.account_id = notes.account_id
     AND sent_note_counts.transaction_id = notes.transaction_id
LEFT JOIN pool_crossings
     ON pool_crossings.account_id = notes.account_id
     AND pool_crossings.transaction_id = notes.transaction_id
GROUP BY notes.account_id, notes.transaction_id;
CREATE INDEX idx_ironwood_one_time_keys_account_receiver
                ON ironwood_one_time_keys(account_id, receiver);
CREATE INDEX idx_ironwood_one_time_keys_scanning
                ON ironwood_one_time_keys(closed_at, active_from);
CREATE INDEX idx_ironwood_received_notes_one_time_key ON ironwood_received_notes (
                one_time_key_id ASC
            ) WHERE one_time_key_id IS NOT NULL;
CREATE INDEX idx_ironwood_one_time_operations_key
                ON ironwood_one_time_operations(one_time_key_id);
CREATE INDEX idx_ironwood_one_time_sweeps_due ON ironwood_one_time_sweeps(done_height, next_attempt_at);
