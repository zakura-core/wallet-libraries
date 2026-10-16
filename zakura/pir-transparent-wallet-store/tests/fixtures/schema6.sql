-- Schema from the published transparent-wallet-store 0.1.0-rc.3.

CREATE TABLE IF NOT EXISTS wallet_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scripts (
    script BLOB PRIMARY KEY,
    origin TEXT NOT NULL,
    required_from INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
    script BLOB NOT NULL,
    start_height INTEGER NOT NULL,
    end_height INTEGER NOT NULL,
    kind TEXT NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    terminal_block_hash TEXT NOT NULL,
    source_anchor TEXT,
    PRIMARY KEY (script, start_height)
);
CREATE TABLE IF NOT EXISTS receives (
    txid BLOB NOT NULL,
    output_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    event BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY (txid, output_index)
);
CREATE TABLE IF NOT EXISTS spends (
    spending_txid BLOB NOT NULL,
    input_index INTEGER NOT NULL,
    spent_txid BLOB NOT NULL,
    spent_output_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    event BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY (spending_txid, input_index, spent_txid, spent_output_index),
    UNIQUE (spent_txid, spent_output_index)
);
CREATE INDEX IF NOT EXISTS spends_by_transaction ON spends(spending_txid);
CREATE TABLE IF NOT EXISTS pending_work (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    script BLOB NOT NULL,
    cursor_child INTEGER NOT NULL,
    cursor_row INTEGER NOT NULL,
    cursor_older_runs INTEGER,
    carried BLOB NOT NULL,
    fragments BLOB NOT NULL,
    target_anchor TEXT,
    attempts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_cache (
    child_digest TEXT NOT NULL,
    script BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    events BLOB NOT NULL,
    older TEXT,
    PRIMARY KEY (child_digest, script)
);
CREATE INDEX IF NOT EXISTS run_cache_by_shard ON run_cache(shard_id, script);
CREATE TABLE IF NOT EXISTS setup_cache (
    set_digest TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    tbl TEXT NOT NULL,
    segment INTEGER NOT NULL,
    public_params_base64 TEXT NOT NULL,
    public_params_sha256 TEXT NOT NULL,
    PRIMARY KEY (set_digest, revision_digest, tbl, segment)
);
CREATE TABLE IF NOT EXISTS filter_cache (
    revision_digest TEXT PRIMARY KEY,
    filter_hash TEXT NOT NULL,
    sealed INTEGER NOT NULL,
    bytes BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);

INSERT INTO wallet_meta VALUES ('schema_version', '6');
