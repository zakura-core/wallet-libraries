-- Captured with the unchanged pre-packaging implementation. Synthetic example.invalid data.
BEGIN TRANSACTION;
CREATE TABLE commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE coverage (
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
CREATE TABLE failed_entries (
    shard_id INTEGER NOT NULL,
    script BLOB NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (shard_id, script)
);
CREATE TABLE filter_cache (
    revision_digest TEXT PRIMARY KEY,
    filter_hash TEXT NOT NULL,
    sealed INTEGER NOT NULL,
    bytes BLOB NOT NULL
);
CREATE TABLE pending_work (
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
CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);
INSERT INTO "pir_bridge_binding" VALUES('format','transparent-reference-companion-v3');
INSERT INTO "pir_bridge_binding" VALUES('account-source',X'44D0F6FA11FCD6BDD03EDBB0AB9C9A14C6DE520C87B357BEE1F004879A816C89');
INSERT INTO "pir_bridge_binding" VALUES('recut-epoch',0);
CREATE TABLE pir_bridge_catalog (
        source BLOB NOT NULL CHECK(length(source)=32),
        start_height INTEGER NOT NULL CHECK(start_height>=0),
        digest TEXT NOT NULL,
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
        current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
        PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));
CREATE TABLE pir_bridge_exports (
        source BLOB NOT NULL CHECK(length(source)=32),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        PRIMARY KEY(source,lineage), UNIQUE(source,revision));
CREATE TABLE receives (
    txid BLOB NOT NULL,
    output_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    event BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    PRIMARY KEY (txid, output_index)
);
CREATE TABLE run_cache (
    child_digest TEXT NOT NULL,
    script BLOB NOT NULL,
    shard_id INTEGER NOT NULL,
    events BLOB NOT NULL,
    older TEXT,
    PRIMARY KEY (child_digest, script)
);
CREATE TABLE scripts (
    script BLOB PRIMARY KEY,
    origin TEXT NOT NULL,
    required_from INTEGER NOT NULL
);
CREATE TABLE setup_cache (
    set_digest TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    tbl TEXT NOT NULL,
    segment INTEGER NOT NULL,
    public_params_base64 TEXT NOT NULL,
    public_params_sha256 TEXT NOT NULL,
    PRIMARY KEY (set_digest, revision_digest, tbl, segment)
);
CREATE TABLE spends (
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
CREATE TABLE wallet_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO "wallet_meta" VALUES('schema_version','7');
CREATE INDEX spends_by_transaction ON spends(spending_txid);
CREATE INDEX run_cache_by_shard ON run_cache(shard_id, script);
DELETE FROM "sqlite_sequence";
COMMIT;
