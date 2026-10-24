#!/usr/bin/env python3
"""Verify upgrades from disposable published rc5 to rc9.3 wallets and the last pre-migration revision.

Older consumers ingest transaction/UTXO fixtures before the current library upgrades them: the
published rc5, rc7 (the mobile 0.0.50 baseline), rc9, rc9.1, rc9.2 and rc9.3 releases, and this repository at
PRE_MIGRATIONS, the last revision before the unconditional ironwood_unsupported_memo_retry,
ironwood_transparent_output_shape, transparent_txid_enhancement, one_time_ivk and
one_time_ivk_discovery migrations. Abandoned feature progress has no compatibility contract. The probe
verifies preserved data, classification values, legacy provenance, that the upgrade queues no
private work for a wallet that never had a private policy, repeat initialization, and how older
readers treat the upgraded database. The rc9.2 wallet also uses that release's one-time IVK
feature, reserving a receive address and a refund key and quoting both, so the upgrade's legacy
one-time branch runs on real data: it must keep the keys and operations, drop the abandoned
discovery progress, and leave recovery disabled. rc9 onwards and the pre-migration fork must refuse unknown
migrations without changing it; rc5 and rc7 lack that guard and their successful opens are
reported, not qualified. Separate consumers retain their own dependency families; no user wallet
is accepted.
"""
import argparse
import fcntl
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import tarfile
import tomllib
import io
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "librustzcash/zcash_client_backend/tests/fixtures/ironwood-fee-expiry.hex"
# The last revision before the unconditional migrations below.
PRE_MIGRATIONS = "cf1dcfec88062c420322578226d5240328002d3d"
UNCONDITIONAL_MIGRATIONS = {
    "ironwood_unsupported_memo_retry": "3d1c7a52-8e0b-4f6d-9a47-5be2c0f19e84",
    "ironwood_transparent_output_shape": "8f4c3210-04e1-49eb-9de2-d713ee0a8426",
    "transparent_txid_enhancement": "73d751a3-dbdc-461a-9154-e061903aae4f",
    "one_time_ivk": "57756102-9583-4af5-b411-5eead49fc9f0",
    "one_time_ivk_discovery": "c5b63b3b-8190-4d0f-b217-3921d7aac225",
    "one_time_pir": "2eed2da7-2176-4d72-9461-c9ae27491b0a",
}
# Current feature tables must remain empty for an ordinary wallet upgrade.
ONE_TIME_IVK_TABLES = (
    "ironwood_one_time_keys", "ironwood_one_time_operations", "ironwood_one_time_operation_receipts",
    "ironwood_one_time_payment_recovery",
    "ironwood_one_time_recovery", "ironwood_one_time_lookups",
    "ironwood_spend_journal", "ironwood_spend_journal_nullifiers", "ironwood_journal_coverage",
)
WRITERS = ("rc5", "rc7", "rc9", "rc9.1", "rc9.2", "rc9.3", "pre-migrations")
# Writers whose library refuses a database with migrations it does not know.
REFUSING_READERS = ("rc9", "rc9.1", "rc9.2", "rc9.3", "pre-migrations")
# Writers that also use the published one-time IVK feature before the upgrade.
ONE_TIME_WRITERS = ("rc9.2",)
# Each published writer's Zakura Common family and the PCZT release built on it.
COMMON = {
    "rc9": ("3.0.0", "0.1.0-rc6"),
    "rc9.1": ("4.0.0-rc2", "0.1.0-rc7"),
    "rc9.2": ("4.0.0-rc3", "0.1.0-rc8"),
    "rc9.3": ("4.0.0", "0.1.0-rc9"),
}
# One-time state the upgrade keeps: keys and operations, compared by these columns.
ONE_TIME_KEPT = {
    "ironwood_one_time_keys": "account_id, purpose, key_index, receiver, reserved_at, released_at",
    "ironwood_one_time_operations": "one_time_key_id, request, reference, memo, deadline, begun_at, started",
}
# rc9.2's scan priority code for a scanned range.
SCANNED = 10


def source_tree(root, rev):
    """This repository's tree at `rev`, extracted without touching the checkout."""
    dest = root / f"source-{rev}"
    archive = subprocess.run(["git", "archive", rev], cwd=ROOT, check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        # The `data` filter needs Python 3.12; the archive is this repository's own tree.
        try:
            tar.extractall(dest, filter="data")
        except TypeError:
            tar.extractall(dest)
    return dest


def workspace_source(package):
    """Use the wallet's version and source, so probe types belong to the same crate family."""
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    for alias, dependency in manifest["workspace"]["dependencies"].items():
        if isinstance(dependency, dict) and dependency.get("package", alias) == package:
            source = {
                key: dependency[key]
                for key in ("version", "git", "rev", "branch", "tag", "registry")
                if key in dependency
            }
            if "version" in source:
                source["version"] = "=" + source["version"].removeprefix("=")
            return ", ".join(
                f"{key} = {json.dumps(value)}" for key, value in source.items()
            )
    raise SystemExit(f"no {package} dependency in the workspace manifest")


def consumer(root, version):
    dest = root / version
    (dest / "src").mkdir(parents=True)
    (dest / "src/main.rs").write_text((ROOT / "scripts/probes/published_wallet_upgrades.rs").read_text())
    # `ledger` marks explicit transparent ledger modes, and `current` this tree.
    probe = version.replace(".", "-")
    manifest = f'[package]\nname = "legacy-writers-probe-{probe}"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[features]\nledger = []\ncurrent = ["ledger"]\none-time-rc9 = []\n[dependencies]\nhex = "0.4"\nsecrecy = "0.8"\n'
    tree = {"current": ROOT, "pre-migrations": root / f"source-{PRE_MIGRATIONS}"}.get(version)
    for alias, package, directory in [
        ("zcash_client_sqlite", "zakura-client-sqlite", "zcash_client_sqlite"),
        ("zcash_client_backend", "zakura-client-backend", "zcash_client_backend"),
    ]:
        source = f'path = {json.dumps(str(tree / "librustzcash" / directory))}' if tree else f'version = "=0.1.0-{version}"'
        manifest += f'{alias} = {{ package = "{package}", {source}, features = ["orchard", "transparent-inputs", "test-dependencies"] }}\n'
    if version == "rc5":
        manifest += 'zcash_primitives = { package = "zakura-primitives", version = "=1.2.0" }\nzcash_protocol = "=0.10.4"\n'
        manifest += 'transparent = { package = "zcash_transparent", version = "=0.10.0" }\n'
    else:
        # The current tree uses the workspace's Zakura Common family; rc9 uses 3.0.0, and rc7
        # and pre-migrations use 2.0.0.
        for alias, package in [
            ("zcash_primitives", "zakura-primitives"),
            ("zcash_protocol", "zakura-protocol"),
            ("transparent", "zakura-transparent"),
        ]:
            if version == "current":
                source = workspace_source(package)
            else:
                common = COMMON.get(version, ("2.0.0",))[0]
                source = f'version = "={common}"'
            manifest += f'{alias} = {{ package = "{package}", {source} }}\n'
    # Pin the PCZT prerelease used by Vizor: caret prerelease resolution otherwise selects
    # rc4's newer dependency family while testing rc5's published writer.
    if version == "rc5":
        manifest += 'pczt = { package = "zakura-pczt", version = "=0.1.0-rc3", default-features = false, features = ["io-finalizer"] }\n'
    elif version == "rc7":
        manifest += 'pczt = { package = "zakura-pczt", version = "=0.1.0-rc4", features = ["io-finalizer"] }\n'
    elif version in COMMON:
        manifest += f'pczt = {{ package = "zakura-pczt", version = "={COMMON[version][1]}", features = ["io-finalizer"] }}\n'
    (dest / "Cargo.toml").write_text(manifest)
    # Retain the writer's locked common dependency versions instead of floating to a
    # newer minor release. Cargo adjusts only the legacy families absent from this lockfile.
    (dest / "Cargo.lock").write_text(((tree or ROOT) / "Cargo.lock").read_text())
    return dest


def dump(path):
    """Every row of every table, in a canonical order."""
    with sqlite3.connect(path) as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {table: sorted(map(repr, conn.execute(f'SELECT * FROM "{table}"'))) for table in tables}


def assert_no_private_work(path, version, kept=None):
    """A wallet that never had a private policy gets no private obligations from the upgrade.

    One-time IVK tables must be empty, and abandoned progress tables must be gone. For a wallet
    that used the published one-time feature, `kept` holds its keys and operations, which the
    upgrade keeps unchanged while recovery starts disabled with no queued work.
    """
    with sqlite3.connect(path) as conn:
        applied = {row[0] for row in conn.execute("SELECT id FROM schemer_migrations")}
        for name, migration in UNCONDITIONAL_MIGRATIONS.items():
            assert uuid.UUID(migration).bytes in applied, f"{version}: {name} not applied"
        assert conn.execute("SELECT applied_mode, policy_generation FROM tpir_meta").fetchall() == [(0, 0)]
        for table in ("transparent_detail_work", "transparent_tx_display", "ironwood_memo_retrieval_queue", "ironwood_enhance_metadata_queue"):
            count = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            assert count == 0, f"{version}: the upgrade queued {count} rows in {table}"
        assert conn.execute("SELECT count(*) FROM ironwood_enhance_routing WHERE route = 2").fetchone()[0] == 0
        for table in ONE_TIME_IVK_TABLES:
            if kept is not None and table in ONE_TIME_KEPT:
                assert one_time_rows(conn, table) == kept[table], f"{version}: the upgrade changed {table}"
                continue
            count = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            assert count == 0, f"{version}: the upgrade left {count} rows in {table}"
        for table in ABANDONED_TABLES:
            assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name = ?", (table,)).fetchone()[0] == 0, f"{version}: {table} survived"
        assert conn.execute("SELECT count(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM tx_retrieval_queue WHERE policy_generation != 0").fetchone()[0] == 0


# Discovery progress the one-time PIR rebaseline abandons.
ABANDONED_TABLES = (
    "ironwood_one_time_lookup_reads", "ironwood_one_time_discovery", "ironwood_one_time_publications",
    "ironwood_one_time_fresh_accounts", "ironwood_nullifier_scan_blocks",
    "ironwood_one_time_spend_retention", "ironwood_one_time_sweeps",
)


def one_time_rows(conn, table):
    """`table`'s kept one-time rows, by the columns both schemas share."""
    return conn.execute(f"SELECT {ONE_TIME_KEPT[table]} FROM {table} ORDER BY {ONE_TIME_KEPT[table]}").fetchall()


def columns(conn, relation):
    """`relation`'s column names, in order."""
    return [row[1] for row in conn.execute(f"PRAGMA table_info({relation})")]


def has_column(conn, relation, column):
    return column in columns(conn, relation)


def snapshot(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT id FROM schemer_migrations ORDER BY id").fetchall()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=Path.home() / ".cache/wallet-libraries/legacy-writers")
    args = parser.parse_args()
    args.target_dir.mkdir(parents=True, exist_ok=True)
    lease = (args.target_dir / "owner.lock").open("w")
    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with tempfile.TemporaryDirectory(prefix="legacy-writers-") as tmp:
        root = Path(tmp)
        source_tree(root, PRE_MIGRATIONS)
        consumers = {v: consumer(root, v) for v in ("current", *WRITERS)}
        def run(version, command, db, *extra, capture=False):
            argv = ["cargo", "run", "--manifest-path", str(consumers[version] / "Cargo.toml"), "--target-dir", str(args.target_dir)]
            if version == "current":
                argv += ["--features", "current"]
            elif version in ONE_TIME_WRITERS:
                argv += ["--features", "ledger,one-time-rc9"]
            elif version in REFUSING_READERS:
                argv += ["--features", "ledger"]
            argv += ["--", command, str(db), str(FIXTURE), *extra]
            return subprocess.run(argv, cwd=ROOT, check=True, stdout=subprocess.PIPE if capture else None, text=True)
        downgrade = {}
        for version in WRITERS:
            db = root / f"{version}.sqlite"
            run(version, "init", db)
            run(version, "ingest", db)
            kept = None
            if version in ONE_TIME_WRITERS:
                # The probe stores no blocks; mark the chain scanned through the tip so the
                # published issuance checks pass.
                with sqlite3.connect(db) as conn:
                    (birthday,) = conn.execute("SELECT MIN(birthday_height) FROM accounts").fetchone()
                    (end,) = conn.execute("SELECT MAX(block_range_end) FROM scan_queue").fetchone()
                    conn.execute("DELETE FROM scan_queue")
                    conn.execute(
                        "INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES (?, ?, ?)",
                        (birthday, end, SCANNED))
                run(version, "one-time", db)
                with sqlite3.connect(db) as conn:
                    kept = {table: one_time_rows(conn, table) for table in ONE_TIME_KEPT}
                    assert len(kept["ironwood_one_time_keys"]) == 2, kept
                    assert len(kept["ironwood_one_time_operations"]) == 2, kept
            with sqlite3.connect(db) as conn:
                accounts = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
                old_rows = conn.execute("SELECT txid, raw, min_observed_height, mined_height, zip318_kind FROM transactions ORDER BY txid").fetchall()
                old_outputs = conn.execute("SELECT * FROM transparent_received_outputs ORDER BY id").fetchall()
                assert len(accounts) == 1
                assert len(old_rows) == 2
                assert len(old_outputs) == 2
            run("current", "init", db)
            after_upgrade = snapshot(db)
            run("current", "init", db)
            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT * FROM accounts ORDER BY id").fetchall() == accounts
                assert conn.execute("SELECT txid, raw, min_observed_height, mined_height, zip318_kind FROM transactions ORDER BY txid").fetchall() == old_rows
                assert conn.execute("SELECT * FROM transparent_received_outputs ORDER BY id").fetchall() == old_outputs
                assert conn.execute("SELECT output_id, origin FROM tpir_output_origins ORDER BY output_id,origin").fetchall() == [(row[0], 0) for row in old_outputs]
                assert has_column(conn, "transactions", "zip318_kind")
                assert has_column(conn, "v_transactions", "zip318_kind")
                assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
                assert conn.execute("SELECT count(*) FROM tpir_coverage").fetchone()[0] == 0
            assert snapshot(db) == after_upgrade
            assert_no_private_work(db, version, kept)
            one_time = "; one-time keys and operations kept, abandoned progress dropped, recovery disabled" if kept else ""
            print(f"PASS {version}: ingestion before upgrade; current upgrade preserved accounts, transactions, classification values and UTXOs; legacy provenance grants no coverage; the unconditional migrations queued no private work; repeat initialization preserved journal{one_time}", flush=True)
            # The writer, now a prior reader, opens the upgraded database. A build that checks
            # for unknown migrations refuses it and changes nothing; rc5 and rc7 predate that
            # check, which is reported rather than assumed.
            upgraded = dump(db)
            # A nonzero exit alone is not evidence of the downgrade guard: a
            # schema, seed or build error could cause it. The guarded reader
            # succeeds only after matching its typed UnknownMigrations error.
            refused = version in REFUSING_READERS
            run(version, "refuse-old" if refused else "init", db)
            unchanged = dump(db) == upgraded
            assert unchanged, f"{version}: older reader changed the upgraded wallet"
            downgrade[version] = (refused, unchanged)
            print(f"{'PASS' if refused and unchanged else 'REPORT'} {version} as a prior reader: {'refused' if refused else 'OPENED'} the upgraded database; {'unchanged' if unchanged else 'CHANGED it'}", flush=True)
        # Revisions with the unknown-migration check must refuse a newer database.
        for version in REFUSING_READERS:
            assert downgrade[version] == (True, True), f"{version} did not refuse the upgraded database cleanly"



if __name__ == "__main__":
    main()
