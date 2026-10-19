#!/usr/bin/env python3
"""Verify upgrades from disposable published rc5/rc7/rc9 wallets and the last pre-migration revision.

Older consumers ingest transaction/UTXO fixtures before the current library upgrades them: the
published rc5, rc7 (the mobile 0.0.50 baseline) and rc9 releases, and this repository at
PRE_MIGRATIONS, the last revision before the unconditional ironwood_unsupported_memo_retry,
ironwood_transparent_output_shape, transparent_txid_enhancement, one_time_ivk and
one_time_ivk_discovery migrations. rc9, which shipped one_time_ivk, also starts an incoming swap
and reserves a refund key, which the current library must keep and be able to use. The probe
verifies preserved data, classification values, legacy provenance, that the upgrade queues no
private work for a wallet that never had a private policy, repeat initialization, and how older
readers treat the upgraded database. rc9 and the pre-migration fork must refuse unknown
migrations without changing it; rc5 and rc7 lack that guard and their successful opens are
reported, not qualified. Separate consumers retain their own dependency families; no user wallet
is accepted.
"""
import argparse
import fcntl
import json
import re
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import tarfile
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
}
# One-time IVK tables left after one_time_ivk_discovery, which an upgrade must leave empty
# unless the writer stored one-time IVK data.
ONE_TIME_IVK_TABLES = (
    "ironwood_one_time_keys", "ironwood_one_time_operations", "ironwood_one_time_payment_recovery",
    "ironwood_one_time_publications", "ironwood_one_time_lookups", "ironwood_one_time_lookup_reads",
    "ironwood_one_time_recovery", "ironwood_one_time_receiver_cache", "ironwood_one_time_obligations",
    "ironwood_spend_journal", "ironwood_spend_journal_nullifiers", "ironwood_journal_coverage",
)
WRITERS = ("rc5", "rc7", "rc9", "pre-migrations")
# Writers whose library refuses a database with migrations it does not know.
REFUSING_READERS = ("rc9", "pre-migrations")
# Writers that also store one-time IVK keys and operations, and the tables holding them.
ONE_TIME_WRITERS = ("rc9",)
ONE_TIME_SEEDED_TABLES = ("ironwood_one_time_keys", "ironwood_one_time_operations", "ironwood_one_time_fresh_accounts")
# The seeded tables an upgrade keeps; it drops the fresh account marks.
ONE_TIME_KEPT_TABLES = ONE_TIME_SEEDED_TABLES[:2]


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


def workspace_version(package):
    """The version this workspace's root manifest requires of `package`."""
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        if f'package = "{package}"' in line:
            match = re.search(r'version = "([^"]+)"', line)
            if match:
                return match.group(1)
    raise SystemExit(f"no {package} version in the workspace manifest")


def consumer(root, version):
    dest = root / version
    (dest / "src").mkdir(parents=True)
    (dest / "src/main.rs").write_text((ROOT / "scripts/probes/published_wallet_upgrades.rs").read_text())
    # `ledger` marks a library with explicit transparent ledger modes, `one-time` a published
    # writer that stores one-time IVK data, and `current` this tree.
    manifest = f'[package]\nname = "legacy-writers-probe-{version}"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[features]\nledger = []\none-time = ["ledger"]\ncurrent = ["ledger"]\n[dependencies]\nhex = "0.4"\nsecrecy = "0.8"\n'
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
                common = workspace_version(package).removeprefix("=")
            else:
                common = {"rc9": "3.0.0"}.get(version, "2.0.0")
            manifest += f'{alias} = {{ package = "{package}", version = "={common}" }}\n'
    # Pin the PCZT prerelease used by Vizor: caret prerelease resolution otherwise selects
    # rc4's newer dependency family while testing rc5's published writer.
    if version == "rc5":
        manifest += 'pczt = { package = "zakura-pczt", version = "=0.1.0-rc3", default-features = false, features = ["io-finalizer"] }\n'
    elif version == "rc7":
        manifest += 'pczt = { package = "zakura-pczt", version = "=0.1.0-rc4", features = ["io-finalizer"] }\n'
    elif version == "rc9":
        manifest += 'pczt = { package = "zakura-pczt", version = "=0.1.0-rc6", features = ["io-finalizer"] }\n'
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


def assert_no_private_work(path, version):
    """A wallet that never had a private policy gets no private obligations from the upgrade.

    One-time IVK tables must be empty, except the ones a one-time writer seeded.
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
        seeded = ONE_TIME_SEEDED_TABLES if version in ONE_TIME_WRITERS else ()
        for table in (t for t in ONE_TIME_IVK_TABLES if t not in seeded):
            count = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            assert count == 0, f"{version}: the upgrade left {count} rows in {table}"
        assert conn.execute("SELECT count(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM tx_retrieval_queue WHERE policy_generation != 0").fetchone()[0] == 0


def columns(conn, relation):
    """`relation`'s column names, in order."""
    return [row[1] for row in conn.execute(f"PRAGMA table_info({relation})")]


def one_time_rows(path, kept=None):
    """Each seeded one-time IVK table's rows, or each table `kept` names restricted to its
    columns there."""
    with sqlite3.connect(path) as conn:
        rows = {}
        for table in kept if kept else ONE_TIME_SEEDED_TABLES:
            names = kept[table][0] if kept else columns(conn, table)
            select = ", ".join(f'"{name}"' for name in names)
            rows[table] = (names, conn.execute(f'SELECT {select} FROM "{table}" ORDER BY rowid').fetchall())
        return rows


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
                argv += ["--features", "one-time"]
            elif version == "pre-migrations":
                argv += ["--features", "ledger"]
            argv += ["--", command, str(db), str(FIXTURE), *extra]
            return subprocess.run(argv, cwd=ROOT, check=True, stdout=subprocess.PIPE if capture else None, text=True)
        downgrade = {}
        for version in WRITERS:
            db = root / f"{version}.sqlite"
            run(version, "init", db)
            run(version, "ingest", db)
            with sqlite3.connect(db) as conn:
                accounts = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
                old_rows = conn.execute("SELECT txid, raw, min_observed_height, mined_height, zip318_kind FROM transactions ORDER BY txid").fetchall()
                old_outputs = conn.execute("SELECT * FROM transparent_received_outputs ORDER BY id").fetchall()
                assert len(accounts) == 1
                assert len(old_rows) == 2
                assert len(old_outputs) == 2
            one_time = version in ONE_TIME_WRITERS
            if one_time:
                seeded = run(version, "one-time", db, capture=True).stdout.split()
                old_one_time = one_time_rows(db)
                assert [len(old_one_time[t][1]) for t in ONE_TIME_SEEDED_TABLES] == [2, 2, 1], old_one_time
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
            assert_no_private_work(db, version)
            print(f"PASS {version}: ingestion before upgrade; current upgrade preserved accounts, transactions, classification values and UTXOs; legacy provenance grants no coverage; the unconditional migrations queued no private work; repeat initialization preserved journal", flush=True)
            if one_time:
                kept = {t: old_one_time[t] for t in ONE_TIME_KEPT_TABLES}
                assert one_time_rows(db, kept) == kept, f"{version}: the upgrade changed one-time IVK rows"
                with sqlite3.connect(db) as conn:
                    floors = conn.execute("SELECT reservation_floor FROM ironwood_one_time_keys").fetchall()
                    dropped = conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'ironwood_one_time_fresh_accounts'").fetchone()[0]
                assert floors == [(None,)] * 2, f"{version}: upgraded keys got {floors}"
                assert dropped == 0, f"{version}: the upgrade kept the fresh account marks"
                run("current", "one-time-use", db, *seeded)
                print(f"PASS {version} one-time IVK data: the upgrade preserved its keys and operations with no reservation floor and dropped the fresh account mark; the current wallet resumed the started incoming swap, built the refund funding memo and kept both keys open", flush=True)
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
