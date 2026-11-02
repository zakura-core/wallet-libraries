//! Differential tests against the published migration engine and SQLite adapter.

use std::{
    cell::Cell,
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    rc::Rc,
};

use rusqlite::{Connection, Transaction, types::Value};
use uuid::Uuid;

use crate::migration::{Migration, SqliteMigration, TABLE, initialize, migrate};

type Nodes<E> = Vec<Box<dyn SqliteMigration<Error = E>>>;
type OracleNodes<E> = Vec<Box<dyn schemerz_rusqlite::RusqliteMigration<Error = E>>>;

struct Frozen<E> {
    node: Box<dyn SqliteMigration<Error = E>>,
    dependencies: HashSet<Uuid>,
}

impl<E> Migration for Frozen<E> {
    fn id(&self) -> Uuid {
        self.node.id()
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        self.dependencies.clone()
    }

    fn description(&self) -> &'static str {
        self.node.description()
    }
}

impl<E: From<rusqlite::Error>> SqliteMigration for Frozen<E> {
    type Error = E;

    fn up(&self, transaction: &Transaction<'_>) -> Result<(), E> {
        self.node.up(transaction)
    }

    fn down(&self, transaction: &Transaction<'_>) -> Result<(), E> {
        self.node.down(transaction)
    }
}

impl<E> schemerz::Migration<Uuid> for Frozen<E> {
    fn id(&self) -> Uuid {
        Migration::id(self)
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        Migration::dependencies(self)
    }

    fn description(&self) -> &'static str {
        Migration::description(self)
    }
}

impl<E: From<rusqlite::Error>> schemerz_rusqlite::RusqliteMigration for Frozen<E> {
    type Error = E;

    fn up(&self, transaction: &Transaction<'_>) -> Result<(), E> {
        SqliteMigration::up(self, transaction)
    }

    fn down(&self, transaction: &Transaction<'_>) -> Result<(), E> {
        SqliteMigration::down(self, transaction)
    }
}

fn frozen_pair<E: From<rusqlite::Error> + 'static>(
    candidate: Nodes<E>,
    oracle: Nodes<E>,
) -> (Nodes<E>, OracleNodes<E>) {
    // Cloning a HashSet retains its hasher and iteration order. The algorithms
    // see the same ordered dependencies without replacing either algorithm.
    let dependencies: HashMap<_, _> = candidate
        .iter()
        .map(|node| (node.id(), node.dependencies()))
        .collect();
    let wrap = |node: Box<dyn SqliteMigration<Error = E>>| Frozen {
        dependencies: dependencies[&node.id()].clone(),
        node,
    };
    (
        candidate
            .into_iter()
            .map(|node| Box::new(wrap(node)) as Box<dyn SqliteMigration<Error = E>>)
            .collect(),
        oracle
            .into_iter()
            .map(|node| {
                Box::new(wrap(node)) as Box<dyn schemerz_rusqlite::RusqliteMigration<Error = E>>
            })
            .collect(),
    )
}

fn run_oracle<E: Error + From<rusqlite::Error> + Send + Sync + 'static>(
    conn: &mut Connection,
    nodes: OracleNodes<E>,
    targets: &[Uuid],
) -> Result<(), schemerz::MigratorError<Uuid, E>> {
    let adapter = schemerz_rusqlite::RusqliteAdapter::new(conn, Some(TABLE.to_owned()));
    adapter.init().map_err(E::from)?;
    let mut runner = schemerz::Migrator::new(adapter);
    runner.register_multiple(nodes.into_iter())?;
    if targets.is_empty() {
        runner.up(None)?;
    } else {
        for target in targets {
            runner.up(Some(*target))?;
        }
    }
    Ok(())
}

fn id(index: u128) -> Uuid {
    Uuid::from_u128(index + 1)
}

#[derive(Clone, Copy, Default)]
enum Failure {
    #[default]
    None,
    Sql,
    Commit,
}

#[derive(Clone)]
struct Step {
    id: Uuid,
    dependencies: HashSet<Uuid>,
    failure: Failure,
}

impl Migration for Step {
    fn id(&self) -> Uuid {
        self.id
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        self.dependencies.clone()
    }

    fn description(&self) -> &'static str {
        "Differential migration"
    }
}

impl SqliteMigration for Step {
    type Error = rusqlite::Error;

    fn up(&self, transaction: &Transaction<'_>) -> Result<(), Self::Error> {
        transaction.execute(
            "INSERT INTO effects (id) VALUES (?1)",
            [self.id.as_bytes().as_slice()],
        )?;
        match self.failure {
            Failure::None => Ok(()),
            Failure::Sql => Err(rusqlite::Error::InvalidQuery),
            Failure::Commit => {
                transaction.execute("INSERT INTO deferred_failure VALUES (1)", [])?;
                Ok(())
            }
        }
    }
}

fn nodes(steps: &[Step]) -> Nodes<rusqlite::Error> {
    steps
        .iter()
        .cloned()
        .map(|step| Box::new(step) as Box<dyn SqliteMigration<Error = rusqlite::Error>>)
        .collect()
}

fn steps() -> Vec<Step> {
    [vec![], vec![0], vec![0], vec![1, 2], vec![], vec![3, 4]]
        .into_iter()
        .enumerate()
        .map(|(index, parents)| Step {
            id: id(index as u128),
            dependencies: parents.into_iter().map(id).collect(),
            failure: Failure::None,
        })
        .collect()
}

fn connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE effects (seq INTEGER PRIMARY KEY, id BLOB UNIQUE);
         CREATE TABLE parent (id INTEGER PRIMARY KEY);
         CREATE TABLE deferred_failure (
             id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED
         );",
    )
    .unwrap();
    initialize(&conn).unwrap();
    conn
}

fn snapshot(conn: &Connection) -> BTreeMap<String, Vec<String>> {
    let mut tables = BTreeMap::new();
    let mut schema = conn
        .prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap();
    tables.insert(
        "schema".to_owned(),
        schema
            .query_map([], |row| {
                Ok(format!(
                    "{:?}",
                    (
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    )
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap(),
    );
    let mut names = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap();
    for name in names.query_map([], |row| row.get::<_, String>(0)).unwrap() {
        let name = name.unwrap();
        let quoted = name.replace('"', "\"\"");
        let mut statement = conn
            .prepare(&format!("SELECT * FROM \"{quoted}\""))
            .unwrap();
        let columns = statement.column_count();
        let mut rows: Vec<_> = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, Value>(column))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|row| format!("{row:?}"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        tables.insert(name, rows);
    }
    tables
}

fn journal_order(conn: &Connection) -> Vec<String> {
    conn.prepare(&format!("SELECT hex(id) FROM {TABLE} ORDER BY rowid"))
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn assert_same(candidate: &Connection, oracle: &Connection) {
    assert_eq!(journal_order(candidate), journal_order(oracle));
    assert_eq!(snapshot(candidate), snapshot(oracle));
}

#[test]
fn published_engine_matches_order_targets_partial_journals_and_reopens() {
    for rotation in 0..6 {
        let mut steps = steps();
        steps.rotate_left(rotation);
        for applied in [0_u8, 1, 3, 0b10_1010, 0b11_1111] {
            for targets in [vec![], vec![id(3)], vec![id(3), id(5)]] {
                let mut candidate = connection();
                let mut oracle = connection();
                for conn in [&candidate, &oracle] {
                    for index in 0..6 {
                        if applied & (1 << index) != 0 {
                            let bytes = id(index).as_bytes().to_vec();
                            conn.execute("INSERT INTO effects (id) VALUES (?1)", [&bytes])
                                .unwrap();
                            conn.execute(
                                &format!("INSERT INTO {TABLE} (id) VALUES (?1)"),
                                [&bytes],
                            )
                            .unwrap();
                        }
                    }
                }
                let (local, old) = frozen_pair(nodes(&steps), nodes(&steps));
                migrate(&mut candidate, &local, &targets).unwrap();
                run_oracle(&mut oracle, old, &targets).unwrap();
                assert_same(&candidate, &oracle);
                let (local, old) = frozen_pair(nodes(&steps), nodes(&steps));
                migrate(&mut candidate, &local, &[]).unwrap();
                run_oracle(&mut oracle, old, &[]).unwrap();
                assert_same(&candidate, &oracle);
                let before = snapshot(&candidate);
                migrate(&mut candidate, &local, &[]).unwrap();
                assert_eq!(snapshot(&candidate), before);
            }
        }
    }
}

#[test]
fn failed_sql_journal_inserts_and_commits_match_rollback_and_retry() {
    for failure in [Failure::Sql, Failure::Commit, Failure::None] {
        let mut steps = steps();
        // A chain makes the successful prefix independent of sibling ordering.
        for index in 1..steps.len() {
            steps[index].dependencies = HashSet::from([steps[index - 1].id]);
        }
        steps[3].failure = failure;
        let mut candidate = connection();
        let mut oracle = connection();
        if matches!(failure, Failure::None) {
            for conn in [&candidate, &oracle] {
                conn.execute_batch(&format!(
                    "CREATE TRIGGER fail_journal BEFORE INSERT ON {TABLE}
                     WHEN NEW.id = X'{:032x}' BEGIN
                         SELECT RAISE(ABORT, 'injected journal failure');
                     END;",
                    steps[3].id.as_u128()
                ))
                .unwrap();
            }
        }
        let (local, old) = frozen_pair(nodes(&steps), nodes(&steps));
        let local_error = migrate(&mut candidate, &local, &[]).unwrap_err();
        let old_error = run_oracle(&mut oracle, old, &[]).unwrap_err();
        assert_eq!(local_error.to_string(), old_error.to_string());
        assert_eq!(
            local_error.source().unwrap().to_string(),
            old_error.source().unwrap().to_string()
        );
        assert_same(&candidate, &oracle);
        assert_eq!(journal_order(&candidate).len(), 3);
        for conn in [&candidate, &oracle] {
            conn.execute_batch("DROP TRIGGER IF EXISTS fail_journal")
                .unwrap();
        }
        steps[3].failure = Failure::None;
        let (local, old) = frozen_pair(nodes(&steps), nodes(&steps));
        migrate(&mut candidate, &local, &[]).unwrap();
        run_oracle(&mut oracle, old, &[]).unwrap();
        assert_same(&candidate, &oracle);
        assert_eq!(journal_order(&candidate).len(), steps.len());
    }
}

#[test]
fn invalid_graphs_and_targets_fail_before_migration_writes() {
    let mut duplicate = steps();
    duplicate.push(duplicate[0].clone());
    let mut unknown = steps();
    unknown[0].dependencies.insert(id(100));
    let mut cycle = steps();
    cycle[0].dependencies.insert(id(5));
    for (steps, targets) in [
        (duplicate, vec![]),
        (unknown, vec![]),
        (cycle, vec![]),
        (steps(), vec![id(100)]),
    ] {
        let mut candidate = connection();
        let mut oracle = connection();
        let before = snapshot(&candidate);
        let (local, old) = frozen_pair(nodes(&steps), nodes(&steps));
        let local_error = migrate(&mut candidate, &local, &targets).unwrap_err();
        let old_error = run_oracle(&mut oracle, old, &targets).unwrap_err();
        assert_eq!(local_error.to_string(), old_error.to_string());
        assert_eq!(snapshot(&candidate), before);
        assert_same(&candidate, &oracle);
    }
}

#[test]
fn malformed_journal_values_match_the_published_adapter() {
    for value in [
        Value::Null,
        Value::Text("not a UUID".to_owned()),
        Value::Blob(vec![]),
        Value::Blob(vec![0; 15]),
        Value::Blob(vec![0; 17]),
    ] {
        let mut candidate = connection();
        let mut oracle = connection();
        for conn in [&candidate, &oracle] {
            conn.execute(&format!("INSERT INTO {TABLE} (id) VALUES (?1)"), [&value])
                .unwrap();
        }
        let before = snapshot(&candidate);
        let (local, old) = frozen_pair(nodes(&steps()), nodes(&steps()));
        let local_error = migrate(&mut candidate, &local, &[]).unwrap_err();
        let old_error = run_oracle(&mut oracle, old, &[]).unwrap_err();
        assert_eq!(local_error.to_string(), old_error.to_string());
        assert_eq!(
            local_error.source().unwrap().to_string(),
            old_error.source().unwrap().to_string()
        );
        assert_eq!(snapshot(&candidate), before);
        assert_same(&candidate, &oracle);
    }
}

struct SeedStep {
    step: Step,
    supplied: Rc<Cell<bool>>,
}

impl Migration for SeedStep {
    fn id(&self) -> Uuid {
        self.step.id()
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        self.step.dependencies()
    }

    fn description(&self) -> &'static str {
        self.step.description()
    }
}

impl SqliteMigration for SeedStep {
    type Error = crate::wallet::init::WalletMigrationError;

    fn up(&self, transaction: &Transaction<'_>) -> Result<(), Self::Error> {
        self.step.up(transaction)?;
        if self.id() == id(1) && !self.supplied.get() {
            return Err(Self::Error::SeedRequired);
        }
        Ok(())
    }
}

#[test]
fn seed_required_source_rollback_and_retry_match_the_published_engine() {
    use crate::wallet::init::WalletMigrationError;

    let supplied = Rc::new(Cell::new(false));
    let make = || -> Nodes<WalletMigrationError> {
        steps()[..2]
            .iter()
            .cloned()
            .map(|step| {
                Box::new(SeedStep {
                    step,
                    supplied: Rc::clone(&supplied),
                }) as Box<dyn SqliteMigration<Error = WalletMigrationError>>
            })
            .collect()
    };
    let mut candidate = connection();
    let mut oracle = connection();
    let (local, old) = frozen_pair(make(), make());
    let local_error = migrate(&mut candidate, &local, &[]).unwrap_err();
    let old_error = run_oracle(&mut oracle, old, &[]).unwrap_err();
    for source in [local_error.source(), old_error.source()] {
        assert!(matches!(
            source.and_then(|source| source.downcast_ref()),
            Some(WalletMigrationError::SeedRequired)
        ));
    }
    assert_same(&candidate, &oracle);
    assert_eq!(journal_order(&candidate).len(), 1);
    supplied.set(true);
    let (local, old) = frozen_pair(make(), make());
    migrate(&mut candidate, &local, &[]).unwrap();
    run_oracle(&mut oracle, old, &[]).unwrap();
    assert_same(&candidate, &oracle);
    assert_eq!(journal_order(&candidate).len(), 2);
}

#[test]
fn real_wallet_graph_matches_the_published_engine() {
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::migrations,
    };
    use zcash_protocol::consensus::Network;

    for targets in [migrations::V_0_4_0, migrations::V_0_19_0, &[]] {
        let local_file = tempfile::NamedTempFile::new().unwrap();
        let old_file = tempfile::NamedTempFile::new().unwrap();
        let mut candidate = WalletDb::for_path(
            local_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let mut oracle = WalletDb::for_path(
            old_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        for conn in [&candidate.conn, &oracle.conn] {
            conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
            initialize(conn).unwrap();
        }
        for phase in [targets, &[]] {
            let make = || {
                migrations::all_migrations(&Network::TestNetwork, test_clock(), test_rng(), None)
            };
            let (local, old) = frozen_pair(make(), make());
            migrate(&mut candidate.conn, &local, phase).unwrap();
            run_oracle(&mut oracle.conn, old, phase).unwrap();
            assert_same(&candidate.conn, &oracle.conn);
        }
    }
}
