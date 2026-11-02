//! The wallet's UUID-based SQLite migration runner.
//!
//! SQLite journal encoding and transaction handling retain the implementation
//! from `schemerz-rusqlite` 0.371.0, licensed under MIT OR Apache-2.0.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
};

use rusqlite::{Connection, Transaction};
use uuid::Uuid;

pub(crate) const TABLE: &str = "schemer_migrations";

/// An error while preparing or applying a wallet database migration.
///
/// The underlying wallet or SQLite error is available through
/// [`Error::source`]. Failed migrations also retain their identifier and
/// description in the error's display text.
#[derive(Debug)]
pub struct MigrationError<E> {
    context: Context<E>,
}

#[derive(Debug)]
enum Context<E> {
    Dependency(DependencyError),
    Adapter(E),
    Migration {
        id: Uuid,
        description: &'static str,
        error: E,
    },
}

impl<E> From<E> for MigrationError<E> {
    fn from(error: E) -> Self {
        Self {
            context: Context::Adapter(error),
        }
    }
}

impl<E: fmt::Display> fmt::Display for MigrationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Context::Dependency(_) => {
                f.write_str("An error occurred due to migration dependencies")
            }
            Context::Adapter(_) => {
                f.write_str("An error occurred while interacting with the adapter.")
            }
            Context::Migration {
                id,
                description,
                error,
            } => write!(
                f,
                "An error occurred while applying migration {id} ({description}) up: {error}."
            ),
        }
    }
}

impl<E: Error + 'static> Error for MigrationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match &self.context {
            Context::Dependency(error) => error,
            Context::Adapter(error) | Context::Migration { error, .. } => error,
        })
    }
}

#[derive(Debug)]
enum DependencyError {
    Duplicate(Uuid),
    Unknown(Uuid),
    Cycle { from: Uuid, to: Uuid },
}

impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(id) => write!(f, "Duplicate migration ID {id}"),
            Self::Unknown(id) => write!(f, "Unknown migration ID {id}"),
            Self::Cycle { from, to } => write!(
                f,
                "Cyclic dependency caused by edge from migration IDs {from} to {to}"
            ),
        }
    }
}

impl Error for DependencyError {}

impl<E> MigrationError<E> {
    fn dependency(error: DependencyError) -> Self {
        Self {
            context: Context::Dependency(error),
        }
    }
}

pub(crate) trait Migration {
    fn id(&self) -> Uuid;
    fn dependencies(&self) -> HashSet<Uuid>;
    fn description(&self) -> &'static str;
}

pub(crate) trait SqliteMigration: Migration {
    type Error: From<rusqlite::Error>;

    fn up(&self, _transaction: &Transaction<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    // Retain the existing migration SQL for the independent old-engine oracle.
    #[cfg_attr(not(test), expect(dead_code))]
    fn down(&self, _transaction: &Transaction<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct Graph {
    ids: Vec<Uuid>,
    positions: HashMap<Uuid, usize>,
    parents: Vec<Vec<usize>>,
    sinks: Vec<usize>,
}

impl Graph {
    fn new<E>(migrations: &[Box<dyn SqliteMigration<Error = E>>]) -> Result<Self, DependencyError> {
        let ids: Vec<_> = migrations.iter().map(|migration| migration.id()).collect();
        let mut positions = HashMap::with_capacity(ids.len());
        for (index, id) in ids.iter().copied().enumerate() {
            if positions.insert(id, index).is_some() {
                return Err(DependencyError::Duplicate(id));
            }
        }
        let mut has_child = vec![false; ids.len()];
        let parents = migrations
            .iter()
            .map(|migration| {
                migration
                    .dependencies()
                    .into_iter()
                    .map(|id| {
                        let index = *positions.get(&id).ok_or(DependencyError::Unknown(id))?;
                        has_child[index] = true;
                        Ok(index)
                    })
                    .collect::<Result<Vec<_>, DependencyError>>()
            })
            .collect::<Result<_, _>>()?;
        let graph = Self {
            ids,
            positions,
            parents,
            sinks: has_child
                .iter()
                .enumerate()
                .filter_map(|(index, has_child)| (!has_child).then_some(index))
                .collect(),
        };
        let mut state = vec![0; graph.ids.len()];
        let mut order = Vec::new();
        for index in 0..graph.ids.len() {
            graph.visit(index, &mut state, &mut order)?;
        }
        Ok(graph)
    }

    fn visit(
        &self,
        index: usize,
        state: &mut [u8],
        order: &mut Vec<usize>,
    ) -> Result<(), DependencyError> {
        if state[index] == 2 {
            return Ok(());
        }
        state[index] = 1;
        for &parent in &self.parents[index] {
            if state[parent] == 1 {
                return Err(DependencyError::Cycle {
                    from: self.ids[parent],
                    to: self.ids[index],
                });
            }
            self.visit(parent, state, order)?;
        }
        state[index] = 2;
        order.push(index);
        Ok(())
    }

    fn order(&self, target: Option<Uuid>) -> Result<Vec<usize>, DependencyError> {
        let mut state = vec![0; self.ids.len()];
        let mut order = Vec::new();
        match target {
            Some(id) => {
                let index = *self
                    .positions
                    .get(&id)
                    .ok_or(DependencyError::Unknown(id))?;
                self.visit(index, &mut state, &mut order)?;
            }
            None => {
                for &index in &self.sinks {
                    self.visit(index, &mut state, &mut order)?;
                }
            }
        }
        Ok(order)
    }
}

pub(crate) fn initialize(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute(
        &format!(
            r#"
                    CREATE TABLE IF NOT EXISTS {} (
                        id blob PRIMARY KEY
                    )
                "#,
            TABLE
        ),
        [],
    )?;
    Ok(())
}

struct StoredUuid(Uuid);

impl rusqlite::types::FromSql for StoredUuid {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(Self(Uuid::from_slice(value.as_blob()?).map_err(
            |error| rusqlite::types::FromSqlError::Other(Box::new(error)),
        )?))
    }
}

pub(crate) fn migrate<E: From<rusqlite::Error>>(
    conn: &mut Connection,
    migrations: &[Box<dyn SqliteMigration<Error = E>>],
    targets: &[Uuid],
) -> Result<(), MigrationError<E>> {
    let graph = Graph::new(migrations).map_err(MigrationError::dependency)?;
    let targets: Vec<_> = if targets.is_empty() {
        vec![None]
    } else {
        targets.iter().copied().map(Some).collect()
    };
    for target in targets {
        match target {
            Some(id) => tracing::info!("Migrating up to target: {}", id),
            None => tracing::info!("Migrating everything"),
        }
        let order = graph.order(target).map_err(MigrationError::dependency)?;
        let mut statement = conn
            .prepare(&format!("SELECT id FROM {};", TABLE))
            .map_err(E::from)?;
        let applied = statement
            .query_map([], |row| row.get::<_, StoredUuid>(0))
            .map_err(E::from)?
            .map(|row| row.map(|id| id.0))
            .collect::<Result<HashSet<_>, _>>()
            .map_err(E::from)?;
        drop(statement);
        for index in order {
            let migration = &migrations[index];
            let id = migration.id();
            if applied.contains(&id) {
                continue;
            }
            let description = migration.description();
            tracing::info!("Applying migration {} ({})", id, description);
            let result = (|| -> Result<(), E> {
                let transaction = conn.transaction()?;
                migration.up(&transaction)?;
                let uuid_bytes = &id.as_bytes()[..];
                transaction.execute(
                    &format!("INSERT INTO {} (id) VALUES (?1);", TABLE),
                    [&uuid_bytes],
                )?;
                transaction.commit().map_err(E::from)
            })();
            result.map_err(|error| MigrationError {
                context: Context::Migration {
                    id,
                    description,
                    error,
                },
            })?;
        }
    }
    Ok(())
}
