// Both binaries compile this single source file so strict config and CLI parsing cannot diverge.
#[path = "../config.rs"]
pub mod config;

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rusqlite::{Connection, OpenFlags};

const SCHEMA_SQL: &str = include_str!("../../db/schema.sql");
const ASSESSMENTS_TABLE_EXISTS_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assessments')";

/// Reports operator-command failures while retaining the exact path and SQLite source.
#[derive(Debug)]
enum InitDbError {
    Config(config::ConfigError),
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Inspect {
        path: PathBuf,
        source: rusqlite::Error,
    },
    AlreadyInitialized {
        path: PathBuf,
    },
    Begin {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Apply {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Commit {
        path: PathBuf,
        source: rusqlite::Error,
    },
}

/// Applies the schema only through this deliberate operator command.
fn main() -> ExitCode {
    match run() {
        Ok(path) => {
            println!("initialized audit database at {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("database initialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Loads strict configuration and initializes its database path exactly once.
fn run() -> Result<PathBuf, InitDbError> {
    let config_path = config::config_path_from_args(config::process_args())?;
    let config = config::Config::load(&config_path)?;
    initialize_database(&config.database.path)?;
    Ok(config.database.path)
}

/// Creates the database file but refuses to alter an existing assessments schema.
fn initialize_database(path: &Path) -> Result<(), InitDbError> {
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|source| InitDbError::Open {
        path: path.to_path_buf(),
        source,
    })?;

    let schema_exists = connection
        .query_row(ASSESSMENTS_TABLE_EXISTS_SQL, [], |row| {
            row.get::<_, bool>(0)
        })
        .map_err(|source| InitDbError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    if schema_exists {
        return Err(InitDbError::AlreadyInitialized {
            path: path.to_path_buf(),
        });
    }

    // DDL is atomic: a partial schema must never be mistaken for an initialized store.
    let transaction = connection
        .transaction()
        .map_err(|source| InitDbError::Begin {
            path: path.to_path_buf(),
            source,
        })?;
    transaction
        .execute_batch(SCHEMA_SQL)
        .map_err(|source| InitDbError::Apply {
            path: path.to_path_buf(),
            source,
        })?;
    transaction.commit().map_err(|source| InitDbError::Commit {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}

impl fmt::Display for InitDbError {
    /// Names the failed initialization boundary without erasing SQLite diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(formatter, "{source}"),
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "failed to create database {}: {source}",
                    path.display()
                )
            }
            Self::Inspect { path, source } => write!(
                formatter,
                "failed to inspect database {} before initialization: {source}",
                path.display()
            ),
            Self::AlreadyInitialized { path } => write!(
                formatter,
                "database {} already contains the assessments table; refusing to modify it",
                path.display()
            ),
            Self::Begin { path, source } => write!(
                formatter,
                "failed to begin schema transaction for {}: {source}",
                path.display()
            ),
            Self::Apply { path, source } => write!(
                formatter,
                "failed to apply schema to {}: {source}",
                path.display()
            ),
            Self::Commit { path, source } => write!(
                formatter,
                "failed to commit schema for {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for InitDbError {
    /// Exposes configuration and SQLite causes for operator diagnostics.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Open { source, .. }
            | Self::Inspect { source, .. }
            | Self::Begin { source, .. }
            | Self::Apply { source, .. }
            | Self::Commit { source, .. } => Some(source),
            Self::AlreadyInitialized { .. } => None,
        }
    }
}

impl From<config::ConfigError> for InitDbError {
    /// Preserves strict configuration failures without duplicating argument parsing.
    fn from(source: config::ConfigError) -> Self {
        Self::Config(source)
    }
}
