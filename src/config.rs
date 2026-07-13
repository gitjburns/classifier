use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use tracing_subscriber::filter::LevelFilter;

const DEFAULT_CONFIG_PATH: &str = "config.toml";
const JSON_BODY_OVERHEAD_BYTES: usize = 16 * 1024;
const JSON_ESCAPE_EXPANSION_FACTOR: usize = 6;

/// Contains every required operational setting after strict parsing and validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Carries the already-parsed listener address for the future HTTP boundary.
    pub server: ServerConfig,
    /// Constrains untrusted content and its transport representation.
    pub limits: LimitsConfig,
    /// Points startup at the single authoritative rule inventory.
    pub rules: RulesConfig,
    /// Points startup at the service-owned audit store.
    pub database: DatabaseConfig,
    /// Bounds read volume and wall-clock database work.
    pub query: QueryConfig,
    /// Locates the secret without placing it in the configuration document.
    pub auth: AuthConfig,
    /// Controls both stderr and durable file diagnostics.
    pub logging: LoggingConfig,
}

/// Holds network settings that later phases use when binding the HTTP listener.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Is parsed during config loading so an invalid address fails before server assembly.
    pub bind_addr: SocketAddr,
}

/// Defines request-size limits and validates the future JSON transport bound.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Caps original content before any assessment work is attempted.
    pub max_content_bytes: usize,
}

/// Identifies the rules file that must be loaded during rules-engine startup.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    /// Remains repository-relative under the service's working-directory contract.
    pub path: PathBuf,
}

/// Identifies the service-owned audit database without creating or migrating it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Names an existing database; runtime code must never create its schema.
    pub path: PathBuf,
}

/// Holds bounded query settings used by the later read-only database path.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryConfig {
    /// Applies when the caller omits a page size.
    pub default_limit: usize,
    /// Prevents callers from requesting unbounded result pages.
    pub max_limit: usize,
    /// Bounds synchronous SQLite statement execution at the read boundary.
    pub timeout_ms: u64,
}

/// Identifies the external bearer-token file while keeping the secret out of config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Is read only after durable logging has initialized.
    pub token_file: PathBuf,
}

/// Defines the durable service-log destination and its validated severity filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Must have an existing parent directory; startup does not create operational paths.
    pub path: PathBuf,
    /// Is parsed eagerly so an unsupported filter cannot be silently ignored.
    #[serde(deserialize_with = "deserialize_level")]
    pub level: LevelFilter,
}

/// Preserves the source failure and affected path for fatal startup diagnostics.
#[derive(Debug)]
pub enum ConfigError {
    /// Rejects unsupported or incomplete process arguments before file access.
    Arguments(String),
    /// Retains the OS failure encountered while loading the selected config path.
    ReadConfig { path: PathBuf, source: io::Error },
    /// Retains TOML location and schema context for strict parsing failures.
    ParseConfig {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// Identifies a typed value whose derived operational bound is unsafe.
    InvalidValue {
        key: &'static str,
        reason: &'static str,
    },
    /// Retains the OS failure without exposing any token contents.
    ReadToken { path: PathBuf, source: io::Error },
    /// Distinguishes an unreadable token from one that contains no credential.
    EmptyToken { path: PathBuf },
}

impl Config {
    /// Loads the complete file atomically and rejects both malformed and unsafe settings.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::ReadConfig {
            path: path.to_path_buf(),
            source,
        })?;
        let config =
            toml::from_str::<Self>(&contents).map_err(|source| ConfigError::ParseConfig {
                path: path.to_path_buf(),
                source,
            })?;

        config.limits.request_body_limit()?;
        Ok(config)
    }
}

impl LimitsConfig {
    /// Computes the Phase 7 JSON body cap while proving its arithmetic cannot overflow.
    pub fn request_body_limit(&self) -> Result<usize, ConfigError> {
        self.max_content_bytes
            .checked_mul(JSON_ESCAPE_EXPANSION_FACTOR)
            .and_then(|size| size.checked_add(JSON_BODY_OVERHEAD_BYTES))
            .ok_or(ConfigError::InvalidValue {
                key: "limits.max_content_bytes",
                reason: "is too large to derive the HTTP request-body limit",
            })
    }
}

impl fmt::Display for ConfigError {
    /// Formats startup failures with their exact configuration boundary and source context.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(reason) => write!(formatter, "invalid command line: {reason}"),
            Self::ReadConfig { path, source } => {
                write!(
                    formatter,
                    "failed to read config {}: {source}",
                    path.display()
                )
            }
            Self::ParseConfig { path, source } => {
                write!(
                    formatter,
                    "failed to parse config {}: {source}",
                    path.display()
                )
            }
            Self::InvalidValue { key, reason } => {
                write!(formatter, "invalid config key {key}: {reason}")
            }
            Self::ReadToken { path, source } => {
                write!(
                    formatter,
                    "failed to read token file {}: {source}",
                    path.display()
                )
            }
            Self::EmptyToken { path } => {
                write!(formatter, "token file {} is empty", path.display())
            }
        }
    }
}

impl Error for ConfigError {
    /// Exposes underlying I/O and parse failures without erasing their concrete types.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadConfig { source, .. } | Self::ReadToken { source, .. } => Some(source),
            Self::ParseConfig { source, .. } => Some(source),
            Self::Arguments(_) | Self::InvalidValue { .. } | Self::EmptyToken { .. } => None,
        }
    }
}

/// Accepts only the single supported flag so startup never silently ignores an argument.
pub fn config_path_from_args<I>(args: I) -> Result<PathBuf, ConfigError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(flag) = args.next() else {
        return Ok(PathBuf::from(DEFAULT_CONFIG_PATH));
    };

    if flag != "--config" {
        return Err(ConfigError::Arguments(format!(
            "unknown argument {} (expected --config <path>)",
            flag.to_string_lossy()
        )));
    }

    let path = args.next().ok_or_else(|| {
        ConfigError::Arguments("--config requires a repository-local path".to_owned())
    })?;
    if args.next().is_some() {
        return Err(ConfigError::Arguments(
            "only --config <path> is supported".to_owned(),
        ));
    }
    if path.is_empty() {
        return Err(ConfigError::Arguments(
            "--config path must not be empty".to_owned(),
        ));
    }

    Ok(PathBuf::from(path))
}

/// Reads the bearer token exactly, removing only one conventional trailing line ending.
pub fn load_token(path: &Path) -> Result<String, ConfigError> {
    let token = fs::read_to_string(path).map_err(|source| ConfigError::ReadToken {
        path: path.to_path_buf(),
        source,
    })?;
    let token = token
        .strip_suffix("\r\n")
        .or_else(|| token.strip_suffix('\n'))
        .unwrap_or(&token);

    if token.is_empty() {
        return Err(ConfigError::EmptyToken {
            path: path.to_path_buf(),
        });
    }

    Ok(token.to_owned())
}

/// Converts the configured text level during deserialization so invalid levels fail startup.
fn deserialize_level<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let level = String::deserialize(deserializer)?;
    match level.as_str() {
        "trace" => Ok(LevelFilter::TRACE),
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(D::Error::custom(format!(
            "logging.level has unsupported value {level:?}; expected trace, debug, or info so mandatory lifecycle records remain visible"
        ))),
    }
}

/// Provides the process arguments after the executable name for the startup parser.
pub fn process_args() -> impl Iterator<Item = OsString> {
    env::args_os().skip(1)
}
