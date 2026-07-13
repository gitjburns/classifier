use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, LineWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};

/// Preserves the exact boundary that prevented durable logging from initializing.
#[derive(Debug)]
pub enum LoggingError {
    /// Reports an unavailable configured destination before a subscriber exists.
    OpenLog { path: PathBuf, source: io::Error },
    /// Reports process-global subscriber conflicts without discarding the source.
    SetGlobalSubscriber(tracing::subscriber::SetGlobalDefaultError),
}

impl fmt::Display for LoggingError {
    /// Includes the configured path or subscriber failure in the pre-logger stderr message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenLog { path, source } => {
                write!(
                    formatter,
                    "failed to open service log {}: {source}",
                    path.display()
                )
            }
            Self::SetGlobalSubscriber(source) => {
                write!(formatter, "failed to install service logger: {source}")
            }
        }
    }
}

impl Error for LoggingError {
    /// Retains the concrete I/O or subscriber installation error for diagnostics.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenLog { source, .. } => Some(source),
            Self::SetGlobalSubscriber(source) => Some(source),
        }
    }
}

/// Shares one line-buffered file across tracing events without a lossy worker queue.
#[derive(Clone)]
struct FileMakeWriter {
    inner: Arc<Mutex<LineWriter<File>>>,
}

/// Holds the shared writer for one tracing event and locks only during actual writes.
struct FileWriter {
    inner: Arc<Mutex<LineWriter<File>>>,
}

impl FileMakeWriter {
    /// Wraps the opened append-only file in the synchronous durability boundary.
    fn new(file: File) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LineWriter::new(file))),
        }
    }
}

impl FileWriter {
    /// Converts mutex poisoning into an I/O failure visible to the tracing layer.
    fn lock(&self) -> io::Result<MutexGuard<'_, LineWriter<File>>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("service log writer mutex is poisoned"))
    }
}

impl<'a> MakeWriter<'a> for FileMakeWriter {
    type Writer = FileWriter;

    /// Creates a lightweight event writer while preserving the single shared file position.
    fn make_writer(&'a self) -> Self::Writer {
        FileWriter {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Write for FileWriter {
    /// Writes synchronously so a completed log call has reached the line buffer.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.lock()?.write(buffer)
    }

    /// Flushes the shared writer at explicit tracing flush boundaries.
    fn flush(&mut self) -> io::Result<()> {
        self.lock()?.flush()
    }
}

/// Installs matching stderr and durable-file layers before any secret is loaded.
pub fn initialize(path: &Path, level: LevelFilter) -> Result<(), LoggingError> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| LoggingError::OpenLog {
            path: path.to_path_buf(),
            source,
        })?;
    let file_writer = FileMakeWriter::new(file);

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(level);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_filter(level);
    let subscriber = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer);

    install_global(subscriber)
}

/// Keeps the concrete subscriber type local while preserving installation error context.
fn install_global<S>(subscriber: S) -> Result<(), LoggingError>
where
    S: Subscriber + Send + Sync + 'static,
{
    tracing::subscriber::set_global_default(subscriber).map_err(LoggingError::SetGlobalSubscriber)
}
