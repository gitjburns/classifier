use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, LineWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, MakeWriter};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Identifies fatal process events that must reach both stderr and the durable log.
pub(crate) const PROCESS_ERROR_TARGET: &str = "classifier::process_error";

// Console events are derived operator summaries, not authoritative lifecycle evidence.
const CONSOLE_OUTCOME_TARGET: &str = "classifier::console_outcome";
const STARTUP_MILESTONE_TARGET: &str = "classifier::startup_milestone";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_BOLD_RED: &str = "\x1b[1;31m";
const ANSI_RESET: &str = "\x1b[0m";

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

/// Formats derived console outcomes as one message-only line with terminal-safe emphasis.
#[derive(Clone, Copy)]
struct ConsoleEventFormat {
    ansi: bool,
}

impl<S, N> FormatEvent<S, N> for ConsoleEventFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    /// Omits metadata and fields so each console outcome remains exactly one concise line.
    fn format_event(
        &self,
        _context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let style = if self.ansi {
            match *event.metadata().level() {
                Level::WARN => Some(ANSI_YELLOW),
                Level::ERROR => Some(ANSI_BOLD_RED),
                _ => None,
            }
        } else {
            None
        };

        if let Some(style) = style {
            fmt::Write::write_str(&mut writer, style)?;
        }
        let mut visitor = ConsoleMessageVisitor::new(&mut writer);
        event.record(&mut visitor);
        visitor.finish()?;
        if style.is_some() {
            fmt::Write::write_str(&mut writer, ANSI_RESET)?;
        }
        fmt::Write::write_char(&mut writer, '\n')
    }
}

/// Writes only tracing's synthetic `message` field and discards all structured fields.
struct ConsoleMessageVisitor<'writer, 'buffer> {
    writer: &'writer mut Writer<'buffer>,
    result: fmt::Result,
}

impl<'writer, 'buffer> ConsoleMessageVisitor<'writer, 'buffer> {
    /// Binds message extraction to the formatter's current event buffer.
    fn new(writer: &'writer mut Writer<'buffer>) -> Self {
        Self {
            writer,
            result: Ok(()),
        }
    }

    /// Returns any formatting failure after tracing has finished visiting fields.
    fn finish(self) -> fmt::Result {
        self.result
    }

    /// Records a message fragment only while the output writer remains healthy.
    fn record_message(&mut self, field: &Field, value: fmt::Arguments<'_>) {
        if field.name() == "message" && self.result.is_ok() {
            self.result = fmt::Write::write_fmt(self.writer, value);
        }
    }
}

impl Visit for ConsoleMessageVisitor<'_, '_> {
    /// Renders tracing's formatted message without exposing unrelated structured fields.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_message(field, format_args!("{value:?}"));
    }

    /// Preserves string messages without the quotes added by debug formatting.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_message(field, format_args!("{value}"));
    }
}

/// Emits an unstyled successful outcome to the console-only tracing route.
pub(crate) fn console_info(message: String) {
    tracing::info!(target: CONSOLE_OUTCOME_TARGET, "{message}");
}

/// Emits a warning outcome that is yellow when stderr is an interactive terminal.
pub(crate) fn console_warn(message: String) {
    tracing::warn!(target: CONSOLE_OUTCOME_TARGET, "{message}");
}

/// Emits a failed outcome that is bold red when stderr is an interactive terminal.
pub(crate) fn console_error(message: String) {
    tracing::error!(target: CONSOLE_OUTCOME_TARGET, "{message}");
}

/// Emits one successful startup milestone without duplicating it in the durable log.
pub(crate) fn startup_milestone(message: String) {
    tracing::info!(target: STARTUP_MILESTONE_TARGET, "{message}");
}

/// Installs concise stderr routes and a complete synchronous durable-file route.
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
    let stderr_is_terminal = io::stderr().is_terminal();

    // Derived console events are intentionally isolated from durable lifecycle evidence.
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .event_format(ConsoleEventFormat {
            ansi: stderr_is_terminal,
        })
        .with_filter(
            Targets::new()
                .with_default(LevelFilter::OFF)
                .with_target(CONSOLE_OUTCOME_TARGET, LevelFilter::TRACE)
                .with_target(STARTUP_MILESTONE_TARGET, LevelFilter::TRACE),
        );
    let process_error_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_ansi(stderr_is_terminal)
        .with_filter(
            Targets::new()
                .with_default(LevelFilter::OFF)
                .with_target(PROCESS_ERROR_TARGET, LevelFilter::ERROR),
        );
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_filter(
            Targets::new()
                .with_default(level)
                .with_target(CONSOLE_OUTCOME_TARGET, LevelFilter::OFF)
                .with_target(STARTUP_MILESTONE_TARGET, LevelFilter::OFF),
        );
    let subscriber = tracing_subscriber::registry()
        .with(console_layer)
        .with(process_error_layer)
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
