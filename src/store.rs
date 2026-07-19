use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::string::FromUtf8Error;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, params_from_iter};
use tokio::sync::{mpsc, oneshot};

use crate::types::{Finding, Severity, Span, Verdict};

const INSERT_ASSESSMENT_SQL: &str = "INSERT INTO assessments (
    request_id, created_at_ms, verdict, content_sha256, content,
    sanitized_sha256, sanitized_content, ruleset_version, elapsed_ms
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
const INSERT_FINDING_SQL: &str = "INSERT INTO findings (
    request_id, rule_id, severity, span_start, span_end
) VALUES (?1, ?2, ?3, ?4, ?5)";
const ASSESSMENTS_SCHEMA_CHECK_SQL: &str = "SELECT
    request_id, created_at_ms, verdict, content_sha256, content,
    sanitized_sha256, sanitized_content, ruleset_version, elapsed_ms
FROM assessments LIMIT 0";
const FINDINGS_SCHEMA_CHECK_SQL: &str =
    "SELECT request_id, rule_id, severity, span_start, span_end FROM findings LIMIT 0";
const REQUIRED_INDEX_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_master
WHERE type = 'index' AND name IN (
    'idx_assessments_created', 'idx_assessments_verdict',
    'idx_assessments_hash', 'idx_findings_request'
)";
const LIST_ASSESSMENTS_BASE_SQL: &str = "SELECT
    request_id, created_at_ms, verdict, content_sha256, sanitized_sha256,
    ruleset_version, elapsed_ms
FROM assessments WHERE 1 = 1";
const LIST_ASSESSMENTS_ORDER_SQL: &str = " ORDER BY created_at_ms DESC, request_id DESC LIMIT ?";
const SELECT_ASSESSMENT_SQL: &str = "SELECT
    request_id, created_at_ms, verdict, content_sha256, content,
    sanitized_sha256, sanitized_content, ruleset_version, elapsed_ms
FROM assessments WHERE request_id = ?1";
const SELECT_FINDINGS_SQL: &str = "SELECT rule_id, severity, span_start, span_end
FROM findings WHERE request_id = ?1 ORDER BY span_start, span_end, rowid LIMIT ?2";
const REQUIRED_INDEX_COUNT: i64 = 4;
const PROGRESS_HANDLER_INSTRUCTION_INTERVAL: i32 = 1_000;
// Queue capacity bounds handler backpressure; the batch cap bounds worst-case batch latency and
// the size of an atomic batch failure. Both are writer-throughput tuning, not correctness limits.
const PERSIST_QUEUE_CAPACITY: usize = 1_024;
const MAX_PERSIST_BATCH: usize = 128;

/// Owns the queue feeding the dedicated audit-writer thread and the bounds applied to every
/// read-only query connection. The writer connection itself lives on that thread; this sender
/// is the only runtime path to it, making the single-write-path invariant structural.
pub struct Store {
    path: PathBuf,
    persist_tx: mpsc::Sender<PersistRequest>,
    query_timeout: Duration,
    max_query_rows: usize,
    max_findings_per_assessment: usize,
    max_cell_bytes: usize,
}

/// Carries one validated assessment to the audit-writer thread together with the channel that
/// confirms its durable batch commit; the verdict is released only after that confirmation.
struct PersistRequest {
    record: AssessmentRecord,
    /// Marks enqueue time so failure records can attribute queue wait separately from commit.
    enqueued: Instant,
    /// Receives the committing batch sequence, or the shared cause of an atomic batch failure.
    responder: oneshot::Sender<Result<u64, Arc<StoreError>>>,
}

/// Carries every field committed as one authoritative assessment record.
#[derive(Debug, Clone)]
pub struct AssessmentRecord {
    /// Correlates the durable record with request lifecycle diagnostics.
    pub request_id: String,
    /// Records the UTC Unix epoch timestamp assigned by the assessment handler.
    pub created_at_ms: i64,
    /// Preserves the terminal decision produced by the approved ruleset.
    pub verdict: Verdict,
    /// Binds the stored original content to the bytes submitted by its caller.
    pub content_sha256: String,
    /// Retains the full original text as authoritative audit evidence.
    pub content: String,
    /// Binds sanitized bytes only when the verdict permits forwarding them.
    pub sanitized_sha256: Option<String>,
    /// Retains the cleared redacted text only for sanitized verdicts.
    pub sanitized_content: Option<String>,
    /// Identifies the exact rule inventory used for the decision.
    pub ruleset_version: String,
    /// Records the complete assessment duration measured outside the pure pipeline.
    pub elapsed_ms: u64,
    /// Preserves evidence from the initial scan of the submitted content.
    pub findings: Vec<Finding>,
}

/// Omits content columns from list results so bulk inspection cannot retrieve submitted text.
#[derive(Debug, Clone)]
pub struct AssessmentSummary {
    /// Correlates metadata with the full detail record and service log.
    pub request_id: String,
    /// Supports stable newest-first keyset ordering.
    pub created_at_ms: i64,
    /// Preserves the historical decision without retrieving content.
    pub verdict: Verdict,
    /// Supports exact-content filtering and caller-side correlation.
    pub content_sha256: String,
    /// Identifies available sanitized content without returning that content.
    pub sanitized_sha256: Option<String>,
    /// Identifies the rule inventory used for this historical decision.
    pub ruleset_version: String,
    /// Reports the original operation duration as metadata.
    pub elapsed_ms: u64,
    /// Returns initial-scan evidence without matched excerpts.
    pub findings: Vec<Finding>,
}

/// Defines already-validated execution filters for the bounded list query.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Restricts results to an explicit verdict subset; empty means all verdicts.
    pub verdicts: Vec<Verdict>,
    /// Restricts results to assessments of exactly matching original bytes.
    pub content_sha256: Option<String>,
    /// Restricts results to records at or after this UTC epoch-millisecond boundary.
    pub created_since_ms: Option<i64>,
    /// Continues strictly after the previous page's final keyset position.
    pub cursor: Option<Cursor>,
    /// Caps returned assessments before the execution boundary is entered.
    pub limit: usize,
}

/// Returns one bounded page and an opaque continuation token only when more rows exist.
#[derive(Debug, Clone)]
pub struct AssessmentPage {
    /// Contains at most the caller's validated page limit.
    pub assessments: Vec<AssessmentSummary>,
    /// Exists only when the sentinel row proves more records remain.
    pub next_cursor: Option<String>,
}

/// Represents the two-column keyset position encoded into caller-facing cursors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Carries the primary descending sort key from the prior page.
    pub created_at_ms: i64,
    /// Carries the deterministic tie-break key from the prior page.
    pub request_id: String,
}

/// Preserves database boundary failures without exposing stored content in error text.
#[derive(Debug)]
pub enum StoreError {
    Open {
        path: PathBuf,
        role: &'static str,
        source: rusqlite::Error,
    },
    Configure {
        path: PathBuf,
        role: &'static str,
        source: rusqlite::Error,
    },
    Schema {
        path: PathBuf,
        source: rusqlite::Error,
    },
    SchemaMismatch {
        path: PathBuf,
        detail: String,
    },
    InvalidLimit {
        requested: usize,
        maximum: usize,
    },
    TooManyFindings {
        actual: usize,
        maximum: usize,
    },
    CellTooLarge {
        field: &'static str,
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    InvalidStoredValue {
        field: &'static str,
        detail: String,
    },
    WriterUnavailable,
    WriterSpawn {
        source: std::io::Error,
    },
    WriterResponseLost {
        request_id: String,
    },
    Batch {
        request_id: String,
        source: Arc<StoreError>,
    },
    Begin {
        batch_seq: u64,
        source: rusqlite::Error,
    },
    WriteAssessment {
        request_id: String,
        source: rusqlite::Error,
    },
    WriteFinding {
        request_id: String,
        rule_id: String,
        source: rusqlite::Error,
    },
    Commit {
        batch_seq: u64,
        batch_size: usize,
        source: rusqlite::Error,
    },
    Query {
        operation: &'static str,
        source: rusqlite::Error,
    },
}

/// Distinguishes malformed opaque cursors from database failures.
#[derive(Debug)]
pub enum CursorError {
    Hex(hex::FromHexError),
    Utf8(FromUtf8Error),
    Shape,
    Timestamp(std::num::ParseIntError),
    RequestId(uuid::Error),
}

#[derive(Debug)]
struct RawAssessmentSummary {
    request_id: String,
    created_at_ms: i64,
    verdict: String,
    content_sha256: String,
    sanitized_sha256: Option<String>,
    ruleset_version: String,
    elapsed_ms: i64,
}

#[derive(Debug)]
struct RawAssessmentRecord {
    request_id: String,
    created_at_ms: i64,
    verdict: String,
    content_sha256: String,
    content: String,
    sanitized_sha256: Option<String>,
    sanitized_content: Option<String>,
    ruleset_version: String,
    elapsed_ms: i64,
}

impl Store {
    /// Opens existing writer and reader roles, verifies schema, spawns the dedicated
    /// audit-writer thread, and never creates runtime state. The returned join handle lets
    /// shutdown wait for the writer's queue drain after the last sender drops.
    pub fn open(
        path: &Path,
        query_timeout_ms: u64,
        max_query_rows: usize,
        max_findings_per_assessment: usize,
        max_cell_bytes: usize,
    ) -> Result<(Self, thread::JoinHandle<()>), StoreError> {
        let query_timeout = Duration::from_millis(query_timeout_ms);
        let writer = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(
            |source| StoreError::Open {
                path: path.to_path_buf(),
                role: "writer",
                source,
            },
        )?;
        configure_writer(&writer, path, query_timeout)?;
        verify_journal_mode(&writer, path)?;
        verify_schema(&writer, path)?;

        // Opening and checking the read role at startup prevents later query traffic from being
        // the first point at which filesystem permissions or query-only setup are discovered.
        let reader = open_reader(path, query_timeout)?;
        verify_schema(&reader, path)?;

        // The verified writer connection moves permanently onto its dedicated thread; from here
        // on, the bounded queue is the sole runtime write path.
        let (persist_tx, persist_rx) = mpsc::channel(PERSIST_QUEUE_CAPACITY);
        let writer_thread = thread::Builder::new()
            .name("audit-writer".to_owned())
            .spawn(move || run_audit_writer(writer, persist_rx))
            .map_err(|source| StoreError::WriterSpawn { source })?;

        Ok((
            Self {
                path: path.to_path_buf(),
                persist_tx,
                query_timeout,
                max_query_rows,
                max_findings_per_assessment,
                max_cell_bytes,
            },
            writer_thread,
        ))
    }

    /// Validates one assessment, queues it for the dedicated audit writer, and waits for the
    /// batch commit that makes it durable. Returns the committing batch sequence for the
    /// caller's terminal record; the verdict is released only after this confirmation.
    pub async fn persist_assessment(&self, record: AssessmentRecord) -> Result<u64, StoreError> {
        validate_record(
            &record,
            self.max_cell_bytes,
            self.max_findings_per_assessment,
        )?;
        let request_id = record.request_id.clone();
        let (responder, confirmation) = oneshot::channel();
        let request = PersistRequest {
            record,
            enqueued: Instant::now(),
            responder,
        };
        // A closed queue means shutdown already stopped the writer; nothing was committed, so
        // this is a definite persistence failure, not an unknown outcome. A full queue simply
        // awaits here, which is the intended backpressure on request intake.
        if self.persist_tx.send(request).await.is_err() {
            tracing::error!(
                request_id = %request_id,
                stage = "audit_enqueue",
                error = "audit writer queue is closed",
                "audit persistence rejected"
            );
            return Err(StoreError::WriterUnavailable);
        }
        match confirmation.await {
            Ok(Ok(batch_seq)) => Ok(batch_seq),
            Ok(Err(shared)) => Err(StoreError::Batch {
                request_id,
                source: shared,
            }),
            // The writer dropped the responder without answering: it panicked or exited between
            // enqueue and commit, so the commit state cannot safely be claimed either way.
            Err(_) => Err(StoreError::WriterResponseLost { request_id }),
        }
    }

    /// Executes a capped newest-first keyset query without selecting content columns.
    pub fn list_assessments(&self, filter: &ListFilter) -> Result<AssessmentPage, StoreError> {
        if filter.limit == 0 || filter.limit > self.max_query_rows {
            return Err(StoreError::InvalidLimit {
                requested: filter.limit,
                maximum: self.max_query_rows,
            });
        }

        let connection = open_reader(&self.path, self.query_timeout)?;
        let (sql, values) = build_list_query(filter)?;
        let mut raw_rows = {
            let mut statement = connection
                .prepare(&sql)
                .map_err(|source| StoreError::Query {
                    operation: "prepare assessment list",
                    source,
                })?;
            let rows = statement
                .query_map(params_from_iter(values.iter()), raw_summary_from_row)
                .map_err(|source| StoreError::Query {
                    operation: "execute assessment list",
                    source,
                })?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|source| StoreError::Query {
                    operation: "read assessment list",
                    source,
                })?
        };

        let has_more = raw_rows.len() > filter.limit;
        if has_more {
            raw_rows.truncate(filter.limit);
        }

        let mut assessments = Vec::with_capacity(raw_rows.len());
        for raw in raw_rows {
            let findings = load_findings(
                &connection,
                &raw.request_id,
                self.max_findings_per_assessment,
                self.max_cell_bytes,
            )?;
            assessments.push(summary_from_raw(raw, findings, self.max_cell_bytes)?);
        }
        let next_cursor = if has_more {
            assessments.last().map(|assessment| {
                Cursor {
                    created_at_ms: assessment.created_at_ms,
                    request_id: assessment.request_id.clone(),
                }
                .encode()
            })
        } else {
            None
        };

        Ok(AssessmentPage {
            assessments,
            next_cursor,
        })
    }

    /// Retrieves one deliberate full-content audit record through a read-only connection.
    pub fn get_assessment(&self, request_id: &str) -> Result<Option<AssessmentRecord>, StoreError> {
        let connection = open_reader(&self.path, self.query_timeout)?;
        let raw = connection
            .query_row(SELECT_ASSESSMENT_SQL, [request_id], raw_record_from_row)
            .optional()
            .map_err(|source| StoreError::Query {
                operation: "read assessment detail",
                source,
            })?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let findings = load_findings(
            &connection,
            &raw.request_id,
            self.max_findings_per_assessment,
            self.max_cell_bytes,
        )?;
        record_from_raw(raw, findings, self.max_cell_bytes).map(Some)
    }
}

impl Cursor {
    /// Encodes the keyset as opaque lowercase hex without exposing a caller-constructible format.
    pub fn encode(&self) -> String {
        hex::encode(format!("{}:{}", self.created_at_ms, self.request_id))
    }

    /// Rejects cursors whose hex, UTF-8, timestamp, or UUID shape is not exact.
    pub fn decode(encoded: &str) -> Result<Self, CursorError> {
        let bytes = hex::decode(encoded).map_err(CursorError::Hex)?;
        let decoded = String::from_utf8(bytes).map_err(CursorError::Utf8)?;
        let (timestamp, request_id) = decoded.split_once(':').ok_or(CursorError::Shape)?;
        if timestamp.is_empty() || request_id.is_empty() || request_id.contains(':') {
            return Err(CursorError::Shape);
        }
        let created_at_ms = timestamp.parse::<i64>().map_err(CursorError::Timestamp)?;
        if created_at_ms < 0 {
            return Err(CursorError::Shape);
        }
        uuid::Uuid::parse_str(request_id).map_err(CursorError::RequestId)?;

        Ok(Self {
            created_at_ms,
            request_id: request_id.to_owned(),
        })
    }
}

/// Runs the dedicated audit-writer thread: the sole runtime write path. It drains queued
/// assessments into batched transactions so concurrent requests share one commit fsync, and
/// answers every waiter only after its batch's durable commit. The loop ends when every queue
/// sender has dropped and the queue is drained, which is the graceful-shutdown path.
fn run_audit_writer(mut connection: Connection, mut queue: mpsc::Receiver<PersistRequest>) {
    let mut batch: Vec<PersistRequest> = Vec::with_capacity(MAX_PERSIST_BATCH);
    let mut batch_seq: u64 = 0;
    while let Some(first) = queue.blocking_recv() {
        batch.push(first);
        // Natural batching: take whatever accumulated while the previous transaction ran,
        // without waiting for more. An idle service commits batches of one and adds no latency;
        // a saturated one amortizes each fsync across everything that queued behind it.
        while batch.len() < MAX_PERSIST_BATCH {
            match queue.try_recv() {
                Ok(request) => batch.push(request),
                // Empty or disconnected: either way, commit what is already held.
                Err(_) => break,
            }
        }
        batch_seq += 1;
        commit_batch(&mut connection, batch_seq, &mut batch);
    }
    tracing::info!(
        stage = "audit_writer_exit",
        batches_committed = batch_seq,
        "audit writer queue closed and drained; writer thread exiting"
    );
}

/// Commits one batch atomically and answers every member's waiter with the durable outcome.
/// On any error the whole batch rolls back and every member receives the shared cause;
/// nothing is ever claimed partially committed.
fn commit_batch(connection: &mut Connection, batch_seq: u64, batch: &mut Vec<PersistRequest>) {
    let batch_size = batch.len();
    match execute_batch_transaction(connection, batch_seq, batch) {
        Ok(timings) => {
            // One consolidated success record per batch carries every phase duration. Each
            // member's request-keyed durable evidence is its handler's terminal record, which
            // cites this batch_seq after confirmation; per-member success lines here would
            // reserialize the log writer per request and defeat the batching.
            tracing::info!(
                batch_seq,
                batch_size,
                begin_elapsed_ms = timings.begin_ms,
                inserts_elapsed_ms = timings.inserts_ms,
                commit_elapsed_ms = timings.commit_ms,
                transaction_elapsed_ms = timings.transaction_ms,
                "audit batch committed"
            );
            for request in batch.drain(..) {
                if request.responder.send(Ok(batch_seq)).is_err() {
                    // The record is durable; only the waiting handler is gone (cancelled), so
                    // its terminal record will never cite the batch. Record it here instead.
                    tracing::info!(
                        request_id = %request.record.request_id,
                        stage = "audit_commit_notify",
                        batch_seq,
                        "assessment committed but its verdict waiter had gone"
                    );
                }
            }
        }
        Err(error) => {
            let shared = Arc::new(error);
            tracing::error!(
                batch_seq,
                batch_size,
                error = %shared,
                "audit batch persistence failed; every member fails with this cause"
            );
            // Error paths stay per-request: each member's failure record carries its own
            // identifiers and queue wait, per the diagnostics policy.
            for request in batch.drain(..) {
                tracing::error!(
                    request_id = %request.record.request_id,
                    stage = "audit_batch_member_failed",
                    batch_seq,
                    queue_wait_elapsed_ms = duration_ms(request.enqueued),
                    error = %shared,
                    "assessment persistence failed with its batch"
                );
                let _ = request.responder.send(Err(Arc::clone(&shared)));
            }
        }
    }
}

/// Carries the per-phase durations of one committed batch for the consolidated success record.
struct BatchTimings {
    begin_ms: f64,
    inserts_ms: f64,
    commit_ms: f64,
    transaction_ms: f64,
}

/// Executes every member's inserts and the shared commit inside one transaction. Errors keep
/// each member's local context (request id, rule id); logging belongs to the caller.
fn execute_batch_transaction(
    connection: &mut Connection,
    batch_seq: u64,
    batch: &[PersistRequest],
) -> Result<BatchTimings, StoreError> {
    let transaction_started = Instant::now();
    let begin_started = Instant::now();
    let transaction = connection
        .transaction()
        .map_err(|source| StoreError::Begin { batch_seq, source })?;
    let begin_ms = duration_ms(begin_started);

    let inserts_started = Instant::now();
    for request in batch {
        let record = &request.record;
        let elapsed_ms = i64_from_u64(record.elapsed_ms, "elapsed_ms")?;
        // `prepare_cached` keeps SQL compilation out of the writer's serialized path: the sole
        // writer connection caches both insert statements permanently. The `CachedStatement`
        // drops back into the cache at the end of each `and_then`, leaving no borrow to
        // conflict with `commit()`; re-fetching per record is a cache hit and keeps prepare
        // failures mapped with the same per-record error context.
        transaction
            .prepare_cached(INSERT_ASSESSMENT_SQL)
            .and_then(|mut statement| {
                statement.execute(params![
                    record.request_id,
                    record.created_at_ms,
                    verdict_name(record.verdict),
                    record.content_sha256,
                    record.content,
                    record.sanitized_sha256.as_deref(),
                    record.sanitized_content.as_deref(),
                    record.ruleset_version,
                    elapsed_ms,
                ])
            })
            .map_err(|source| StoreError::WriteAssessment {
                request_id: record.request_id.clone(),
                source,
            })?;
        for finding in &record.findings {
            let span_start = i64_from_usize(finding.span.start, "span_start")?;
            let span_end = i64_from_usize(finding.span.end, "span_end")?;
            transaction
                .prepare_cached(INSERT_FINDING_SQL)
                .and_then(|mut statement| {
                    statement.execute(params![
                        record.request_id,
                        finding.rule_id,
                        severity_name(finding.severity),
                        span_start,
                        span_end,
                    ])
                })
                .map_err(|source| StoreError::WriteFinding {
                    request_id: record.request_id.clone(),
                    rule_id: finding.rule_id.clone(),
                    source,
                })?;
        }
    }
    let inserts_ms = duration_ms(inserts_started);

    let commit_started = Instant::now();
    transaction.commit().map_err(|source| StoreError::Commit {
        batch_seq,
        batch_size: batch.len(),
        source,
    })?;
    Ok(BatchTimings {
        begin_ms,
        inserts_ms,
        commit_ms: duration_ms(commit_started),
        transaction_ms: duration_ms(transaction_started),
    })
}

/// Configures the single write role without granting schema-creation behavior.
fn configure_writer(
    connection: &Connection,
    path: &Path,
    busy_timeout: Duration,
) -> Result<(), StoreError> {
    connection
        .busy_timeout(busy_timeout)
        .and_then(|()| connection.pragma_update(None, "foreign_keys", true))
        // FULL is the deliberate durability decision for the audit writer: in WAL mode it costs
        // one WAL fsync per commit and guarantees a returned verdict's audit row survives power
        // loss. Set explicitly so the decision is visible rather than inherited from SQLite
        // defaults; relaxing to NORMAL is an operator-approved change, not a tuning knob.
        .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
        .map_err(|source| StoreError::Configure {
            path: path.to_path_buf(),
            role: "writer",
            source,
        })
}

/// Confirms the persistent WAL journal mode that initialization establishes; the runtime
/// verifies this database-file property and never sets it (migration rule).
fn verify_journal_mode(connection: &Connection, path: &Path) -> Result<(), StoreError> {
    let journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(|source| StoreError::Schema {
            path: path.to_path_buf(),
            source,
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::SchemaMismatch {
            path: path.to_path_buf(),
            detail: format!(
                "journal mode is '{journal_mode}' but 'wal' is required; initialize a new database with the init command, or apply the deliberate WAL migration step to an existing database"
            ),
        });
    }
    Ok(())
}

/// Opens an isolated read-only role and applies query-only plus wall-clock enforcement.
fn open_reader(path: &Path, query_timeout: Duration) -> Result<Connection, StoreError> {
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|source| {
            StoreError::Open {
                path: path.to_path_buf(),
                role: "reader",
                source,
            }
        })?;
    connection
        .busy_timeout(query_timeout)
        .and_then(|()| connection.pragma_update(None, "query_only", true))
        .map_err(|source| StoreError::Configure {
            path: path.to_path_buf(),
            role: "reader",
            source,
        })?;

    // The timer belongs to this short-lived connection, so every public query receives its own
    // complete timeout budget while all statements used to assemble that result share the cap.
    let query_started = Instant::now();
    connection
        .progress_handler(
            PROGRESS_HANDLER_INSTRUCTION_INTERVAL,
            Some(move || query_started.elapsed() >= query_timeout),
        )
        .map_err(|source| StoreError::Configure {
            path: path.to_path_buf(),
            role: "reader progress handler",
            source,
        })?;
    Ok(connection)
}

/// Confirms the required tables, columns, and indexes without modifying the database.
fn verify_schema(connection: &Connection, path: &Path) -> Result<(), StoreError> {
    connection
        .prepare(ASSESSMENTS_SCHEMA_CHECK_SQL)
        .and_then(|_| connection.prepare(FINDINGS_SCHEMA_CHECK_SQL))
        .map_err(|source| StoreError::Schema {
            path: path.to_path_buf(),
            source,
        })?;
    let index_count = connection
        .query_row(REQUIRED_INDEX_COUNT_SQL, [], |row| row.get::<_, i64>(0))
        .map_err(|source| StoreError::Schema {
            path: path.to_path_buf(),
            source,
        })?;
    if index_count != REQUIRED_INDEX_COUNT {
        return Err(StoreError::SchemaMismatch {
            path: path.to_path_buf(),
            detail: format!(
                "expected {REQUIRED_INDEX_COUNT} required indexes but found {index_count}; run the init command against a new database"
            ),
        });
    }
    Ok(())
}

/// Assembles parameterized optional predicates while retaining a fixed row cap.
fn build_list_query(filter: &ListFilter) -> Result<(String, Vec<Value>), StoreError> {
    let mut sql = String::from(LIST_ASSESSMENTS_BASE_SQL);
    let mut values = Vec::new();

    if !filter.verdicts.is_empty() {
        sql.push_str(" AND verdict IN (");
        for index in 0..filter.verdicts.len() {
            if index > 0 {
                sql.push_str(", ");
            }
            sql.push('?');
            values.push(Value::Text(verdict_name(filter.verdicts[index]).to_owned()));
        }
        sql.push(')');
    }
    if let Some(content_sha256) = &filter.content_sha256 {
        sql.push_str(" AND content_sha256 = ?");
        values.push(Value::Text(content_sha256.clone()));
    }
    if let Some(created_since_ms) = filter.created_since_ms {
        sql.push_str(" AND created_at_ms >= ?");
        values.push(Value::Integer(created_since_ms));
    }
    if let Some(cursor) = &filter.cursor {
        sql.push_str(" AND (created_at_ms, request_id) < (?, ?)");
        values.push(Value::Integer(cursor.created_at_ms));
        values.push(Value::Text(cursor.request_id.clone()));
    }
    sql.push_str(LIST_ASSESSMENTS_ORDER_SQL);
    let fetch_count = filter
        .limit
        .checked_add(1)
        .ok_or(StoreError::InvalidLimit {
            requested: filter.limit,
            maximum: usize::MAX - 1,
        })?;
    values.push(Value::Integer(i64_from_usize(fetch_count, "limit")?));

    Ok((sql, values))
}

/// Loads at most cap-plus-one findings so excess evidence fails instead of being truncated.
fn load_findings(
    connection: &Connection,
    request_id: &str,
    max_findings_per_assessment: usize,
    max_cell_bytes: usize,
) -> Result<Vec<Finding>, StoreError> {
    let fetch_count =
        max_findings_per_assessment
            .checked_add(1)
            .ok_or(StoreError::InvalidLimit {
                requested: max_findings_per_assessment,
                maximum: usize::MAX - 1,
            })?;
    let fetch_count = i64_from_usize(fetch_count, "max_findings_per_assessment")?;
    let mut statement =
        connection
            .prepare(SELECT_FINDINGS_SQL)
            .map_err(|source| StoreError::Query {
                operation: "prepare assessment findings",
                source,
            })?;
    let rows = statement
        .query_map(params![request_id, fetch_count], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|source| StoreError::Query {
            operation: "execute assessment findings",
            source,
        })?;

    let mut findings = Vec::new();
    for row in rows {
        let (rule_id, severity, span_start, span_end) =
            row.map_err(|source| StoreError::Query {
                operation: "read assessment findings",
                source,
            })?;
        validate_cell("rule_id", &rule_id, max_cell_bytes)?;
        let severity = parse_severity(&severity)?;
        let start = usize_from_i64(span_start, "span_start")?;
        let end = usize_from_i64(span_end, "span_end")?;
        if start > end {
            return Err(StoreError::InvalidStoredValue {
                field: "span",
                detail: "start exceeds end".to_owned(),
            });
        }
        findings.push(Finding {
            rule_id,
            severity,
            span: Span { start, end },
        });
    }
    if findings.len() > max_findings_per_assessment {
        return Err(StoreError::TooManyFindings {
            actual: findings.len(),
            maximum: max_findings_per_assessment,
        });
    }
    Ok(findings)
}

/// Maps SQLite list columns without performing domain parsing inside rusqlite callbacks.
fn raw_summary_from_row(row: &Row<'_>) -> rusqlite::Result<RawAssessmentSummary> {
    Ok(RawAssessmentSummary {
        request_id: row.get(0)?,
        created_at_ms: row.get(1)?,
        verdict: row.get(2)?,
        content_sha256: row.get(3)?,
        sanitized_sha256: row.get(4)?,
        ruleset_version: row.get(5)?,
        elapsed_ms: row.get(6)?,
    })
}

/// Maps SQLite detail columns without collapsing corrupt domain values into SQL errors.
fn raw_record_from_row(row: &Row<'_>) -> rusqlite::Result<RawAssessmentRecord> {
    Ok(RawAssessmentRecord {
        request_id: row.get(0)?,
        created_at_ms: row.get(1)?,
        verdict: row.get(2)?,
        content_sha256: row.get(3)?,
        content: row.get(4)?,
        sanitized_sha256: row.get(5)?,
        sanitized_content: row.get(6)?,
        ruleset_version: row.get(7)?,
        elapsed_ms: row.get(8)?,
    })
}

/// Converts a raw metadata row into the typed contract used by the query handler.
fn summary_from_raw(
    raw: RawAssessmentSummary,
    findings: Vec<Finding>,
    max_cell_bytes: usize,
) -> Result<AssessmentSummary, StoreError> {
    validate_common_cells(
        &raw.request_id,
        &raw.content_sha256,
        raw.sanitized_sha256.as_deref(),
        &raw.ruleset_version,
        max_cell_bytes,
    )?;
    validate_request_id(&raw.request_id)?;
    Ok(AssessmentSummary {
        request_id: raw.request_id,
        created_at_ms: raw.created_at_ms,
        verdict: parse_verdict(&raw.verdict)?,
        content_sha256: raw.content_sha256,
        sanitized_sha256: raw.sanitized_sha256,
        ruleset_version: raw.ruleset_version,
        elapsed_ms: u64_from_i64(raw.elapsed_ms, "elapsed_ms")?,
        findings,
    })
}

/// Converts a raw full row while applying the same cell bounds used before persistence.
fn record_from_raw(
    raw: RawAssessmentRecord,
    findings: Vec<Finding>,
    max_cell_bytes: usize,
) -> Result<AssessmentRecord, StoreError> {
    validate_common_cells(
        &raw.request_id,
        &raw.content_sha256,
        raw.sanitized_sha256.as_deref(),
        &raw.ruleset_version,
        max_cell_bytes,
    )?;
    validate_cell("content", &raw.content, max_cell_bytes)?;
    if let Some(sanitized_content) = &raw.sanitized_content {
        validate_cell("sanitized_content", sanitized_content, max_cell_bytes)?;
    }
    validate_request_id(&raw.request_id)?;
    Ok(AssessmentRecord {
        request_id: raw.request_id,
        created_at_ms: raw.created_at_ms,
        verdict: parse_verdict(&raw.verdict)?,
        content_sha256: raw.content_sha256,
        content: raw.content,
        sanitized_sha256: raw.sanitized_sha256,
        sanitized_content: raw.sanitized_content,
        ruleset_version: raw.ruleset_version,
        elapsed_ms: u64_from_i64(raw.elapsed_ms, "elapsed_ms")?,
        findings,
    })
}

/// Rejects oversized cells, excess evidence, and invalid spans before a transaction starts.
fn validate_record(
    record: &AssessmentRecord,
    max_cell_bytes: usize,
    max_findings_per_assessment: usize,
) -> Result<(), StoreError> {
    if record.findings.len() > max_findings_per_assessment {
        return Err(StoreError::TooManyFindings {
            actual: record.findings.len(),
            maximum: max_findings_per_assessment,
        });
    }
    validate_common_cells(
        &record.request_id,
        &record.content_sha256,
        record.sanitized_sha256.as_deref(),
        &record.ruleset_version,
        max_cell_bytes,
    )?;
    validate_cell("content", &record.content, max_cell_bytes)?;
    if let Some(sanitized_content) = &record.sanitized_content {
        validate_cell("sanitized_content", sanitized_content, max_cell_bytes)?;
    }
    validate_request_id(&record.request_id)?;
    if record.created_at_ms < 0 {
        return Err(StoreError::InvalidStoredValue {
            field: "created_at_ms",
            detail: "must not be negative".to_owned(),
        });
    }
    for finding in &record.findings {
        validate_cell("rule_id", &finding.rule_id, max_cell_bytes)?;
        if finding.span.start > finding.span.end || finding.span.end > record.content.len() {
            return Err(StoreError::InvalidStoredValue {
                field: "span",
                detail: "must be ordered and contained in original content".to_owned(),
            });
        }
    }
    Ok(())
}

/// Applies shared bounds to identifiers, hashes, and version metadata.
fn validate_common_cells(
    request_id: &str,
    content_sha256: &str,
    sanitized_sha256: Option<&str>,
    ruleset_version: &str,
    max_cell_bytes: usize,
) -> Result<(), StoreError> {
    validate_cell("request_id", request_id, max_cell_bytes)?;
    validate_cell("content_sha256", content_sha256, max_cell_bytes)?;
    if let Some(sanitized_sha256) = sanitized_sha256 {
        validate_cell("sanitized_sha256", sanitized_sha256, max_cell_bytes)?;
    }
    validate_cell("ruleset_version", ruleset_version, max_cell_bytes)
}

/// Enforces the execution-boundary cap without copying or logging cell contents.
fn validate_cell(field: &'static str, value: &str, maximum_bytes: usize) -> Result<(), StoreError> {
    if value.len() > maximum_bytes {
        return Err(StoreError::CellTooLarge {
            field,
            actual_bytes: value.len(),
            maximum_bytes,
        });
    }
    Ok(())
}

/// Keeps the UUID API contract intact when reading potentially corrupted audit state.
fn validate_request_id(request_id: &str) -> Result<(), StoreError> {
    uuid::Uuid::parse_str(request_id).map_err(|source| StoreError::InvalidStoredValue {
        field: "request_id",
        detail: source.to_string(),
    })?;
    Ok(())
}

/// Converts verdicts to the exact stable lowercase database representation.
fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Safe => "safe",
        Verdict::Unsafe => "unsafe",
        Verdict::Sanitized => "sanitized",
    }
}

/// Converts severity values to the exact stable lowercase database representation.
fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Suspect => "suspect",
        Severity::Advisory => "advisory",
    }
}

/// Rejects database verdict strings outside the protocol's closed set.
fn parse_verdict(value: &str) -> Result<Verdict, StoreError> {
    match value {
        "safe" => Ok(Verdict::Safe),
        "unsafe" => Ok(Verdict::Unsafe),
        "sanitized" => Ok(Verdict::Sanitized),
        _ => Err(StoreError::InvalidStoredValue {
            field: "verdict",
            detail: format!("unknown value {value:?}"),
        }),
    }
}

/// Rejects database severity strings outside the protocol's closed set.
fn parse_severity(value: &str) -> Result<Severity, StoreError> {
    match value {
        "critical" => Ok(Severity::Critical),
        "suspect" => Ok(Severity::Suspect),
        "advisory" => Ok(Severity::Advisory),
        _ => Err(StoreError::InvalidStoredValue {
            field: "severity",
            detail: format!("unknown value {value:?}"),
        }),
    }
}

/// Converts bounded durations into SQLite's signed integer representation.
fn i64_from_u64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidStoredValue {
        field,
        detail: "exceeds SQLite INTEGER range".to_owned(),
    })
}

/// Converts byte offsets and limits into SQLite's signed integer representation.
fn i64_from_usize(value: usize, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidStoredValue {
        field,
        detail: "exceeds SQLite INTEGER range".to_owned(),
    })
}

/// Converts nonnegative SQLite integers into API duration values.
fn u64_from_i64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidStoredValue {
        field,
        detail: "must not be negative".to_owned(),
    })
}

/// Converts nonnegative SQLite span offsets into platform string indexes.
fn usize_from_i64(value: i64, field: &'static str) -> Result<usize, StoreError> {
    usize::try_from(value).map_err(|_| StoreError::InvalidStoredValue {
        field,
        detail: "is negative or exceeds the platform index range".to_owned(),
    })
}

/// Converts monotonic storage-boundary durations into fractional diagnostic milliseconds at
/// microsecond resolution, because the writer's serialized phases complete in well under 1 ms
/// and integer milliseconds floor them to zero.
fn duration_ms(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0
}

impl StoreError {
    /// True when the commit outcome cannot safely be claimed either way — the writer died
    /// between enqueue and confirmation — so callers must report unknown status rather than a
    /// definite persistence failure.
    pub fn commit_state_unknown(&self) -> bool {
        matches!(self, Self::WriterResponseLost { .. })
    }
}

impl fmt::Display for StoreError {
    /// Names the exact storage boundary and safe identifiers involved in a failure.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, role, source } => write!(
                formatter,
                "failed to open {role} audit database {}: {source}; initialize it with `cargo run --bin init-db -- --config config.toml`",
                path.display()
            ),
            Self::Configure { path, role, source } => write!(
                formatter,
                "failed to configure {role} audit database {}: {source}",
                path.display()
            ),
            Self::Schema { path, source } => write!(
                formatter,
                "audit database {} does not contain the expected schema: {source}; initialize it with `cargo run --bin init-db -- --config config.toml`",
                path.display()
            ),
            Self::SchemaMismatch { path, detail } => write!(
                formatter,
                "audit database {} schema mismatch: {detail}",
                path.display()
            ),
            Self::InvalidLimit { requested, maximum } => write!(
                formatter,
                "query limit {requested} is outside the execution bound 1..={maximum}"
            ),
            Self::TooManyFindings { actual, maximum } => write!(
                formatter,
                "assessment contains at least {actual} findings, exceeding the configured {maximum}-finding bound"
            ),
            Self::CellTooLarge {
                field,
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "audit field {field} is {actual_bytes} bytes, exceeding the {maximum_bytes}-byte cell cap"
            ),
            Self::InvalidStoredValue { field, detail } => {
                write!(formatter, "invalid audit field {field}: {detail}")
            }
            Self::WriterUnavailable => write!(formatter, "audit writer queue is closed"),
            Self::WriterSpawn { source } => write!(
                formatter,
                "failed to spawn the audit writer thread: {source}"
            ),
            Self::WriterResponseLost { request_id } => write!(
                formatter,
                "audit commit confirmation was lost for request {request_id}; commit state is unknown"
            ),
            Self::Batch { request_id, source } => write!(
                formatter,
                "audit batch persistence failed for request {request_id}: {source}"
            ),
            Self::Begin { batch_seq, source } => write!(
                formatter,
                "failed to begin audit transaction for batch {batch_seq}: {source}"
            ),
            Self::WriteAssessment { request_id, source } => write!(
                formatter,
                "failed to persist assessment row for request {request_id}: {source}"
            ),
            Self::WriteFinding {
                request_id,
                rule_id,
                source,
            } => write!(
                formatter,
                "failed to persist finding {rule_id} for request {request_id}: {source}"
            ),
            Self::Commit {
                batch_seq,
                batch_size,
                source,
            } => write!(
                formatter,
                "failed to commit audit transaction for batch {batch_seq} of {batch_size} assessments: {source}"
            ),
            Self::Query { operation, source } => {
                write!(formatter, "failed to {operation}: {source}")
            }
        }
    }
}

impl Error for StoreError {
    /// Exposes SQLite causes while keeping validation failures as typed local errors.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. }
            | Self::Configure { source, .. }
            | Self::Schema { source, .. }
            | Self::Begin { source, .. }
            | Self::WriteAssessment { source, .. }
            | Self::WriteFinding { source, .. }
            | Self::Commit { source, .. }
            | Self::Query { source, .. } => Some(source),
            Self::WriterSpawn { source } => Some(source),
            Self::Batch { source, .. } => Some(source.as_ref()),
            Self::SchemaMismatch { .. }
            | Self::InvalidLimit { .. }
            | Self::TooManyFindings { .. }
            | Self::CellTooLarge { .. }
            | Self::InvalidStoredValue { .. }
            | Self::WriterUnavailable
            | Self::WriterResponseLost { .. } => None,
        }
    }
}

impl fmt::Display for CursorError {
    /// Reports cursor-shape failures without echoing the opaque caller value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(source) => write!(formatter, "cursor is not valid hex: {source}"),
            Self::Utf8(source) => write!(formatter, "cursor payload is not UTF-8: {source}"),
            Self::Shape => write!(formatter, "cursor payload has an invalid shape"),
            Self::Timestamp(source) => {
                write!(formatter, "cursor timestamp is invalid: {source}")
            }
            Self::RequestId(source) => {
                write!(formatter, "cursor request id is invalid: {source}")
            }
        }
    }
}

impl Error for CursorError {
    /// Retains concrete decoding causes for handler-side diagnostics.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hex(source) => Some(source),
            Self::Utf8(source) => Some(source),
            Self::Timestamp(source) => Some(source),
            Self::RequestId(source) => Some(source),
            Self::Shape => None,
        }
    }
}
