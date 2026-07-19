# Classifier Architecture

Classifier is a deterministic Rust service that assesses untrusted text before
another service forwards that text to an LLM. It detects recognizable content
risk signals, returns an auditable verdict, and records every completed
assessment in a service-owned SQLite database.

The implementation deliberately excludes model inference. Its detection path is
made of finite built-in analyzers and linear-time regular-expression rules so a
verdict is a reproducible consequence of a named ruleset.

## Architectural invariants

The following constraints define the system rather than merely describing its
current implementation:

- **The server owns assessment logic.** Callers provide content and its hash;
  they do not select rules, calculate verdicts, or override sanitization.
- **Verdicts are deterministic for a content byte sequence and ruleset.** There
  are no numeric scores, probabilistic thresholds, or model calls.
- **Every finding refers to original UTF-8 bytes.** Spans are end-exclusive byte
  offsets into the submitted content, even when a pattern matched normalized
  text.
- **A successful assessment is auditable.** The service does not return a
  verdict until the assessment row and all initial findings have committed in
  one SQLite transaction.
- **The audit store retains content; diagnostics do not.** Original and cleared
  sanitized content belong in SQLite. Service logs carry safe identifiers,
  hashes, counts, state transitions, and errors, never submitted content or
  secrets.
- **There is exactly one runtime database write path.** Only assessment
  persistence uses the writer. All history access uses short-lived read-only,
  query-only connections.
- **Schema work is never a runtime side effect.** An explicit operator command
  initializes a new database. Startup only opens and verifies an existing
  schema.
- **Configuration is explicit.** Missing files, missing keys, unknown keys,
  invalid values, unreadable rules, an unavailable token, or a schema mismatch
  are fatal startup errors.
- **Failure is visible and closed.** A missing verdict never clears content, and
  each meaningful operation boundary leaves diagnostic evidence once logging is
  available.

## Component map

| Component | Responsibility |
|---|---|
| `src/main.rs` | Ordered startup, immutable application-state assembly, listener binding, readiness, signal registration, serving, and graceful shutdown. |
| `src/config.rs` | Strict typed TOML configuration, command-line parsing, derived body-limit validation, query-bound validation, and bearer-token loading. |
| `src/logging.rs` | Concise terminal outcomes, fatal-process stderr routing, and complete configured-level lifecycle tracing to the synchronous append-only file. |
| `src/rules.rs` | Strict rules-file parsing, analyzer-setting validation, rule-ID validation, individual regular-expression and candidate-set compilation, and atomic `CompiledRuleset` construction. |
| `src/analyzers/` | Six pure original-text analyzers that return UTF-8 byte spans, with Unicode-only scans skipped for ASCII input. |
| `src/normalize.rs` | ASCII identity handling, NFKC normalization, and outward-rounding translation from normalized spans to original byte spans. |
| `src/pipeline.rs` | Pure assessment, finding collection, verdict selection, redaction, and one complete re-assessment. |
| `src/types.rs` | Single definitions of `Severity`, `Verdict`, `Finding`, and `Span`. |
| `src/store.rs` | The dedicated audit-writer thread committing batched single-fsync transactions, bounded read-only history access, schema and journal-mode verification, cursor encoding, and stored-value validation. |
| `src/http/auth.rs` | Bearer authentication for every route except health. |
| `src/http/assess.rs` | Assessment operation identity, strict request validation, bounded blocking-pipeline dispatch, blocking persistence boundary, and response shaping. |
| `src/http/query.rs` | Strict list-filter validation, blocking history reads, keyset pagination, detail retrieval, and RFC 3339 timestamp rendering. |
| `src/http/error.rs` | Stable basic errors, typed corrective query errors, and response-handoff diagnostics. |
| `src/http/mod.rs` | Route composition, shared state, body-limit placement, and readiness health response. |
| `src/bin/init_db.rs` | Deliberate one-time application of `db/schema.sql`; refuses an already initialized database. |
| `rules.toml` | Versioned analyzer settings and data-driven pattern inventory. |
| `db/schema.sql` | Authoritative schema applied only by `init-db`. |

## Runtime ownership

After startup, handlers share one `Arc<AppState>` containing:

- the validated configuration;
- the derived HTTP request-body cap;
- the bearer token loaded into memory;
- one fully compiled, immutable ruleset;
- one `Store` containing the bounded queue to the audit-writer thread and
  read-path limits;
- the CPU parallelism detected during startup; and
- a semaphore with that many classification permits.

The `Arc` expresses intentional process-wide ownership. The ruleset, token, and
configuration do not change while the process runs. The sole writer connection
lives on a dedicated thread spawned at startup; the store's bounded queue is
the only runtime path to it, so the single-write-path invariant is structural.
The thread drains whatever requests accumulated while the previous transaction
ran and commits them as one batch, sharing a single fsync; an idle service
commits batches of one and adds no latency. Read operations do not touch that
thread; each opens an isolated read-only connection. The semaphore bounds
concurrent deterministic-pipeline work independently of the number of HTTP or
blocking-pool tasks.

## Startup and readiness

Startup follows one ordered path:

```text
arguments
  -> strict configuration
  -> concise stderr + durable file logging routes
  -> available-CPU detection and classification semaphore
  -> bearer token
  -> complete ruleset parse and compilation
  -> audit writer open and schema verification
  -> independent read-only role open and schema verification
  -> shutdown-signal registration
  -> HTTP listener bind
  -> readiness log
  -> serve
```

Argument and configuration failures occur before a configured logger exists and
are reported to stderr. Once logging initializes, later fatal startup errors are
written to stderr and the durable file. Detailed nonfatal startup lifecycle
records go to the file at the configured level. After each corresponding durable
success event, a separate console-only target emits these message-only `INFO`
milestones in order: `STARTUP logging_initialized`, `STARTUP
cpu_parallelism_configured`, `STARTUP token_loaded`, `STARTUP rules_compiled`,
`STARTUP audit_store_verified`, `STARTUP listener_bound`, and `READY`. Their safe
fields identify the applicable configuration or token path, bind address,
parallelism, ruleset version and counts, or database path. The durable file
explicitly excludes this target because the milestones derive from, rather than
replace, its authoritative lifecycle events.

The process does not publish readiness until every dependency is usable and the
listener has bound. Because the health route is reachable only through the
already-serving router, `GET /healthz` returning `200` means startup completed.
Health is the only unauthenticated route.

On Unix, `SIGINT` and `SIGTERM` listeners are registered before the bind so the
service is never declared ready without shutdown control. The server stops
accepting work through Axum's graceful-shutdown path and logs the trigger and
terminal result. Non-Unix platforms use Tokio's Ctrl-C notification.

## Rule inventory and loading

`rules.toml` contains a required version, one explicit section for every known
analyzer, and an array of pattern rules. Analyzer sections own enablement,
severity, and analyzer-specific thresholds. Pattern entries own an ID, severity,
description, and regular expression.

The loader uses `deny_unknown_fields` throughout. It rejects:

- an unknown key or analyzer ID;
- an omitted analyzer section, even when the operator intended it to be off;
- duplicate pattern IDs;
- a pattern ID colliding with a built-in analyzer ID;
- a non-finite `high-nonascii.max_ratio` or one outside `0.0..=1.0`; or
- any regular expression that does not compile.

The complete file is validated and compiled before a `CompiledRuleset` exists,
so requests cannot observe a partially loaded inventory. Pattern matching uses
Rust's finite-automaton `regex` implementation, preserving linear-time behavior
over bounded untrusted input. Compilation also builds a `RegexSet` from the same
pattern sources. At assessment time the set selects candidate pattern indices;
the corresponding individual regular expressions remain authoritative for
repeated matches and exact spans, in rules-file order.

The shipped built-in analyzers are:

| Analyzer | Behavior |
|---|---|
| `unicode-tags` | Finds maximal runs in the Unicode tag block. |
| `zero-width` | Finds selected zero-width controls, while excluding ZWJ directly between two extended-pictographic characters and ZWNJ directly between two Arabic-script letters. |
| `bidi-override` | Finds runs of directional formatting controls in U+202A–U+202E and U+2066–U+2069. |
| `mixed-script` | Finds alphabetic words that mix disallowed scripts; finite Japanese, Korean, and Chinese script combinations are allowed. |
| `encoded-blob` | Finds sufficiently long, sufficiently high-entropy runs in the base64/hex alphabet. It detects but never decodes them. |
| `high-nonascii` | Emits one whole-document advisory finding when configured length and non-ASCII ratio bounds are exceeded. |

The shipped data-driven patterns detect chat-template tokens,
instruction-override phrasing, line-leading role spoofing, prompt-extraction
requests, and outbound Markdown link/image beacons. Operators may tune the
rules file, but changing it has no effect until a controlled process restart.
The version string is stored with and returned by every assessment.

## Normalization and span ownership

Built-in analyzers scan original text because normalization can remove the
formatting evidence they detect. Pattern rules scan NFKC-normalized text so
compatibility forms, styled characters, and composed/decomposed equivalents can
match one signature. Case handling belongs to each regular expression; the
pipeline does not case-fold the whole input.

For all-ASCII input, normalization copies the bytes once and uses identity span
translation. The analyzer dispatcher skips only the Unicode-specific analyzers,
which cannot produce ASCII findings; the encoded-blob analyzer still runs in its
inventory position. These paths preserve the same evidence and ordering rules.

Full-string normalization cannot be mapped character by character because
composition can cross input-character boundaries. `normalize.rs` instead divides
the original into normalization-closed segments. Concatenating the NFKC result
of those segments is equivalent to full-string NFKC, while each segment retains
its original and normalized byte ranges.

When a normalized pattern matches, translation rounds the match outward to the
complete original segments it touches. The result may conservatively cover a
whole combining sequence or expanded compatibility character, but it cannot
select an invalid UTF-8 boundary or under-cover the source of a match.

## Assessment flow

```text
authenticated POST /v1/assess
  -> assign request UUID and timestamp
  -> enforce bounded JSON body and strict request shape
  -> reject empty or oversized content
  -> compute SHA-256 and require exact lowercase caller match
  -> wait for one startup-sized classification permit
  -> dispatch pure deterministic pipeline through spawn_blocking
       -> original-text analyzers
       -> NFKC normalization and normalized-text patterns
       -> original-byte findings ordered by span start
       -> verdict decision
       -> optional redaction and one complete re-assessment
  -> release the owned permit when the blocking task finishes
  -> queue the validated record for the dedicated audit writer
  -> commit assessment + initial findings with the writer's current batch
     in one SQLite transaction sharing one fsync
  -> return the verdict only after that batch's durable commit confirmation
```

Authentication occurs before the handler assigns a `request_id`. Missing,
malformed, duplicate, or incorrect authorization headers therefore return `401`
without an assessment identity. Token comparison processes the complete expected
token and folds length into the result instead of using an early-exit string
comparison.

After authentication, the handler assigns a UUID before reading the body. Every
subsequent assessment validation or internal failure can therefore return a
`request_id` for service-log correlation. The request shape allows exactly
`content` and `content_sha256`. Axum enforces a body cap derived as six times the
configured content-byte limit plus 16 KiB for worst-case JSON escaping and
structure. The decoded content is separately capped by `max_content_bytes` and
is never truncated.

The caller's lowercase SHA-256 must exactly equal the service's digest of the
decoded content's UTF-8 bytes. This integrity check binds the verdict and every
finding span to the same bytes the caller intended to submit.

The handler acquires an owned classification permit before dispatch. That permit
moves into the non-cancellable blocking closure, so cancellation of the handler
does not advertise CPU capacity while its pipeline work is still running. Permit
wait and pipeline execution are recorded separately in lifecycle diagnostics.

### Verdict and sanitization

The pipeline applies set logic over finding severities:

1. Any `critical` finding produces `unsafe`; sanitization is not attempted.
2. Otherwise, any `suspect` finding starts one sanitization attempt.
3. With no `critical` or `suspect` findings, the verdict is `safe`; advisory
   findings remain in the response and audit record.

Sanitization sorts suspect spans and merges overlaps or touching ranges. Each
merged span is replaced in the original text by the literal `[REDACTED]`; text
is never silently removed. The complete pipeline, including normalization and
every enabled analyzer and pattern, runs once more over the redacted text. A
clean re-scan produces `sanitized` plus the cleared text and its SHA-256. Any
remaining critical or suspect finding produces `unsafe`. No second redaction
round is attempted.

Caller-visible findings always come from the initial scan. Re-scan results exist
only to certify sanitized output and provide diagnostic state. Pipeline code is
pure, synchronous, clock-free, and independent of Axum, Tokio, SQLite, and the
filesystem.

## Audit persistence

The SQLite schema separates one assessment row from its zero or more finding
rows. An assessment row stores request identity, UTC epoch milliseconds,
verdict, original content and hash, optional sanitized content and hash,
ruleset version, and elapsed milliseconds. Finding rows store the rule ID,
severity, and original-content byte span.

The writer connection opens with read/write permission but never with create
permission. Startup prepares statements against the expected columns and checks
all required indexes. Missing or incompatible state is fatal and points the
operator to `init-db` rather than modifying the database.

Before enqueueing a write, the store validates field sizes, UUID shape,
timestamp and duration representations, finding count, and that every span is
ordered and contained in the original content. The validated record then joins
the dedicated writer thread's current batch: all members' rows and findings are
inserted in one transaction whose single commit fsync they share, and each
waiting handler receives the batch sequence only after that durable commit.
Batches fail atomically — every member receives the shared cause and per-member
failure records keep local identifiers. Only a confirmed commit permits an HTTP
verdict. A normal persistence error reports `audit_persistence_failed`; a lost
confirmation (the writer died between enqueue and commit) reports
`audit_status_unknown` because commit state cannot safely be claimed.

## History query flow

The list and detail handlers assign internal operation UUIDs for diagnostics.
These are not assessment `request_id` values and are not exposed to callers.

List parsing retains the exact structure needed to report unknown or duplicate
filters. Values are converted into a typed `ListFilter` only after validating
the closed verdict set, lowercase content hash, positive hour range, configured
page bound, and opaque cursor. The store builds parameterized SQL and orders
rows by `(created_at_ms DESC, request_id DESC)`. It fetches one sentinel row past
the requested limit; that row determines whether to issue a continuation cursor.
List SQL never selects either content column.

Each public history operation opens a new SQLite connection with
`SQLITE_OPEN_READ_ONLY`, enables `query_only`, installs a busy timeout, and uses
a progress handler to enforce the configured wall-clock budget across all
statements assembling the result. Findings are fetched up to the configured cap
plus one sentinel. If the sentinel exists, the operation fails rather than
returning incomplete evidence. Stored cells and domain values are validated at
the execution boundary before becoming an API response.

Detail lookup first validates the path as a UUID, then deliberately selects the
full assessment row and its complete findings through the same read-only role.
Because this retrieves stored submitted content, its accepted request and
terminal outcome are recorded as their own diagnostic operation.

## Async and blocking boundaries

Tokio owns naturally asynchronous work: the server, HTTP request extraction,
transport response handoff, signal handling, and blocking-task coordination.
The deterministic pipeline remains a synchronous, framework-independent
function, but assessment handlers dispatch it through `spawn_blocking` so CPU
work does not occupy Tokio workers. A startup-sized semaphore bounds concurrent
pipeline tasks to the host's detected available parallelism. Its owned permits
remain in their blocking closures through handler cancellation.

`rusqlite` remains synchronous. History reads cross `tokio::task::spawn_blocking`
at the HTTP call sites. Assessment persistence crosses a bounded channel to the
dedicated audit-writer thread, where all SQLite write work stays synchronous;
the handler's only async work is awaiting the durable-commit confirmation.
Both boundaries are explicit and prevent SQLite work from blocking Tokio worker
threads.

## Diagnostics

`logging.rs` separates three output roles. A message-only stderr layer accepts
two derived targets: the seven unstyled `INFO` startup milestones and one concise
line for each assessment outcome or authentication failure. For outcomes, `safe`
is an unstyled `INFO` event, `sanitized` and caller-correctable rejections are
yellow `WARN`, and `unsafe` and internal failures are bold-red `ERROR`. ANSI
styling is enabled only when stderr is a terminal. A second stderr layer retains
formatted fatal process errors. The third layer is the synchronous line-buffered
file opened in append mode; it records complete lifecycle evidence at the
configured level and explicitly excludes both derived console-only targets. Its
parent directory must exist. There is no asynchronous logging worker or lossy
queue between a lifecycle event and the shared file writer.

Diagnostics cover:

- startup stages, failure boundaries, listener binding, readiness, and shutdown;
- assessment acceptance, validation, classification-permit wait, pipeline
  execution and summary, redaction/re-scan state, audit transaction phases,
  terminal result, and transport handoff;
- list/detail acceptance, safe filter facts, read outcome, caps, elapsed time,
  terminal result, and transport handoff; and
- one consolidated record per committed audit batch (batch sequence, batch
  size, begin, insertion, and commit durations), per-member failure records
  with local identifiers, and local source errors; each request's terminal
  record cites its committing batch sequence.

The HTTP stack can confirm that a response was constructed and handed to the
transport, but it cannot reliably prove socket-level delivery afterward. Logs
state that remaining outcome as unknown instead of claiming delivery.

Submitted content, full model-style payloads, bearer tokens, cursor values, and
unbounded process output do not belong in logs. The SQLite audit record—not the
service log—is the authoritative content-bearing evidence.

## Security and data lifecycle

The bearer token is kept outside TOML, loaded only after logging is available,
and retained in process memory. Authentication failures log method and path but
never the presented token. The service has no anonymous assessment or history
surface.

The audit database contains sensitive full content and has no automatic expiry.
Filesystem access, backup, retention, and disposal are operator responsibilities.
The database and token must be accessible only to the service identity. History
list operations avoid accidental bulk content disclosure, but authenticated
detail retrieval intentionally returns content and must be treated accordingly.

## Intentional limitations

- `safe` means no enabled critical or suspect deterministic signal matched;
  advisory findings may still be present, and the verdict is not proof that the
  text is harmless.
- Encoded segments are detected and optionally redacted but never decoded or
  recursively inspected.
- Unicode handling is deliberately finite. In particular, Indic
  virama/ZWNJ shaping is not exempted by the narrow Arabic-script ZWNJ rule and
  may be sanitized conservatively.
- The service assesses one content item per request. It has no batch endpoint.
- There is no rate limiter, metrics endpoint, audit-retention automation, or
  hidden fallback data source.
- The current repository verification workflow does not include automated
  tests. Pure domain logic remains isolated so automated verification can be
  added later without coupling it to HTTP, Tokio, SQLite, or network access.
