# Implementation Plan — Content Risk Assessment Service (MVP)

Governing documents: `SPEC.md` (system design), `PROTOCOL.md` (caller
contract), `PRINCIPLES.md`, `AGENTS.md`, `DIAGNOSTICS.md`.

## Current Status

Last updated: 2026-07-14

- Specification complete and approved: `SPEC.md`, `PROTOCOL.md`.
- `AGENTS.md` SQLite rule amended for the service-owned audit store
  (single write path).
- Phases 0–8 are complete. The Phase 2 startup validation matrix and the Phase 3
  through Phase 8 Cargo gates and second-pass reviews completed with the
  intentional staging warnings governed below. Phase 4 follows its documented
  MVP complexity ceiling, with broader Unicode shaping coverage deferred. Phase
  6 includes the approved 10,000-findings execution bound. Phase 7 includes the
  HTTP service, authenticated assess endpoint, health endpoint, and graceful
  shutdown. Phase 8 includes the authenticated list and detail query endpoints,
  strict bounded filters, and corrective query-error responses. Live request
  verification remains deferred to Phase 9 as planned. Next step: Phase 9,
  awaiting approval.
- The service is non-operational throughout Phases 0–10. It must not receive
  caller traffic until every phase is complete and the user has explicitly
  approved operational readiness. Explicitly approved phase-verification runs
  are development checks, not operational use.

| Phase | Title                                  | Status      |
|-------|----------------------------------------|-------------|
| 0     | Scaffolding                            | complete    |
| 1     | Config, secrets, logging, startup      | complete    |
| 2     | Rules engine and shipped rules file    | complete    |
| 3     | Normalization and span map             | complete    |
| 4     | Built-in analyzers                     | complete    |
| 5     | Pipeline and verdict                   | complete    |
| 6     | Audit store                            | complete    |
| 7     | HTTP service and assess endpoint       | complete    |
| 8     | Query API                              | complete    |
| 9     | End-to-end verification                | not started |
| 10    | Documentation                           | not started |

## Process Rules

- Phases run in order. Each phase begins only after explicit user approval
  and ends with a status update in this file.
- Every phase that touches Rust ends with the mandatory gate:
  `cargo fmt`, `cargo check`, `cargo clippy`. Warnings caused by defects or
  sloppy code are fixed within the phase. Dead-code warnings caused solely by
  approved phase staging are recorded and allowed to resolve when the planned
  consumer is implemented; they do not justify artificial uses, lint
  suppression, visibility changes, new abstractions, or architecture work.
- Diagnostics coverage (per `DIAGNOSTICS.md`) is implemented in the same
  phase as the code it observes, never deferred.
- No automated tests (per `AGENTS.md`). Pure logic is still structured so it
  could be tested later without the HTTP server or Tokio runtime.
- Runtime verification that starts the server or touches the network requires
  separate explicit user approval at the point of use (Phases 7 and 9).
- Files created before operational readiness, including `config.toml`, the
  token file, logs, and database, are scratch development state. Their creation,
  modification, and deletion still require the approvals defined by
  `AGENTS.md`.
- Creating or modifying `config.toml` requires separate explicit user approval;
  `config.example.toml` is a repository artifact covered by phase approval.

## Target Layout

```
Cargo.toml
config.example.toml        # committed defaults (Phase 1)
config.toml                # approved scratch config (Phase 1); reviewed for readiness in Phase 9
rules.toml                 # shipped rule inventory (Phase 2)
db/schema.sql              # audit store DDL (Phase 6)
data/                      # scratch audit.db created in Phase 6
logs/                      # scratch service log directory created in Phase 1
secrets/api-token          # scratch bearer token file created in Phase 1
src/
  main.rs                  # startup sequence, runtime assembly
  config.rs                # strict config model + loading
  logging.rs               # service log initialization
  types.rs                 # Severity, Verdict, Finding, Span — single source of truth
  normalize.rs             # NFKC normalization + span map (Phase 3)
  rules.rs                 # rules-file model, validation, compiled ruleset (Phase 2)
  analyzers/
    mod.rs                 # analyzer trait + registry
    unicode_tags.rs
    zero_width.rs
    bidi_override.rs
    mixed_script.rs
    encoded_blob.rs
    high_nonascii.rs
  pipeline.rs              # assess → findings → verdict → redact → re-scan (Phase 5)
  store.rs                 # audit store: write path, read path, SQL constants (Phase 6)
  http/
    mod.rs                 # router, state, graceful shutdown
    auth.rs                # bearer-token middleware
    error.rs               # error reason codes + response shape
    assess.rs              # POST /v1/assess
    query.rs               # GET /v1/assessments, GET /v1/assessments/{id}
  bin/
    init_db.rs             # explicit schema-apply command (Phase 6)
```

---

## Phase 0 — Scaffolding

**Goal**: a compiling, empty binary crate with the full dependency set.

Steps:

1. `cargo init --name classifier` in the repo root (creates `Cargo.toml`,
   `src/main.rs`). No git initialization.
2. Edit `Cargo.toml`: latest stable Rust edition and the dependencies below.
   Versions are indicative — confirm latest stable versions during this phase
   (`cargo add` contacts crates.io; the build requires registry access, which
   is standard Cargo behavior, distinct from runtime network verification).

| Crate | Purpose | Notes |
|-------|---------|-------|
| `axum` (0.8) | HTTP server | |
| `tokio` (1) | async runtime | features: `rt-multi-thread`, `macros`, `signal` |
| `serde` (1) | data model | feature: `derive` |
| `serde_json` (1) | API bodies | |
| `toml` (0.8) | config + rules parsing | |
| `regex` (1) | pattern rules | linear-time engine, required property per SPEC §4 |
| `rusqlite` (0.32) | audit store | features: `bundled` (vendored SQLite, no system dependency), `hooks` (gates the progress-handler API used for query timeouts; confirm the gate when versions are confirmed) |
| `sha2` (0.10) | content hashing | |
| `hex` (0.4) | hash + cursor encoding | |
| `uuid` (1) | request ids | feature: `v4` |
| `time` (0.3) | Unix timestamp to RFC 3339 conversion | feature: `formatting` |
| `unicode-normalization` (0.1) | NFKC | |
| `unicode-script` (0.5) | script tables for `mixed-script` | |
| `icu_properties` (2.2) | Unicode binary properties for analyzer exclusions | compiled data exposes `Extended_Pictographic` directly |
| `tracing`, `tracing-subscriber` | service log | see Phase 1 writer decision |

3. `src/main.rs` reduced to a stub `main` that exits with a "not yet
   configured" error message (no functionality).

**Completion criteria**: `cargo fmt` / `cargo check` / `cargo clippy` clean.

---

## Phase 1 — Config, Secrets, Logging, Startup

**Goal**: the strict configuration model from SPEC §7, the service log, and
the fatal-error startup skeleton.

Files: `src/config.rs`, `src/logging.rs`, `src/main.rs`,
`config.example.toml`; approved scratch verification artifacts:
`config.toml`, `secrets/api-token`, `logs/`.

Steps:

1. **Config model** (`src/config.rs`). Typed structs mirroring SPEC §7
   exactly — sections `[server]`, `[limits]`, `[rules]`, `[database]`,
   `[query]`, `[auth]`, `[logging]`; keys `bind_addr`, `max_content_bytes`,
   `path` (rules), `path` (database), `default_limit`, `max_limit`,
   `timeout_ms`, `token_file`, `path` + `level` (logging). Every struct
   carries `#[serde(deny_unknown_fields)]`; no `#[serde(default)]` anywhere;
   every key required. `bind_addr` parses to `SocketAddr` at load; `level`
   parses to a tracing level filter at load. Validate with checked arithmetic
   that `6 * max_content_bytes + 16 KiB` fits the body-limit size type needed
   by Phase 7. Validation failures are fatal with the offending key named.
2. **Config path**: `--config <path>` CLI flag, defaulting to `config.toml`
   in the working directory. Argument parsing is hand-rolled (one flag; a
   CLI-parsing dependency is not justified).
3. **Token file**: read the file named by `auth.token_file`; trim a single
   trailing newline; empty or unreadable file is fatal.
4. **Service log** (`src/logging.rs`): `tracing-subscriber` with two layers —
   stderr and the file at `logging.path`. The file writer is **synchronous**
   (line-buffered file behind a mutex), not `tracing-appender`'s non-blocking
   worker: DIAGNOSTICS.md treats the log as durable evidence, and a
   non-blocking writer can lose the final — most diagnostic — lines on a
   crash. Log volume here is low; durability wins over throughput.
5. **Startup sequence** (`src/main.rs`): parse args → load config → initialize
   logging → then continue initialization. Every fatal startup error is written
   to stderr. Once the configured file logger has initialized, the same fatal
   error is also written to the service log. Failures that prevent obtaining or
   opening `logging.path` therefore use stderr alone. After logging initializes,
   log the config path and parse success, token file publication status (never
   the token), and each subsequent initialization stage as later phases add
   them. `main` stays synchronous in this phase; the Tokio runtime arrives in
   Phase 7.
6. `config.example.toml`: the SPEC §7 example verbatim, as committed
   defaults.
7. **Development verification artifacts**: with the required file-write
   approvals, create scratch `config.toml`, `secrets/api-token`, and `logs/`
   at their eventual repository-local paths. Creation or modification of
   `config.toml` requires its own explicit approval. These artifacts exist only
   to verify configuration, token loading, and durable logging; they do not make
   the service operational, and this phase does not start a server.

**Completion criteria**: cargo gate clean; running the binary against a
missing/invalid config produces the specified fatal errors on stderr; fatal
errors after file logging initializes appear on stderr and in the service log;
a valid config + token file at the approved scratch paths reaches "initialized"
logging and exits cleanly (no server yet).

---

## Phase 2 — Rules Engine and Shipped Rules File

**Goal**: rules-file parsing, validation, compilation; the shipped
`rules.toml` with the approved eleven-rule inventory.

Files: `src/rules.rs`, `src/types.rs`, `rules.toml`.

Steps:

1. **Shared types** (`src/types.rs`): `Severity` (`critical` | `suspect` |
   `advisory`), `Span { start, end }` (UTF-8 byte offsets, end exclusive),
   `Finding { rule_id, severity, span }`, `Verdict` (`safe` | `unsafe` |
   `sanitized`). Defined once; rules, pipeline, store, and HTTP layers all
   import from here (single source of truth per `AGENTS.md`).
2. **Rules file model** (`src/rules.rs`):
   - Top level: required `version` string; `[analyzer.<id>]` sections;
     `[[pattern]]` array.
   - Analyzer sections are **statically typed per analyzer id** — a struct
     with one optional field per known analyzer (`unicode-tags`,
     `zero-width`, `bidi-override`, `mixed-script`, `encoded-blob`,
     `high-nonascii`, via `serde(rename)` for the hyphenated names) and
     `deny_unknown_fields` on the container. An unknown `[analyzer.x]`
     section is therefore a fatal parse error by construction, satisfying
     SPEC §4's "unknown analyzer id is fatal" without string-matching logic.
     Each analyzer struct: `enabled: bool`, `severity: Severity`, plus its
     own typed parameters.
   - Pattern entries: `id`, `severity`, `description`, `regex` (all
     required).
   - Validation (all failures fatal, naming the rule id): duplicate pattern
     ids; a pattern id colliding with an analyzer id (findings share one
     `rule_id` namespace); regex compile failure. Every enabled analyzer
     section must be present in the file — a missing section for a known
     analyzer is fatal (config is explicit; absence is not "disabled").
   - Output: a `CompiledRuleset { version, patterns: Vec<CompiledPattern>,
     analyzers: AnalyzerSettings }` handed to the pipeline.
3. **Startup integration**: load + compile during startup, then log rules
   path, `version`, pattern count, enabled-analyzer count.
4. **Shipped `rules.toml`** — the approved inventory. Initial pattern drafts
   (tuned during this phase's review; `(?i)`/`(?im)` flags per the SPEC §3
   normalization refinement):
   - `template-token` (critical):
     `(?im)(<\|im_(start|end)\|>)|(\[/?INST\])|(<</?SYS>>)|(^#{2,4}[ \t]*(instruction|system)s?[ \t]*$)`
   - `instruction-override` (suspect):
     `(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(instruction|prompt|rule|direction|guideline)s?\b`
   - `role-spoof` (suspect): `(?im)^[ \t]*(system|assistant|developer)[ \t]*:[ \t]`
   - `prompt-extraction` (suspect):
     `(?i)\b(repeat|reveal|show|print|display|output)\b[^.\n]{0,60}\b(system[ \t]+prompt|initial[ \t]+prompt|your[ \t]+(instructions|prompt|rules)|hidden[ \t]+(instructions|prompt))\b`
   - `exfil-beacon` (suspect):
     `(?i)!?\[[^\]]*\]\(\s*https?://[^)\s]+[?&][^)\s]+\)`
   - Analyzer parameter drafts: `encoded-blob` → `min_run_length = 64`,
     `min_entropy = 4.0`; `high-nonascii` → `max_ratio = 0.5`,
     `min_total_chars = 200`; the other four have no parameters
     (`enabled` + `severity` only).

**Completion criteria**: cargo gate clean; startup with the shipped file logs
version and counts; deliberately broken files (unknown key, bad regex,
duplicate id) each produce the specific fatal error.

---

## Phase 3 — Normalization and Span Map

**Goal**: NFKC normalization producing normalized text plus a total,
outward-rounding map from normalized byte spans to original byte spans. This
is the correctness-critical component (SPEC §3); it is pure, synchronous, and
isolated in one module.

File: `src/normalize.rs`.

Design (recorded here because it is the hard part):

1. **Segmentation.** Full-string NFKC cannot be mapped char-by-char because
   canonical composition crosses character boundaries (`e` + combining acute
   → `é`). Instead, test a candidate **normalization-closed boundary** at each
   original character with canonical combining class 0. Independently
   normalize the current segment and candidate character; retain the boundary
   only when the candidate's normalized form starts with a starter and
   normalizing the concatenated normalized sides makes no further change.
   Otherwise, keep the candidate in the current segment. This data-driven
   check uses the Unicode normalization implementation as the authority for
   every cross-starter composition, including Bengali split vowel signs and
   Hangul L+V/LV+T, rather than maintaining an incomplete exception list. Once
   the right side begins with a starter and the concatenation is already NFKC,
   later input cannot change the normalized left side. Per-segment NFKC
   therefore equals full-string NFKC, while every ASCII character still forms
   its own fine-grained segment.
2. **Map representation.** `Vec<Segment { norm_start, norm_end, orig_start,
   orig_end }>` in ascending order, with the normalized text built by
   concatenating per-segment NFKC output. The map is total: every normalized
   byte falls in exactly one segment.
3. **Span translation with outward rounding.** A normalized span translates
   to the original span from the `orig_start` of the segment containing its
   start byte to the `orig_end` of the segment containing its last byte.
   Rounding outward means a match can never select half a combining sequence
   or half an expanded compatibility character; redaction over-covers by at
   most a segment boundary rather than ever under-covering.
4. **Invariants to document in code** (comment requirements per `AGENTS.md`):
   translation always returns spans lying on original character boundaries;
   concatenated segment ranges tile both strings with no gaps; empty input
   yields empty output and an empty map.

**Completion criteria**: cargo gate clean; module exposes
`normalize(&str) -> Normalized` and
`Normalized::to_original_span(Span) -> Span`; hand-verification against a
worked set of cases (ASCII, combining sequences, Bengali split vowel signs,
conjoining Hangul Jamo — L+V and LV+T, full-width forms, mathematical
alphanumerics, emoji ZWJ sequences) recorded in module comments.

---

## Phase 4 — Built-in Analyzers

**Goal**: the six algorithmic detectors, each a pure function from original
text to findings with original-content byte spans.

Files: `src/analyzers/mod.rs` + one module per analyzer.

Common shape: `mod.rs` defines the analyzer interface (scan original text →
`Vec<Span>`; id and severity attach at the registry level from Phase 2
settings) and the registry that Phase 2's `AnalyzerSettings` binds to.

**MVP complexity ceiling**: Phase 4 implements the narrow, deterministic
coverage specified below. It does not add dependencies, abstractions, or
language-specific Unicode handling to pursue comprehensive edge-case coverage.
An uncovered legitimate-text case that does not contradict the caller contract
is recorded as deferred coverage rather than expanding this phase. The MVP may
therefore sanitize some legitimate text conservatively; post-MVP tuning will use
observed operational inputs rather than speculative completeness work.

Per-analyzer algorithms:

1. **`unicode_tags`** — flag each maximal run of U+E0000–U+E007F. One finding
   per run.
2. **`zero_width`** — flag U+200B, U+200C, U+200D, U+2060, and non-leading
   U+FEFF, with two documented exclusions: U+200D (ZWJ) when both neighboring
   characters are `Extended_Pictographic` (emoji sequences), and U+200C
   (ZWNJ) when both neighbors are alphabetic characters whose Unicode Script
   value is Arabic. This narrow rule covers Persian and Arabic-script word
   joining without expanding the MVP into general shaping analysis. Adjacent
   flagged characters merge into one finding.
3. **`bidi_override`** — flag each occurrence-run of U+202A–U+202E and
   U+2066–U+2069.
4. **`mixed_script`** — split into words (maximal alphabetic runs); per word,
   collect script values via `unicode-script`, ignoring `Common` and
   `Inherited`; flag words whose script set is not covered by an allowed
   combination. Allowed combinations follow UTS #39 practice: {Han, Hiragana,
   Katakana}, {Han, Hangul}, {Han, Bopomofo} — Japanese, Korean, and Chinese
   text must not false-positive. One finding per offending word.
5. **`encoded_blob`** — find maximal runs of the base64 alphabet
   (`A–Z a–z 0–9 + / =`) or hex alphabet at least `min_run_length` chars
   long; compute Shannon entropy (bits/char) over the run; flag runs with
   entropy ≥ `min_entropy`. The entropy check keeps repeated-character and
   plain-word runs (which are also base64-alphabet) from false-positiving.
6. **`high_nonascii`** — advisory: when total chars ≥ `min_total_chars` and
   the non-ASCII proportion exceeds `max_ratio`, emit one finding spanning
   the entire content (span `0..len`). Whole-content span is intentional —
   the signal is a property of the document, not a location.

Deferred post-MVP coverage:

- Indic `letter + virama + ZWNJ + letter` shaping contexts. The immediate
  neighbor before ZWNJ is a virama rather than a letter, so this case is
  intentionally outside the narrow Arabic-script exclusion above. Legitimate
  Indic text using this form may be sanitized by the MVP and should be revisited
  after operational inputs are available.

**Completion criteria**: cargo gate clean; each analyzer hand-verified
against positive and negative cases (including the emoji, Persian ZWNJ, and
Japanese exclusion cases) recorded in module comments.

---

## Phase 5 — Pipeline and Verdict

**Goal**: the full assessment function — pure, synchronous, clock-free, and
reviewable without Tokio or HTTP (PRINCIPLES §Rust Design Rules).

File: `src/pipeline.rs`.

Steps:

1. **Assessment core**: `assess(original: &str, ruleset: &CompiledRuleset)
   -> AssessmentOutcome`.
   - Run analyzers on the original text (SPEC §3 refinement).
   - Normalize once; run every pattern rule on the normalized text;
     translate match spans to original offsets via Phase 3.
   - Collect findings sorted by span start.
2. **Verdict decision table** (exactly SPEC §2): any critical → `unsafe`;
   else any suspect → sanitization attempt; else → `safe`.
3. **Sanitization**: merge suspect spans (sort; merge overlapping or
   touching, where touching means `end == start`); build the sanitized
   string by replacing each merged span in the **original** text with the
   literal `[REDACTED]`; re-run `assess` recursively with a
   depth guard permitting exactly one redaction round. Re-run yields no
   critical/suspect findings → `sanitized`; otherwise `unsafe`.
4. **Outcome shape**: `AssessmentOutcome { verdict, findings /* initial scan
   */, sanitized: Option<SanitizedOutput { content, sha256 }>, rescan_clean:
   bool }`. Findings are always the initial scan's (SPEC §3); the re-scan
   outcome is surfaced only for logging.
5. **No clock access** inside the pipeline: elapsed time is measured by the
   HTTP handler (Phase 7), keeping this module deterministic.

**Completion criteria**: cargo gate clean; the three verdict paths and the
failed-sanitization path hand-verified with worked examples recorded in
module comments.

---

## Phase 6 — Audit Store

**Goal**: schema file, explicit init command, write path, bounded read path —
per SPEC §6 and the amended `AGENTS.md` SQLite rule.

Files: `Cargo.toml`, `db/schema.sql`, `src/store.rs`, `src/bin/init_db.rs`,
`src/main.rs`, `src/config.rs`, `config.example.toml`, `SPEC.md`; approved
scratch verification artifacts: `config.toml`, `data/`, `data/audit.db`.

Steps:

1. **`db/schema.sql`**: the SPEC §6 DDL verbatim (tables `assessments`,
   `findings`; the four indexes).
2. **`init-db` binary** (`src/bin/init_db.rs`): accepts `--config <path>`
   (same default and parsing as the main binary); opens the database file at
   `database.path` with create permission; **fails with a clear error if the
   `assessments` table already exists** (checked via `sqlite_master`);
   otherwise applies `db/schema.sql` in one transaction and reports success.
   Add the explicit Cargo target declaration
   `[[bin]] name = "init-db", path = "src/bin/init_db.rs"`; without it, Cargo
   derives the target name `init_db` and the documented command does not work.
   Output goes to stdout/stderr — this is an operator command, not the
   service. Run as: `cargo run --bin init-db -- --config config.toml`.
3. **Development database artifact**: with the required file-write and command
   approvals, create `data/` and run
   `cargo run --bin init-db -- --config config.toml` to initialize the scratch
   `data/audit.db`. This database remains non-operational development state
   until the final readiness approval.
4. **Connection roles** (`src/store.rs`):
   - One **writer** connection, opened `READ_WRITE` (never `CREATE` — a
     missing file or missing schema at startup is fatal, and the error names
     the init command). Held behind a mutex; used only by the assessment
     write path.
   - **Reader** connections opened `READ_ONLY` with `PRAGMA query_only`,
     used by the query endpoints.
   - Both roles set a busy timeout; readers install a progress handler that
     aborts a statement once `query.timeout_ms` wall-clock elapses (rusqlite
     has no native statement timeout; the progress handler — behind the
     `hooks` feature from Phase 0 — is the explicit execution-boundary
     enforcement SPEC §6 requires).
5. **Write path**: `persist_assessment(record) -> Result<()>` — reject records
   above the configured `query.max_findings_per_assessment = 10000` bound,
   then use one transaction to insert the assessment row and all findings rows.
   Lifecycle logging per DIAGNOSTICS.md records each phase's start,
   success/failure, `request_id`, and elapsed milliseconds.
6. **Read path**: list query assembled from the SPEC §5.2 filters —
   `verdict IN (…)`, `content_sha256 = ?`, `created_at_ms >= now_ms - hours`,
   keyset predicate `(created_at_ms, request_id) < (cursor.ts, cursor.id)` —
   ordered `created_at_ms DESC, request_id DESC`, fetching `limit + 1` rows
   to detect continuation. Detail query by `request_id` returns the full
   record including content columns. Findings reads fetch
   `max_findings_per_assessment + 1` rows and fail explicitly rather than
   returning partial evidence when the configured bound is exceeded.
7. **SQL placement**: all statements as named `const` items at the top of
   `store.rs` (PRINCIPLES §External-Language Artifacts; they are short
   operational statements — a separate query file is not warranted at this
   size).
8. **Cursor encoding** (used by Phase 8, defined here with the keyset):
   `hex("{created_at_ms}:{request_id}")` — opaque to callers, no new
   dependency. Decode failures are the caller error `invalid_cursor`.
9. **Blocking boundary**: `store.rs` is synchronous `rusqlite` throughout;
   async callers (Phases 7–8) reach it via `tokio::task::spawn_blocking`.
   The boundary lives at the call site, not inside the store (PRINCIPLES
   §Async And Blocking Work).

**Completion criteria**: cargo gate clean; `init-db` verified against a
scratch database file under `data/` (creates schema; second run fails as
specified); startup schema verification produces the fatal error naming the
init command when pointed at a missing/empty database; second-pass review
confirms configured findings bounds and complete persistence diagnostics.

---

## Phase 7 — HTTP Service and Assess Endpoint

**Goal**: the axum server, auth, `POST /v1/assess`, `GET /healthz`, error
shapes, graceful shutdown — per SPEC §5.1/§5.4 and PROTOCOL.md.

Files: `src/http/mod.rs`, `src/http/auth.rs`, `src/http/error.rs`,
`src/http/assess.rs`, `src/pipeline.rs`; `src/main.rs` gains the Tokio runtime.

Steps:

1. **Runtime assembly** (`main.rs`): after Phase 1 startup and Phase 2/6
   initialization succeed, build shared state
   `Arc<AppState { config, ruleset, store }>` (intentional shared server
   state per PRINCIPLES), bind the listener (log attempt and success),
   serve with graceful shutdown on SIGTERM/ctrl-c (log shutdown begin/end),
   log readiness after successful bind.
2. **Auth middleware** (`auth.rs`): `Authorization: Bearer <token>` compared
   against the loaded token in **constant time** (fold byte differences with
   bitwise OR over equal-length buffers; length mismatch handled without
   early exit) — a plain `==` on secrets leaks length/prefix timing. Failure
   → 401 without a `request_id`, logged with the request path and never the
   presented token. Authentication failures occur before an assessment
   operation is accepted. Applied to all routes except `/healthz`.
3. **Error module** (`error.rs`): preserve the PROTOCOL.md error shape
   `{ "reason", "request_id"? }` with no separate message field. Reasons are
   human-readable machine identifiers defined as shared static `const`s so
   responses remain useful, generic, and compile-time safe without exposing
   source errors or implementation details. Phase 7 defines `unauthorized`,
   `invalid_body`, `empty_content`, `content_too_large`,
   `content_hash_mismatch`, `audit_persistence_failed`,
   `audit_status_unknown`, and `internal_error`. Concrete store, task-join,
   clock, and server errors remain in the service log. Every authenticated
   `POST /v1/assess` error includes `request_id`; authentication failures and
   errors from other endpoints may omit it. Error responses never echo content.
4. **Body limit**: request-body cap of `6 * max_content_bytes + 16 KiB`.
   The factor of six admits the worst-case JSON representation of content
   within the configured limit (each one-byte character encoded as `\uXXXX`);
   the fixed allowance covers the hash, JSON structure, and reasonable
   whitespace. A breach maps to 400 `content_too_large` with the assessment's
   `request_id`.
5. **`POST /v1/assess`** (`assess.rs`):
   - Immediately after authentication, assign `request_id` (UUID v4), start the
     elapsed clock, and log operation start. This happens before reading or
     validating the body, so every later failure can use the same identifier.
   - Strict deserialize (`deny_unknown_fields`) → `invalid_body` with
     `request_id`.
   - Validate: non-empty (`empty_content`), `content.len() ≤
     max_content_bytes` (`content_too_large`). Log each failure with
     `request_id` and return that identifier in the error response.
   - Compute SHA-256 of the received content bytes; compare its lowercase
     hex encoding **exactly** (byte-for-byte) to `content_sha256` →
     `content_hash_mismatch` on any difference. Uppercase input is a
     mismatch: PROTOCOL.md specifies lowercase hex, and strict parsing wins
     over leniency. Log a mismatch and return it with `request_id`.
   - After validation succeeds, log acceptance with content byte size and hash.
     Only validated assessments proceed to the pipeline and audit store;
     rejected request IDs correlate with service logs but have no audit record.
   - Run the pipeline **inline** in the handler: it is bounded CPU work
     (input capped by `max_content_bytes`, linear-time regex), well under
     blocking-boundary thresholds; a `spawn_blocking` hop would add latency
     and complexity for no safety gain. This rationale is documented at the
     call site (PRINCIPLES §Async: tradeoff documented at the boundary).
   - Extend `AssessmentOutcome` with `redaction_span_count`. The pipeline sets
     it from the same merged suspect spans used for redaction and uses zero when
     no sanitization is attempted, keeping diagnostic facts authoritative
     without duplicating span-merging logic in the HTTP layer.
   - Persist via `spawn_blocking` → store write path. A returned store failure
     maps to 500 `audit_persistence_failed`; a task panic or cancellation maps
     to 500 `audit_status_unknown`, because durable commit state cannot be
     claimed. Other unexpected failures map to 500 `internal_error`. Each
     response includes `request_id`, and no verdict is reported unless audit
     persistence is confirmed (SPEC §6).
   - Respond per SPEC §5.1. Log verdict, findings count per severity,
     redaction span count and re-scan outcome when sanitizing, elapsed ms,
     and response handoff. **Delivery caveat**: the point of durable
     visibility is handler completion and transport handoff; socket-level
     delivery failure after handoff is not reliably observable in
     axum/hyper — per DIAGNOSTICS.md, the log records handoff explicitly so
     the unknown remainder is explicit rather than implied.
6. **`GET /healthz`**: unauthenticated 200 once serving (bind is the last
   startup step, so reachability implies readiness; documented in code).

**Completion criteria**: cargo gate clean. Live request verification
(starting the server, sending sample safe/unsafe/sanitized requests) requires
explicit user approval and is otherwise deferred to Phase 9.

---

## Phase 8 — Query API

**Goal**: `GET /v1/assessments` (list) and `GET /v1/assessments/{request_id}`
(detail) — per SPEC §5.2/§5.3 and PROTOCOL.md §5.

Files: `src/http/query.rs`, `src/http/error.rs`, `PROTOCOL.md`.

Steps:

1. **Parameter parsing**, strict per SPEC:
   - `verdict`: comma-split; each token one of `safe|unsafe|sanitized`, or
     the single token `all`; unknown token, duplicate, or `all` combined
     with anything → 400 `invalid_verdict_filter`. Omitted ≡ `all`.
   - `content_sha256`: optional; must be 64 lowercase-hex chars →
     `invalid_content_hash_filter` otherwise.
   - `since_hours`: optional; integer ≥ 1 → `invalid_since_hours` otherwise.
   - `limit`: optional; 1 ≤ n ≤ `query.max_limit` → `invalid_limit`
     otherwise; default `query.default_limit`.
   - `cursor`: optional; decoded per Phase 6 → `invalid_cursor` on any
     decode/shape failure.
2. **List handler**: filters → store read path via `spawn_blocking`;
   assemble rows (metadata + findings, no content columns);
   `next_cursor` from the `limit + 1` sentinel row. Log acceptance with
   compact filter facts (which filters present, limit — not cursor
   contents), row count, whether capped, elapsed ms.
3. **Detail handler**: UUID path parameter; unknown id → 404
   `assessment_not_found`. Returns the full record including `content` and
   `sanitized_content`. Each retrieval logged with target `request_id` —
   content retrieval is an individually auditable act (SPEC §5.3).
4. Convert `created_at_ms` with the `time` crate and render it as RFC 3339 UTC
   `created_at` in responses (PROTOCOL.md shape).
5. Extend `error.rs` with static reason constants `invalid_verdict_filter`,
   `invalid_content_hash_filter`, `invalid_since_hours`, `invalid_limit`,
   `invalid_cursor`, and `assessment_not_found`. Update `PROTOCOL.md` in the
   same phase so its caller-facing reason inventory matches the implemented
   contract; the response shape remains `{ "reason", "request_id"? }` with no
   separate message field.

**Completion criteria**: cargo gate clean; parameter-validation matrix
hand-verified; live query verification deferred to Phase 9.

---

## Phase 9 — End-to-End Verification

**Goal**: verify the assembled service against SPEC and DIAGNOSTICS
requirements. Everything below that starts the server or modifies scratch
runtime state happens only with explicit user approval at the time.

Steps:

1. **Operational-readiness artifact review**: validate every path and value in
   the scratch `config.toml`; confirm appropriate permissions for
   `secrets/api-token`, `data/audit.db`, and `logs/classifier.log`; replace the
   development token if required. Every artifact modification requires explicit
   approval, and every `config.toml` modification requires its own separate
   explicit approval.
2. **Store verification**: verify the schema created in Phase 6 and confirm
   that `cargo run --bin init-db -- --config config.toml` fails rather than
   modifying the existing database.
3. **Startup**: run the service; walk the log against the DIAGNOSTICS.md
   startup checklist (config, rules version/counts, DB roles, bind,
   readiness).
4. **Assess round-trips** via `curl` against `127.0.0.1`:
   - plain content → `safe`;
   - content matching `instruction-override` → `sanitized`, marker present,
     spans correct against the submitted bytes;
   - content with tag-block characters → `unsafe`, no sanitization
     attempted;
   - wrong hash → 400 `content_hash_mismatch`; oversize → 400; unknown field
     → 400; bad token → 401.
5. **Query round-trips**: list with each filter and combination, pagination
   across a cursor, detail fetch returning content, 404 on unknown id,
   invalid filter/cursor → 400s.
6. **Audit verification**: inspect `data/audit.db` rows for a sanitized case
   (content, hashes, findings spans); confirm the service log for the same
   `request_id` contains the full lifecycle and no content.
7. **Log-coverage review**: walk DIAGNOSTICS.md "Required Lifecycle
   Coverage" section against the observed log; any gap is a defect fixed
   before closing the phase.
8. Update this plan's status table.

**Completion criteria**: all verifications pass or their deviations are
documented and accepted by the user; status table updated to complete.

---

## Phase 10 — Documentation

**Goal**: replace the onboarding placeholders with user and developer
documentation that describes the verified implementation rather than planned
behavior.

Files: `README.md`, `ARCHITECTURE.md`.

Steps:

1. **User documentation** (`README.md`): document the service purpose,
   prerequisites, configuration and bearer-token setup, database
   initialization, startup, and normal operation. Link to `PROTOCOL.md` for the
   caller contract instead of duplicating its API definitions.
2. **Developer architecture** (`ARCHITECTURE.md`): document the implemented
   module boundaries and request/data flow, including the async HTTP boundary,
   synchronous SQLite roles, audit ownership, and durable diagnostics path.
   Link to `SPEC.md` for design requirements rather than copying them.
3. **Accuracy pass**: verify every documented command, path, configuration key,
   and behavior against the completed repository and the Phase 9 observations.
   Remove planned or speculative wording and keep each fact owned by one
   canonical document.
4. **Operational-readiness gate**: completing implementation and verification
   does not authorize caller traffic. After all Phase 0–10 work is complete and
   the status table is current, request the user's explicit approval before
   treating the service as operationally ready.

**Completion criteria**: both placeholders are replaced; the documentation
matches the verified service; the status table is updated to complete with user
approval; the service remains non-operational unless the user separately
approves operational readiness.

---

## Standing Risks and Open Items

- **Rule tuning is expected**: the Phase 2 regex drafts and analyzer
  parameters are initial values; Phase 9's round-trips are the first honest
  calibration. False-positive/negative tuning beyond that is post-MVP
  operator work via `rules.toml`.
- **Unicode analyzer coverage is deliberately narrow for the MVP**: Phase 4's
  complexity ceiling favors finite, deterministic detectors over comprehensive
  language shaping support. Known deferred cases, beginning with Indic
  virama/ZWNJ shaping, remain documented in Phase 4 for review after the MVP is
  operational and downstream integrations are running.
- **Normalization segmentation** (Phase 3) is the highest-correctness-risk
  component; its worked-example verification set is the mitigation.
- **Delivery observability limit** (Phase 7): socket-level delivery outcome
  after transport handoff is not reliably observable; logs make the unknown
  explicit per DIAGNOSTICS.md.
- **Dependency versions** in Phase 0 are indicative and confirmed at
  implementation time.
