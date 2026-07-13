# Content Risk Assessment Service — MVP Specification

Scope: deterministic, rules-based assessment only. No model inference in the MVP.

## 1. Overview

The classifier service assesses external text before that text is used as input
to an LLM. Callers submit content to a REST endpoint; the service returns one
of three verdicts:

- `safe` — no risk signals were found.
- `unsafe` — the content should not be forwarded to the LLM.
- `sanitized` — flagged sections were replaced with redaction markers and the
  resulting text passed re-assessment; the caller may forward the sanitized
  version instead of the original.

Every assessment is recorded in a service-owned audit database and can be
retrieved later through a query API.

### Risk model

The MVP detects content carrying recognizable signals of instruction
interference (commonly called prompt injection) or data leakage. Signal
categories:

1. **Concealed text** — invisible or format-manipulating Unicode that can hide
   instructions from human review (tag-block characters, zero-width characters,
   directional formatting, look-alike script mixing).
2. **Instruction-override phrasing** — text that directs the model to disregard
   its prior instructions or adopt a different role.
3. **Conversation-framing tokens** — literal chat-template control sequences
   that imitate the model's own conversation structure.
4. **Outbound beacons** — markdown links or image references constructed to
   transmit request data to external endpoints.
5. **Encoded segments** — long high-entropy runs consistent with base64 or hex
   encoding, whose contents cannot be reviewed as plain text.

### MVP boundary (stated limitation)

Deterministic rules detect recognizable signals, not intent. Fluent, novel
instruction-override phrasing with no known signature and no formatting anomaly
will receive a `safe` verdict. `safe` therefore means **"no known risk signals
found"**, not "verified harmless". The pipeline is deliberately structured so a
model-based analyzer can later be added as one more finding producer without
changing the verdict, sanitization, or API layers.

## 2. Verdict Model

Every rule is assigned one of three severity classes in the rules file:

| Severity   | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `critical` | Signal with essentially no legitimate occurrence. Not eligible for sanitization. |
| `suspect`  | Meaningful signal with rare but real legitimate occurrences. Eligible for redaction. |
| `advisory` | Context only. Reported in findings, never drives the verdict.  |

The verdict is pure set logic over findings — no numeric scores or thresholds:

1. Any `critical` finding → **`unsafe`**. No sanitization is attempted.
2. Otherwise, any `suspect` finding → redact the flagged spans and re-assess
   (Section 3). Re-assessment yields no `critical`/`suspect` findings →
   **`sanitized`**; otherwise **`unsafe`**.
3. Otherwise (no findings, or `advisory` findings only) → **`safe`**.

Rationale: a verdict must be a provable consequence of named rules. "Unsafe
because rule `unicode-tags` (critical) matched at span 214–231" is fully
auditable; a tuned numeric threshold is not. Set logic also means findings
cannot be diluted by surrounding volume — verdicts do not vary with document
length the way additive scores do.

## 3. Assessment Pipeline

```
original content (UTF-8 bytes)
  → validate (size cap, UTF-8, hash match)
  → normalize for matching (NFKC), maintaining a span map
    from normalized offsets back to original byte offsets
  → run built-in analyzers on the original text
    and pattern rules on the normalized text
  → findings: { rule_id, severity, span in ORIGINAL byte offsets }
  → verdict decision table (Section 2)
  → if sanitizing: merge overlapping/adjacent suspect spans,
    replace each merged span in the ORIGINAL text with the marker,
    re-run this full pipeline once on the redacted text
```

Rules and invariants:

- **Pattern rules match normalized text; analyzers scan original text;
  redaction applies to original text.** Pattern rules see the NFKC-normalized
  form, so full-width, styled, or decomposed variants of a signature still
  match. Case-insensitivity comes from the `(?i)` flag inside each pattern,
  not from a case-fold pass: case folding can change byte lengths (`ß` →
  `ss`), which would complicate the span map for no benefit. Built-in
  analyzers scan the original text directly: NFKC removes some of the very
  evidence they detect (styled characters normalize to plain ASCII — which is
  precisely what lets pattern rules match the underlying text), and analyzers
  report original offsets natively. All spans reported anywhere (API, audit
  store) are UTF-8 byte offsets into the **original** content; pattern-rule
  spans are translated through the span map, which is the
  correctness-critical component of that path: a wrong mapping redacts the
  wrong bytes.
- **Redaction marker.** Each merged suspect span is replaced by the fixed
  string `[REDACTED]`. The marker is plain ASCII, matches no rule, and makes
  the alteration visible to whatever consumes the sanitized text. Spans are
  never spliced out silently: removing text outright can join two innocent
  fragments into a new sentence that was never reviewed.
- **Re-assessment is complete.** The redacted text goes through the entire
  pipeline, normalization included. The `safe` certification of sanitized
  output is exactly the certification original content gets. Exactly one
  redaction round is attempted; if the re-run still produces `critical` or
  `suspect` findings, the verdict is `unsafe`.
- **Encoded segments are never decoded.** The `encoded-blob` analyzer flags
  encoded runs; the service does not attempt base64/hex decoding or recursive
  re-assessment of decoded bytes. Encoded content is treated as unreviewable
  and therefore redactable. This is an explicit MVP boundary.
- **Findings in the response and audit record are those of the initial scan**
  (the scan of the submitted content). The re-scan exists only to certify the
  sanitized output; its stage outcome is recorded in the service log.

## 4. Rule Catalog

### Two rule kinds

- **Built-in analyzers** — algorithmic detectors implemented in Rust (Unicode
  class scanning, entropy measurement, script-mixing analysis). Each analyzer
  is configured by an `[analyzer.<id>]` section in the rules file: `enabled`,
  `severity`, and analyzer-specific parameters. Code owns the algorithm; the
  file owns the tuning. A rules file referencing an analyzer id that the binary
  does not implement is a fatal startup error.
- **Pattern rules** — pure data: `[[pattern]]` entries with `id`, `severity`,
  `description`, and `regex`, matched against the normalized text. Adding a new
  signature is a file edit; no rebuild.

### Rules file

A single TOML file; its path is set in `config.toml`. Loading follows the
configuration philosophy: unknown keys fatal, missing required fields fatal,
any regex that fails to compile fatal, duplicate rule ids fatal. Rules never
half-load. The required top-level `version` string flows into every API
response and audit record as `ruleset_version`.

```toml
version = "2026-07-13.1"

[analyzer.unicode-tags]
enabled  = true
severity = "critical"

[analyzer.encoded-blob]
enabled        = true
severity       = "suspect"
min_run_length = 64
min_entropy    = 4.0

[[pattern]]
id          = "instruction-override"
severity    = "suspect"
description = "Directs the model to disregard prior instructions"
regex       = '(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)'
```

Pattern matching uses the Rust `regex` crate, which compiles to finite
automata with guaranteed linear-time matching. Because this service evaluates
externally supplied text against every pattern on every request, predictable
matching time regardless of input is a required property, not an
implementation detail. Regex features that require backtracking are therefore
unavailable by construction, and rule authors must work within that subset.

### Initial inventory

| Rule id                | Kind     | Severity | Detects |
|------------------------|----------|----------|---------|
| `unicode-tags`         | analyzer | critical | Tag-block characters (U+E0000–U+E007F), which can encode text invisible to human readers |
| `template-token`       | pattern  | critical | Literal chat-template control tokens: `<\|im_start\|>`, `[INST]`, `### Instruction`, and similar |
| `zero-width`           | analyzer | suspect  | Zero-width characters inside words; ZWJ within emoji sequences is excluded |
| `bidi-override`        | analyzer | suspect  | Directional formatting characters (U+202A–U+202E, U+2066–U+2069) |
| `mixed-script`         | analyzer | suspect  | Characters from multiple scripts within a single word (look-alike substitution) |
| `encoded-blob`         | analyzer | suspect  | Long high-entropy runs consistent with base64/hex encoding |
| `instruction-override` | pattern  | suspect  | "ignore/disregard previous instructions" phrasing family |
| `role-spoof`           | pattern  | suspect  | Line-leading role labels (`System:`, `Assistant:`) imitating conversation participants |
| `prompt-extraction`    | pattern  | suspect  | Requests to reveal system instructions or configuration |
| `exfil-beacon`         | pattern  | suspect  | Markdown image/link constructs that transmit data to external endpoints via query strings |
| `high-nonascii`        | analyzer | advisory | Unusually high proportion of non-ASCII characters |

Severity assignments worth their rationale:

- `bidi-override` is `suspect`, not `critical`: legitimate mixed-direction text
  (Arabic or Hebrew quoted inside English) genuinely produces these
  codepoints. Redaction handles the problematic case without hard-failing
  legitimate multilingual content.
- `template-token` is `critical`: these exact token sequences have no reason to
  exist in genuine user content — their presence imitates the model's own
  conversation framing, and such content is not eligible for sanitization.
- `zero-width` excludes ZWJ inside emoji sequences because family/profession
  emoji are composed with ZWJ; without the exclusion, every such emoji would be
  a false positive.

## 5. REST API

All endpoints except `GET /healthz` require `Authorization: Bearer <token>`,
where the token is read at startup from the file named in `config.toml`.
Request bodies are parsed strictly: unknown fields are rejected with 400.
Error responses never echo submitted content.

### 5.1 `POST /v1/assess`

Request:

```json
{ "content": "<text to assess>", "content_sha256": "<lowercase hex>" }
```

- `content`: required, non-empty, valid UTF-8, at most `max_content_bytes`
  (from config). Oversize content is rejected with 400 — it is never truncated
  and assessed, because truncation could split a signal and let the remainder
  pass.
- `content_sha256`: required. SHA-256 over the UTF-8 bytes of the `content`
  string value — the raw text bytes after JSON unescaping, not the escaped
  JSON form. The service computes its own hash of the received bytes;
  mismatch → 400 with reason `content_hash_mismatch`. This binds the verdict
  to the exact bytes the caller intended: span offsets are meaningless if any
  transport layer altered the text.

Response — HTTP 200 for **all three verdicts** (the assessment succeeded; the
verdict is data, not a transport error — keeping every verdict on the success
path prevents caller error-handling from accidentally treating `unsafe` as a
retryable failure):

```json
{
  "request_id": "<server-assigned UUID>",
  "verdict": "safe" | "unsafe" | "sanitized",
  "content_sha256": "<service-computed hash of received content>",
  "sanitized_content": "<present only when verdict = sanitized>",
  "sanitized_sha256": "<present only when verdict = sanitized>",
  "findings": [
    { "rule_id": "zero-width", "severity": "suspect",
      "span": { "start": 214, "end": 231 } }
  ],
  "ruleset_version": "2026-07-13.1"
}
```

- Spans are UTF-8 **byte** offsets into the original content (end exclusive).
  Byte offsets are the only encoding-unambiguous choice; callers indexing by
  code points must convert.
- Findings carry no content excerpts. With a verified matching hash, the
  caller's own copy of the content is authoritative — slicing the span from it
  reproduces the evidence exactly.
- `request_id` correlates with the audit record and service log entries.
  The hash identifies the *content*; the request id identifies the
  *assessment event* — identical content submitted twice shares a hash but
  never a request id.

Errors: 400 with a machine-readable `reason` (`invalid_body`, `empty_content`,
`content_too_large`, `content_hash_mismatch`, …), 401 for missing/invalid
token, 500 with `request_id` for log correlation.

### 5.2 `GET /v1/assessments` (list)

Query parameters, all optional, combined with AND:

- `verdict` — comma-separated subset of `safe,unsafe,sanitized`, or the single
  token `all`. Omitted means `all`. Unknown values, duplicates, or `all`
  combined with anything else → 400.
- `content_sha256` — exact-match filter: every assessment of that exact
  content.
- `since_hours` — positive integer; `since_hours=48` returns records created
  within the previous 48 hours. Zero, negative, or non-integer → 400.
- `limit` — page size; defaults to `query.default_limit`, capped at
  `query.max_limit` (both from config).
- `cursor` — opaque continuation token from a previous response. Callers must
  not parse it.

Results are ordered newest-first with keyset pagination (cursor encodes the
last row's `created_at` + `request_id`), so rows written mid-pagination cannot
shift entries between pages. The response states its own completeness:

```json
{
  "assessments": [
    {
      "request_id": "…",
      "created_at": "<RFC 3339 UTC>",
      "verdict": "sanitized",
      "content_sha256": "…",
      "sanitized_sha256": "…",
      "ruleset_version": "…",
      "elapsed_ms": 3,
      "findings": [ { "rule_id": "…", "severity": "…", "span": { "start": 0, "end": 9 } } ]
    }
  ],
  "next_cursor": "<present only when more rows exist>"
}
```

List rows are metadata-only — hashes, never content. Bulk queries must not
ship stored content as a side effect of surveying; retrieving content is a
deliberate per-record act (5.3).

### 5.3 `GET /v1/assessments/{request_id}` (detail)

Returns the full audit record for one assessment: every list-row field plus
`content` (the original submitted text) and `sanitized_content` (when one was
produced). Unknown `request_id` → 404. Each detail retrieval is logged as its
own operation in the service log.

### 5.4 `GET /healthz`

Unauthenticated. Returns 200 once the service is fully initialized (config
loaded, rules compiled, database opened, listener bound); used for liveness
checks.

## 6. Audit Store

Every `POST /v1/assess` request that passes validation is persisted, whatever
its verdict. Storage is SQLite via `rusqlite`, synchronous, reached through an
explicit blocking boundary from async handler code.

### Full-content storage

The store holds the original content and, when produced, the sanitized
content — not just hashes. Rationale: the store exists for audit, and a
verdict record whose subject text is gone is a claim, not evidence. Full
records make every historical verdict re-examinable and allow replaying past
submissions against an updated ruleset. The service **log** remains
content-free (Section 8); the **database** is the content-bearing audit
record. That boundary is deliberate and must not blur in either direction.

Operational obligations that follow: the database file must be readable only
by the service user, and retention/disposal of stored content is an operator
policy decision, out of scope for the MVP (no automatic expiry).

### Access rules

Exactly one write path exists: the assessment pipeline persisting audit
records. The query endpoints use read-only connections. All queries are
bounded (row caps from config, wall-clock timeout); a capped result is always
explicit (`next_cursor`), never silently truncated. This mirrors the SQLite
rules in `AGENTS.md`.

### Schema

Schema DDL lives in a dedicated file, `db/schema.sql`. It is applied only by
an explicit, operator-run init command (a dedicated binary target, e.g.
`cargo run --bin init-db -- --config config.toml`), which fails if the schema
already exists. The runtime never creates or alters schema — startup verifies
the expected schema is present and treats its absence as a fatal error naming
the init command.

```sql
CREATE TABLE assessments (
  request_id        TEXT PRIMARY KEY,          -- UUID
  created_at_ms     INTEGER NOT NULL,          -- unix epoch milliseconds, UTC
  verdict           TEXT NOT NULL,             -- 'safe' | 'unsafe' | 'sanitized'
  content_sha256    TEXT NOT NULL,
  content           TEXT NOT NULL,             -- original submitted text
  sanitized_sha256  TEXT,                      -- NULL unless verdict = 'sanitized'
  sanitized_content TEXT,                      -- NULL unless verdict = 'sanitized'
  ruleset_version   TEXT NOT NULL,
  elapsed_ms        INTEGER NOT NULL
);

CREATE TABLE findings (
  request_id TEXT NOT NULL REFERENCES assessments(request_id),
  rule_id    TEXT NOT NULL,
  severity   TEXT NOT NULL,                    -- 'critical' | 'suspect' | 'advisory'
  span_start INTEGER NOT NULL,                 -- UTF-8 byte offset, original content
  span_end   INTEGER NOT NULL                  -- end exclusive
);

CREATE INDEX idx_assessments_created ON assessments (created_at_ms DESC, request_id);
CREATE INDEX idx_assessments_verdict ON assessments (verdict, created_at_ms DESC);
CREATE INDEX idx_assessments_hash    ON assessments (content_sha256, created_at_ms DESC);
CREATE INDEX idx_findings_request    ON findings (request_id);
```

The audit write happens after the verdict is determined and before the
response is sent; write failure is a 500 (the assessment is not reported as
completed if its audit evidence could not be committed).

## 7. Configuration

Operational configuration lives in `config.toml`; committed defaults live in
`config.example.toml`. Parsing is strict per `PRINCIPLES.md`: missing file,
missing required keys, unknown keys, or a missing/unreadable token file are
fatal startup errors. No runtime defaults for operational settings.

```toml
[server]
bind_addr = "127.0.0.1:8080"

[limits]
max_content_bytes = 65536

[rules]
path = "rules.toml"

[database]
path = "data/audit.db"

[query]
default_limit = 50
max_limit     = 500
timeout_ms    = 2000

[auth]
token_file = "secrets/api-token"

[logging]
path  = "logs/classifier.log"
level = "info"
```

The bearer token is the only secret; it lives in the file named by
`auth.token_file`, outside version control, and is never logged.

## 8. Diagnostics

Coverage follows `DIAGNOSTICS.md`. The service log is the durable evidence of
what happened; it carries identifiers, hashes, rule ids, counts, sizes,
statuses, and elapsed times — **never content, tokens, or secrets**.

Required lifecycle coverage mapped to this service:

- **Startup**: config path and parse result; rules file path, `version`,
  pattern/analyzer counts, compile success; database open (path, read-only vs
  write role) and schema verification; token file publication status (without
  the token); HTTP bind attempt and success; readiness; any fatal error with
  its local cause.
- **Per assessment** (keyed by `request_id`): accepted (content size and
  `content_sha256`); validation failure with reason; pipeline start; findings
  summary (count per severity, rule ids — not matched text); verdict; when
  sanitizing — redaction span count and re-scan outcome; audit transaction
  begin / commit / failure; response delivery success or failure (delivery is
  its own boundary: backend outcome and delivery outcome are logged
  distinctly); total elapsed milliseconds.
- **Per query** (list and detail): accepted with compact parameter facts
  (filters, limit — not cursor contents); row count and whether the result was
  capped; elapsed milliseconds; detail retrievals additionally log the target
  `request_id` (each content retrieval is an auditable act).
- **Errors** preserve source context: SQL, config, and validation errors
  surface with their local facts, never replaced by generic messages.

## 9. Non-Goals (MVP)

- No model inference of any kind; the design reserves the analyzer slot for it.
- No decoding of encoded segments (detect and redact only).
- No batch assessment endpoint; one content item per request.
- No rate limiting; callers are internal services behind the bearer token.
- No retention automation for the audit store; disposal is operator policy.
- No metrics endpoint; the service log is the observability surface.
- Automated tests remain disabled per `AGENTS.md`; verification is
  `cargo fmt` / `cargo check` / `cargo clippy` plus the startup and runtime
  guarantees above.
