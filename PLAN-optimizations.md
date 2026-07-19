# Optimization Plan — Single-Host Assessment Throughput

Authoritative cross-session tracker for the throughput-optimization work
items. The measurement harness is specified in `bench/SPEC.md`; measurement
rounds are recorded in `bench/RESULTS.md`; `bench/PLAN.md` covers the harness
work (its Phases 0–2, complete) and is superseded by this file for
optimization items (its Phases 3–6 map to O3, O2, O1, and the measurement
procedure below, respectively).

**Session resume:** read this file, `bench/SPEC.md`, and `bench/RESULTS.md`.
Update the **Current status** section and item **Status** lines as work
completes, with user approval, so any session can pick up from here.

## Goal and constraints

- Maximize concurrent `/v1/assess` throughput on one host, one service
  instance, before any multi-host design is considered. Multi-process was
  evaluated and rejected (one process already saturates all cores; the
  binding constraints are shared-file serialization points that multiple
  processes would worsen).
- Architectural invariants hold unless an item explicitly proposes a change
  and the user approves it: verdict only after audit commit, exactly one
  runtime database write path, lossless observability per `DIAGNOSTICS.md`,
  no runtime schema or database-property changes (migration rule).
- The live service runs from this repository (port 9090) and serves real
  callers. It is never stopped, restarted, or signaled by this work. Load
  runs happen only inside operator-announced maintenance windows.

## Measured baseline (Round 1, 2026-07-18 — full data in `bench/RESULTS.md`)

- Throughput saturates at **~2,650 req/s by 16 connections**; added
  concurrency converts to queueing latency (p50 ≈ connections ÷ 2,650).
- The ceiling is a **serialized ~0.38 ms/request section**, not CPU: 32 KiB
  content (32× pipeline work) costs only ~10% throughput.
- Commit fsync is cheap on this host (APFS `fsync()`; macOS `F_FULLFSYNC`
  not used by default): single-connection p50 is 0.45 ms round trip.
- Every assessment writes ~17 durable log lines through one global
  `Mutex<LineWriter<File>>` (`src/logging.rs:64`), 8 of them while holding
  the SQLite writer mutex (`src/store.rs:281-419`). This in-lock and
  cross-request serialized logging is the prime suspect for the ceiling.
- Rare unattributed stalls (max latency 150–810 ms) appear in every run.

## Work items

### O1 — Hot-path log consolidation (diagnostics-policy decision required)

**Status: candidate; ordering and design approval pending.**

Collapse start/success log pairs on the success path into single
boundary-completion records carrying the same boundary facts (stage, ids,
elapsed times); keep every error path and every currently logged fact.
Affected: `src/http/assess.rs` (9 lines/request today), `src/store.rs`
`persist_assessment` (8 lines/request today, in-lock). `DIAGNOSTICS.md`
governs granularity, so a concrete line-by-line design proposal must be
approved before implementation. Expected effect: shrinks both the writer-mutex
critical section and total log-mutex traffic (~1.8 GiB log per measurement
round today).

### O2 — Cached insert statements

**Status: candidate; ordering decision pending.**

Replace `transaction.execute(SQL, …)` with `prepare_cached` for
`INSERT_ASSESSMENT_SQL` and `INSERT_FINDING_SQL` in
`Store::persist_assessment` (`src/store.rs:313`, `:358`). Removes per-call
SQL parsing from inside the writer mutex. Mechanical; no behavior change;
kept regardless of measured size.

### O3 — WAL journal mode and synchronous policy

**Status: deferred; re-evaluate after O1/O2 measurements.**

Baseline weakened the premise (fsync is cheap on this host), so WAL's value
is shortening the serialized section (no rollback-journal churn), not
removing large fsyncs. `journal_mode=WAL` is a persistent database-file
property: per the migration rule it must be applied by a deliberate operator
step (expected: extension of `init-db` or a dedicated one-time command), with
startup verifying — never setting — the expected mode. The `synchronous`
choice (`FULL`: one WAL fsync per commit; `NORMAL`: no per-commit fsync,
last commits lost on power failure, not process crash) is an explicit
operator durability decision to be made when this item is proposed in detail.

### O4 — Dedicated audit-writer thread (conditional)

**Status: only if measurements after O1–O3 still show writer-path pressure.**

Today each request parks a blocking-pool thread on the writer mutex;
pipeline and persistence tasks share that pool (default cap 512). A single
writer thread fed by a channel would remove the parking, at the cost of an
architectural change to the persistence boundary. Requires a full design
proposal; not justified by current evidence.

### Open investigation — rare large stalls

150–810 ms maxima (~1,000× median) in every Round 1 run, unattributed.
Candidates: SQLite file growth, filesystem flush stalls, log-writer
contention. Re-check in each post-change round before investigating
separately; O1/O2/O3 may remove or expose the cause.

## Measurement procedure (after each landed item)

Requires a maintenance window (~5 minutes of load). From the repo root:

1. `rm bench/data/audit.db && ./target/release/init-db --config bench/config.toml`
   (fresh B-tree each round for comparability; approved scratch deletion).
2. Start the scratch instance: `./target/release/classifier --config bench/config.toml`
   (capture its PID in `bench/scratch.pid`; kill only that PID afterward).
3. Run the `bench/SPEC.md` §3 matrix:
   `./target/release/bench-load --addr 127.0.0.1:8081 --token-file secrets/api-token --connections <1|4|16|64|256> --duration-secs 30 --warmup-secs 5 --content-bytes 1024`
   plus the `--connections 64 --content-bytes 32768` run.
4. Kill the scratch instance; append the round to `bench/RESULTS.md` with
   date, code state, and observations.

The scratch log (`bench/logs/classifier.log`) accumulates across rounds
(~1.8 GiB per round at baseline volume) and is cleared only with explicit
user approval.

## Open decisions

1. **Ordering: O1 or O2 first.** Presented 2026-07-18, undecided.
   Recommendation on record: O1 first, measured alone, because its size
   determines whether the diagnostics-policy trade is kept; O2 is kept
   regardless, so its attribution is not decision-relevant.
2. **O3 `synchronous` policy** (`FULL` vs `NORMAL`) — decide when O3 is
   proposed in detail, with O1/O2 measurements in hand.

## Decision log

- 2026-07-18 — Harness decisions and baseline through Round 1: recorded in
  `bench/PLAN.md`'s decision log (authoritative for harness history).
- 2026-07-18 — This file created as the authoritative optimization tracker;
  `bench/PLAN.md` Phases 3–6 superseded by items O3, O2, O1, and the
  measurement procedure above.

## Current status

Baseline complete (Round 1). No service source, service config, or schema
changes made yet. Next: user decides O1-vs-O2 ordering, then the first item's
concrete design proposal goes to the user for approval.
