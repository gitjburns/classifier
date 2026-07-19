# Single-Host Throughput Plan

Historical plan for the benchmark-harness work (Phases 0–2, complete) that
established the baseline for the throughput effort. The harness itself is
specified in `bench/SPEC.md`; measurements live in `bench/RESULTS.md`.

**The optimization work items formerly tracked here as Phases 3–6 are
superseded: work from `PLAN-optimizations.md` in the repository root.** This
file remains authoritative only for harness history and the decisions
recorded in its decision log.

## Goal and constraints

- Serve the maximum number of concurrent assessment requests on a single host;
  multi-host designs are out of scope until this is exhausted.
- One service instance. Multi-process was considered and rejected: the
  pipeline semaphore already saturates all cores from one process, and the
  binding constraints (SQLite writer serialization, shared log file) get worse
  with multiple processes contending for the same files.
- All architectural invariants hold unless a phase explicitly proposes a
  change and it is approved: verdict only after audit commit, one runtime
  write path, lossless observability, no runtime schema changes.
- The live service runs from this repository directory and serves real
  callers. Benchmark work never stops, restarts, or signals it. Full load
  runs happen only inside an operator-announced maintenance window.

## Measured bottleneck analysis (2026-07-18 code review)

Ranked by expected impact; line references are to the reviewed revision.

1. **Audit commit durability.** `configure_writer` (`src/store.rs:557`) leaves
   SQLite on defaults: `journal_mode=DELETE`, `synchronous=FULL`. Every
   assessment pays multiple fsyncs inside the writer-mutex critical section.
   Estimated cap: low hundreds of assessments/second regardless of CPU count.
2. **Hot-path durable-log volume.** ~17 `info!` lines per successful
   assessment (9 in `src/http/assess.rs`, 8 in `src/store.rs:281-419`), all
   serialized through one `Mutex<LineWriter<File>>` (`src/logging.rs:64`).
   The 8 store lines execute while holding the SQLite writer mutex,
   lengthening the serialized section.
3. **Per-call SQL re-preparation.** `transaction.execute()` re-parses the
   INSERT statements per assessment and per finding (`src/store.rs:313`,
   `:358`); `prepare_cached` removes this without design impact.
4. **Blocking-pool head-of-line risk.** Persistence tasks park blocking-pool
   threads on the writer mutex; under extreme concurrency they compete with
   pipeline tasks for the same pool (default cap 512). Only relevant if
   measurements still show pressure after items 1–3.
5. **Long-term insert degradation (accepted characteristic, no planned fix).**
   Random-UUID TEXT primary key plus four indexes (`db/schema.sql`) scatter
   B-tree inserts; sustained throughput declines as the table grows.

**Measured revision (2026-07-18, after Round 1 in `bench/RESULTS.md`):**
item 1's "low hundreds per second" estimate was wrong for this host — APFS
`fsync()` is cheap (macOS `F_FULLFSYNC` is not used by default), and the
measured ceiling is ~2,650 req/s. The serialized section is dominated by
fixed per-request work inside and around the writer mutex — including the
8 in-lock durable log lines of item 2 — not by fsync cost. Item 2 (log
consolidation, Phase 5) is therefore likely a larger lever than item 1
(WAL, Phase 3) on this host; phase ordering is under review.

## Phases

### Phase 0 — Documentation

**Status: complete (2026-07-18).**

`bench/SPEC.md` and this file.

### Phase 1 — Harness implementation and smoke test

**Status: complete (2026-07-18).** Implementation note: the load generator
uses blocking `std::net::TcpStream` with one thread per connection (SPEC.md
amended accordingly) because the crate's unified tokio features exclude
`io-util`. Smoke test: 5 s at 2 connections, 8,631 requests, 0 errors,
~1,726 req/s, p50 0.67 ms. `bench/scratch.pid` holds the scratch instance
PID while it runs.

Scope (all details in `bench/SPEC.md`):

1. Write `bench/config.toml`; create `bench/data/` and `bench/logs/`.
2. Write `src/bin/bench_load.rs`.
3. Add the `[[bin]]` entry for `bench-load` to `Cargo.toml` (approved config
   change; no dependency changes).
4. Mandatory verification: `cargo fmt`, `cargo check`, `cargo clippy`.
5. `cargo build --release`
6. `cargo run --bin init-db -- --config bench/config.toml`
7. Smoke test (outside the window is acceptable): start the scratch instance,
   drive ~5 s at 2 connections, verify sane output, kill the scratch instance
   (its PID only).

### Phase 2 — Baseline measurement

**Status: complete (2026-07-18).** Full results in `bench/RESULTS.md`
(Round 1). Headline: throughput saturates at ~2,650 req/s by 16 connections;
added concurrency converts to queueing latency (serialized section
~0.38 ms/request); 32 KiB content costs only ~10% throughput, so CPU is not
the constraint; zero errors. Scratch log grows ~1.8 GiB per round and is not
cleared automatically.

1. Re-initialize the scratch database fresh: delete `bench/data/audit.db`
   (scratch file; deletion is part of this approved phase) and rerun
   `cargo run --bin init-db -- --config bench/config.toml`.
2. Start the scratch instance:
   `./target/release/classifier --config bench/config.toml`
3. Run the matrix from `bench/SPEC.md` §3, e.g.:
   `./target/release/bench-load --addr 127.0.0.1:8081 --token-file secrets/api-token --connections 64 --duration-secs 30 --content-bytes 1024`
4. Kill the scratch instance (captured PID only).
5. Record results in `bench/RESULTS.md` (created in this phase): matrix
   table, ruleset version, host notes, date.

### Phases 3–6 — SUPERSEDED (2026-07-18)

Migrated to `PLAN-optimizations.md`: Phase 3 → item O3, Phase 4 → item O2,
Phase 5 → item O1, Phase 6 → the measurement procedure there. The text below
is retained as history only; do not work from it.

### Phase 3 — WAL journal mode and synchronous policy

**Status: blocked on a design decision (not yet proposed in detail).**

Direction: `journal_mode=WAL` is a persistent database-file property; per the
migration rule it belongs in a deliberate operator step, not runtime code.
Expected shape: a one-time operator action applies WAL to the database;
startup verifies (never sets) the expected mode. The `synchronous` choice
(`FULL`: one fsync per commit; `NORMAL`: no per-commit fsync, last commits
may be lost on power failure — not process crash) is an explicit durability
decision for the operator. Concrete proposal, including where the operator
step lives and what startup verification asserts, comes after baseline
numbers exist.

### Phase 4 — Cached insert statements

**Status: pending.**

Replace `transaction.execute(SQL, …)` with `prepare_cached` for
`INSERT_ASSESSMENT_SQL` and `INSERT_FINDING_SQL` in
`Store::persist_assessment`. Mechanical; no behavior change.

### Phase 5 — Hot-path log consolidation

**Status: blocked on a diagnostics-policy decision.**

Direction to be proposed: collapse start/success pairs into single
boundary-completion records on the success path (keeping every error path and
all required boundary facts), reducing ~17 lines per assessment to ~6–7.
Requires explicit approval because DIAGNOSTICS.md governs log granularity.

### Phase 6 — Re-measure and reassess

**Status: pending.**

Repeat the Phase 2 matrix identically (fresh scratch database). Compare
against `bench/RESULTS.md` baseline. Decide whether remaining pressure
justifies proposing the dedicated-writer-thread change (bottleneck item 4) or
whether the single-host goal is met.

## Decision log

- 2026-07-18 — Single host, single instance; maximize before any multi-host
  work. Multi-process rejected (see constraints).
- 2026-07-18 — Measure before changing: baseline harness first (Option A).
- 2026-07-18 — Live service keeps running throughout; benchmark load runs
  only in maintenance windows, with notice from the implementer.
- 2026-07-18 — Load generator implemented on `std::net` + threads instead of
  tokio (unified feature set lacks `io-util`; no manifest feature added).
  SPEC.md amended.
- 2026-07-18 — Baseline measured (Round 1): ~2,650 req/s ceiling, serialized
  ~0.38 ms/request section, CPU not the constraint, fsync cheap on this
  host. Consequence recorded in the measured revision note above: Phase 5
  is likely a larger lever than Phase 3; ordering to be decided before
  Phase 3 work starts.
- 2026-07-18 — `PLAN-optimizations.md` created in the repository root as the
  authoritative optimization tracker; Phases 3–6 of this file superseded
  (mapping: 3 → O3, 4 → O2, 5 → O1, 6 → measurement procedure). This file is
  now harness history only.

## Current status

Phases 0–2 complete; the harness work this file tracks is finished. Baseline
recorded in `bench/RESULTS.md` Round 1. Only benchmark-harness artifacts have
been added (`bench/`, `src/bin/bench_load.rs`, the `bench-load` `[[bin]]`
entry in `Cargo.toml`); no service source, service config, or schema changes
have been made. All further work proceeds from `PLAN-optimizations.md` in the
repository root, whose first open decision is the O1-versus-O2 ordering.
