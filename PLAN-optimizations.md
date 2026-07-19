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

**Status: implemented and measured 2026-07-18 (Round 2); kept.**

Implemented shape: 17 → 4 durable records per successful assessment —
request accepted, in-closure pipeline summary (survives handler
cancellation), one consolidated post-commit store record carrying every
per-phase elapsed duration and written after the writer mutex is released
(zero log writes inside the SQLite writer lock on the success path), and
response handoff with `persistence_elapsed_ms`. Every error record kept
with full local context; `writer_wait_elapsed_ms` moved onto the
begin-failure record. `DIAGNOSTICS.md` Boundary Rule and Required
Lifecycle Coverage amended to permit success-path consolidation.

Measured effect (Round 2, accepted): saturation throughput +17–20%
(64 connections 2,654 → 3,097 req/s; 256 connections 2,563 → 3,082;
64 × 32 KiB 2,397 → 2,676), p50 improved in all six runs, scratch log
~2.7× smaller (1.8 GiB → 656 MiB). The diagnostics-policy trade this item
hinged on is confirmed worthwhile. Round 2 runs 1–3 were contaminated by
a transient stall burst (see the stall investigation below) and are not
comparable to Round 1 at low concurrency.

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

**Status: implemented 2026-07-18; kept.** `prepare_cached` for both insert
statements (now inside the O4 batch loop). No measurable throughput change
alone — parse cost was small next to the commit cycle — retained per the
"kept regardless of measured size" decision below.

Replace `transaction.execute(SQL, …)` with `prepare_cached` for
`INSERT_ASSESSMENT_SQL` and `INSERT_FINDING_SQL` in
`Store::persist_assessment` (`src/store.rs:313`, `:358`). Removes per-call
SQL parsing from inside the writer mutex. Mechanical; no behavior change;
kept regardless of measured size.

### O3 — WAL journal mode and synchronous policy

**Status: implemented 2026-07-19; kept.** `init-db` sets `journal_mode=WAL`
(and, after a measured reversal of a 1024-byte experiment, an explicit
4096-byte `page_size`) on new databases; startup verifies — never sets — the
mode. `synchronous=FULL` set explicitly on the writer: `NORMAL` was probed
once (+22% pre-O4) and rejected as a permanent option on durability grounds.
Effect at the time: ~2.1× saturation throughput and complete elimination of
the ≥100 ms commit stalls (root cause: rollback-journal write amplification;
see `bench/RESULTS.md` Round 3). No migration command: per decision, existing
databases (including the live one) are deleted and re-initialized.

Baseline weakened the premise (fsync is cheap on this host), so WAL's value
is shortening the serialized section (no rollback-journal churn), not
removing large fsyncs. `journal_mode=WAL` is a persistent database-file
property: per the migration rule it must be applied by a deliberate operator
step (expected: extension of `init-db` or a dedicated one-time command), with
startup verifying — never setting — the expected mode. The `synchronous`
choice (`FULL`: one WAL fsync per commit; `NORMAL`: no per-commit fsync,
last commits lost on power failure, not process crash) is an explicit
operator durability decision to be made when this item is proposed in detail.

### O4 — Dedicated audit-writer thread with group commit

**Status: implemented 2026-07-19; kept.** The writer connection moved onto a
dedicated thread fed by a bounded channel; each wake drains whatever queued
(cap 128) into one atomic transaction sharing one fsync, and every waiter
receives its verdict only after that durable commit. Batches fail atomically
with per-member error records; shutdown drains and joins the thread.
Companion changes landed with it: UUIDv7 `request_id` (ordered primary-key
inserts) and microsecond-resolution timing fields (integer-millisecond
truncation had been hiding half the commit cost). Combined effect: 12,800–
13,900 req/s at saturation (4.8–5.2× baseline), with throughput now rising
under added load as batches deepen. Full data in `bench/RESULTS.md` Round 3.

Today each request parks a blocking-pool thread on the writer mutex;
pipeline and persistence tasks share that pool (default cap 512). A single
writer thread fed by a channel would remove the parking, at the cost of an
architectural change to the persistence boundary. Requires a full design
proposal; not justified by current evidence.

### Closed investigation — rare large stalls (root cause found 2026-07-19)

**Resolved.** The stalls were self-generated commit/fsync pressure from
rollback-journal write amplification: ~170 KB of device writes per 1 KiB
request (~60× the durable payload), ~80 GB per measurement round, with
device-level stall debt accumulating across same-day rounds. Proof chain:
per-phase consolidated records located every stall at `commit_elapsed_ms`;
stalls persisted after all pre-round deletions were replaced by moves
(falsifying the APFS-reclamation hypothesis); iostat showed the disk idle
except under benchmark load. O3 (WAL) removed the journal churn and the
stalls with it — no commit ≥ 100 ms in the final round. Original notes
follow for history.

150–810 ms maxima (~1,000× median) in every Round 1 run, initially
unattributed. Round 2's consolidated commit record (O1) located every
large stall in `commit_elapsed_ms` — the commit/fsync boundary — with none
in permit wait, insertion, or the log writer. Round 2 additionally showed
a burst of 56 commits ≥ 100 ms concentrated in the round's first two
minutes (contaminating runs 1–3); unverified hypothesis: APFS reclamation
of the ~5 GiB of prior-round artifacts deleted immediately before run 1.
Re-check in each post-change round; O3 (WAL) is the item most likely to
change commit-boundary behavior. A settle delay after the pre-round
deletions is a candidate procedure tweak, to be decided when Round 3 is
proposed.

## Measurement procedure (after each landed item)

Requires a maintenance window (~5 minutes of load). From the repo root:

1. Stop any prior scratch instance first (`kill $(cat bench/scratch.pid)`),
   then **move — never delete** — the prior artifacts (including any
   `-wal`/`-shm` sidecars) into `bench/trash/`, e.g.
   `mv bench/data/audit.db bench/trash/audit-<round>.db`, and initialize
   fresh: `./target/release/init-db --config bench/config.toml`. Same-volume
   moves are metadata-only, so no filesystem reclamation can overlap the
   measurement (rule recorded 2026-07-19). Disposal of `bench/trash/` is a
   separate operator action outside measurement windows.
2. `mv bench/logs/classifier.log bench/trash/classifier-<round>.log` (fresh
   scratch log each round so each round's diagnostic volume and contents stay
   attributable to that round).
3. Start the scratch instance: `./target/release/classifier --config bench/config.toml`
   (capture its PID in `bench/scratch.pid`; kill only that PID afterward).
4. Run the `bench/SPEC.md` §3 matrix:
   `./target/release/bench-load --addr 127.0.0.1:8081 --token-file secrets/api-token --connections <1|4|16|64|256> --duration-secs 30 --warmup-secs 5 --content-bytes 1024`
   plus the `--connections 64 --content-bytes 32768` run.
5. Kill the scratch instance; append the round to `bench/RESULTS.md` with
   date, code state, and observations.

## Open decisions

None. The O3 `synchronous` policy was decided 2026-07-19: `FULL`, explicit;
`NORMAL` rejected as a permanent option (probe results retained in the O3
item and `bench/RESULTS.md` Round 3).

## Decision log

- 2026-07-18 — Harness decisions and baseline through Round 1: recorded in
  `bench/PLAN.md`'s decision log (authoritative for harness history).
- 2026-07-18 — This file created as the authoritative optimization tracker;
  `bench/PLAN.md` Phases 3–6 superseded by items O3, O2, O1, and the
  measurement procedure above.
- 2026-07-18 — Ordering decided: O1 first, measured alone. O1 design
  approved and implemented the same day (see the O1 item for the landed
  shape); `DIAGNOSTICS.md` amended as part of that approval.
- 2026-07-18 — Scratch-log clearing added as measurement-procedure step 2
  with standing user approval; the scratch log no longer accumulates
  across rounds.
- 2026-07-18 — Round 2 accepted as the O1 measurement despite contaminated
  low-concurrency runs 1–3 (transient commit-stall burst; hypothesis: APFS
  reclamation of pre-round deletions). O1 kept.
- 2026-07-18/19 — O2 implemented. Three Round 3 attempts discarded by
  decision (storage-stall contamination; results not recorded). Procedure
  rule adopted: benchmark artifacts are moved to `bench/trash/`, never
  deleted, around measurements. The move-not-delete test falsified the
  APFS-reclamation hypothesis; stall root cause traced to rollback-journal
  write amplification (~170 KB device writes per request).
- 2026-07-19 — O3 implemented (WAL via `init-db`, startup verifies; explicit
  `synchronous=FULL`). Decided: no migration command — existing databases,
  including the live one, are deleted and re-initialized (test machine).
  `NORMAL` probed under approval and reverted; rejected as permanent.
- 2026-07-19 — Microsecond-resolution timing fields adopted after integer
  truncation was shown to hide half the commit cost. UUIDv7 `request_id`
  adopted. A 1024-byte `page_size` was implemented, measured (regressed
  batching and 32 KiB content), and reverted to an explicit 4096.
- 2026-07-19 — O4 implemented (dedicated writer thread, natural group
  commit, atomic batch failure, drain-on-shutdown). `DIAGNOSTICS.md`
  batch-consolidation amendment, `ARCHITECTURE.md`, and `README.md` updated.
  Final matrix recorded as Round 3: 12,783 req/s at 64 connections, 13,906
  at 256 (4.8–5.2× baseline), zero commit stalls.

## Current status

**All optimization items complete.** O1–O4 implemented and kept, plus UUIDv7
request ids, explicit 4096-byte pages, and microsecond timing diagnostics.
Final measurement (Round 3, `bench/RESULTS.md`): 12,783 req/s at 64
connections and 13,906 at 256 — 4.8–5.2× the Round 1 baseline — with zero
errors, zero ≥100 ms commit stalls, and throughput that rises under load as
commit batches deepen. The stall investigation is closed with root cause.

Remaining operator actions, outside this plan's scope: dispose of
`bench/trash/` (~15 GiB) at leisure, and for production deployment delete the
live database and re-run `init-db` (decided 2026-07-19; the new binary
refuses non-WAL databases by design).
