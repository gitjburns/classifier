# Benchmark Results

Measurement rounds defined by `bench/SPEC.md` §3. Newest round last. Each
round starts from a freshly initialized scratch database.

## Round 1 — Baseline (pre-optimization)

- **Date:** 2026-07-18 (local)
- **Code state:** unmodified service; no performance changes applied yet.
- **Ruleset version:** 2026-07-13.1 (5 patterns, 6 enabled analyzers)
- **Host:** macOS (Darwin 24.6.0), 10-core parallelism detected by the
  service. The production instance was running on port 9090 but idle
  (maintenance window, no caller traffic).
- **Config:** production-identical limits, `logging.level = "info"`,
  SQLite defaults (`journal_mode=DELETE`, `synchronous=FULL`).

| Run | Connections | Content bytes | Requests ok | Errors | Throughput (req/s) | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1024 | 61,051 | 0 | 2,035 | 0.45 | 0.61 | 0.83 | 551.67 |
| 2 | 4 | 1024 | 72,270 | 0 | 2,409 | 1.41 | 1.90 | 2.75 | 810.15 |
| 3 | 16 | 1024 | 78,502 | 0 | 2,617 | 5.87 | 6.97 | 8.30 | 446.20 |
| 4 | 64 | 1024 | 79,609 | 0 | 2,654 | 23.65 | 26.66 | 30.48 | 157.18 |
| 5 | 256 | 1024 | 76,896 | 0 | 2,563 | 95.91 | 103.96 | 211.12 | 373.85 |
| 6 | 64 | 32768 | 71,903 | 0 | 2,397 | 26.17 | 29.27 | 36.30 | 161.92 |

### Observations

- **Throughput saturates near ~2,650 req/s by 16 connections.** Beyond that,
  added concurrency converts almost entirely into queueing latency: p50 tracks
  `connections / ~2,650 req/s` closely (64 → ~24 ms, 256 → ~96 ms), the
  signature of a serialized section of ~0.38 ms per request that every
  assessment must pass through.
- **The pipeline is not the bottleneck at saturation.** Raising content from
  1 KiB to 32 KiB (32× the analyzer/normalization/hash work) cost only ~10%
  throughput at 64 connections. The serialized commit-plus-logging path, not
  CPU, sets the ceiling.
- **Commit cost is far below the pre-measurement estimate.** Single-connection
  p50 of 0.45 ms round trip means SQLite's default `fsync()` on this APFS host
  is cheap (macOS `F_FULLFSYNC` is not used by default). The WAL change
  (Phase 3) should therefore be justified by shortening the serialized
  section, not by removing multi-millisecond fsyncs.
- **Rare large stalls appear in every run** (max latency 150–810 ms,
  ~1,000× the median). Not yet attributed; candidates include SQLite file
  growth, filesystem flush stalls, and log-writer contention. Worth
  re-checking after Phases 3–5 rather than investigating in isolation.
- Zero errors in all runs; 514,745 assessments persisted across the round.

### Artifact sizes after the round

Scratch database: 3.3 GiB. Scratch service log: 1.8 GiB (~17 durable log
lines per assessment at `info`). The log is not reset by the round procedure
and accumulates across rounds until manually cleared.

## Round 2 — After O1 (hot-path log consolidation)

- **Date:** 2026-07-18 (local, same day as Round 1)
- **Code state:** O1 implemented — 17 → 4 durable log lines per successful
  assessment; the consolidated post-commit store record is written after the
  writer mutex is released. O2/O3 not applied.
- **Ruleset version:** 2026-07-13.1 (5 patterns, 6 enabled analyzers)
- **Host:** macOS (Darwin 24.6.0), 10-core parallelism detected. Live
  instance on port 9090 idle (maintenance window).
- **Config:** production-identical limits, `logging.level = "info"`,
  SQLite defaults (`journal_mode=DELETE`, `synchronous=FULL`).
- **Procedure note:** first round using the scratch-log-clearing step; the
  Round 1 artifacts (~3.3 GiB database + ~1.8 GiB log, ~5 GiB total) were
  deleted immediately before run 1.

| Run | Connections | Content bytes | Requests ok | Errors | Throughput (req/s) | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1024 | 50,848 | 0 | 1,695 | 0.39 | 0.54 | 0.78 | 1,089.93 |
| 2 | 4 | 1024 | 57,753 | 0 | 1,925 | 1.21 | 1.71 | 5.11 | 1,314.19 |
| 3 | 16 | 1024 | 54,071 | 0 | 1,802 | 5.02 | 6.30 | 19.98 | 1,159.79 |
| 4 | 64 | 1024 | 92,918 | 0 | 3,097 | 20.26 | 22.57 | 25.41 | 139.84 |
| 5 | 256 | 1024 | 92,444 | 0 | 3,082 | 82.03 | 86.67 | 99.74 | 326.71 |
| 6 | 64 | 32768 | 80,284 | 0 | 2,676 | 22.99 | 25.90 | 44.99 | 524.39 |

### Observations

- **Saturation throughput improved ~17–20% over Round 1** with clean tails:
  64 connections 2,654 → 3,097 req/s (+17%, max 140 ms), 256 connections
  2,563 → 3,082 req/s (+20%), 64 × 32 KiB 2,397 → 2,676 req/s (+12%).
  p50 improved in every run, consistent with a shorter serialized
  per-request section.
- **Runs 1–3 are contaminated and not comparable to Round 1.** Commit
  stalls up to ~1.3 s (run maxima 1,090–1,314 ms) depressed their
  throughput below baseline despite better medians. The consolidated
  commit record attributes them precisely: 56 commits took ≥ 100 ms
  (largest `commit_elapsed_ms=970`), 51 of them within the round's first
  two minutes (runs 1–2), fading to one by the final runs. Hypothesis
  (unverified): APFS background reclamation of the ~5 GiB deleted
  immediately before run 1 — Round 1 deleted nothing comparable
  beforehand.
- **Round 1's "rare unattributed stalls" are now attributable.** The O1
  consolidated record carries per-phase durations, and every large stall
  this round landed in `commit_elapsed_ms` — the commit/fsync boundary,
  not permit wait, insertion, or the log writer.
- Zero errors; 428,318 measured successful assessments (plus warmup
  traffic) persisted.

### Artifact sizes after the round

Scratch database: 3.6 GiB. Scratch log: 656 MiB — ~2.7× smaller than
Round 1's 1.8 GiB at a higher persisted-request volume.

## Round 3 — Post-optimization (O2, O3, UUIDv7, explicit 4 KiB pages, O4)

- **Date:** 2026-07-19 (local)
- **Code state:** O2 (`prepare_cached` inserts), O3 (`journal_mode=WAL` set by
  `init-db`, verified — never set — at startup; explicit `synchronous=FULL`),
  UUIDv7 `request_id` (time-ordered primary-key inserts), explicit 4096-byte
  pages set by `init-db`, O4 (dedicated audit-writer thread with natural group
  commit: batched single-fsync transactions, verdict released only after the
  batch's durable commit), and microsecond-resolution writer/handler timing
  fields.
- **Ruleset version:** 2026-07-13.1 (5 patterns, 6 enabled analyzers)
- **Host:** macOS (Darwin 24.6.0), 10-core parallelism detected. Live
  instance on port 9090 idle (maintenance window). Disk verified idle
  outside runs via iostat.
- **Procedure change:** pre-round artifacts are moved into `bench/trash/`
  (same-volume rename), never deleted, so filesystem reclamation cannot
  overlap a measurement. Disposal of `bench/trash/` is a separate operator
  action outside measurement windows.
- **Discarded attempts:** three earlier Round 3 attempts (2026-07-18/19) were
  discarded by decision: two were degraded by host-storage stall accumulation
  under the old rollback-journal write pattern, and one measured the
  1024-byte-page experiment, which regressed batching and large-content runs
  and was reverted (see observations).

| Run | Connections | Content bytes | Requests ok | Errors | Throughput (req/s) | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1024 | 174,626 | 0 | 5,821 | 0.13 | 0.17 | 0.30 | 72.75 |
| 2 | 4 | 1024 | 304,007 | 0 | 10,134 | 0.23 | 0.36 | 6.76 | 63.42 |
| 3 | 16 | 1024 | 384,465 | 0 | 12,816 | 0.64 | 10.03 | 11.71 | 66.11 |
| 4 | 64 | 1024 | 383,480 | 0 | 12,783 | 2.49 | 18.39 | 20.74 | 94.55 |
| 5 | 256 | 1024 | 417,184 | 0 | 13,906 | 23.70 | 31.97 | 35.66 | 139.96 |
| 6 | 64 | 32768 | 123,834 | 0 | 4,128 | 15.61 | 23.14 | 27.84 | 124.99 |

### Observations

- **Saturation throughput is 4.8–5.2× Round 1** (64 connections 2,654 →
  12,783; 256 connections 2,563 → 13,906) with p50 improved at every
  concurrency and zero errors across 2.1M measured requests.
- **Throughput now rises with load.** Deeper queues form larger commit
  batches (503,675 batches; mean size 4.2, max 128; ~52% singletons), so
  amortization improves exactly when pressure grows. Serialized per-request
  writer cost fell from 0.161 ms (pre-O4, measured at microsecond
  resolution) to 0.089 ms.
- **The Round 1–2 stall mystery is closed.** Root cause: the rollback
  journal's per-commit page copies, double fsync, and journal-file churn
  produced ~170 KB of device writes per 1 KiB request (~60× amplification,
  ~80 GB per matrix), and sustained rounds accumulated device-level stall
  debt — self-generated, as proved when stalls persisted with all deletions
  replaced by moves and the disk otherwise idle. WAL removed the journal
  churn; no commit ≥ 100 ms appears in this round.
- **Negative results worth keeping:** 1024-byte pages (tried with the
  UUIDv7 change) defeated batch page-sharing and multiplied large-content
  overflow pages — 64 × 32 KiB fell to 1,978 req/s — and were reverted to
  an explicit 4096. `synchronous=NORMAL` was probed once (+22% pre-O4) and
  rejected as a permanent option on durability grounds; O4's shared fsync
  achieves the amortization with `FULL` durability intact.
- Graceful shutdown drained and joined the writer thread cleanly
  (`audit_writer_exit` after 503,675 batches).

### Artifact sizes after the round

Scratch database: 7.8 GiB. Scratch log: 2.2 GiB. Both moved to
`bench/trash/` with all prior-round artifacts (~15 GiB total) pending
operator disposal.
