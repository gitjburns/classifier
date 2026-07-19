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
