# Benchmark Harness Specification

## Purpose

Measure the maximum sustainable `/v1/assess` throughput and latency of the
classifier service on a single host, so that every performance change made to
the service has a defensible measured before/after comparison.

The harness is scratch tooling. It must never read from or write to the live
service's runtime state (`data/`, `logs/`, `config.toml`, or the running
process). It shares only two read-only inputs with the live deployment:
`rules.toml` and `secrets/api-token`.

## Components

### 1. Scratch service configuration — `bench/config.toml`

A complete service configuration identical to the production shape, differing
only in instance-specific paths and port:

| Key | Value | Reason |
|---|---|---|
| `server.bind_addr` | `127.0.0.1:8081` | Must not collide with the live instance. |
| `limits.max_content_bytes` | `65536` | Same as production so limits match. |
| `rules.path` | `rules.toml` | Same ruleset as production; read-only. |
| `database.path` | `bench/data/audit.db` | Scratch database, created by `init-db`. |
| `query.*` | same values as production | Measurement must reflect production bounds. |
| `auth.token_file` | `secrets/api-token` | Reused read-only; no new credential. |
| `logging.path` | `bench/logs/classifier.log` | Scratch log. |
| `logging.level` | `info` | Same as production so measured throughput includes the real logging cost. |

`bench/data/` and `bench/logs/` must exist before startup; the service refuses
to create parent directories.

### 2. Load generator — `src/bin/bench-load` (`src/bin/bench_load.rs`)

A dedicated Rust binary in this repository. It uses only existing
dependencies: `sha2` + `hex` (content hashing) and `serde_json`
(request/response bodies). Socket I/O is blocking `std::net::TcpStream` with
one OS thread per configured connection: the crate's unified tokio feature
set does not include `io-util` (the async read/write helpers), and a
fixed-concurrency request/response client needs no async runtime. The project
deliberately has no HTTP client dependency, so the generator speaks minimal
hand-rolled HTTP/1.1:

- One persistent keep-alive TCP connection per worker thread.
- Request: `POST /v1/assess` with `Authorization: Bearer <token>`,
  `Content-Type: application/json`, `Content-Length`, and a JSON body of
  exactly `{"content", "content_sha256"}`.
- Response parsing: status line, headers until the blank line, then exactly
  `Content-Length` body bytes. Chunked encoding is not implemented; a chunked
  or connection-close response counts as an error.

Command-line arguments (all required except where noted):

| Argument | Meaning |
|---|---|
| `--addr <host:port>` | Target service address. |
| `--token-file <path>` | Bearer token file; same trailing-newline handling as the service. |
| `--connections <n>` | Number of concurrent keep-alive connections (workers). |
| `--duration-secs <n>` | Measured run length, excluding warmup. |
| `--warmup-secs <n>` | Optional, default `5`. Requests sent and discarded before measurement starts. |
| `--content-bytes <n>` | Approximate UTF-8 byte length of generated content. |

Each worker loops for the run duration:

1. Generate unique ASCII content of the requested size (a per-request unique
   prefix over a fixed ASCII filler). Uniqueness keeps `content_sha256` index
   inserts realistically random; repeated identical content would make B-tree
   inserts artificially cheap. Plain ASCII keeps the pipeline on its ASCII
   fast path and the expected verdict `safe`.
2. Compute the lowercase SHA-256 client-side.
3. Send the request, read the full response, record wall-clock latency.
4. Validate: HTTP `200`, body parses as JSON, `verdict == "safe"`. Anything
   else counts as an error; error responses are counted and the first few are
   printed verbatim for diagnosis, then the worker reconnects and continues.

Output after each run, printed to stdout:

- configuration echo (address, connections, duration, content bytes);
- total requests, total errors;
- throughput (successful requests / measured seconds);
- latency p50 / p95 / p99 / max in milliseconds, computed from all recorded
  successful-request latencies.

The generator is a client-side measuring tool: it may use wall clocks and
randomness freely, and it is exempt from the service's diagnostics policy. It
must never be wired into the service binary.

### 3. Baseline measurement matrix

Run inside a maintenance window (load runs saturate all host cores by design
and contend with live traffic for CPU and disk sync):

| Run | Connections | Content bytes | Duration |
|---|---|---|---|
| 1–5 | 1, 4, 16, 64, 256 | 1024 | 30 s each + 5 s warmup |
| 6 | 64 | 32768 | 30 s + 5 s warmup |

Runs 1–5 sweep concurrency to find the throughput knee and its latency cost.
Run 6 shifts work toward the CPU-bound pipeline to show how content size moves
the bottleneck. The scratch database is initialized fresh before the matrix so
every baseline starts from an empty B-tree; later re-measurements must do the
same for comparability.

## Measurement invariants

- The scratch instance and load generator never touch live runtime state.
- The live service process is never stopped, started, or signaled by benchmark
  work. Only the scratch instance (identified by the PID captured at launch)
  is ever killed.
- A smoke test (a few seconds, 2 connections) outside the window validates the
  harness; full matrix runs happen only inside a window.
- Results are only comparable across identical matrix definitions, a fresh
  scratch database, and the same host conditions; record the ruleset version
  and any host anomalies alongside results.
