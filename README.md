# Classifier

Classifier is a deterministic content-risk service intended to run in front of
LLM calls. A caller submits untrusted text before forwarding it to an LLM. The
service returns one of three verdicts:

- `safe`: the submitted text may be forwarded.
- `unsafe`: the submitted text must not be forwarded.
- `sanitized`: only the returned redacted text may be forwarded.

The service records every completed assessment, including the original content,
in its own SQLite audit database. It does not use model inference. Detection is
performed by built-in Unicode and encoded-content analyzers plus configurable
regular-expression rules.

The complete caller-facing HTTP contract is in [PROTOCOL.md](PROTOCOL.md).

## Operational status

Building the binary, initializing its database, or receiving a successful
health response does not by itself approve production use. Do not route caller
traffic to an installation until its operator has explicitly approved that
installation as operationally ready.

## Prerequisites

- A Rust toolchain with Rust 2024 edition support.
- Native build tools capable of compiling the bundled SQLite dependency.
- A repository-local working directory containing the configuration, rules,
  token, database, and log paths described below.

The service does not create parent directories, generate credentials, or create
its runtime database schema during startup.

## Build

From the repository root:

```sh
cargo build --release --bin classifier --bin init-db
```

The resulting binaries are:

- `target/release/classifier`: the HTTP service.
- `target/release/init-db`: the explicit one-time schema initializer.

## Configure

Create the repository-local operational directories and configuration with a
restrictive process umask:

```sh
umask 077
install -d -m 700 data logs secrets
cp config.example.toml config.toml
```

Create `secrets/api-token` using the deployment environment's secret-management
mechanism. The file must be readable by the service user and contain a nonempty
bearer token. The loader removes at most one trailing LF or CRLF; every other
byte is part of the token. Do not commit or log this file.

Review every value in `config.toml` before initialization or startup:

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
max_limit = 500
max_findings_per_assessment = 10000
timeout_ms = 2000

[auth]
token_file = "secrets/api-token"

[logging]
path = "logs/classifier.log"
level = "info"
```

Configuration is strict: every section and key is required, unknown keys are
rejected, and invalid values are fatal. Relative paths are resolved from the
service process's working directory. The available durable-log levels are
`trace`, `debug`, and `info`; quieter levels are intentionally unsupported
because they would suppress required lifecycle records. Concise stderr outcomes
and fatal process errors use fixed routes independent of this setting.

The settings have these effects:

| Setting | Effect |
|---|---|
| `server.bind_addr` | Socket address on which the HTTP service listens. |
| `limits.max_content_bytes` | Maximum UTF-8 byte length of submitted content; larger content is rejected, not truncated. |
| `rules.path` | Rules file loaded and compiled atomically during startup. |
| `database.path` | Existing service-owned SQLite audit database. Runtime startup never creates or migrates it. |
| `query.default_limit` | List page size when the caller omits `limit`. Must be within `1..=query.max_limit`. |
| `query.max_limit` | Maximum list page size and storage execution row bound. |
| `query.max_findings_per_assessment` | Maximum complete finding set the service will persist or return. Excess evidence fails rather than being truncated. |
| `query.timeout_ms` | SQLite busy timeout and wall-clock budget for each read-only query connection. |
| `auth.token_file` | File containing the required bearer token. |
| `logging.path` | Append-only service log. Its parent directory must already exist. |
| `logging.level` | Minimum level for lifecycle diagnostics in the append-only service log. |

`config.example.toml` is the visible starting point for operational values.
`config.toml`, the token, database, and logs are environment-specific runtime
state and must remain outside version control. The token and audit database must
be accessible only to the service identity; the database contains full submitted
content.

## Initialize the audit database

Run the initializer once, after the configured database parent directory exists:

```sh
./target/release/init-db --config config.toml
```

The initializer applies `db/schema.sql` in one transaction. It refuses to modify
a database that already contains the `assessments` table. Schema changes and
data migrations are deliberate operator actions; the service runtime never
creates or alters schema.

When developing without a release build, the equivalent command is:

```sh
cargo run --bin init-db -- --config config.toml
```

## Start and stop the service

Start the release binary from the repository root:

```sh
./target/release/classifier --config config.toml
```

The `--config <path>` argument is optional and defaults to `config.toml`. It is
the only accepted command-line option.

Startup is fail-fast and ordered. Before accepting traffic, the process must:

1. load and validate the complete configuration;
2. initialize stderr and file logging;
3. detect the host's available CPU parallelism and create that many
   classification permits;
4. load the bearer token;
5. load and compile the complete ruleset;
6. open the audit writer and verify an independent read-only database role;
7. verify the required tables, columns, and indexes;
8. register shutdown signals and bind the HTTP listener.

`GET /healthz` returns `200` without authentication only after this sequence has
completed and the router is serving. The service log also records
`service ready to accept requests` with `stage="readiness"`.

On Unix, send `SIGINT` or `SIGTERM` for graceful shutdown. On other supported
platforms, use the process's Ctrl-C notification. The process records shutdown
start and completion in the service log.

## Normal operation

All API routes except `/healthz` require the exact configured bearer token. Use
the assessment verdict—not HTTP `200` alone—to decide whether content may be
forwarded. Treat timeouts, transport failures, error responses, and unparseable
responses as not cleared.

Each accepted assessment waits for one startup-sized classification permit
before the deterministic pipeline is dispatched to Tokio's blocking pool. The
owned permit remains with the blocking task until classification finishes, even
if its HTTP handler is cancelled, so abandoned requests cannot bypass the CPU
work bound.

The rules and token are immutable startup state. After deliberately changing
`rules.toml` or rotating the token file, restart the service through the normal
operator-controlled deployment procedure before expecting the new values to
take effect. Each assessment records the ruleset version that produced it.

The audit database has one runtime write path: committing a validated assessment
and all its initial findings in one transaction. History endpoints open
short-lived read-only, query-only connections. List responses contain metadata
and findings but no submitted content; retrieving one detail record deliberately
returns its stored content and is logged as an auditable operation.

There is no automatic audit retention. Protect, retain, back up, and dispose of
the database according to the operator's content-handling policy.

## Diagnostics and troubleshooting

After file logging initializes, the configured append-only service log retains
complete lifecycle evidence at `logging.level`. Stderr instead reports one
concise line for each assessment outcome or authentication failure: `safe` is
`INFO`, `sanitized` and caller-correctable rejections are yellow `WARN`, and
`unsafe` verdicts and internal failures are bold-red `ERROR`. Color and emphasis
are emitted only when stderr is a terminal. These derived summaries are excluded
from the durable log; its structured terminal and lifecycle records remain
authoritative. Fatal process errors also remain on stderr, and failures before
the log file can be opened are available there only.

Diagnostics contain safe identifiers, hashes, counts, limits, statuses, and
elapsed times; they do not contain submitted content, full prompts, model output,
bearer tokens, or cursor values. Assessment dispatch records permit-wait and
pipeline-execution timing. Audit transaction-begin records include time spent
waiting for the sole SQLite writer mutex.

Common startup failures:

- **Configuration cannot be read or parsed:** verify the selected config path,
  required keys, value types, and absence of unknown keys.
- **The log cannot be opened:** create the configured parent directory and
  verify service-user permissions. This failure appears on stderr only.
- **The token cannot be loaded:** verify `auth.token_file`, service-user read
  access, and that the file is nonempty.
- **Rules fail to load:** verify every built-in analyzer section is present,
  rule IDs are unique, pattern IDs do not collide with analyzer IDs,
  `high-nonascii.max_ratio` is finite and within `0.0..=1.0`, and every regular
  expression compiles.
- **The database is missing or has the wrong schema:** initialize a new database
  with `init-db`; do not attempt a runtime migration.
- **The listener cannot bind:** verify `server.bind_addr` and that the address is
  available to the service identity.

For assessment failures after authentication, use the returned `request_id` to
correlate the response with the service log. Validation failures are logged but
not persisted. Query operations use an internal operation ID in diagnostics and
do not expose it in the caller response.

## Repository reference

- [PROTOCOL.md](PROTOCOL.md): standalone caller integration contract.
- [ARCHITECTURE.md](ARCHITECTURE.md): implemented component boundaries and data flow.
- `config.example.toml`: complete configuration shape and visible starting values.
- `rules.toml`: shipped ruleset, analyzer settings, and ruleset version.
- `db/schema.sql`: schema applied only by `init-db`.
