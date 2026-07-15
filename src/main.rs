mod analyzers;
mod config;
mod http;
mod logging;
mod normalize;
mod pipeline;
mod rules;
mod store;
mod types;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

/// Runs ordered startup, serves only after readiness, and reports every terminal server boundary.
#[tokio::main]
async fn main() -> ExitCode {
    let config_path = match config::config_path_from_args(config::process_args()) {
        Ok(path) => path,
        Err(error) => return fatal_before_logging(&error),
    };
    let config = match config::Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => return fatal_before_logging(&error),
    };
    if let Err(error) = logging::initialize(&config.logging.path, config.logging.level) {
        return fatal_before_logging(&error);
    }

    tracing::info!(
        config_path = %config_path.display(),
        bind_addr = %config.server.bind_addr,
        max_content_bytes = config.limits.max_content_bytes,
        rules_path = %config.rules.path.display(),
        database_path = %config.database.path.display(),
        query_default_limit = config.query.default_limit,
        query_max_limit = config.query.max_limit,
        query_max_findings_per_assessment = config.query.max_findings_per_assessment,
        query_timeout_ms = config.query.timeout_ms,
        log_path = %config.logging.path.display(),
        "configuration loaded and service logging initialized"
    );
    // Each derived milestone follows its authoritative durable success event so stderr cannot
    // claim that a later startup boundary completed when the detailed lifecycle record did not.
    logging::startup_milestone(format!(
        "STARTUP logging_initialized config_path={} bind_addr={}",
        config_path.display(),
        config.server.bind_addr
    ));

    // Concurrency is fixed before serving so every request observes the same CPU-work bound.
    let pipeline_parallelism_started = Instant::now();
    tracing::info!(
        stage = "pipeline_parallelism",
        "classification pipeline parallelism detection started"
    );
    let pipeline_parallelism = match std::thread::available_parallelism() {
        Ok(parallelism) => parallelism.get(),
        Err(error) => {
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "pipeline_parallelism",
                elapsed_ms = elapsed_ms(pipeline_parallelism_started),
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        stage = "pipeline_parallelism",
        pipeline_parallelism,
        elapsed_ms = elapsed_ms(pipeline_parallelism_started),
        "classification pipeline parallelism configured"
    );
    logging::startup_milestone(format!(
        "STARTUP cpu_parallelism_configured pipeline_parallelism={pipeline_parallelism}"
    ));
    let pipeline_permits = Arc::new(tokio::sync::Semaphore::new(pipeline_parallelism));

    // The token stays in memory only; diagnostics expose its path, never its value. Duration
    // conversion saturates so even an extreme uptime cannot make error reporting fail.
    let token_load_started = Instant::now();
    tracing::info!(
        stage = "token_load",
        token_file = %config.auth.token_file.display(),
        "authentication token load started"
    );
    let token = match config::load_token(&config.auth.token_file) {
        Ok(token) => token,
        Err(error) => {
            let token_elapsed_ms = elapsed_ms(token_load_started);
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "token_load",
                elapsed_ms = token_elapsed_ms,
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    let token_elapsed_ms = elapsed_ms(token_load_started);
    tracing::info!(
        stage = "token_load",
        token_file = %config.auth.token_file.display(),
        elapsed_ms = token_elapsed_ms,
        "authentication token loaded"
    );
    logging::startup_milestone(format!(
        "STARTUP token_loaded token_file={}",
        config.auth.token_file.display()
    ));

    // Rules compile as one startup unit so no request can observe a partially valid inventory.
    let rules_load_started = Instant::now();
    tracing::info!(
        stage = "rules_load",
        rules_path = %config.rules.path.display(),
        "rules load and compilation started"
    );
    let ruleset = match rules::CompiledRuleset::load(&config.rules.path) {
        Ok(ruleset) => ruleset,
        Err(error) => {
            let rules_elapsed_ms = elapsed_ms(rules_load_started);
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "rules_load",
                rules_path = %config.rules.path.display(),
                elapsed_ms = rules_elapsed_ms,
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    let rules_elapsed_ms = elapsed_ms(rules_load_started);
    tracing::info!(
        stage = "rules_load",
        rules_path = %config.rules.path.display(),
        ruleset_version = %ruleset.version,
        pattern_count = ruleset.patterns.len(),
        enabled_analyzer_count = ruleset.analyzers.enabled_count(),
        elapsed_ms = rules_elapsed_ms,
        "rules loaded and compiled"
    );
    logging::startup_milestone(format!(
        "STARTUP rules_compiled ruleset_version={} pattern_count={} enabled_analyzer_count={}",
        ruleset.version,
        ruleset.patterns.len(),
        ruleset.analyzers.enabled_count()
    ));
    // Reuse the proven transport bound as the maximum SQLite cell size: it covers original and
    // expanded sanitized content while preventing unbounded reads from externally altered files.
    let request_body_limit = match config.limits.request_body_limit() {
        Ok(limit) => limit,
        Err(error) => {
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "audit_store_bounds",
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    let store_open_started = Instant::now();
    tracing::info!(
        stage = "audit_store_open",
        database_path = %config.database.path.display(),
        writer_role = "read_write",
        reader_role = "read_only_query_only",
        query_timeout_ms = config.query.timeout_ms,
        query_max_limit = config.query.max_limit,
        query_max_findings_per_assessment = config.query.max_findings_per_assessment,
        "audit store open and schema verification started"
    );
    let store = match store::Store::open(
        &config.database.path,
        config.query.timeout_ms,
        config.query.max_limit,
        config.query.max_findings_per_assessment,
        request_body_limit,
    ) {
        Ok(store) => store,
        Err(error) => {
            let store_elapsed_ms = elapsed_ms(store_open_started);
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "audit_store_open",
                database_path = %config.database.path.display(),
                elapsed_ms = store_elapsed_ms,
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    let store_elapsed_ms = elapsed_ms(store_open_started);
    tracing::info!(
        stage = "audit_store_open",
        database_path = %config.database.path.display(),
        writer_role = "read_write",
        reader_role = "read_only_query_only",
        elapsed_ms = store_elapsed_ms,
        "audit store opened and schema verified"
    );
    logging::startup_milestone(format!(
        "STARTUP audit_store_verified database_path={}",
        config.database.path.display()
    ));
    let bind_addr = config.server.bind_addr;
    let state = Arc::new(http::AppState {
        config,
        pipeline_parallelism,
        pipeline_permits,
        request_body_limit,
        token,
        ruleset,
        store,
    });
    let app = http::router(state);

    #[cfg(unix)]
    let signal_registration_started = Instant::now();
    #[cfg(unix)]
    tracing::info!(
        stage = "shutdown_signal_registration",
        signal_count = 2,
        "shutdown signal registration started"
    );
    #[cfg(unix)]
    let shutdown_signals = match register_shutdown_signals() {
        Ok(signals) => signals,
        Err(error) => {
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "shutdown_signal_registration",
                elapsed_ms = elapsed_ms(signal_registration_started),
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    tracing::info!(
        stage = "shutdown_signal_registration",
        signal_count = 2,
        elapsed_ms = elapsed_ms(signal_registration_started),
        "shutdown signals registered"
    );

    let bind_started = Instant::now();
    tracing::info!(
        stage = "http_bind",
        bind_addr = %bind_addr,
        "HTTP listener bind attempt"
    );
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "http_bind",
                bind_addr = %bind_addr,
                elapsed_ms = elapsed_ms(bind_started),
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        stage = "http_bind",
        bind_addr = %bind_addr,
        elapsed_ms = elapsed_ms(bind_started),
        "HTTP listener bound"
    );
    logging::startup_milestone(format!("STARTUP listener_bound bind_addr={bind_addr}"));
    tracing::info!(
        stage = "readiness",
        bind_addr = %bind_addr,
        "service ready to accept requests"
    );
    logging::startup_milestone(format!("READY bind_addr={bind_addr}"));

    let serving_started = Instant::now();
    tracing::info!(
        stage = "http_serve",
        bind_addr = %bind_addr,
        "HTTP serving started"
    );
    #[cfg(unix)]
    let shutdown = shutdown_signal(shutdown_signals);
    #[cfg(not(unix))]
    let shutdown = shutdown_signal();
    match axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => {
            tracing::info!(
                stage = "shutdown",
                elapsed_ms = elapsed_ms(serving_started),
                "graceful shutdown completed"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(
                target: logging::PROCESS_ERROR_TARGET,
                stage = "http_serve",
                bind_addr = %bind_addr,
                elapsed_ms = elapsed_ms(serving_started),
                error = %error,
                "HTTP server terminated with an error"
            );
            ExitCode::FAILURE
        }
    }
}

/// Holds pre-registered Unix listeners so readiness is never published without shutdown control.
#[cfg(unix)]
type ShutdownSignals = (tokio::signal::unix::Signal, tokio::signal::unix::Signal);

#[cfg(unix)]
/// Registers interrupt and terminate listeners before the HTTP bind makes the service reachable.
fn register_shutdown_signals() -> std::io::Result<ShutdownSignals> {
    let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok((interrupt, terminate))
}

#[cfg(unix)]
/// Waits for either supported Unix shutdown signal and records the trigger or stream failure.
async fn shutdown_signal((mut interrupt, mut terminate): ShutdownSignals) {
    tokio::select! {
        received = interrupt.recv() => log_shutdown_trigger("SIGINT", received),
        received = terminate.recv() => log_shutdown_trigger("SIGTERM", received),
    }
}

#[cfg(unix)]
/// Records whether a Unix signal arrived or its registered stream closed unexpectedly.
fn log_shutdown_trigger(signal: &'static str, received: Option<()>) {
    if received.is_some() {
        tracing::info!(stage = "shutdown", signal, "graceful shutdown started");
    } else {
        tracing::error!(
            target: logging::PROCESS_ERROR_TARGET,
            stage = "shutdown",
            signal,
            "shutdown signal stream closed; graceful shutdown forced"
        );
    }
}

#[cfg(not(unix))]
/// Waits for the platform interrupt notification where Unix signal streams are unavailable.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!(
            stage = "shutdown",
            signal = "ctrl-c",
            "graceful shutdown started"
        ),
        Err(error) => tracing::error!(
            target: logging::PROCESS_ERROR_TARGET,
            stage = "shutdown",
            signal = "ctrl-c",
            error = %error,
            "shutdown signal listener failed; graceful shutdown forced"
        ),
    }
}

/// Converts monotonic startup durations into the bounded millisecond field used by diagnostics.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Reports failures through stderr while no durable service-log writer is available.
fn fatal_before_logging(error: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("fatal startup error: {error}");
    ExitCode::FAILURE
}
