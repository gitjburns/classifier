mod config;
mod logging;

use std::process::ExitCode;
use std::time::Instant;

/// Runs the ordered startup boundaries and keeps Phase 1 intentionally non-serving.
fn main() -> ExitCode {
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
        query_timeout_ms = config.query.timeout_ms,
        log_path = %config.logging.path.display(),
        "configuration loaded and service logging initialized"
    );

    // The token stays in memory only; diagnostics expose its path, never its value. Duration
    // conversion saturates so even an extreme uptime cannot make error reporting fail.
    let token_load_started = Instant::now();
    tracing::info!(
        stage = "token_load",
        token_file = %config.auth.token_file.display(),
        "authentication token load started"
    );
    let _token = match config::load_token(&config.auth.token_file) {
        Ok(token) => token,
        Err(error) => {
            let elapsed_ms =
                u64::try_from(token_load_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            tracing::error!(
                stage = "token_load",
                elapsed_ms,
                error = %error,
                "fatal startup error"
            );
            return ExitCode::FAILURE;
        }
    };
    let elapsed_ms = u64::try_from(token_load_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(
        stage = "token_load",
        token_file = %config.auth.token_file.display(),
        elapsed_ms,
        "authentication token loaded"
    );
    tracing::info!("phase 1 startup initialization complete; service is not yet serving");

    ExitCode::SUCCESS
}

/// Reports failures through stderr while no durable service-log writer is available.
fn fatal_before_logging(error: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("fatal startup error: {error}");
    ExitCode::FAILURE
}
