mod analyzers;
mod config;
mod logging;
mod normalize;
mod pipeline;
mod rules;
mod store;
mod types;

use std::process::ExitCode;
use std::time::Instant;

/// Runs the ordered startup boundaries and keeps the partially built service non-serving.
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
        query_max_findings_per_assessment = config.query.max_findings_per_assessment,
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
            let token_elapsed_ms = elapsed_ms(token_load_started);
            tracing::error!(
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
    // Reuse the proven transport bound as the maximum SQLite cell size: it covers original and
    // expanded sanitized content while preventing unbounded reads from externally altered files.
    let max_cell_bytes = match config.limits.request_body_limit() {
        Ok(limit) => limit,
        Err(error) => {
            tracing::error!(
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
    let _store = match store::Store::open(
        &config.database.path,
        config.query.timeout_ms,
        config.query.max_limit,
        config.query.max_findings_per_assessment,
        max_cell_bytes,
    ) {
        Ok(store) => store,
        Err(error) => {
            let store_elapsed_ms = elapsed_ms(store_open_started);
            tracing::error!(
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
    tracing::info!("phase 6 startup initialization complete; service is not yet serving");

    ExitCode::SUCCESS
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
