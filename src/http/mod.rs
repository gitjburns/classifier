mod assess;
mod auth;
mod error;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};

use crate::config::Config;
use crate::rules::CompiledRuleset;
use crate::store::Store;

/// Owns the immutable startup products and sole audit store shared by HTTP handlers.
pub(crate) struct AppState {
    /// Retains validated operational limits and the listener configuration.
    pub(crate) config: Config,
    /// Carries the overflow-checked cap enforced before JSON deserialization.
    pub(crate) request_body_limit: usize,
    /// Retains the credential loaded after durable logging initialized.
    pub(crate) token: String,
    /// Retains the atomic rule inventory used for every assessment.
    pub(crate) ruleset: CompiledRuleset,
    /// Retains the sole writer and bounded read-only database role configuration.
    pub(crate) store: Store,
}

/// Builds the public health route and applies authentication only to protected API routes.
pub(crate) fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route(
            "/v1/assess",
            post(assess::assess).layer(DefaultBodyLimit::max(state.request_body_limit)),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_bearer,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state)
}

/// Reports readiness because the router is served only after every startup boundary succeeds.
async fn healthz() -> StatusCode {
    StatusCode::OK
}
