use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::logging::console_warn;

use super::AppState;
use super::error::{ApiError, UNAUTHORIZED};

const BEARER_PREFIX: &[u8] = b"Bearer ";

/// Rejects unauthenticated traffic before an assessment operation can be accepted.
pub(crate) async fn require_bearer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let mut authorization_values = request.headers().get_all(AUTHORIZATION).iter();
    let authorization = authorization_values.next();
    let has_duplicate = authorization_values.next().is_some();
    let presented = authorization
        .filter(|_| !has_duplicate)
        .and_then(|value| value.as_bytes().strip_prefix(BEARER_PREFIX));

    let authenticated = presented
        .map(|token| tokens_equal(token, state.token.as_bytes()))
        .unwrap_or(false);
    if !authenticated {
        tracing::warn!(
            stage = "authentication",
            method = %request.method(),
            path = %request.uri().path(),
            "request authentication failed"
        );
        console_warn(format!(
            "method={} path={} status={} reason={UNAUTHORIZED}",
            request.method(),
            request.uri().path(),
            StatusCode::UNAUTHORIZED.as_u16()
        ));
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, UNAUTHORIZED, None));
    }

    Ok(next.run(request).await)
}

/// Compares against every configured-token byte and folds length into the final result.
fn tokens_equal(presented: &[u8], expected: &[u8]) -> bool {
    let mut difference = presented.len() ^ expected.len();
    for (index, expected_byte) in expected.iter().enumerate() {
        let presented_byte = presented.get(index).copied().unwrap_or_default();
        difference |= usize::from(presented_byte ^ expected_byte);
    }
    difference == 0
}
