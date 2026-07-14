use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Identifies a request whose bearer credential is missing or invalid.
pub(crate) const UNAUTHORIZED: &str = "unauthorized";
/// Identifies JSON that cannot be parsed into the strict assessment request shape.
pub(crate) const INVALID_BODY: &str = "invalid_body";
/// Identifies a request whose submitted content contains no bytes.
pub(crate) const EMPTY_CONTENT: &str = "empty_content";
/// Identifies a body or decoded content value above its configured limit.
pub(crate) const CONTENT_TOO_LARGE: &str = "content_too_large";
/// Identifies a caller digest that does not bind the received content bytes.
pub(crate) const CONTENT_HASH_MISMATCH: &str = "content_hash_mismatch";
/// Identifies a known audit-store failure that prevented a confirmed commit.
pub(crate) const AUDIT_PERSISTENCE_FAILED: &str = "audit_persistence_failed";
/// Identifies a task failure that leaves the audit commit outcome unknown.
pub(crate) const AUDIT_STATUS_UNKNOWN: &str = "audit_status_unknown";
/// Identifies an unexpected service failure without exposing implementation details.
pub(crate) const INTERNAL_ERROR: &str = "internal_error";

/// Serializes the stable caller error contract without optional fields set to null.
#[derive(Serialize)]
struct ErrorBody {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

/// Couples a generic caller reason with its HTTP status and optional operation identity.
pub(crate) struct ApiError {
    status: StatusCode,
    reason: &'static str,
    request_id: Option<String>,
}

impl ApiError {
    /// Builds one response while keeping concrete source errors exclusively in diagnostics.
    pub(crate) fn new(
        status: StatusCode,
        reason: &'static str,
        request_id: Option<String>,
    ) -> Self {
        Self {
            status,
            reason,
            request_id,
        }
    }
}

impl IntoResponse for ApiError {
    /// Converts the internal status selection into the stable JSON error shape.
    fn into_response(self) -> Response {
        tracing::info!(
            request_id = ?self.request_id.as_deref(),
            stage = "error_response_handoff",
            status = self.status.as_u16(),
            reason = self.reason,
            socket_delivery = "unknown_after_transport_handoff",
            "error response ready and handed to the HTTP transport"
        );
        (
            self.status,
            Json(ErrorBody {
                reason: self.reason,
                request_id: self.request_id,
            }),
        )
            .into_response()
    }
}
