use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::logging::{console_error, console_warn};

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
/// Identifies one or more filter names outside the query endpoint's declared surface.
pub(crate) const UNKNOWN_FILTER: &str = "unknown_filter";
/// Identifies malformed query encoding or one or more exactly reported duplicate filters.
pub(crate) const INVALID_FILTER: &str = "invalid_filter";
/// Identifies a verdict filter outside the protocol's unique closed subset.
pub(crate) const INVALID_VERDICT_FILTER: &str = "invalid_verdict_filter";
/// Identifies a content hash filter that is not exactly 64 lowercase hexadecimal characters.
pub(crate) const INVALID_CONTENT_HASH_FILTER: &str = "invalid_content_hash_filter";
/// Identifies a nonpositive or non-integer assessment age filter.
pub(crate) const INVALID_SINCE_HOURS: &str = "invalid_since_hours";
/// Identifies a page size outside the configured nonempty bound.
pub(crate) const INVALID_LIMIT: &str = "invalid_limit";
/// Identifies an opaque continuation token that cannot be decoded exactly.
pub(crate) const INVALID_CURSOR: &str = "invalid_cursor";
/// Identifies a detail path value that is not a UUID.
pub(crate) const INVALID_REQUEST_ID: &str = "invalid_request_id";
/// Identifies an assessment detail identifier that has no stored record.
pub(crate) const ASSESSMENT_NOT_FOUND: &str = "assessment_not_found";
/// Identifies a known audit-store failure that prevented a confirmed commit.
pub(crate) const AUDIT_PERSISTENCE_FAILED: &str = "audit_persistence_failed";
/// Identifies a task failure that leaves the audit commit outcome unknown.
pub(crate) const AUDIT_STATUS_UNKNOWN: &str = "audit_status_unknown";
/// Identifies an unexpected service failure without exposing implementation details.
pub(crate) const INTERNAL_ERROR: &str = "internal_error";

/// Preserves the original assessment-error shape without forcing query details into every error.
#[derive(Serialize)]
struct BasicErrorBody {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

/// Defines compile-time corrective fields for every caller-fixable query failure.
#[derive(Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub(crate) enum QueryErrorBody {
    /// Names every unsupported filter and repeats the complete accepted filter surface.
    UnknownFilter {
        message: &'static str,
        unknown_filters: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        duplicate_filters: Vec<String>,
        valid_filters: &'static [&'static str],
    },
    /// Explains query-level encoding failures or identifies filters supplied more than once.
    InvalidFilter {
        message: &'static str,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        duplicate_filters: Vec<String>,
        valid_filters: &'static [&'static str],
    },
    /// Describes invalid, repeated, or mutually exclusive verdict values in one response.
    InvalidVerdictFilter {
        message: &'static str,
        parameter: &'static str,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        invalid_values: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        duplicate_values: Vec<String>,
        valid_values: &'static [&'static str],
        constraints: &'static [&'static str],
    },
    /// States the exact lowercase SHA-256 representation required by the equality filter.
    InvalidContentHashFilter {
        message: &'static str,
        parameter: &'static str,
        required_format: &'static str,
    },
    /// States the positive-integer boundary required for the relative-time filter.
    InvalidSinceHours {
        message: &'static str,
        parameter: &'static str,
        required_type: &'static str,
        minimum: u64,
    },
    /// Publishes the live configured page-size bound needed to correct the request.
    InvalidLimit {
        message: &'static str,
        parameter: &'static str,
        required_type: &'static str,
        minimum: usize,
        maximum: usize,
    },
    /// Directs callers back to the opaque token issued by the preceding page.
    InvalidCursor {
        message: &'static str,
        parameter: &'static str,
        correction: &'static str,
    },
    /// Distinguishes malformed path syntax from a valid UUID with no stored record.
    InvalidRequestId {
        message: &'static str,
        parameter: &'static str,
        required_format: &'static str,
    },
    /// Confirms that the syntactically valid assessment identifier has no matching record.
    AssessmentNotFound {
        message: &'static str,
        parameter: &'static str,
    },
}

impl QueryErrorBody {
    /// Returns the stable discriminator used by both serialization and diagnostics.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::UnknownFilter { .. } => UNKNOWN_FILTER,
            Self::InvalidFilter { .. } => INVALID_FILTER,
            Self::InvalidVerdictFilter { .. } => INVALID_VERDICT_FILTER,
            Self::InvalidContentHashFilter { .. } => INVALID_CONTENT_HASH_FILTER,
            Self::InvalidSinceHours { .. } => INVALID_SINCE_HOURS,
            Self::InvalidLimit { .. } => INVALID_LIMIT,
            Self::InvalidCursor { .. } => INVALID_CURSOR,
            Self::InvalidRequestId { .. } => INVALID_REQUEST_ID,
            Self::AssessmentNotFound { .. } => ASSESSMENT_NOT_FOUND,
        }
    }
}

/// Selects either the unchanged assessment body or the expanded corrective query body.
#[derive(Serialize)]
#[serde(untagged)]
enum CallerErrorBody {
    Basic(BasicErrorBody),
    Query(QueryErrorBody),
}

/// Couples a generic caller reason with its HTTP status and optional operation identity.
pub(crate) struct ApiError {
    status: StatusCode,
    reason: &'static str,
    request_id: Option<String>,
    operation_id: Option<String>,
    query_body: Option<QueryErrorBody>,
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
            operation_id: None,
            query_body: None,
        }
    }

    /// Builds a corrective query response while retaining its reason for handoff diagnostics.
    pub(crate) fn query(status: StatusCode, body: QueryErrorBody) -> Self {
        Self {
            status,
            reason: body.reason(),
            request_id: None,
            operation_id: None,
            query_body: Some(body),
        }
    }

    /// Correlates non-assessment error handoff without changing the caller-facing body.
    pub(crate) fn with_operation_id(mut self, operation_id: String) -> Self {
        self.operation_id = Some(operation_id);
        self
    }
}

impl IntoResponse for ApiError {
    /// Converts the internal status selection into the stable JSON error shape.
    fn into_response(self) -> Response {
        tracing::info!(
            request_id = ?self.request_id.as_deref(),
            operation_id = ?self.operation_id.as_deref(),
            stage = "error_response_handoff",
            status = self.status.as_u16(),
            reason = self.reason,
            socket_delivery = "unknown_after_transport_handoff",
            "error response ready and handed to the HTTP transport"
        );
        // Only assessment errors carry request IDs; authentication reports at its boundary,
        // while query errors intentionally remain in the durable diagnostic stream alone.
        if let Some(request_id) = self.request_id.as_deref() {
            let summary = format!(
                "request_id={request_id} status={} reason={}",
                self.status.as_u16(),
                self.reason
            );
            if self.status.is_client_error() {
                console_warn(summary);
            } else if self.status.is_server_error() {
                console_error(summary);
            }
        }
        let body = match self.query_body {
            Some(body) => CallerErrorBody::Query(body),
            None => CallerErrorBody::Basic(BasicErrorBody {
                reason: self.reason,
                request_id: self.request_id,
            }),
        };
        (self.status, Json(body)).into_response()
    }
}
