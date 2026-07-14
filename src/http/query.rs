use std::fmt;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::AppState;
use super::error::{ApiError, INTERNAL_ERROR, QueryErrorBody};
use crate::config::QueryConfig;
use crate::store::{AssessmentPage, AssessmentRecord, AssessmentSummary, Cursor, ListFilter};
use crate::types::{Finding, Verdict};

const MILLISECONDS_PER_HOUR: u128 = 60 * 60 * 1_000;
const FILTER_VERDICT: &str = "verdict";
const FILTER_CONTENT_SHA256: &str = "content_sha256";
const FILTER_SINCE_HOURS: &str = "since_hours";
const FILTER_LIMIT: &str = "limit";
const FILTER_CURSOR: &str = "cursor";
const VALID_FILTERS: &[&str] = &[
    FILTER_VERDICT,
    FILTER_CONTENT_SHA256,
    FILTER_SINCE_HOURS,
    FILTER_LIMIT,
    FILTER_CURSOR,
];
const VALID_VERDICT_VALUES: &[&str] = &["safe", "unsafe", "sanitized", "all"];
const VERDICT_CONSTRAINTS: &[&str] = &["values must be unique", "all must appear alone"];

/// Retains accepted values plus exact structural violations for one corrective response.
#[derive(Debug, Default)]
pub(crate) struct ListQueryParameters {
    verdict: Option<String>,
    content_sha256: Option<String>,
    since_hours: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
    unknown_filters: Vec<String>,
    duplicate_filters: Vec<String>,
}

impl<'de> Deserialize<'de> for ListQueryParameters {
    /// Preserves every decoded key before field validation so structural errors remain actionable.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ListQueryVisitor)
    }
}

/// Owns the one-pass map traversal that detects duplicate and unsupported filter names.
struct ListQueryVisitor;

impl<'de> Visitor<'de> for ListQueryVisitor {
    type Value = ListQueryParameters;

    /// Describes the query-map shape expected from Axum's URL-decoding extractor.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("assessment list query parameters")
    }

    /// Retains the first value for each known filter while collecting every structural violation.
    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut parameters = ListQueryParameters::default();
        let mut seen_filters = Vec::new();

        while let Some(name) = map.next_key::<String>()? {
            let value = map.next_value::<String>()?;
            if seen_filters.iter().any(|seen| seen == &name) {
                push_unique(&mut parameters.duplicate_filters, name.clone());
            } else {
                seen_filters.push(name.clone());
            }

            match name.as_str() {
                FILTER_VERDICT => retain_first(&mut parameters.verdict, value),
                FILTER_CONTENT_SHA256 => retain_first(&mut parameters.content_sha256, value),
                FILTER_SINCE_HOURS => retain_first(&mut parameters.since_hours, value),
                FILTER_LIMIT => retain_first(&mut parameters.limit, value),
                FILTER_CURSOR => retain_first(&mut parameters.cursor, value),
                _ => push_unique(&mut parameters.unknown_filters, name),
            }
        }

        Ok(parameters)
    }
}

/// Keeps the first known-filter value because duplicates are rejected before value validation.
fn retain_first(slot: &mut Option<String>, value: String) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

/// Appends caller-supplied names or values once while preserving their request order.
fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Separates caller-correctable responses from failures that only diagnostics can explain.
enum FilterValidationError {
    Caller {
        body: Box<QueryErrorBody>,
        parameter: &'static str,
    },
    Internal {
        parameter: &'static str,
        source: String,
    },
}

impl FilterValidationError {
    /// Couples a typed corrective body with the safe parameter name used in diagnostics.
    fn caller(body: QueryErrorBody, parameter: &'static str) -> Self {
        // Validation failures are exceptional; boxing keeps every Result's success path compact
        // while preserving the complete typed response until the handler serializes it.
        Self::Caller {
            body: Box::new(body),
            parameter,
        }
    }

    /// Preserves local source context for an internal validation-boundary failure.
    fn internal(parameter: &'static str, source: impl ToString) -> Self {
        Self::Internal {
            parameter,
            source: source.to_string(),
        }
    }
}

/// Serializes one bounded metadata-only page of historical assessments.
#[derive(Serialize)]
pub(crate) struct AssessmentListResponse {
    assessments: Vec<AssessmentSummaryResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

/// Preserves list-row metadata and findings without exposing either stored content column.
#[derive(Serialize)]
struct AssessmentSummaryResponse {
    request_id: String,
    created_at: String,
    verdict: Verdict,
    content_sha256: String,
    sanitized_sha256: Option<String>,
    ruleset_version: String,
    elapsed_ms: u64,
    findings: Vec<Finding>,
}

/// Adds the deliberately retrieved content columns to one assessment's metadata.
#[derive(Serialize)]
pub(crate) struct AssessmentDetailResponse {
    request_id: String,
    created_at: String,
    verdict: Verdict,
    content_sha256: String,
    content: String,
    sanitized_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_content: Option<String>,
    ruleset_version: String,
    elapsed_ms: u64,
    findings: Vec<Finding>,
}

/// Validates filters, executes one bounded read, and returns metadata without stored content.
pub(crate) async fn list_assessments(
    State(state): State<Arc<AppState>>,
    query: Result<Query<ListQueryParameters>, QueryRejection>,
) -> Result<Json<AssessmentListResponse>, ApiError> {
    let operation_id = Uuid::new_v4().to_string();
    let operation_started = Instant::now();
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_list",
        stage = "query_start",
        "assessment list query started"
    );

    let Query(parameters) = match query {
        Ok(parameters) => parameters,
        Err(rejection) => {
            let body = QueryErrorBody::InvalidFilter {
                message: "query parameters must use valid URL encoding",
                duplicate_filters: Vec::new(),
                valid_filters: VALID_FILTERS,
            };
            tracing::warn!(
                operation_id = %operation_id,
                operation = "assessment_list",
                stage = "query_validation",
                reason = body.reason(),
                rejection_status = rejection.status().as_u16(),
                elapsed_ms = duration_ms(operation_started),
                "assessment list terminal error ready"
            );
            return Err(corrective_query_error(
                StatusCode::BAD_REQUEST,
                body,
                &operation_id,
            ));
        }
    };

    if let Some(body) = structural_filter_error(&parameters) {
        tracing::warn!(
            operation_id = %operation_id,
            operation = "assessment_list",
            stage = "query_validation",
            reason = body.reason(),
            unknown_filter_count = parameters.unknown_filters.len(),
            duplicate_filter_count = parameters.duplicate_filters.len(),
            elapsed_ms = duration_ms(operation_started),
            "assessment list terminal error ready"
        );
        return Err(corrective_query_error(
            StatusCode::BAD_REQUEST,
            body,
            &operation_id,
        ));
    }

    let filter = validate_list_filter(&parameters, &state.config.query)
        .map_err(|error| invalid_filter_error(&operation_id, operation_started, error))?;
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_list",
        stage = "query_validation",
        verdict_filter_count = filter.verdicts.len(),
        content_hash_filter_present = filter.content_sha256.is_some(),
        since_hours_filter_present = filter.created_since_ms.is_some(),
        cursor_present = filter.cursor.is_some(),
        limit = filter.limit,
        elapsed_ms = duration_ms(operation_started),
        "assessment list query accepted"
    );

    let store_started = Instant::now();
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_list",
        stage = "query_store_read",
        "assessment list store read started"
    );
    let query_state = Arc::clone(&state);
    let page = match tokio::task::spawn_blocking(move || {
        query_state.store.list_assessments(&filter)
    })
    .await
    {
        Ok(Ok(page)) => page,
        Ok(Err(error)) => {
            tracing::error!(
                operation_id = %operation_id,
                operation = "assessment_list",
                stage = "query_store_read",
                reason = INTERNAL_ERROR,
                elapsed_ms = duration_ms(store_started),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment list terminal error ready"
            );
            return Err(internal_query_error(&operation_id));
        }
        Err(error) => {
            tracing::error!(
                operation_id = %operation_id,
                operation = "assessment_list",
                stage = "query_store_read",
                reason = INTERNAL_ERROR,
                task_cancelled = error.is_cancelled(),
                task_panicked = error.is_panic(),
                elapsed_ms = duration_ms(store_started),
                operation_elapsed_ms = duration_ms(operation_started),
                "assessment list terminal error ready"
            );
            return Err(internal_query_error(&operation_id));
        }
    };
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_list",
        stage = "query_store_read",
        row_count = page.assessments.len(),
        capped = page.next_cursor.is_some(),
        elapsed_ms = duration_ms(store_started),
        "assessment list store read completed"
    );

    let response = list_response(page).map_err(|error| {
        tracing::error!(
            operation_id = %operation_id,
            operation = "assessment_list",
            stage = "query_response_shape",
            reason = INTERNAL_ERROR,
            elapsed_ms = duration_ms(operation_started),
            error = %error,
            "assessment list terminal error ready"
        );
        internal_query_error(&operation_id)
    })?;
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_list",
        stage = "query_response_handoff",
        status = StatusCode::OK.as_u16(),
        row_count = response.assessments.len(),
        capped = response.next_cursor.is_some(),
        socket_delivery = "unknown_after_transport_handoff",
        elapsed_ms = duration_ms(operation_started),
        "assessment list result ready and handed to the HTTP transport"
    );

    Ok(Json(response))
}

/// Retrieves one full audit record only after the path is proven to be a valid UUID.
pub(crate) async fn get_assessment(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> Result<Json<AssessmentDetailResponse>, ApiError> {
    let operation_id = Uuid::new_v4().to_string();
    let operation_started = Instant::now();
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_detail",
        stage = "query_start",
        "assessment detail query started"
    );

    let request_id = match Uuid::parse_str(&request_id) {
        Ok(request_id) => request_id.to_string(),
        Err(_) => {
            let body = QueryErrorBody::InvalidRequestId {
                message: "request_id must be a UUID",
                parameter: "request_id",
                required_format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            };
            tracing::warn!(
                operation_id = %operation_id,
                operation = "assessment_detail",
                stage = "query_validation",
                reason = body.reason(),
                elapsed_ms = duration_ms(operation_started),
                "assessment detail terminal error ready"
            );
            return Err(corrective_query_error(
                StatusCode::BAD_REQUEST,
                body,
                &operation_id,
            ));
        }
    };
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_detail",
        stage = "query_validation",
        request_id = %request_id,
        elapsed_ms = duration_ms(operation_started),
        "assessment detail query accepted"
    );

    let store_started = Instant::now();
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_detail",
        stage = "query_store_read",
        request_id = %request_id,
        "assessment detail store read started"
    );
    let query_state = Arc::clone(&state);
    let store_request_id = request_id.clone();
    let record = match tokio::task::spawn_blocking(move || {
        query_state.store.get_assessment(&store_request_id)
    })
    .await
    {
        Ok(Ok(Some(record))) => record,
        Ok(Ok(None)) => {
            let body = QueryErrorBody::AssessmentNotFound {
                message: "no stored assessment exists for the supplied request_id",
                parameter: "request_id",
            };
            tracing::warn!(
                operation_id = %operation_id,
                operation = "assessment_detail",
                stage = "query_store_read",
                request_id = %request_id,
                reason = body.reason(),
                elapsed_ms = duration_ms(store_started),
                operation_elapsed_ms = duration_ms(operation_started),
                "assessment detail terminal error ready"
            );
            return Err(corrective_query_error(
                StatusCode::NOT_FOUND,
                body,
                &operation_id,
            ));
        }
        Ok(Err(error)) => {
            tracing::error!(
                operation_id = %operation_id,
                operation = "assessment_detail",
                stage = "query_store_read",
                request_id = %request_id,
                reason = INTERNAL_ERROR,
                elapsed_ms = duration_ms(store_started),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment detail terminal error ready"
            );
            return Err(internal_query_error(&operation_id));
        }
        Err(error) => {
            tracing::error!(
                operation_id = %operation_id,
                operation = "assessment_detail",
                stage = "query_store_read",
                request_id = %request_id,
                reason = INTERNAL_ERROR,
                task_cancelled = error.is_cancelled(),
                task_panicked = error.is_panic(),
                elapsed_ms = duration_ms(store_started),
                operation_elapsed_ms = duration_ms(operation_started),
                "assessment detail terminal error ready"
            );
            return Err(internal_query_error(&operation_id));
        }
    };
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_detail",
        stage = "query_store_read",
        request_id = %request_id,
        elapsed_ms = duration_ms(store_started),
        "assessment detail store read completed"
    );

    let response = detail_response(record).map_err(|error| {
        tracing::error!(
            operation_id = %operation_id,
            operation = "assessment_detail",
            stage = "query_response_shape",
            request_id = %request_id,
            reason = INTERNAL_ERROR,
            elapsed_ms = duration_ms(operation_started),
            error = %error,
            "assessment detail terminal error ready"
        );
        internal_query_error(&operation_id)
    })?;
    tracing::info!(
        operation_id = %operation_id,
        operation = "assessment_detail",
        stage = "query_response_handoff",
        request_id = %response.request_id,
        status = StatusCode::OK.as_u16(),
        socket_delivery = "unknown_after_transport_handoff",
        elapsed_ms = duration_ms(operation_started),
        "assessment detail result ready and handed to the HTTP transport"
    );

    Ok(Json(response))
}

/// Builds one structural correction containing every unknown or repeated filter name.
fn structural_filter_error(parameters: &ListQueryParameters) -> Option<QueryErrorBody> {
    if !parameters.unknown_filters.is_empty() {
        return Some(QueryErrorBody::UnknownFilter {
            message: "query contains filters that this endpoint does not support",
            unknown_filters: parameters.unknown_filters.clone(),
            duplicate_filters: parameters.duplicate_filters.clone(),
            valid_filters: VALID_FILTERS,
        });
    }
    if !parameters.duplicate_filters.is_empty() {
        return Some(QueryErrorBody::InvalidFilter {
            message: "each query filter may appear at most once",
            duplicate_filters: parameters.duplicate_filters.clone(),
            valid_filters: VALID_FILTERS,
        });
    }
    None
}

/// Converts caller strings into the store's already-validated bounded filter shape.
fn validate_list_filter(
    parameters: &ListQueryParameters,
    config: &QueryConfig,
) -> Result<ListFilter, FilterValidationError> {
    let verdicts = parse_verdict_filter(parameters.verdict.as_deref())?;
    let content_sha256 = parse_content_hash_filter(parameters.content_sha256.as_deref())?;
    let since_hours = parse_since_hours(parameters.since_hours.as_deref())?;
    let limit = parse_limit(parameters.limit.as_deref(), config)?;
    let cursor = parse_cursor(parameters.cursor.as_deref())?;

    // Stored timestamps are nonnegative, so a lookback reaching before the Unix epoch means the
    // filter includes every possible record rather than overflowing or rejecting a valid integer.
    let created_since_ms = if let Some(hours) = since_hours {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| FilterValidationError::internal("system_clock", error))?;
        let now_ms = elapsed.as_millis();
        let lookback_ms = hours.saturating_mul(MILLISECONDS_PER_HOUR);
        let boundary_ms = now_ms.saturating_sub(lookback_ms);
        Some(
            i64::try_from(boundary_ms)
                .map_err(|error| FilterValidationError::internal("system_clock", error))?,
        )
    } else {
        None
    };

    Ok(ListFilter {
        verdicts,
        content_sha256,
        created_since_ms,
        cursor,
        limit,
    })
}

/// Accepts `all` or a unique comma-separated subset of the protocol's three verdicts.
fn parse_verdict_filter(value: Option<&str>) -> Result<Vec<Verdict>, FilterValidationError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let mut verdicts = Vec::new();
    let mut seen_values = Vec::new();
    let mut invalid_values = Vec::new();
    let mut duplicate_values = Vec::new();
    let mut contains_all = false;
    for token in value.split(',') {
        if seen_values.iter().any(|seen| seen == token) {
            push_unique(&mut duplicate_values, token.to_owned());
        } else {
            seen_values.push(token.to_owned());
        }
        match token {
            "safe" => verdicts.push(Verdict::Safe),
            "unsafe" => verdicts.push(Verdict::Unsafe),
            "sanitized" => verdicts.push(Verdict::Sanitized),
            "all" => contains_all = true,
            _ => push_unique(&mut invalid_values, token.to_owned()),
        }
    }

    let all_combined = contains_all && seen_values.len() > 1;
    if !invalid_values.is_empty() || !duplicate_values.is_empty() || all_combined {
        return Err(FilterValidationError::caller(
            QueryErrorBody::InvalidVerdictFilter {
                message: "verdict must be all or a unique comma-separated subset of the valid values",
                parameter: FILTER_VERDICT,
                invalid_values,
                duplicate_values,
                valid_values: VALID_VERDICT_VALUES,
                constraints: VERDICT_CONSTRAINTS,
            },
            FILTER_VERDICT,
        ));
    }
    if contains_all {
        verdicts.clear();
    }
    Ok(verdicts)
}

/// Requires an exact lowercase SHA-256 representation when the hash filter is present.
fn parse_content_hash_filter(value: Option<&str>) -> Result<Option<String>, FilterValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(FilterValidationError::caller(
            QueryErrorBody::InvalidContentHashFilter {
                message: "content_sha256 must contain exactly 64 lowercase hexadecimal characters",
                parameter: FILTER_CONTENT_SHA256,
                required_format: "64 lowercase hexadecimal characters",
            },
            FILTER_CONTENT_SHA256,
        ));
    }
    Ok(Some(value.to_owned()))
}

/// Parses the optional positive lookback without imposing an undocumented upper bound.
fn parse_since_hours(value: Option<&str>) -> Result<Option<u128>, FilterValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let positive_integer = !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte != b'0');
    if !positive_integer {
        return Err(FilterValidationError::caller(
            QueryErrorBody::InvalidSinceHours {
                message: "since_hours must be a positive integer",
                parameter: FILTER_SINCE_HOURS,
                required_type: "integer",
                minimum: 1,
            },
            FILTER_SINCE_HOURS,
        ));
    }

    // Values beyond u128 already reach before the Unix epoch, so saturating preserves their exact
    // filter meaning without imposing an artificial caller-visible maximum.
    Ok(Some(value.parse::<u128>().unwrap_or(u128::MAX)))
}

/// Uses the validated startup default or enforces the caller's configured page-size cap.
fn parse_limit(value: Option<&str>, config: &QueryConfig) -> Result<usize, FilterValidationError> {
    let Some(value) = value else {
        return Ok(config.default_limit);
    };
    match value.parse::<usize>() {
        Ok(limit) if limit > 0 && limit <= config.max_limit => Ok(limit),
        _ => Err(FilterValidationError::caller(
            QueryErrorBody::InvalidLimit {
                message: "limit must be an integer within the returned inclusive bounds",
                parameter: FILTER_LIMIT,
                required_type: "integer",
                minimum: 1,
                maximum: config.max_limit,
            },
            FILTER_LIMIT,
        )),
    }
}

/// Decodes only the exact opaque keyset representation owned by the store module.
fn parse_cursor(value: Option<&str>) -> Result<Option<Cursor>, FilterValidationError> {
    value.map(Cursor::decode).transpose().map_err(|_| {
        FilterValidationError::caller(
            QueryErrorBody::InvalidCursor {
                message: "cursor must be an unmodified next_cursor from a previous response",
                parameter: FILTER_CURSOR,
                correction: "use the complete next_cursor value returned by the preceding page",
            },
            FILTER_CURSOR,
        )
    })
}

/// Logs a field-attributable validation failure and produces its stable caller response.
fn invalid_filter_error(
    operation_id: &str,
    operation_started: Instant,
    error: FilterValidationError,
) -> ApiError {
    match error {
        FilterValidationError::Caller { body, parameter } => {
            tracing::warn!(
                operation_id,
                operation = "assessment_list",
                stage = "query_validation",
                parameter,
                reason = body.reason(),
                elapsed_ms = duration_ms(operation_started),
                "assessment list terminal error ready"
            );
            corrective_query_error(StatusCode::BAD_REQUEST, *body, operation_id)
        }
        FilterValidationError::Internal { parameter, source } => {
            tracing::error!(
                operation_id,
                operation = "assessment_list",
                stage = "query_validation",
                parameter,
                reason = INTERNAL_ERROR,
                error = %source,
                elapsed_ms = duration_ms(operation_started),
                "assessment list terminal error ready"
            );
            internal_query_error(operation_id)
        }
    }
}

/// Attaches lifecycle identity to a corrective body without exposing that identity to callers.
fn corrective_query_error(
    status: StatusCode,
    body: QueryErrorBody,
    operation_id: &str,
) -> ApiError {
    ApiError::query(status, body).with_operation_id(operation_id.to_owned())
}

/// Keeps non-correctable service failures on the compact generic error contract.
fn internal_query_error(operation_id: &str) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR, None)
        .with_operation_id(operation_id.to_owned())
}

/// Converts a store page into the protocol shape while preserving its sentinel-derived cursor.
fn list_response(page: AssessmentPage) -> Result<AssessmentListResponse, String> {
    let assessments = page
        .assessments
        .into_iter()
        .map(summary_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AssessmentListResponse {
        assessments,
        next_cursor: page.next_cursor,
    })
}

/// Converts one content-free store row without narrowing findings or optional hash metadata.
fn summary_response(summary: AssessmentSummary) -> Result<AssessmentSummaryResponse, String> {
    Ok(AssessmentSummaryResponse {
        request_id: summary.request_id,
        created_at: format_created_at(summary.created_at_ms)?,
        verdict: summary.verdict,
        content_sha256: summary.content_sha256,
        sanitized_sha256: summary.sanitized_sha256,
        ruleset_version: summary.ruleset_version,
        elapsed_ms: summary.elapsed_ms,
        findings: summary.findings,
    })
}

/// Converts the deliberate full-content store result into the detail response contract.
fn detail_response(record: AssessmentRecord) -> Result<AssessmentDetailResponse, String> {
    Ok(AssessmentDetailResponse {
        request_id: record.request_id,
        created_at: format_created_at(record.created_at_ms)?,
        verdict: record.verdict,
        content_sha256: record.content_sha256,
        content: record.content,
        sanitized_sha256: record.sanitized_sha256,
        sanitized_content: record.sanitized_content,
        ruleset_version: record.ruleset_version,
        elapsed_ms: record.elapsed_ms,
        findings: record.findings,
    })
}

/// Renders the stored millisecond timestamp as the protocol's RFC 3339 UTC string.
fn format_created_at(created_at_ms: i64) -> Result<String, String> {
    let timestamp_ns = i128::from(created_at_ms) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(timestamp_ns)
        .map_err(|error| format!("stored created_at_ms is outside the supported range: {error}"))?
        .format(&Rfc3339)
        .map_err(|error| format!("failed to format stored created_at_ms as RFC 3339: {error}"))
}

/// Converts monotonic query durations into the bounded millisecond diagnostic field.
fn duration_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
