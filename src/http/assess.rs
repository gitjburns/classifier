use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::AppState;
use super::error::{
    AUDIT_PERSISTENCE_FAILED, AUDIT_STATUS_UNKNOWN, ApiError, CONTENT_HASH_MISMATCH,
    CONTENT_TOO_LARGE, EMPTY_CONTENT, INTERNAL_ERROR, INVALID_BODY,
};
use crate::store::AssessmentRecord;
use crate::types::{Finding, Severity, Verdict};
use crate::{logging, pipeline};

/// Defines the complete strict caller input for one assessment operation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessRequest {
    content: String,
    content_sha256: String,
}

/// Serializes one completed and durably recorded assessment for its caller.
#[derive(Serialize)]
pub(crate) struct AssessResponse {
    request_id: String,
    verdict: Verdict,
    content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_sha256: Option<String>,
    findings: Vec<Finding>,
    ruleset_version: String,
}

/// Holds the compact severity summary written to diagnostics after the pure pipeline returns.
struct FindingCounts {
    critical: usize,
    suspect: usize,
    advisory: usize,
}

/// Validates, assesses, records, and returns one authenticated content submission.
pub(crate) async fn assess(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<AssessResponse>, ApiError> {
    let request_id = Uuid::new_v4().to_string();
    let operation_started = Instant::now();
    tracing::info!(
        request_id = %request_id,
        stage = "assessment_start",
        "assessment operation started"
    );

    let created_at_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => match i64::try_from(duration.as_millis()) {
            Ok(created_at_ms) => created_at_ms,
            Err(error) => {
                tracing::error!(
                    request_id = %request_id,
                    stage = "assessment_timestamp",
                    reason = INTERNAL_ERROR,
                    elapsed_ms = duration_ms(operation_started),
                    error = %error,
                    "assessment terminal error ready"
                );
                return Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    INTERNAL_ERROR,
                    Some(request_id),
                ));
            }
        },
        Err(error) => {
            tracing::error!(
                request_id = %request_id,
                stage = "assessment_timestamp",
                reason = INTERNAL_ERROR,
                elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
                Some(request_id),
            ));
        }
    };

    // Extraction is invoked after operation identity is assigned so every body rejection can be
    // correlated, while the route-level DefaultBodyLimit still enforces the configured cap.
    let Json(payload) = match Json::<AssessRequest>::from_request(request, &state).await {
        Ok(payload) => payload,
        Err(rejection) => {
            let reason = rejection_reason(&rejection);
            tracing::warn!(
                request_id = %request_id,
                stage = "assessment_validation",
                reason,
                rejection_kind = rejection_kind(&rejection),
                rejection_status = rejection.status().as_u16(),
                elapsed_ms = duration_ms(operation_started),
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                reason,
                Some(request_id),
            ));
        }
    };

    if payload.content.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            stage = "assessment_validation",
            reason = EMPTY_CONTENT,
            elapsed_ms = duration_ms(operation_started),
            "assessment terminal error ready"
        );
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            EMPTY_CONTENT,
            Some(request_id),
        ));
    }
    if payload.content.len() > state.config.limits.max_content_bytes {
        tracing::warn!(
            request_id = %request_id,
            stage = "assessment_validation",
            reason = CONTENT_TOO_LARGE,
            content_bytes = payload.content.len(),
            max_content_bytes = state.config.limits.max_content_bytes,
            elapsed_ms = duration_ms(operation_started),
            "assessment terminal error ready"
        );
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            CONTENT_TOO_LARGE,
            Some(request_id),
        ));
    }

    let content_sha256 = sha256_hex(payload.content.as_bytes());
    if payload.content_sha256 != content_sha256 {
        tracing::warn!(
            request_id = %request_id,
            stage = "assessment_validation",
            reason = CONTENT_HASH_MISMATCH,
            content_bytes = payload.content.len(),
            elapsed_ms = duration_ms(operation_started),
            "assessment terminal error ready"
        );
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            CONTENT_HASH_MISMATCH,
            Some(request_id),
        ));
    }

    tracing::info!(
        request_id = %request_id,
        stage = "assessment_validation",
        content_bytes = payload.content.len(),
        content_sha256 = %content_sha256,
        elapsed_ms = duration_ms(operation_started),
        "assessment request accepted"
    );

    let pipeline_wait_started = Instant::now();
    tracing::info!(
        request_id = %request_id,
        stage = "assessment_pipeline_dispatch",
        ruleset_version = %state.ruleset.version,
        pipeline_parallelism = state.pipeline_parallelism,
        "assessment pipeline permit wait started"
    );
    let permit = match Arc::clone(&state.pipeline_permits).acquire_owned().await {
        Ok(permit) => permit,
        Err(error) => {
            tracing::error!(
                request_id = %request_id,
                stage = "assessment_pipeline_dispatch",
                reason = INTERNAL_ERROR,
                pipeline_parallelism = state.pipeline_parallelism,
                wait_elapsed_ms = duration_ms(pipeline_wait_started),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
                Some(request_id),
            ));
        }
    };
    let pipeline_wait_ms = duration_ms(pipeline_wait_started);
    tracing::info!(
        request_id = %request_id,
        stage = "assessment_pipeline_dispatch",
        pipeline_parallelism = state.pipeline_parallelism,
        wait_elapsed_ms = pipeline_wait_ms,
        "assessment pipeline permit acquired"
    );

    let pipeline_task_started = Instant::now();
    let pipeline_state = Arc::clone(&state);
    let pipeline_request_id = request_id.clone();
    let pipeline_task_request_id = request_id.clone();
    let content = payload.content;
    // The owned permit stays inside the non-cancellable closure so dropping the HTTP future cannot
    // advertise CPU capacity while classification is still running. Completion is logged inside
    // that closure so handler cancellation cannot erase the spawned task's terminal evidence.
    // Returning the owned content avoids cloning it before the later audit-persistence boundary.
    let (content, outcome, pipeline_execution_ms) = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let execution_started = Instant::now();
        let outcome = pipeline::assess(&content, &pipeline_state.ruleset);
        let execution_elapsed_ms = duration_ms(execution_started);
        tracing::info!(
            request_id = %pipeline_task_request_id,
            stage = "assessment_pipeline_dispatch",
            pipeline_parallelism = pipeline_state.pipeline_parallelism,
            wait_elapsed_ms = pipeline_wait_ms,
            task_elapsed_ms = duration_ms(pipeline_task_started),
            execution_elapsed_ms,
            "assessment pipeline task completed"
        );
        (content, outcome, execution_elapsed_ms)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                request_id = %pipeline_request_id,
                stage = "assessment_pipeline_dispatch",
                reason = INTERNAL_ERROR,
                pipeline_parallelism = state.pipeline_parallelism,
                wait_elapsed_ms = pipeline_wait_ms,
                task_elapsed_ms = duration_ms(pipeline_task_started),
                task_cancelled = error.is_cancelled(),
                task_panicked = error.is_panic(),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
                Some(pipeline_request_id),
            ));
        }
    };
    let finding_counts = finding_counts(&outcome.findings);
    let rule_ids = unique_rule_ids(&outcome.findings);
    tracing::info!(
        request_id = %request_id,
        stage = "assessment_pipeline",
        verdict = verdict_name(outcome.verdict),
        critical_findings = finding_counts.critical,
        suspect_findings = finding_counts.suspect,
        advisory_findings = finding_counts.advisory,
        rule_ids = ?rule_ids,
        redaction_span_count = outcome.redaction_span_count,
        rescan_clean = outcome.rescan_clean,
        elapsed_ms = pipeline_execution_ms,
        "assessment pipeline completed"
    );

    let (sanitized_content, sanitized_sha256) = match outcome.sanitized {
        Some(sanitized) => (Some(sanitized.content), Some(sanitized.sha256)),
        None => (None, None),
    };
    let record = AssessmentRecord {
        request_id,
        created_at_ms,
        verdict: outcome.verdict,
        content_sha256,
        content,
        sanitized_sha256,
        sanitized_content,
        ruleset_version: state.ruleset.version.clone(),
        elapsed_ms: duration_ms(operation_started),
        findings: outcome.findings,
    };

    let persistence_started = Instant::now();
    tracing::info!(
        request_id = %record.request_id,
        stage = "assessment_audit_persistence",
        "assessment audit persistence boundary started"
    );
    // Keep the operation identity outside the moved task so panic or cancellation responses still
    // satisfy the protocol requirement that every authenticated assessment error carries it.
    let persistence_request_id = record.request_id.clone();
    let persistence_state = Arc::clone(&state);
    let record = match tokio::task::spawn_blocking(move || {
        persistence_state
            .store
            .persist_assessment(&record)
            .map(|()| record)
    })
    .await
    {
        Ok(Ok(record)) => record,
        Ok(Err(error)) => {
            tracing::error!(
                request_id = %persistence_request_id,
                stage = "assessment_audit_persistence",
                reason = AUDIT_PERSISTENCE_FAILED,
                elapsed_ms = duration_ms(persistence_started),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                AUDIT_PERSISTENCE_FAILED,
                Some(persistence_request_id.clone()),
            ));
        }
        Err(error) => {
            tracing::error!(
                request_id = %persistence_request_id,
                stage = "assessment_audit_persistence",
                reason = AUDIT_STATUS_UNKNOWN,
                task_cancelled = error.is_cancelled(),
                task_panicked = error.is_panic(),
                elapsed_ms = duration_ms(persistence_started),
                operation_elapsed_ms = duration_ms(operation_started),
                error = %error,
                "assessment terminal error ready"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                AUDIT_STATUS_UNKNOWN,
                Some(persistence_request_id.clone()),
            ));
        }
    };
    tracing::info!(
        request_id = %record.request_id,
        stage = "assessment_audit_persistence",
        elapsed_ms = duration_ms(persistence_started),
        "assessment audit persistence confirmed"
    );

    let response = AssessResponse {
        request_id: record.request_id,
        verdict: record.verdict,
        content_sha256: record.content_sha256,
        sanitized_content: record.sanitized_content,
        sanitized_sha256: record.sanitized_sha256,
        findings: record.findings,
        ruleset_version: record.ruleset_version,
    };
    let operation_elapsed_ms = duration_ms(operation_started);
    let verdict = verdict_name(response.verdict);
    tracing::info!(
        request_id = %response.request_id,
        stage = "assessment_response_handoff",
        status = StatusCode::OK.as_u16(),
        verdict,
        socket_delivery = "unknown_after_transport_handoff",
        elapsed_ms = operation_elapsed_ms,
        "assessment result ready and handed to the HTTP transport"
    );
    // Console output is a concise terminal summary of the persisted backend outcome; the durable
    // handoff record above remains authoritative and explicitly leaves socket delivery unknown.
    let console_message = format!(
        "{} request_id={} status={} verdict={} findings={} elapsed_ms={}",
        verdict.to_ascii_uppercase(),
        response.request_id,
        StatusCode::OK.as_u16(),
        verdict,
        response.findings.len(),
        operation_elapsed_ms
    );
    match response.verdict {
        Verdict::Safe => logging::console_info(console_message),
        Verdict::Sanitized => logging::console_warn(console_message),
        Verdict::Unsafe => logging::console_error(console_message),
    }

    Ok(Json(response))
}

/// Maps Axum's bounded JSON rejection to the stable caller reason without exposing parser details.
fn rejection_reason(rejection: &JsonRejection) -> &'static str {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        CONTENT_TOO_LARGE
    } else {
        INVALID_BODY
    }
}

/// Retains the parser boundary category without logging attacker-controlled rejection text.
fn rejection_kind(rejection: &JsonRejection) -> &'static str {
    match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => "body_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "missing_json_content_type",
        _ => "invalid_json_or_request_shape",
    }
}

/// Produces the lowercase digest used for validation, audit storage, and the caller response.
fn sha256_hex(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

/// Counts findings by verdict severity without changing their authoritative ordered collection.
fn finding_counts(findings: &[Finding]) -> FindingCounts {
    let mut counts = FindingCounts {
        critical: 0,
        suspect: 0,
        advisory: 0,
    };
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::Suspect => counts.suspect += 1,
            Severity::Advisory => counts.advisory += 1,
        }
    }
    counts
}

/// Deduplicates rule identifiers in finding order so summary logs remain compact under repetition.
fn unique_rule_ids(findings: &[Finding]) -> Vec<&str> {
    let mut seen = HashSet::new();
    let mut rule_ids = Vec::new();
    for finding in findings {
        let rule_id = finding.rule_id.as_str();
        if seen.insert(rule_id) {
            rule_ids.push(rule_id);
        }
    }
    rule_ids
}

/// Converts the shared verdict enum to the stable lowercase diagnostic value.
fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Safe => "safe",
        Verdict::Unsafe => "unsafe",
        Verdict::Sanitized => "sanitized",
    }
}

/// Converts monotonic operation durations into the bounded millisecond diagnostic field.
fn duration_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
