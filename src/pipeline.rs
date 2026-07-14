//! Deterministic assessment, verdict selection, redaction, and one-round re-assessment.
//!
//! Worked verdict cases establish the intended control flow:
//! - Content with no critical or suspect finding is `safe`, even with advisory findings.
//! - A critical template-token finding is `unsafe` without a redaction attempt.
//! - A suspect instruction-override finding is replaced with `[REDACTED]`; a clean re-scan makes
//!   the original assessment `sanitized` while preserving the initial finding.
//! - If a rule also flags the redaction marker, the re-scan is not clean and the original
//!   assessment is `unsafe` rather than attempting a second redaction round.

use sha2::{Digest, Sha256};

use crate::analyzers;
use crate::normalize::normalize;
use crate::rules::CompiledRuleset;
use crate::types::{Finding, Severity, Span, Verdict};

const REDACTION_MARKER: &str = "[REDACTED]";
const MAX_REDACTION_ROUNDS: usize = 1;

/// Contains redacted content only after that exact text passes a complete re-assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedOutput {
    /// Replaces every merged suspect span with a visible fixed marker.
    pub content: String,
    /// Binds the cleared text to the bytes a caller may forward.
    pub sha256: String,
}

/// Carries the caller verdict, initial evidence, and the internal re-scan outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentOutcome {
    /// States whether original content, sanitized content, or neither may be forwarded.
    pub verdict: Verdict,
    /// Preserves findings from the submitted content rather than substituting re-scan findings.
    pub findings: Vec<Finding>,
    /// Exists only when the returned redacted content passed its full re-assessment.
    pub sanitized: Option<SanitizedOutput>,
    /// Is true only when a redaction attempt occurred and its complete re-scan was clean.
    pub rescan_clean: bool,
}

/// Assesses submitted content without clocks, I/O, or runtime dependencies.
pub fn assess(original: &str, ruleset: &CompiledRuleset) -> AssessmentOutcome {
    assess_at_depth(original, ruleset, 0)
}

/// Enforces the single permitted redaction round while reusing the complete assessment path.
fn assess_at_depth(
    original: &str,
    ruleset: &CompiledRuleset,
    redaction_rounds: usize,
) -> AssessmentOutcome {
    let findings = collect_findings(original, ruleset);

    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        return terminal_outcome(Verdict::Unsafe, findings);
    }

    if !findings
        .iter()
        .any(|finding| finding.severity == Severity::Suspect)
    {
        return terminal_outcome(Verdict::Safe, findings);
    }

    if redaction_rounds == MAX_REDACTION_ROUNDS {
        return terminal_outcome(Verdict::Unsafe, findings);
    }

    let merged_spans = merge_suspect_spans(&findings);
    let sanitized_content = redact(original, &merged_spans);
    let rescan = assess_at_depth(&sanitized_content, ruleset, redaction_rounds + 1);
    let rescan_clean = rescan.verdict == Verdict::Safe;

    if !rescan_clean {
        return AssessmentOutcome {
            verdict: Verdict::Unsafe,
            findings,
            sanitized: None,
            rescan_clean,
        };
    }

    let sha256 = sha256_hex(sanitized_content.as_bytes());
    AssessmentOutcome {
        verdict: Verdict::Sanitized,
        findings,
        sanitized: Some(SanitizedOutput {
            content: sanitized_content,
            sha256,
        }),
        rescan_clean,
    }
}

/// Runs original-text analyzers and normalized-text patterns into one ordered evidence list.
fn collect_findings(original: &str, ruleset: &CompiledRuleset) -> Vec<Finding> {
    let mut findings = analyzers::scan(original, &ruleset.analyzers);
    let normalized = normalize(original);

    for pattern in &ruleset.patterns {
        findings.extend(
            pattern
                .regex
                .find_iter(&normalized.text)
                .map(|matched| Finding {
                    rule_id: pattern.id.clone(),
                    severity: pattern.severity,
                    span: normalized.to_original_span(Span {
                        start: matched.start(),
                        end: matched.end(),
                    }),
                }),
        );
    }

    // Stable sorting preserves analyzer inventory and rules-file order for findings that begin at
    // the same byte while making span order independent of producer execution order.
    findings.sort_by_key(|finding| finding.span.start);
    findings
}

/// Constructs verdicts that did not complete a successful sanitization re-scan.
fn terminal_outcome(verdict: Verdict, findings: Vec<Finding>) -> AssessmentOutcome {
    AssessmentOutcome {
        verdict,
        findings,
        sanitized: None,
        rescan_clean: false,
    }
}

/// Coalesces touching or overlapping suspect evidence so each original byte is replaced once.
fn merge_suspect_spans(findings: &[Finding]) -> Vec<Span> {
    let mut suspect_spans: Vec<Span> = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Suspect)
        .map(|finding| finding.span)
        .collect();
    suspect_spans.sort_by_key(|span| span.start);

    let mut merged: Vec<Span> = Vec::with_capacity(suspect_spans.len());
    for span in suspect_spans {
        if let Some(previous) = merged.last_mut()
            && span.start <= previous.end
        {
            previous.end = previous.end.max(span.end);
            continue;
        }
        merged.push(span);
    }

    merged
}

/// Rebuilds original text around producer-guaranteed UTF-8 boundaries using visible markers.
fn redact(original: &str, spans: &[Span]) -> String {
    let mut redacted = String::with_capacity(original.len());
    let mut copied_until = 0;

    // Analyzer spans and normalized span translation both guarantee ordered UTF-8 boundaries.
    // The merge step guarantees these ranges do not overlap.
    for span in spans {
        redacted.push_str(&original[copied_until..span.start]);
        redacted.push_str(REDACTION_MARKER);
        copied_until = span.end;
    }
    redacted.push_str(&original[copied_until..]);

    redacted
}

/// Produces the lowercase content digest used to bind sanitized bytes to later callers.
fn sha256_hex(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}
