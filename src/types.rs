use serde::{Deserialize, Serialize};

/// Classifies how strongly a finding affects the assessment verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Prevents sanitization because the matched signal has no expected legitimate use.
    Critical,
    /// Permits one redaction and re-assessment attempt.
    Suspect,
    /// Preserves context without changing the verdict by itself.
    Advisory,
}

/// Identifies an end-exclusive UTF-8 byte range in the original submitted content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct Span {
    /// Points to the first included byte on a UTF-8 character boundary.
    pub start: usize,
    /// Points immediately after the final included byte on a UTF-8 character boundary.
    pub end: usize,
}

/// Connects one named rule match to its severity and original-content location.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Finding {
    /// Names the analyzer or pattern that produced the finding.
    pub rule_id: String,
    /// Determines how the finding participates in verdict selection.
    pub severity: Severity,
    /// Locates the evidence without copying submitted content into diagnostics.
    pub span: Span,
}

/// States whether callers may forward original content, sanitized content, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Allows the original content because no critical or suspect signal matched.
    Safe,
    /// Prevents forwarding because the content could not be cleared.
    Unsafe,
    /// Allows only the separately returned redacted content.
    Sanitized,
}
