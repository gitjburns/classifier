mod bidi_override;
mod encoded_blob;
mod high_nonascii;
mod mixed_script;
mod unicode_tags;
mod zero_width;

use crate::rules::{
    AnalyzerSettings, BIDI_OVERRIDE_ID, ENCODED_BLOB_ID, HIGH_NONASCII_ID, MIXED_SCRIPT_ID,
    UNICODE_TAGS_ID, ZERO_WIDTH_ID,
};
use crate::types::{Finding, Severity, Span};

/// Runs each enabled built-in detector in inventory order and attaches its configured metadata.
pub(crate) fn scan(content: &str, settings: &AnalyzerSettings) -> Vec<Finding> {
    let mut findings = Vec::new();

    if settings.unicode_tags.enabled {
        append_findings(
            &mut findings,
            UNICODE_TAGS_ID,
            settings.unicode_tags.severity,
            unicode_tags::scan(content),
        );
    }
    if settings.zero_width.enabled {
        append_findings(
            &mut findings,
            ZERO_WIDTH_ID,
            settings.zero_width.severity,
            zero_width::scan(content),
        );
    }
    if settings.bidi_override.enabled {
        append_findings(
            &mut findings,
            BIDI_OVERRIDE_ID,
            settings.bidi_override.severity,
            bidi_override::scan(content),
        );
    }
    if settings.mixed_script.enabled {
        append_findings(
            &mut findings,
            MIXED_SCRIPT_ID,
            settings.mixed_script.severity,
            mixed_script::scan(content),
        );
    }
    if settings.encoded_blob.enabled {
        append_findings(
            &mut findings,
            ENCODED_BLOB_ID,
            settings.encoded_blob.severity,
            encoded_blob::scan(
                content,
                settings.encoded_blob.min_run_length,
                settings.encoded_blob.min_entropy,
            ),
        );
    }
    if settings.high_nonascii.enabled {
        append_findings(
            &mut findings,
            HIGH_NONASCII_ID,
            settings.high_nonascii.severity,
            high_nonascii::scan(
                content,
                settings.high_nonascii.max_ratio,
                settings.high_nonascii.min_total_chars,
            ),
        );
    }

    findings
}

/// Converts detector spans into the shared finding shape without duplicating rule metadata.
fn append_findings(
    findings: &mut Vec<Finding>,
    rule_id: &'static str,
    severity: Severity,
    spans: Vec<Span>,
) {
    findings.extend(spans.into_iter().map(|span| Finding {
        rule_id: rule_id.to_owned(),
        severity,
        span,
    }));
}
