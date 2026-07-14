use crate::types::Span;

/// Finds long encoded-alphabet runs whose Shannon entropy meets the configured threshold.
///
/// Worked cases: runs shorter than `min_run_length` and long repeated-character runs are
/// clear; a sufficiently varied 64-character base64 or hexadecimal run is reported; a
/// separator produces distinct candidates. Hex is a subset of the base64 alphabet, so one
/// maximal-run scan covers both without emitting duplicate findings.
pub(super) fn scan(content: &str, min_run_length: usize, min_entropy: f64) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run_start = None;

    for (byte_index, byte) in content.bytes().enumerate() {
        if is_encoded_alphabet(byte) {
            run_start.get_or_insert(byte_index);
        } else if let Some(start) = run_start.take() {
            append_if_opaque(
                &mut spans,
                content,
                start,
                byte_index,
                min_run_length,
                min_entropy,
            );
        }
    }

    if let Some(start) = run_start {
        append_if_opaque(
            &mut spans,
            content,
            start,
            content.len(),
            min_run_length,
            min_entropy,
        );
    }

    spans
}

/// Defines the finite ASCII alphabet whose maximal runs are entropy candidates.
fn is_encoded_alphabet(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// Applies both configured bounds before exposing an encoded candidate as a finding span.
fn append_if_opaque(
    spans: &mut Vec<Span>,
    content: &str,
    start: usize,
    end: usize,
    min_run_length: usize,
    min_entropy: f64,
) {
    if end - start >= min_run_length
        && shannon_entropy(&content.as_bytes()[start..end]) >= min_entropy
    {
        spans.push(Span { start, end });
    }
}

/// Computes bits per byte for an ASCII candidate without retaining its content.
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }

    let length = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|&count| count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}
