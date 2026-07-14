use crate::types::Span;

/// Emits one whole-document span when non-ASCII density exceeds both configured bounds.
///
/// Worked cases: short multilingual text remains clear regardless of ratio; a document exactly
/// at `max_ratio` remains clear because the threshold is exclusive; a longer document above the
/// ratio reports `0..content.len()` so the finding retains original UTF-8 byte semantics.
pub(super) fn scan(content: &str, max_ratio: f64, min_total_chars: usize) -> Vec<Span> {
    let mut total_chars = 0usize;
    let mut nonascii_chars = 0usize;

    for character in content.chars() {
        total_chars += 1;
        if !character.is_ascii() {
            nonascii_chars += 1;
        }
    }

    if total_chars == 0 || total_chars < min_total_chars {
        return Vec::new();
    }

    let ratio = nonascii_chars as f64 / total_chars as f64;
    if ratio > max_ratio {
        vec![Span {
            start: 0,
            end: content.len(),
        }]
    } else {
        Vec::new()
    }
}
