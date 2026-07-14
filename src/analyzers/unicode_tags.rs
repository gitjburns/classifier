use crate::types::Span;

/// Returns maximal runs of tag-block characters whose payload is invisible in ordinary text.
///
/// Worked cases: `plain` has no span; `a\u{e0001}\u{e007f}b` reports the two tag
/// characters as one original-byte span; two runs separated by `a` remain distinct.
pub(super) fn scan(content: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run_start = None;

    for (byte_index, character) in content.char_indices() {
        if ('\u{e0000}'..='\u{e007f}').contains(&character) {
            run_start.get_or_insert(byte_index);
        } else if let Some(start) = run_start.take() {
            spans.push(Span {
                start,
                end: byte_index,
            });
        }
    }

    if let Some(start) = run_start {
        spans.push(Span {
            start,
            end: content.len(),
        });
    }

    spans
}
