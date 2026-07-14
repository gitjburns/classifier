use crate::types::Span;

/// Returns maximal runs of directional formatting controls that can conceal display order.
///
/// Worked cases: ordinary Arabic and Hebrew text has no span; adjacent U+202E/U+202C
/// controls form one span; controls separated by visible text form distinct spans.
pub(super) fn scan(content: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run_start = None;

    for (byte_index, character) in content.char_indices() {
        if is_directional_control(character) {
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

/// Restricts detection to the two directional-formatting ranges approved for the MVP.
fn is_directional_control(character: char) -> bool {
    ('\u{202a}'..='\u{202e}').contains(&character) || ('\u{2066}'..='\u{2069}').contains(&character)
}
