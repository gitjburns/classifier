use icu_properties::{CodePointSetData, CodePointSetDataBorrowed, props::ExtendedPictographic};
use unicode_script::{Script, UnicodeScript};

use crate::types::Span;

/// Finds suspicious zero-width controls while preserving the two narrow MVP exclusions.
///
/// Worked cases: an interior U+200B is reported; a leading U+FEFF is ignored while an
/// interior one is reported; `👩‍💻` keeps its ZWJ; Persian letters on both sides keep their
/// ZWNJ. Indic virama/ZWNJ shaping is deliberately deferred and remains reportable.
pub(super) fn scan(content: &str) -> Vec<Span> {
    // A one-character lookaround is sufficient for both exclusions and avoids retaining the
    // complete character stream solely to inspect immediate neighbors.
    let mut characters = content.char_indices().peekable();
    let extended_pictographic = CodePointSetData::new::<ExtendedPictographic>();
    let mut spans: Vec<Span> = Vec::new();
    let mut previous = None;

    while let Some((start, character)) = characters.next() {
        let next = characters.peek().map(|(_, character)| *character);

        let flagged = match character {
            '\u{200b}' | '\u{2060}' => true,
            '\u{200c}' => !is_arabic_word_joiner(previous, next),
            '\u{200d}' => !is_emoji_joiner(previous, next, &extended_pictographic),
            '\u{feff}' => start != 0,
            _ => false,
        };

        if flagged {
            let end = start + character.len_utf8();
            append_or_merge(&mut spans, Span { start, end });
        }

        previous = Some(character);
    }

    spans
}

/// Exempts only a ZWJ directly connecting two Extended_Pictographic characters.
fn is_emoji_joiner(
    previous: Option<char>,
    next: Option<char>,
    extended_pictographic: &CodePointSetDataBorrowed<'_>,
) -> bool {
    match (previous, next) {
        (Some(previous), Some(next)) => {
            extended_pictographic.contains(previous) && extended_pictographic.contains(next)
        }
        _ => false,
    }
}

/// Exempts the finite MVP case of a ZWNJ joining two Arabic-script alphabetic characters.
fn is_arabic_word_joiner(previous: Option<char>, next: Option<char>) -> bool {
    match (previous, next) {
        (Some(previous), Some(next)) => {
            previous.is_alphabetic()
                && next.is_alphabetic()
                && previous.script() == Script::Arabic
                && next.script() == Script::Arabic
        }
        _ => false,
    }
}

/// Coalesces directly adjacent flagged controls without spanning an excluded character.
fn append_or_merge(spans: &mut Vec<Span>, span: Span) {
    if let Some(previous) = spans.last_mut()
        && previous.end == span.start
    {
        previous.end = span.end;
        return;
    }

    spans.push(span);
}
