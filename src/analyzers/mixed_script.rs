use unicode_script::{Script, UnicodeScript};

use crate::types::Span;

/// Finds alphabetic words containing disallowed combinations of Unicode scripts.
///
/// Worked cases: a Latin word and a Cyrillic word are individually clear; a single word
/// mixing Latin and Cyrillic is reported; Japanese Han/Hiragana/Katakana, Korean Han/Hangul,
/// and Chinese Han/Bopomofo combinations remain clear.
pub(super) fn scan(content: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut word_start = None;
    let mut scripts = Vec::new();

    for (byte_index, character) in content.char_indices() {
        if character.is_alphabetic() {
            word_start.get_or_insert(byte_index);
            let script = character.script();
            if script != Script::Common && script != Script::Inherited && !scripts.contains(&script)
            {
                scripts.push(script);
            }
        } else if let Some(start) = word_start.take() {
            append_if_disallowed(&mut spans, start, byte_index, &scripts);
            scripts.clear();
        }
    }

    if let Some(start) = word_start {
        append_if_disallowed(&mut spans, start, content.len(), &scripts);
    }

    spans
}

/// Emits the whole word only when its significant script set is not an approved combination.
fn append_if_disallowed(spans: &mut Vec<Span>, start: usize, end: usize, scripts: &[Script]) {
    if scripts.len() > 1 && !is_allowed_combination(scripts) {
        spans.push(Span { start, end });
    }
}

/// Applies the three finite East Asian script combinations approved for the MVP.
fn is_allowed_combination(scripts: &[Script]) -> bool {
    is_subset_of(scripts, &[Script::Han, Script::Hiragana, Script::Katakana])
        || is_subset_of(scripts, &[Script::Han, Script::Hangul])
        || is_subset_of(scripts, &[Script::Han, Script::Bopomofo])
}

/// Checks set inclusion over the small de-duplicated script vectors without allocation.
fn is_subset_of(scripts: &[Script], allowed: &[Script]) -> bool {
    scripts.iter().all(|script| allowed.contains(script))
}
