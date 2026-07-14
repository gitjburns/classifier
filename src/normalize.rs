//! NFKC normalization with an outward-rounding map back to submitted UTF-8 bytes.
//!
//! Worked mapping cases establish the intended boundary behavior:
//! - ASCII `abc` remains `abc`, so normalized `1..2` maps to original `1..2`.
//! - `e\u{301}` becomes `é`, so normalized `0..2` maps to original `0..3`.
//! - Bengali `\u{09c7}\u{09be}` becomes `\u{09cb}`, mapping `0..3` to `0..6`.
//! - Hangul Jamo `\u{1100}\u{1161}\u{11a8}` becomes `각`, mapping `0..3` to `0..9`.
//! - Full-width `Ａ` and mathematical `𝔸` become `A`, mapping `0..1` to `0..3`
//!   and `0..4`, respectively.
//! - Emoji ZWJ sequences are unchanged and retain their original byte boundaries.
//! - Empty input produces empty text and an empty segment map.

use unicode_normalization::{UnicodeNormalization, char::canonical_combining_class};

use crate::types::Span;

/// Owns normalized text and the closed segments needed to recover original byte spans.
pub struct Normalized {
    /// Contains the NFKC form consumed by pattern rules.
    pub text: String,
    segments: Vec<Segment>,
    original_len: usize,
}

/// Connects one normalization-closed range in each representation.
struct Segment {
    norm_start: usize,
    norm_end: usize,
    orig_start: usize,
    orig_end: usize,
}

impl Normalized {
    /// Rounds a normalized byte span outward to complete source segments.
    /// Returned offsets therefore always lie on original UTF-8 character boundaries.
    ///
    /// # Panics
    /// Panics when the span is reversed or exceeds the normalized text. Pipeline callers obtain
    /// spans from regex matches over `text`, so either condition is an internal contract defect.
    pub fn to_original_span(&self, span: Span) -> Span {
        assert!(
            span.start <= span.end && span.end <= self.text.len(),
            "normalized span must be ordered and bounded by normalized text"
        );
        if span.start == span.end {
            let boundary = self.original_boundary(span.start);
            return Span {
                start: boundary,
                end: boundary,
            };
        }

        let start_index = self
            .segments
            .partition_point(|segment| segment.norm_end <= span.start);
        let end_index = self
            .segments
            .partition_point(|segment| segment.norm_start < span.end)
            - 1;

        Span {
            start: self.segments[start_index].orig_start,
            end: self.segments[end_index].orig_end,
        }
    }

    /// Maps an empty normalized span to the nearest source boundary on its left.
    fn original_boundary(&self, normalized_offset: usize) -> usize {
        if normalized_offset == self.text.len() {
            return self.original_len;
        }

        let index = self
            .segments
            .partition_point(|segment| segment.norm_end <= normalized_offset);
        self.segments
            .get(index)
            .map_or(self.original_len, |segment| segment.orig_start)
    }
}

/// Normalizes content while retaining segments that tile both byte representations.
pub fn normalize(original: &str) -> Normalized {
    let mut text = String::new();
    let mut segments = Vec::new();
    let mut segment_start = 0;

    for (offset, character) in original.char_indices().skip(1) {
        if canonical_combining_class(character) == 0
            && boundary_is_closed(&original[segment_start..offset], character)
        {
            append_segment(original, segment_start, offset, &mut text, &mut segments);
            segment_start = offset;
        }
    }

    if segment_start < original.len() {
        append_segment(
            original,
            segment_start,
            original.len(),
            &mut text,
            &mut segments,
        );
    }

    Normalized {
        text,
        segments,
        original_len: original.len(),
    }
}

/// Accepts a boundary only when later normalization cannot compose across it.
fn boundary_is_closed(left_original: &str, right_character: char) -> bool {
    let left: String = left_original.nfkc().collect();
    let right: String = std::iter::once(right_character).nfkc().collect();

    // A normalized non-starter still belongs to the preceding composition sequence. Once the
    // right side starts with a starter and their concatenation is already NFKC, that starter
    // blocks later input from changing the normalized left side.
    if right
        .chars()
        .next()
        .is_none_or(|character| canonical_combining_class(character) != 0)
    {
        return false;
    }

    let mut joined = left;
    joined.push_str(&right);
    joined.chars().nfkc().eq(joined.chars())
}

/// Appends one closed segment so its ranges extend both representations without gaps.
fn append_segment(
    original: &str,
    orig_start: usize,
    orig_end: usize,
    text: &mut String,
    segments: &mut Vec<Segment>,
) {
    let norm_start = text.len();
    text.extend(original[orig_start..orig_end].nfkc());
    segments.push(Segment {
        norm_start,
        norm_end: text.len(),
        orig_start,
        orig_end,
    });
}
