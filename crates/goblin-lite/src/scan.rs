use std::ops::Range;

use crate::pattern::{save_len, Atom};

pub type Offset = u64;
const MAX_BACKTRACK_STATES: usize = 1_000_000;
const PREFIX_BUF_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSpan {
    pub mapped: Range<Offset>,
    pub file: Range<usize>,
}

/// Read-only view over a mapped binary image for scanner execution.
pub trait BinaryView {
    fn image(&self) -> &[u8];
    fn code_spans(&self) -> &[CodeSpan];
    fn mapped_to_file_offset(&self, offset: Offset) -> Option<usize>;

    #[inline]
    fn read_u8(&self, offset: Offset) -> Option<u8> {
        self.image()
            .get(self.mapped_to_file_offset(offset)?)
            .copied()
    }

    #[inline]
    fn read_i16(&self, offset: Offset) -> Option<i16> {
        Some(i16::from_le_bytes(self.read_array::<2>(offset)?))
    }

    #[inline]
    fn read_u16(&self, offset: Offset) -> Option<u16> {
        Some(u16::from_le_bytes(self.read_array::<2>(offset)?))
    }

    #[inline]
    fn read_i32(&self, offset: Offset) -> Option<i32> {
        Some(i32::from_le_bytes(self.read_array::<4>(offset)?))
    }

    #[inline]
    fn read_u32(&self, offset: Offset) -> Option<u32> {
        Some(u32::from_le_bytes(self.read_array::<4>(offset)?))
    }

    #[inline]
    fn read_array<const N: usize>(&self, offset: Offset) -> Option<[u8; N]> {
        let file_offset = self.mapped_to_file_offset(offset)?;
        let end = file_offset.checked_add(N)?;
        let bytes = self.image().get(file_offset..end)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Some(out)
    }
}

#[derive(Copy, Clone, Debug)]
/// Pattern scanner over a [`BinaryView`].
pub struct Scanner<'a, B: BinaryView> {
    view: &'a B,
}

impl<'a, B: BinaryView> Scanner<'a, B> {
    /// Creates a scanner for a binary view.
    pub fn new(view: &'a B) -> Self {
        Self { view }
    }

    /// Returns `true` only when the pattern has exactly one code match.
    pub fn finds_code(&self, pat: &[Atom], save: &mut [Offset]) -> bool {
        debug_assert!(
            save.len() >= save_len(pat),
            "caller-provided save buffer must cover all slots referenced by the pattern"
        );
        let mut matches = self.matches_code(pat);
        if !matches.next(save) {
            return false;
        }

        let mut scratch = save.to_vec();
        !matches.next(&mut scratch)
    }

    /// Returns an iterator-like matcher for all code-range matches.
    pub fn matches_code<'p>(&self, pat: &'p [Atom]) -> Matches<'a, 'p, B> {
        let (prefix, prefix_len) = build_prefix(pat);
        Matches {
            scanner: Scanner { view: self.view },
            pat,
            range_index: 0,
            cursor: None,
            prefix,
            prefix_len,
        }
    }

    fn exec(&self, start: Offset, pat: &[Atom], save: &mut [Offset]) -> bool {
        #[derive(Clone)]
        struct State {
            cursor: Offset,
            pc: usize,
            save: Vec<Offset>,
            calls: Vec<Offset>,
            fuzzy: Option<u8>,
        }

        let mut stack = vec![State {
            cursor: start,
            pc: 0,
            save: save.to_vec(),
            calls: Vec::new(),
            fuzzy: None,
        }];

        while let Some(mut state) = stack.pop() {
            loop {
                let Some(atom) = pat.get(state.pc) else {
                    for (dst, src) in save.iter_mut().zip(state.save.iter()) {
                        *dst = *src;
                    }
                    return true;
                };

                match *atom {
                    Atom::Byte(expected) => {
                        let Some(actual) = self.view.read_u8(state.cursor) else {
                            break;
                        };
                        let mask = state.fuzzy.take().unwrap_or(u8::MAX);
                        if (actual & mask) != (expected & mask) {
                            break;
                        }
                        let Some(next) = state.cursor.checked_add(1) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::Fuzzy(mask) => {
                        state.fuzzy = Some(mask);
                        state.pc += 1;
                    }
                    Atom::Save(slot) => {
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = state.cursor;
                        }
                        state.pc += 1;
                    }
                    Atom::Skip(n) => {
                        let Some(next) = state.cursor.checked_add(u64::from(n)) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::SkipRange(min, max) => {
                        debug_assert!(
                            min <= max,
                            "pattern parser enforces inclusive skip ranges with min <= max"
                        );
                        let min = u64::from(min);
                        let max = u64::from(max);
                        for delta in ((min + 1)..=max).rev() {
                            if let Some(next_cursor) = state.cursor.checked_add(delta) {
                                let mut alt = state.clone();
                                alt.cursor = next_cursor;
                                alt.pc += 1;
                                if stack.len() >= MAX_BACKTRACK_STATES {
                                    debug_assert!(
                                        false,
                                        "scanner backtracking stack must stay below MAX_BACKTRACK_STATES for bounded memory"
                                    );
                                    return false;
                                }
                                stack.push(alt);
                            }
                        }
                        let Some(next) = state.cursor.checked_add(min) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::Push(skip) => {
                        let Some(resume_cursor) = state.cursor.checked_add(u64::from(skip)) else {
                            break;
                        };
                        state.calls.push(resume_cursor);
                        state.pc += 1;
                    }
                    Atom::Pop => {
                        let Some(resume_cursor) = state.calls.pop() else {
                            break;
                        };
                        state.cursor = resume_cursor;
                        state.pc += 1;
                    }
                    Atom::Jump1 => {
                        let Some(byte) = self.view.read_u8(state.cursor) else {
                            break;
                        };
                        let disp = byte as i8;
                        let Some(base) = state.cursor.checked_add(1) else {
                            break;
                        };
                        let delta = i64::from(disp);
                        if delta >= 0 {
                            let Some(next) = base.checked_add(delta as u64) else {
                                break;
                            };
                            state.cursor = next;
                        } else {
                            let Some(next) = base.checked_sub((-delta) as u64) else {
                                break;
                            };
                            state.cursor = next;
                        }
                        state.pc += 1;
                    }
                    Atom::Jump4 => {
                        let Some(disp) = self.view.read_i32(state.cursor) else {
                            break;
                        };
                        let Some(base) = state.cursor.checked_add(4) else {
                            break;
                        };
                        let delta = i64::from(disp);
                        if delta >= 0 {
                            let Some(next) = base.checked_add(delta as u64) else {
                                break;
                            };
                            state.cursor = next;
                        } else {
                            let Some(next) = base.checked_sub((-delta) as u64) else {
                                break;
                            };
                            state.cursor = next;
                        }
                        state.pc += 1;
                    }
                    Atom::ReadI8(slot) => {
                        let Some(value) = self.view.read_u8(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = (value as i8) as i64 as u64;
                        }
                        let Some(next) = state.cursor.checked_add(1) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::ReadU8(slot) => {
                        let Some(value) = self.view.read_u8(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = u64::from(value);
                        }
                        let Some(next) = state.cursor.checked_add(1) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::ReadI16(slot) => {
                        let Some(value) = self.view.read_i16(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = value as i64 as u64;
                        }
                        let Some(next) = state.cursor.checked_add(2) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::ReadU16(slot) => {
                        let Some(value) = self.view.read_u16(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = u64::from(value);
                        }
                        let Some(next) = state.cursor.checked_add(2) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::ReadI32(slot) => {
                        let Some(value) = self.view.read_i32(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = value as i64 as u64;
                        }
                        let Some(next) = state.cursor.checked_add(4) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::ReadU32(slot) => {
                        let Some(value) = self.view.read_u32(state.cursor) else {
                            break;
                        };
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = u64::from(value);
                        }
                        let Some(next) = state.cursor.checked_add(4) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::Zero(slot) => {
                        if let Some(dst) = state.save.get_mut(usize::from(slot)) {
                            *dst = 0;
                        }
                        state.pc += 1;
                    }
                    Atom::Back(n) => {
                        let Some(next) = state.cursor.checked_sub(u64::from(n)) else {
                            break;
                        };
                        state.cursor = next;
                        state.pc += 1;
                    }
                    Atom::Aligned(align) => {
                        let mask = (1u64 << u64::from(align)).wrapping_sub(1);
                        if state.cursor & mask != 0 {
                            break;
                        }
                        state.pc += 1;
                    }
                    Atom::Check(slot) => {
                        let expected = state.save.get(usize::from(slot)).copied().unwrap_or(0);
                        if state.cursor != expected {
                            break;
                        }
                        state.pc += 1;
                    }
                    Atom::Case(skip) => {
                        let mut alt = state.clone();
                        let Some(next_pc) = alt.pc.checked_add(usize::from(skip)) else {
                            break;
                        };
                        alt.pc = next_pc;
                        if stack.len() >= MAX_BACKTRACK_STATES {
                            debug_assert!(
                                false,
                                "scanner backtracking stack must stay below MAX_BACKTRACK_STATES for bounded memory"
                            );
                            return false;
                        }
                        stack.push(alt);
                        state.pc += 1;
                    }
                    Atom::Break(skip) => {
                        let Some(next_pc) = state
                            .pc
                            .checked_add(usize::from(skip))
                            .and_then(|value| value.checked_add(1))
                        else {
                            break;
                        };
                        state.pc = next_pc;
                    }
                    Atom::Nop => {
                        state.pc += 1;
                    }
                }
            }
        }

        false
    }
}

#[derive(Clone, Debug)]
/// Stateful matcher produced by [`Scanner::matches_code`].
pub struct Matches<'a, 'p, B: BinaryView> {
    scanner: Scanner<'a, B>,
    pat: &'p [Atom],
    range_index: usize,
    cursor: Option<Offset>,
    prefix: [u8; PREFIX_BUF_LEN],
    prefix_len: usize,
}

impl<'a, 'p, B: BinaryView> Matches<'a, 'p, B> {
    /// Advances to the next match and writes save-slot values into `save`.
    pub fn next(&mut self, save: &mut [Offset]) -> bool {
        while let Some(span) = self.scanner.view.code_spans().get(self.range_index) {
            let start = self.cursor.unwrap_or(span.mapped.start);
            if start >= span.mapped.end {
                self.range_index += 1;
                self.cursor = None;
                continue;
            }
            let matched_at = if self.prefix_len == 0 {
                self.scan_range_linear(span.mapped.clone(), start, save)
            } else if self.prefix_len < 4 {
                self.scan_span_first_byte(span, start, save)
            } else {
                self.scan_span_quick(span, start, save)
            };

            if let Some(cursor) = matched_at {
                self.cursor = cursor.checked_add(1);
                return true;
            }

            self.range_index += 1;
            self.cursor = None;
        }

        false
    }

    fn scan_range_linear(
        &self,
        range: Range<Offset>,
        mut cursor: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        while cursor < range.end {
            if self.scanner.exec(cursor, self.pat, save) {
                return Some(cursor);
            }
            let next = cursor.checked_add(1)?;
            cursor = next;
        }
        None
    }

    fn scan_span_first_byte(
        &self,
        span: &CodeSpan,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let Some(bytes) = self.scanner.view.image().get(span.file.clone()) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };
        let Some(start_file) = mapped_to_file_offset(span, start) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };

        debug_assert_eq!(
            span.mapped.end.checked_sub(span.mapped.start),
            u64::try_from(span.file.end.saturating_sub(span.file.start)).ok(),
            "code span mapped/file ranges must have identical lengths"
        );

        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };
        let needle = self.prefix[0];
        for (delta, byte) in haystack.iter().copied().enumerate() {
            if byte != needle {
                continue;
            }
            let Some(mapped_delta) = Offset::try_from(start_index.checked_add(delta)?).ok() else {
                return None;
            };
            let Some(cursor) = span.mapped.start.checked_add(mapped_delta) else {
                return None;
            };
            if self.scanner.exec(cursor, self.pat, save) {
                return Some(cursor);
            }
        }
        None
    }

    fn scan_range_first_byte(
        &self,
        range: Range<Offset>,
        mut cursor: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let needle = self.prefix[0];
        while cursor < range.end {
            if self.scanner.view.read_u8(cursor) == Some(needle)
                && self.scanner.exec(cursor, self.pat, save)
            {
                return Some(cursor);
            }
            let next = cursor.checked_add(1)?;
            cursor = next;
        }
        None
    }

    fn scan_range_quick(
        &self,
        range: Range<Offset>,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let prefix = &self.prefix[..self.prefix_len];
        let window = u64::try_from(self.prefix_len).ok()?;
        if start >= range.end {
            return None;
        }
        let total = range.end.checked_sub(start)?;
        if total < window {
            return None;
        }

        let mut jumps = [self.prefix_len as u8; 256];
        for (index, byte) in prefix
            .iter()
            .take(self.prefix_len.saturating_sub(1))
            .enumerate()
        {
            jumps[usize::from(*byte)] = (self.prefix_len - index - 1) as u8;
        }

        let last = prefix[self.prefix_len - 1];
        let mut index = 0u64;
        let max_index = total - window;
        while index <= max_index {
            let cursor = start.checked_add(index)?;
            let probe_at = cursor.checked_add(window - 1)?;
            let Some(probe) = self.scanner.view.read_u8(probe_at) else {
                index = index.checked_add(1)?;
                continue;
            };

            let jump = u64::from(jumps[usize::from(probe)].max(1));
            if probe == last
                && self.prefix_matches_mapped(cursor)
                && self.scanner.exec(cursor, self.pat, save)
            {
                return Some(cursor);
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn scan_span_quick(
        &self,
        span: &CodeSpan,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let Some(bytes) = self.scanner.view.image().get(span.file.clone()) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        let Some(start_file) = mapped_to_file_offset(span, start) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };

        let prefix = &self.prefix[..self.prefix_len];
        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        if haystack.len() < self.prefix_len {
            return None;
        }

        let mut jumps = [self.prefix_len as u8; 256];
        for (index, byte) in prefix
            .iter()
            .take(self.prefix_len.saturating_sub(1))
            .enumerate()
        {
            jumps[usize::from(*byte)] = (self.prefix_len - index - 1) as u8;
        }

        let last = prefix[self.prefix_len - 1];
        let mut index = 0usize;
        let max_index = haystack.len() - self.prefix_len;
        while index <= max_index {
            let probe = haystack[index + self.prefix_len - 1];

            let jump = usize::from(jumps[usize::from(probe)].max(1));
            if probe == last
                && haystack
                    .get(index..index + self.prefix_len)
                    .is_some_and(|window| window == prefix)
            {
                let Some(total_index) = start_index.checked_add(index) else {
                    return None;
                };
                let Some(mapped_delta) = Offset::try_from(total_index).ok() else {
                    return None;
                };
                let Some(cursor) = span.mapped.start.checked_add(mapped_delta) else {
                    return None;
                };
                if self.scanner.exec(cursor, self.pat, save) {
                    return Some(cursor);
                }
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn prefix_matches_mapped(&self, cursor: Offset) -> bool {
        for (index, expected) in self.prefix[..self.prefix_len].iter().enumerate() {
            let delta = index as u64;
            let Some(offset) = cursor.checked_add(delta) else {
                return false;
            };
            if self.scanner.view.read_u8(offset) != Some(*expected) {
                return false;
            }
        }
        true
    }
}

fn build_prefix(pat: &[Atom]) -> ([u8; PREFIX_BUF_LEN], usize) {
    let mut prefix = [0u8; PREFIX_BUF_LEN];
    let mut len = 0usize;
    for atom in pat {
        match *atom {
            Atom::Byte(byte) => {
                if len >= PREFIX_BUF_LEN {
                    break;
                }
                prefix[len] = byte;
                len += 1;
            }
            Atom::Save(_) | Atom::Aligned(_) | Atom::Nop => {}
            _ => break,
        }
    }
    (prefix, len)
}

fn mapped_to_file_offset(span: &CodeSpan, mapped: Offset) -> Option<usize> {
    let delta = mapped.checked_sub(span.mapped.start)?;
    if mapped >= span.mapped.end {
        return None;
    }
    let delta_usize = usize::try_from(delta).ok()?;
    span.file.start.checked_add(delta_usize)
}

#[cfg(test)]
mod tests {
    use super::{build_prefix, BinaryView, CodeSpan, Offset, Scanner};
    use crate::pattern::Atom;

    #[derive(Debug)]
    struct TestView {
        bytes: Vec<u8>,
        spans: Vec<CodeSpan>,
    }

    impl TestView {
        fn new(bytes: &[u8]) -> Self {
            let end = bytes.len() as Offset;
            Self {
                bytes: bytes.to_vec(),
                spans: vec![CodeSpan {
                    mapped: 0..end,
                    file: 0..bytes.len(),
                }],
            }
        }
    }

    impl BinaryView for TestView {
        fn image(&self) -> &[u8] {
            &self.bytes
        }

        fn code_spans(&self) -> &[CodeSpan] {
            &self.spans
        }

        fn mapped_to_file_offset(&self, offset: Offset) -> Option<usize> {
            usize::try_from(offset)
                .ok()
                .filter(|index| *index < self.bytes.len())
        }
    }

    #[test]
    fn skip_range_tries_shorter_distances_first() {
        let view = TestView::new(&[0x00, 0x41, 0x41]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::SkipRange(0, 2),
            Atom::Save(1),
            Atom::Byte(0x41),
        ];
        let mut matches = scanner.matches_code(&pat);
        let mut save = [0u64; 2];

        assert!(matches.next(&mut save));
        assert_eq!(save[1], 1);
    }

    #[test]
    fn skip_range_backtracks_to_later_distances() {
        let view = TestView::new(&[0x00, 0x00, 0x41]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::SkipRange(0, 2),
            Atom::Save(1),
            Atom::Byte(0x41),
        ];
        let mut matches = scanner.matches_code(&pat);
        let mut save = [0u64; 2];

        assert!(matches.next(&mut save));
        assert_eq!(save[1], 2);
    }

    #[test]
    fn fuzzy_masks_only_the_next_byte_match() {
        let view = TestView::new(&[0xab, 0x0f]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Fuzzy(0xf0),
            Atom::Byte(0xa0),
            Atom::Byte(0x0f),
        ];
        let mut save = [0u64; 1];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[0], 0);
    }

    #[test]
    fn nop_does_not_change_matching_behavior() {
        let view = TestView::new(&[0x41]);
        let scanner = Scanner::new(&view);
        let pat = [Atom::Save(0), Atom::Nop, Atom::Byte(0x41)];
        let mut save = [0u64; 1];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[0], 0);
    }

    #[test]
    fn finds_code_uses_consistent_save_semantics_for_uniqueness() {
        let view = TestView::new(&[0x00, 0xaa, 0xaa]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Byte(0xaa),
            Atom::Save(1),
            Atom::Check(1),
        ];
        let mut save = [0u64; 2];

        assert!(!scanner.finds_code(&pat, &mut save));
    }

    #[test]
    fn quick_prefix_strategy_finds_match_near_range_end() {
        let view = TestView::new(&[0x00, 0x11, 0x22, 0x33, 0x44]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Byte(0x11),
            Atom::Byte(0x22),
            Atom::Byte(0x33),
            Atom::Byte(0x44),
        ];
        let mut save = [0u64; 1];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[0], 1);
    }

    #[test]
    fn prefix_builder_keeps_optimizable_leading_atoms() {
        let (prefix, len) = build_prefix(&[
            Atom::Save(0),
            Atom::Aligned(0),
            Atom::Nop,
            Atom::Byte(0xaa),
            Atom::Save(1),
            Atom::Byte(0xbb),
            Atom::Check(1),
            Atom::Byte(0xcc),
        ]);

        assert_eq!(len, 2);
        assert_eq!(&prefix[..len], &[0xaa, 0xbb]);
    }
}
