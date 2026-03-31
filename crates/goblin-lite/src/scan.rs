use std::ops::Range;

use crate::pattern::{Atom, save_len};

pub type Offset = u64;
const MAX_BACKTRACK_STATES: usize = 1_000_000;

/// Read-only view over a mapped binary image for scanner execution.
pub trait BinaryView {
    fn code_ranges(&self) -> &[Range<Offset>];
    fn read_u8(&self, offset: Offset) -> Option<u8>;
    fn read_i16(&self, offset: Offset) -> Option<i16>;
    fn read_u16(&self, offset: Offset) -> Option<u16>;
    fn read_i32(&self, offset: Offset) -> Option<i32>;
    fn read_u32(&self, offset: Offset) -> Option<u32>;
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
        Matches {
            scanner: Scanner { view: self.view },
            pat,
            range_index: 0,
            cursor: None,
        }
    }

    fn exec(&self, start: Offset, pat: &[Atom], save: &mut [Offset]) -> bool {
        #[derive(Clone)]
        struct State {
            cursor: Offset,
            pc: usize,
            save: Vec<Offset>,
            calls: Vec<Offset>,
        }

        let mut stack = vec![State {
            cursor: start,
            pc: 0,
            save: save.to_vec(),
            calls: Vec::new(),
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
                        if actual != expected {
                            break;
                        }
                        let Some(next) = state.cursor.checked_add(1) else {
                            break;
                        };
                        state.cursor = next;
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
}

impl<'a, 'p, B: BinaryView> Matches<'a, 'p, B> {
    /// Advances to the next match and writes save-slot values into `save`.
    pub fn next(&mut self, save: &mut [Offset]) -> bool {
        while let Some(range) = self.scanner.view.code_ranges().get(self.range_index) {
            let mut cursor = self.cursor.unwrap_or(range.start);
            while cursor < range.end {
                if self.scanner.exec(cursor, self.pat, save) {
                    self.cursor = cursor.checked_add(1);
                    return true;
                }
                let Some(next) = cursor.checked_add(1) else {
                    break;
                };
                cursor = next;
            }

            self.range_index += 1;
            self.cursor = None;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::{BinaryView, Offset, Scanner};
    use crate::pattern::Atom;

    #[derive(Debug)]
    struct TestView {
        bytes: Vec<u8>,
        ranges: Vec<Range<Offset>>,
    }

    impl TestView {
        fn new(bytes: &[u8]) -> Self {
            let end = bytes.len() as Offset;
            Self {
                bytes: bytes.to_vec(),
                ranges: std::iter::once(0..end).collect(),
            }
        }
    }

    impl BinaryView for TestView {
        fn code_ranges(&self) -> &[Range<Offset>] {
            &self.ranges
        }

        fn read_u8(&self, offset: Offset) -> Option<u8> {
            usize::try_from(offset)
                .ok()
                .and_then(|index| self.bytes.get(index).copied())
        }

        fn read_i16(&self, _offset: Offset) -> Option<i16> {
            None
        }

        fn read_u16(&self, _offset: Offset) -> Option<u16> {
            None
        }

        fn read_i32(&self, _offset: Offset) -> Option<i32> {
            None
        }

        fn read_u32(&self, _offset: Offset) -> Option<u32> {
            None
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
}
