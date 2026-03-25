use std::ops::Range;

use crate::pattern::Atom;

pub type Offset = u64;

pub trait BinaryView {
    fn code_ranges(&self) -> &[Range<Offset>];
    fn read_u8(&self, offset: Offset) -> Option<u8>;
    fn read_i32(&self, offset: Offset) -> Option<i32>;
    fn read_u32(&self, offset: Offset) -> Option<u32>;
}

#[derive(Copy, Clone, Debug)]
pub struct Scanner<'a, B: BinaryView> {
    view: &'a B,
}

impl<'a, B: BinaryView> Scanner<'a, B> {
    pub fn new(view: &'a B) -> Self {
        Self { view }
    }

    pub fn finds_code(&self, pat: &[Atom], save: &mut [Offset]) -> bool {
        let mut matches = self.matches_code(pat);
        if !matches.next(save) {
            return false;
        }
        !matches.next(&mut [])
    }

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
                    Atom::Case(skip) => {
                        let mut alt = state.clone();
                        alt.pc = alt.pc.saturating_add(usize::from(skip));
                        stack.push(alt);
                        state.pc += 1;
                    }
                    Atom::Break(skip) => {
                        state.pc = state.pc.saturating_add(usize::from(skip) + 1);
                    }
                }
            }
        }

        false
    }
}

#[derive(Clone, Debug)]
pub struct Matches<'a, 'p, B: BinaryView> {
    scanner: Scanner<'a, B>,
    pat: &'p [Atom],
    range_index: usize,
    cursor: Option<Offset>,
}

impl<'a, 'p, B: BinaryView> Matches<'a, 'p, B> {
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
