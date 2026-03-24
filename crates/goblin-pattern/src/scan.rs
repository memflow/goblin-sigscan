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
        self.exec_inner(start, pat, 0, save).is_some()
    }

    fn exec_inner(
        &self,
        mut cursor: Offset,
        pat: &[Atom],
        mut pc: usize,
        save: &mut [Offset],
    ) -> Option<usize> {
        while let Some(atom) = pat.get(pc) {
            pc += 1;
            match *atom {
                Atom::Byte(expected) => {
                    let actual = self.view.read_u8(cursor)?;
                    if actual != expected {
                        return None;
                    }
                    cursor = cursor.checked_add(1)?;
                }
                Atom::Save(slot) => {
                    if let Some(dst) = save.get_mut(usize::from(slot)) {
                        *dst = cursor;
                    }
                }
                Atom::Skip(n) => {
                    cursor = cursor.checked_add(u64::from(n))?;
                }
                Atom::Push(skip) => {
                    let resume_cursor = cursor.checked_add(u64::from(skip))?;
                    let next_pc = self.exec_inner(cursor, pat, pc, save)?;
                    cursor = resume_cursor;
                    pc = next_pc;
                }
                Atom::Pop => return Some(pc),
                Atom::Jump4 => {
                    let disp = self.view.read_i32(cursor)?;
                    let base = cursor.checked_add(4)?;
                    let delta = i64::from(disp);
                    if delta >= 0 {
                        cursor = base.checked_add(delta as u64)?;
                    } else {
                        cursor = base.checked_sub((-delta) as u64)?;
                    }
                }
                Atom::ReadU32(slot) => {
                    let value = u64::from(self.view.read_u32(cursor)?);
                    if let Some(dst) = save.get_mut(usize::from(slot)) {
                        *dst = value;
                    }
                    cursor = cursor.checked_add(4)?;
                }
            }
        }
        Some(pc)
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
