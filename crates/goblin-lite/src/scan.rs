use std::ops::Range;

use crate::pattern::{Atom, ParsePatError, save_len};
use memchr::memchr_iter;

pub type Offset = u64;
const MAX_BACKTRACK_STATES: usize = 1_000_000;
const PREFIX_BUF_LEN: usize = 16;
const ANCHOR_MAX_LEN: usize = 4;

#[derive(Copy, Clone, Debug)]
struct BacktrackState {
    cursor: Offset,
    pc: usize,
    fuzzy: Option<u8>,
    calls_len: usize,
    save_log_len: usize,
}

#[derive(Clone, Debug, Default)]
struct ExecScratch {
    work_save: Vec<Offset>,
    calls: Vec<Offset>,
    save_log: Vec<(usize, Offset)>,
    stack: Vec<BacktrackState>,
}

impl ExecScratch {
    fn reset_from_save(&mut self, save: &[Offset]) {
        self.work_save.clear();
        self.work_save.extend_from_slice(save);
    }

    fn commit_to_save(&self, save: &mut [Offset]) {
        debug_assert!(
            self.work_save.len() >= save.len(),
            "scratch save buffer must cover caller save length"
        );
        save.copy_from_slice(&self.work_save[..save.len()]);
    }
}

#[derive(Copy, Clone, Debug)]
struct PatternPlan {
    required_slots: usize,
    linear_exec: bool,
    anchor: [u8; ANCHOR_MAX_LEN],
    anchor_len: usize,
    anchor_offset: u64,
}

/// Reusable scanner metadata and atoms for repeated scans.
#[derive(Clone, Debug)]
pub struct PreparedPattern {
    atoms: Vec<Atom>,
    required_slots: usize,
    linear_exec: bool,
    anchor: [u8; ANCHOR_MAX_LEN],
    anchor_len: usize,
    anchor_offset: u64,
}

impl PreparedPattern {
    /// Builds a prepared pattern from parsed atoms.
    pub fn from_atoms(atoms: Vec<Atom>) -> Self {
        let plan = analyze_pattern(&atoms);
        Self {
            atoms,
            required_slots: plan.required_slots,
            linear_exec: plan.linear_exec,
            anchor: plan.anchor,
            anchor_len: plan.anchor_len,
            anchor_offset: plan.anchor_offset,
        }
    }

    /// Returns the parsed atoms backing this prepared pattern.
    pub fn atoms(&self) -> &[Atom] {
        &self.atoms
    }

    /// Returns the minimum save-slot buffer length required for scanning.
    pub fn required_slots(&self) -> usize {
        self.required_slots
    }
}

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
    fn code_ranges(&self) -> impl Iterator<Item = &Range<Offset>> + '_ {
        self.code_spans().iter().map(|span| &span.mapped)
    }

    #[inline]
    fn is_in_code(&self, mapped: Offset) -> bool {
        span_index_for_offset(self.code_spans(), mapped).is_some()
    }

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

struct ExecReader<'a, B: BinaryView> {
    view: &'a B,
    span_index: Option<usize>,
}

impl<'a, B: BinaryView> ExecReader<'a, B> {
    fn new(view: &'a B, start: Offset) -> Self {
        let mut reader = Self {
            view,
            span_index: None,
        };
        reader.span_index = reader.find_span(start);
        reader
    }

    #[inline]
    fn read_u8(&mut self, offset: Offset) -> Option<u8> {
        let Some(file_offset) = self.span_file_offset(offset) else {
            return self.view.read_u8(offset);
        };
        self.view
            .image()
            .get(file_offset)
            .copied()
            .or_else(|| self.view.read_u8(offset))
    }

    #[inline]
    fn read_i16(&mut self, offset: Offset) -> Option<i16> {
        Some(i16::from_le_bytes(self.read_array::<2>(offset)?))
    }

    #[inline]
    fn read_u16(&mut self, offset: Offset) -> Option<u16> {
        Some(u16::from_le_bytes(self.read_array::<2>(offset)?))
    }

    #[inline]
    fn read_i32(&mut self, offset: Offset) -> Option<i32> {
        Some(i32::from_le_bytes(self.read_array::<4>(offset)?))
    }

    #[inline]
    fn read_u32(&mut self, offset: Offset) -> Option<u32> {
        Some(u32::from_le_bytes(self.read_array::<4>(offset)?))
    }

    fn read_array<const N: usize>(&mut self, offset: Offset) -> Option<[u8; N]> {
        if let Some(file_offset) = self.span_file_offset(offset)
            && let Some(end) = file_offset.checked_add(N)
            && let Some(bytes) = self.view.image().get(file_offset..end)
        {
            let mut out = [0u8; N];
            out.copy_from_slice(bytes);
            return Some(out);
        }

        self.view.read_array::<N>(offset)
    }

    fn span_file_offset(&mut self, offset: Offset) -> Option<usize> {
        let index = self.find_span(offset)?;
        let span = self.view.code_spans().get(index)?;
        let delta = offset.checked_sub(span.mapped.start)?;
        let delta_usize = usize::try_from(delta).ok()?;
        span.file.start.checked_add(delta_usize)
    }

    fn find_span(&mut self, offset: Offset) -> Option<usize> {
        if let Some(index) = self.span_index
            && self
                .view
                .code_spans()
                .get(index)
                .is_some_and(|span| span.mapped.contains(&offset))
        {
            return Some(index);
        }

        if let Some(index) = self.span_index
            && let Some(current) = self.view.code_spans().get(index)
            && offset >= current.mapped.end
            && let Some(next_index) = index.checked_add(1)
            && self
                .view
                .code_spans()
                .get(next_index)
                .is_some_and(|span| span.mapped.contains(&offset))
        {
            self.span_index = Some(next_index);
            return Some(next_index);
        }

        let index = span_index_for_offset(self.view.code_spans(), offset)?;
        self.span_index = Some(index);
        Some(index)
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
        let plan = analyze_pattern(pat);
        let required_slots = plan.required_slots;
        debug_assert!(
            save.len() >= required_slots,
            "caller-provided save buffer must cover all slots referenced by the pattern"
        );
        self.finds_unique_direct(
            pat,
            plan.linear_exec,
            plan.required_slots,
            plan.anchor,
            plan.anchor_len,
            plan.anchor_offset,
            save,
        )
    }

    /// Returns the minimum required save-slot buffer length for `pat`.
    pub fn required_slots(&self, pat: &[Atom]) -> usize {
        save_len(pat)
    }

    /// Prepares reusable scanner metadata for a parsed pattern.
    pub fn prepare_pattern(&self, pat: &[Atom]) -> PreparedPattern {
        PreparedPattern::from_atoms(pat.to_vec())
    }

    /// Parses and prepares a pattern string for scanning.
    ///
    /// This is slower than [`Self::prepare_pattern`] because it performs
    /// runtime text parsing and allocates atom storage on each call.
    pub fn prepare_pattern_str(&self, source: &str) -> Result<PreparedPattern, ParsePatError> {
        let atoms = crate::pattern::parse(source)?;
        Ok(PreparedPattern::from_atoms(atoms))
    }

    /// Returns `true` only when a prepared pattern has exactly one code match.
    pub fn finds_prepared(&self, pat: &PreparedPattern, save: &mut [Offset]) -> bool {
        debug_assert!(
            save.len() >= pat.required_slots,
            "caller-provided save buffer must cover all slots referenced by the prepared pattern"
        );
        self.finds_unique_direct(
            &pat.atoms,
            pat.linear_exec,
            pat.required_slots,
            pat.anchor,
            pat.anchor_len,
            pat.anchor_offset,
            save,
        )
    }

    /// Returns an iterator-like matcher for a prepared pattern.
    pub fn matches_prepared<'p>(&self, pat: &'p PreparedPattern) -> Matches<'a, 'p, B> {
        Matches {
            scanner: Scanner { view: self.view },
            pat: &pat.atoms,
            required_slots: pat.required_slots,
            linear_exec: pat.linear_exec,
            range_index: 0,
            cursor: None,
            anchor: pat.anchor,
            anchor_len: pat.anchor_len,
            anchor_offset: pat.anchor_offset,
            scratch: ExecScratch::default(),
        }
    }

    /// Returns an iterator-like matcher for all code-range matches.
    pub fn matches_code<'p>(&self, pat: &'p [Atom]) -> Matches<'a, 'p, B> {
        let plan = analyze_pattern(pat);
        Matches {
            scanner: Scanner { view: self.view },
            pat,
            required_slots: plan.required_slots,
            linear_exec: plan.linear_exec,
            range_index: 0,
            cursor: None,
            anchor: plan.anchor,
            anchor_len: plan.anchor_len,
            anchor_offset: plan.anchor_offset,
            scratch: ExecScratch::default(),
        }
    }

    fn exec(
        &self,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        scratch: &mut ExecScratch,
    ) -> bool {
        if linear_exec {
            return self.exec_linear(start, pat, save, scratch);
        }
        self.exec_backtracking(start, pat, save, scratch)
    }

    fn finds_unique_direct(
        &self,
        pat: &[Atom],
        linear_exec: bool,
        required_slots: usize,
        anchor: [u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        save: &mut [Offset],
    ) -> bool {
        let mut exec_scratch = ExecScratch::default();
        let mut scratch = vec![0; required_slots];
        let mut found_once = false;

        for span in self.view.code_spans() {
            let mut cursor = span.mapped.start;
            loop {
                let save_buf: &mut [Offset] = if found_once {
                    &mut scratch
                } else {
                    &mut save[..required_slots]
                };
                let matched = self.find_next_direct_in_span(
                    span,
                    cursor,
                    pat,
                    save_buf,
                    linear_exec,
                    &anchor,
                    anchor_len,
                    anchor_offset,
                    &mut exec_scratch,
                );
                let Some(found_at) = matched else {
                    break;
                };

                if found_once {
                    return false;
                }
                found_once = true;

                let Some(next) = found_at.checked_add(1) else {
                    break;
                };
                cursor = next;
            }
        }

        found_once
    }

    fn find_next_direct_in_span(
        &self,
        span: &CodeSpan,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        if start >= span.mapped.end {
            return None;
        }

        if anchor_len == 0 {
            return self.scan_range_linear_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                scratch,
            );
        }
        if anchor_len < 4 {
            return self.scan_span_first_byte_direct(
                span,
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                scratch,
            );
        }
        self.scan_span_quick_direct(
            span,
            start,
            pat,
            save,
            linear_exec,
            anchor,
            anchor_len,
            anchor_offset,
            scratch,
        )
    }

    fn scan_range_linear_direct(
        &self,
        range: Range<Offset>,
        mut cursor: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        while cursor < range.end {
            if self.exec(cursor, pat, save, linear_exec, scratch) {
                return Some(cursor);
            }
            cursor = cursor.checked_add(1)?;
        }
        None
    }

    fn scan_span_first_byte_direct(
        &self,
        span: &CodeSpan,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        let Some(bytes) = self.view.image().get(span.file.clone()) else {
            return self.scan_range_first_byte_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_offset,
                scratch,
            );
        };
        let anchor_start = start.checked_add(anchor_offset)?;
        let Some(start_file) = mapped_to_file_offset(span, anchor_start) else {
            return self.scan_range_first_byte_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_offset,
                scratch,
            );
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_first_byte_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_offset,
                scratch,
            );
        };
        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_first_byte_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_offset,
                scratch,
            );
        };

        let needle = anchor[0];
        let anchor_window = &anchor[..anchor_len];
        for delta in memchr_iter(needle, haystack) {
            if anchor_len > 1
                && !haystack
                    .get(delta..delta + anchor_len)
                    .is_some_and(|window| window == anchor_window)
            {
                continue;
            }
            let anchor_index = start_index.checked_add(delta)?;
            let mapped_delta = Offset::try_from(anchor_index).ok()?;
            let anchor_cursor = span.mapped.start.checked_add(mapped_delta)?;
            let cursor = anchor_cursor.checked_sub(anchor_offset)?;
            if self.exec(cursor, pat, save, linear_exec, scratch) {
                return Some(cursor);
            }
        }
        None
    }

    fn scan_range_first_byte_direct(
        &self,
        range: Range<Offset>,
        mut cursor: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_offset: u64,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        let needle = anchor[0];
        let mut probe = cursor.checked_add(anchor_offset)?;
        while probe < range.end {
            if self.view.read_u8(probe) == Some(needle)
                && self.exec(cursor, pat, save, linear_exec, scratch)
            {
                return Some(cursor);
            }
            cursor = cursor.checked_add(1)?;
            probe = probe.checked_add(1)?;
        }
        None
    }

    fn scan_span_quick_direct(
        &self,
        span: &CodeSpan,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        let Some(bytes) = self.view.image().get(span.file.clone()) else {
            return self.scan_range_quick_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                scratch,
            );
        };
        let anchor_start = start.checked_add(anchor_offset)?;
        let Some(start_file) = mapped_to_file_offset(span, anchor_start) else {
            return self.scan_range_quick_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                scratch,
            );
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_quick_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                scratch,
            );
        };
        let prefix = &anchor[..anchor_len];
        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_quick_direct(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                scratch,
            );
        };
        if haystack.len() < anchor_len {
            return None;
        }

        let mut jumps = [anchor_len as u8; 256];
        for (index, byte) in prefix.iter().take(anchor_len.saturating_sub(1)).enumerate() {
            jumps[usize::from(*byte)] = (anchor_len - index - 1) as u8;
        }

        let last = prefix[anchor_len - 1];
        let mut index = 0usize;
        let max_index = haystack.len() - anchor_len;
        while index <= max_index {
            let probe = haystack[index + anchor_len - 1];
            let jump = usize::from(jumps[usize::from(probe)].max(1));
            if probe == last
                && haystack
                    .get(index..index + anchor_len)
                    .is_some_and(|window| window == prefix)
            {
                let total_index = start_index.checked_add(index)?;
                let mapped_delta = Offset::try_from(total_index).ok()?;
                let cursor = span.mapped.start.checked_add(mapped_delta)?;
                let start_cursor = cursor.checked_sub(anchor_offset)?;
                if self.exec(start_cursor, pat, save, linear_exec, scratch) {
                    return Some(start_cursor);
                }
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn scan_range_quick_direct(
        &self,
        range: Range<Offset>,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        let prefix = &anchor[..anchor_len];
        let window = u64::try_from(anchor_len).ok()?;
        let start = start.checked_add(anchor_offset)?;
        if start >= range.end {
            return None;
        }
        let total = range.end.checked_sub(start)?;
        if total < window {
            return None;
        }

        let mut jumps = [anchor_len as u8; 256];
        for (index, byte) in prefix.iter().take(anchor_len.saturating_sub(1)).enumerate() {
            jumps[usize::from(*byte)] = (anchor_len - index - 1) as u8;
        }

        let last = prefix[anchor_len - 1];
        let mut index = 0u64;
        let max_index = total - window;
        while index <= max_index {
            let cursor = start.checked_add(index)?;
            let probe_at = cursor.checked_add(window - 1)?;
            let Some(probe) = self.view.read_u8(probe_at) else {
                index = index.checked_add(1)?;
                continue;
            };

            let jump = u64::from(jumps[usize::from(probe)].max(1));
            if probe == last
                && prefix_matches_mapped(self.view, cursor, prefix)
                && self.exec(
                    cursor.checked_sub(anchor_offset)?,
                    pat,
                    save,
                    linear_exec,
                    scratch,
                )
            {
                return cursor.checked_sub(anchor_offset);
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn exec_linear(
        &self,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        scratch: &mut ExecScratch,
    ) -> bool {
        if let Some(result) = self.exec_linear_specialized(start, pat, save) {
            return result;
        }
        scratch.reset_from_save(save);
        let work_save = &mut scratch.work_save;
        let mut cursor = start;
        let mut pc = 0usize;
        let mut fuzzy = None;
        let mut reader = ExecReader::new(self.view, cursor);

        loop {
            let Some(atom) = pat.get(pc) else {
                scratch.commit_to_save(save);
                return true;
            };

            match *atom {
                Atom::Byte(expected) => {
                    let Some(actual) = reader.read_u8(cursor) else {
                        return false;
                    };
                    let mask = fuzzy.take().unwrap_or(u8::MAX);
                    if (actual & mask) != (expected & mask) {
                        return false;
                    }
                    cursor = match cursor.checked_add(1) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::Fuzzy(mask) => {
                    fuzzy = Some(mask);
                    pc += 1;
                }
                Atom::Save(slot) => {
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = cursor;
                    }
                    pc += 1;
                }
                Atom::Skip(n) => {
                    cursor = match cursor.checked_add(u64::from(n)) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::Jump1 => {
                    let Some(byte) = reader.read_u8(cursor) else {
                        return false;
                    };
                    let base = match cursor.checked_add(1) {
                        Some(next) => next,
                        None => return false,
                    };
                    let delta = i64::from(byte as i8);
                    cursor = if delta >= 0 {
                        match base.checked_add(delta as u64) {
                            Some(next) => next,
                            None => return false,
                        }
                    } else {
                        match base.checked_sub((-delta) as u64) {
                            Some(next) => next,
                            None => return false,
                        }
                    };
                    pc += 1;
                }
                Atom::Jump4 => {
                    let Some(disp) = reader.read_i32(cursor) else {
                        return false;
                    };
                    let base = match cursor.checked_add(4) {
                        Some(next) => next,
                        None => return false,
                    };
                    let delta = i64::from(disp);
                    cursor = if delta >= 0 {
                        match base.checked_add(delta as u64) {
                            Some(next) => next,
                            None => return false,
                        }
                    } else {
                        match base.checked_sub((-delta) as u64) {
                            Some(next) => next,
                            None => return false,
                        }
                    };
                    pc += 1;
                }
                Atom::ReadI8(slot) => {
                    let Some(value) = reader.read_u8(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = (value as i8) as i64 as u64;
                    }
                    cursor = match cursor.checked_add(1) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::ReadU8(slot) => {
                    let Some(value) = reader.read_u8(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = u64::from(value);
                    }
                    cursor = match cursor.checked_add(1) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::ReadI16(slot) => {
                    let Some(value) = reader.read_i16(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = value as i64 as u64;
                    }
                    cursor = match cursor.checked_add(2) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::ReadU16(slot) => {
                    let Some(value) = reader.read_u16(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = u64::from(value);
                    }
                    cursor = match cursor.checked_add(2) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::ReadI32(slot) => {
                    let Some(value) = reader.read_i32(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = value as i64 as u64;
                    }
                    cursor = match cursor.checked_add(4) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::ReadU32(slot) => {
                    let Some(value) = reader.read_u32(cursor) else {
                        return false;
                    };
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = u64::from(value);
                    }
                    cursor = match cursor.checked_add(4) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::Zero(slot) => {
                    if let Some(dst) = work_save.get_mut(usize::from(slot)) {
                        *dst = 0;
                    }
                    pc += 1;
                }
                Atom::Back(n) => {
                    cursor = match cursor.checked_sub(u64::from(n)) {
                        Some(next) => next,
                        None => return false,
                    };
                    pc += 1;
                }
                Atom::Aligned(align) => {
                    let mask = (1u64 << u64::from(align)).wrapping_sub(1);
                    if cursor & mask != 0 {
                        return false;
                    }
                    pc += 1;
                }
                Atom::Check(slot) => {
                    let expected = work_save.get(usize::from(slot)).copied().unwrap_or(0);
                    if cursor != expected {
                        return false;
                    }
                    pc += 1;
                }
                Atom::Nop => {
                    pc += 1;
                }
                Atom::SkipRange(_, _)
                | Atom::Push(_)
                | Atom::Pop
                | Atom::Case(_)
                | Atom::Break(_) => {
                    debug_assert!(
                        false,
                        "linear exec must only run on patterns without backtracking/control-flow atoms"
                    );
                    return false;
                }
            }
        }
    }

    fn exec_linear_specialized(
        &self,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
    ) -> Option<bool> {
        match pat {
            [Atom::Save(0), Atom::Byte(expected), Atom::Jump4] => {
                let mut reader = ExecReader::new(self.view, start);
                if reader.read_u8(start) != Some(*expected) {
                    return Some(false);
                }
                let read_at = start.checked_add(1)?;
                let disp = reader.read_i32(read_at)?;
                let base = read_at.checked_add(4)?;
                let target = offset_add_signed(base, i64::from(disp))?;
                if let Some(slot) = save.get_mut(0) {
                    *slot = start;
                }
                let _ = target;
                Some(true)
            }
            [
                Atom::Save(0),
                Atom::Byte(expected),
                Atom::Jump4,
                Atom::Save(slot),
            ] => {
                let mut reader = ExecReader::new(self.view, start);
                if reader.read_u8(start) != Some(*expected) {
                    return Some(false);
                }
                let read_at = start.checked_add(1)?;
                let disp = reader.read_i32(read_at)?;
                let base = read_at.checked_add(4)?;
                let target = offset_add_signed(base, i64::from(disp))?;
                if let Some(start_slot) = save.get_mut(0) {
                    *start_slot = start;
                }
                if let Some(target_slot) = save.get_mut(usize::from(*slot)) {
                    *target_slot = target;
                }
                Some(true)
            }
            [Atom::Save(0), Atom::Byte(expected), Atom::Jump1] => {
                let mut reader = ExecReader::new(self.view, start);
                if reader.read_u8(start) != Some(*expected) {
                    return Some(false);
                }
                let read_at = start.checked_add(1)?;
                let disp = reader.read_u8(read_at)? as i8;
                let base = read_at.checked_add(1)?;
                let target = offset_add_signed(base, i64::from(disp))?;
                if let Some(slot) = save.get_mut(0) {
                    *slot = start;
                }
                let _ = target;
                Some(true)
            }
            [
                Atom::Save(0),
                Atom::Byte(expected),
                Atom::Jump1,
                Atom::Save(slot),
            ] => {
                let mut reader = ExecReader::new(self.view, start);
                if reader.read_u8(start) != Some(*expected) {
                    return Some(false);
                }
                let read_at = start.checked_add(1)?;
                let disp = reader.read_u8(read_at)? as i8;
                let base = read_at.checked_add(1)?;
                let target = offset_add_signed(base, i64::from(disp))?;
                if let Some(start_slot) = save.get_mut(0) {
                    *start_slot = start;
                }
                if let Some(target_slot) = save.get_mut(usize::from(*slot)) {
                    *target_slot = target;
                }
                Some(true)
            }
            _ => None,
        }
    }

    fn exec_backtracking(
        &self,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        scratch: &mut ExecScratch,
    ) -> bool {
        scratch.reset_from_save(save);
        let work_save = &mut scratch.work_save;
        scratch.calls.clear();
        scratch.save_log.clear();
        scratch.stack.clear();

        scratch.stack.push(BacktrackState {
            cursor: start,
            pc: 0,
            fuzzy: None,
            calls_len: 0,
            save_log_len: 0,
        });

        #[inline]
        fn rollback(save: &mut [Offset], log: &mut Vec<(usize, Offset)>, target_len: usize) {
            while log.len() > target_len {
                let (slot, old) = log.pop().expect("save log length checked before pop");
                save[slot] = old;
            }
        }

        #[inline]
        fn assign_save(
            save: &mut [Offset],
            log: &mut Vec<(usize, Offset)>,
            slot: usize,
            value: Offset,
        ) {
            if let Some(dst) = save.get_mut(slot) {
                log.push((slot, *dst));
                *dst = value;
            }
        }

        while let Some(state) = scratch.stack.pop() {
            scratch.calls.truncate(state.calls_len);
            rollback(work_save, &mut scratch.save_log, state.save_log_len);

            let mut cursor = state.cursor;
            let mut pc = state.pc;
            let mut fuzzy = state.fuzzy;
            let mut reader = ExecReader::new(self.view, cursor);
            loop {
                let Some(atom) = pat.get(pc) else {
                    scratch.commit_to_save(save);
                    return true;
                };

                match *atom {
                    Atom::Byte(expected) => {
                        let Some(actual) = reader.read_u8(cursor) else {
                            break;
                        };
                        let mask = fuzzy.take().unwrap_or(u8::MAX);
                        if (actual & mask) != (expected & mask) {
                            break;
                        }
                        let Some(next) = cursor.checked_add(1) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::Fuzzy(mask) => {
                        fuzzy = Some(mask);
                        pc += 1;
                    }
                    Atom::Save(slot) => {
                        assign_save(work_save, &mut scratch.save_log, usize::from(slot), cursor);
                        pc += 1;
                    }
                    Atom::Skip(n) => {
                        let Some(next) = cursor.checked_add(u64::from(n)) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::SkipRange(min, max) => {
                        debug_assert!(
                            min <= max,
                            "pattern parser enforces inclusive skip ranges with min <= max"
                        );
                        let min = u64::from(min);
                        let max = u64::from(max);
                        for delta in ((min + 1)..=max).rev() {
                            if let Some(next_cursor) = cursor.checked_add(delta) {
                                if scratch.stack.len() >= MAX_BACKTRACK_STATES {
                                    debug_assert!(
                                        false,
                                        "scanner backtracking stack must stay below MAX_BACKTRACK_STATES for bounded memory"
                                    );
                                    return false;
                                }
                                scratch.stack.push(BacktrackState {
                                    cursor: next_cursor,
                                    pc: pc + 1,
                                    fuzzy,
                                    calls_len: scratch.calls.len(),
                                    save_log_len: scratch.save_log.len(),
                                });
                            }
                        }
                        let Some(next) = cursor.checked_add(min) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::Push(skip) => {
                        let Some(resume_cursor) = cursor.checked_add(u64::from(skip)) else {
                            break;
                        };
                        scratch.calls.push(resume_cursor);
                        pc += 1;
                    }
                    Atom::Pop => {
                        let Some(resume_cursor) = scratch.calls.pop() else {
                            break;
                        };
                        cursor = resume_cursor;
                        pc += 1;
                    }
                    Atom::Jump1 => {
                        let Some(byte) = reader.read_u8(cursor) else {
                            break;
                        };
                        let disp = byte as i8;
                        let Some(base) = cursor.checked_add(1) else {
                            break;
                        };
                        let delta = i64::from(disp);
                        if delta >= 0 {
                            let Some(next) = base.checked_add(delta as u64) else {
                                break;
                            };
                            cursor = next;
                        } else {
                            let Some(next) = base.checked_sub((-delta) as u64) else {
                                break;
                            };
                            cursor = next;
                        }
                        pc += 1;
                    }
                    Atom::Jump4 => {
                        let Some(disp) = reader.read_i32(cursor) else {
                            break;
                        };
                        let Some(base) = cursor.checked_add(4) else {
                            break;
                        };
                        let delta = i64::from(disp);
                        if delta >= 0 {
                            let Some(next) = base.checked_add(delta as u64) else {
                                break;
                            };
                            cursor = next;
                        } else {
                            let Some(next) = base.checked_sub((-delta) as u64) else {
                                break;
                            };
                            cursor = next;
                        }
                        pc += 1;
                    }
                    Atom::ReadI8(slot) => {
                        let Some(value) = reader.read_u8(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            (value as i8) as i64 as u64,
                        );
                        let Some(next) = cursor.checked_add(1) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::ReadU8(slot) => {
                        let Some(value) = reader.read_u8(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            u64::from(value),
                        );
                        let Some(next) = cursor.checked_add(1) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::ReadI16(slot) => {
                        let Some(value) = reader.read_i16(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            value as i64 as u64,
                        );
                        let Some(next) = cursor.checked_add(2) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::ReadU16(slot) => {
                        let Some(value) = reader.read_u16(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            u64::from(value),
                        );
                        let Some(next) = cursor.checked_add(2) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::ReadI32(slot) => {
                        let Some(value) = reader.read_i32(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            value as i64 as u64,
                        );
                        let Some(next) = cursor.checked_add(4) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::ReadU32(slot) => {
                        let Some(value) = reader.read_u32(cursor) else {
                            break;
                        };
                        assign_save(
                            work_save,
                            &mut scratch.save_log,
                            usize::from(slot),
                            u64::from(value),
                        );
                        let Some(next) = cursor.checked_add(4) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::Zero(slot) => {
                        assign_save(work_save, &mut scratch.save_log, usize::from(slot), 0);
                        pc += 1;
                    }
                    Atom::Back(n) => {
                        let Some(next) = cursor.checked_sub(u64::from(n)) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::Aligned(align) => {
                        let mask = (1u64 << u64::from(align)).wrapping_sub(1);
                        if cursor & mask != 0 {
                            break;
                        }
                        pc += 1;
                    }
                    Atom::Check(slot) => {
                        let expected = work_save.get(usize::from(slot)).copied().unwrap_or(0);
                        if cursor != expected {
                            break;
                        }
                        pc += 1;
                    }
                    Atom::Case(skip) => {
                        let Some(next_pc) = pc.checked_add(usize::from(skip)) else {
                            break;
                        };
                        if scratch.stack.len() >= MAX_BACKTRACK_STATES {
                            debug_assert!(
                                false,
                                "scanner backtracking stack must stay below MAX_BACKTRACK_STATES for bounded memory"
                            );
                            return false;
                        }
                        scratch.stack.push(BacktrackState {
                            cursor,
                            pc: next_pc,
                            fuzzy,
                            calls_len: scratch.calls.len(),
                            save_log_len: scratch.save_log.len(),
                        });
                        pc += 1;
                    }
                    Atom::Break(skip) => {
                        let Some(next_pc) = pc
                            .checked_add(usize::from(skip))
                            .and_then(|value| value.checked_add(1))
                        else {
                            break;
                        };
                        pc = next_pc;
                    }
                    Atom::Nop => {
                        pc += 1;
                    }
                }
            }
        }

        false
    }
}

#[inline]
fn offset_add_signed(base: Offset, delta: i64) -> Option<Offset> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub((-delta) as u64)
    }
}

#[derive(Clone, Debug)]
/// Stateful matcher produced by [`Scanner::matches_code`].
pub struct Matches<'a, 'p, B: BinaryView> {
    scanner: Scanner<'a, B>,
    pat: &'p [Atom],
    required_slots: usize,
    linear_exec: bool,
    range_index: usize,
    cursor: Option<Offset>,
    anchor: [u8; ANCHOR_MAX_LEN],
    anchor_len: usize,
    anchor_offset: u64,
    scratch: ExecScratch,
}

impl<'a, 'p, B: BinaryView> Matches<'a, 'p, B> {
    /// Advances to the next match and writes save-slot values into `save`.
    pub fn next(&mut self, save: &mut [Offset]) -> bool {
        debug_assert!(
            save.len() >= self.required_slots,
            "caller-provided save buffer must cover all slots referenced by the pattern"
        );
        let save = &mut save[..self.required_slots];
        while let Some(span) = self.scanner.view.code_spans().get(self.range_index) {
            let start = self.cursor.unwrap_or(span.mapped.start);
            if start >= span.mapped.end {
                self.range_index += 1;
                self.cursor = None;
                continue;
            }
            let matched_at = if self.anchor_len == 0 {
                self.scan_range_linear(span.mapped.clone(), start, save)
            } else if self.anchor_len < 4 {
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
        &mut self,
        range: Range<Offset>,
        mut cursor: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        while cursor < range.end {
            if self
                .scanner
                .exec(cursor, self.pat, save, self.linear_exec, &mut self.scratch)
            {
                return Some(cursor);
            }
            let next = cursor.checked_add(1)?;
            cursor = next;
        }
        None
    }

    fn scan_span_first_byte(
        &mut self,
        span: &CodeSpan,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let Some(bytes) = self.scanner.view.image().get(span.file.clone()) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };
        let Some(anchor_start) = start.checked_add(self.anchor_offset) else {
            return self.scan_range_first_byte(span.mapped.clone(), start, save);
        };
        let Some(start_file) = mapped_to_file_offset(span, anchor_start) else {
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
        let needle = self.anchor[0];
        let anchor = &self.anchor[..self.anchor_len];
        for delta in memchr_iter(needle, haystack) {
            if self.anchor_len > 1
                && !haystack
                    .get(delta..delta + self.anchor_len)
                    .is_some_and(|window| window == anchor)
            {
                continue;
            }
            let Some(anchor_index) = start_index.checked_add(delta) else {
                return None;
            };
            let Some(mapped_delta) = Offset::try_from(anchor_index).ok() else {
                return None;
            };
            let Some(anchor_cursor) = span.mapped.start.checked_add(mapped_delta) else {
                return None;
            };
            let Some(cursor) = anchor_cursor.checked_sub(self.anchor_offset) else {
                return None;
            };
            if self
                .scanner
                .exec(cursor, self.pat, save, self.linear_exec, &mut self.scratch)
            {
                return Some(cursor);
            }
        }
        None
    }

    fn scan_range_first_byte(
        &mut self,
        range: Range<Offset>,
        mut cursor: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let needle = self.anchor[0];
        let Some(mut probe) = cursor.checked_add(self.anchor_offset) else {
            return None;
        };
        while probe < range.end {
            if self.scanner.view.read_u8(probe) == Some(needle)
                && self
                    .scanner
                    .exec(cursor, self.pat, save, self.linear_exec, &mut self.scratch)
            {
                return Some(cursor);
            }
            cursor = cursor.checked_add(1)?;
            probe = probe.checked_add(1)?;
        }
        None
    }

    fn scan_range_quick(
        &mut self,
        range: Range<Offset>,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let prefix = &self.anchor[..self.anchor_len];
        let window = u64::try_from(self.anchor_len).ok()?;
        let start = start.checked_add(self.anchor_offset)?;
        if start >= range.end {
            return None;
        }
        let total = range.end.checked_sub(start)?;
        if total < window {
            return None;
        }

        let mut jumps = [self.anchor_len as u8; 256];
        for (index, byte) in prefix
            .iter()
            .take(self.anchor_len.saturating_sub(1))
            .enumerate()
        {
            jumps[usize::from(*byte)] = (self.anchor_len - index - 1) as u8;
        }

        let last = prefix[self.anchor_len - 1];
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
                && self.scanner.exec(
                    cursor.checked_sub(self.anchor_offset)?,
                    self.pat,
                    save,
                    self.linear_exec,
                    &mut self.scratch,
                )
            {
                return cursor.checked_sub(self.anchor_offset);
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn scan_span_quick(
        &mut self,
        span: &CodeSpan,
        start: Offset,
        save: &mut [Offset],
    ) -> Option<Offset> {
        let Some(bytes) = self.scanner.view.image().get(span.file.clone()) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        let Some(anchor_start) = start.checked_add(self.anchor_offset) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        let Some(start_file) = mapped_to_file_offset(span, anchor_start) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };

        let prefix = &self.anchor[..self.anchor_len];
        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_quick(span.mapped.clone(), start, save);
        };
        if haystack.len() < self.anchor_len {
            return None;
        }

        let mut jumps = [self.anchor_len as u8; 256];
        for (index, byte) in prefix
            .iter()
            .take(self.anchor_len.saturating_sub(1))
            .enumerate()
        {
            jumps[usize::from(*byte)] = (self.anchor_len - index - 1) as u8;
        }

        let last = prefix[self.anchor_len - 1];
        let mut index = 0usize;
        let max_index = haystack.len() - self.anchor_len;
        while index <= max_index {
            let probe = haystack[index + self.anchor_len - 1];

            let jump = usize::from(jumps[usize::from(probe)].max(1));
            if probe == last
                && haystack
                    .get(index..index + self.anchor_len)
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
                let Some(start_cursor) = cursor.checked_sub(self.anchor_offset) else {
                    return None;
                };
                if self.scanner.exec(
                    start_cursor,
                    self.pat,
                    save,
                    self.linear_exec,
                    &mut self.scratch,
                ) {
                    return Some(start_cursor);
                }
            }
            index = index.checked_add(jump)?;
        }

        None
    }

    fn prefix_matches_mapped(&self, cursor: Offset) -> bool {
        for (index, expected) in self.anchor[..self.anchor_len].iter().enumerate() {
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

fn analyze_pattern(pat: &[Atom]) -> PatternPlan {
    let required_slots = save_len(pat);
    let linear_exec = is_linear_pattern(pat);
    let (prefix, prefix_len) = build_prefix(pat);
    let (anchor, anchor_len, anchor_offset) = select_anchor(&prefix, prefix_len);
    PatternPlan {
        required_slots,
        linear_exec,
        anchor,
        anchor_len,
        anchor_offset,
    }
}

/// Chooses the best fixed-size literal anchor window from the prefix.
///
/// The scanner uses this anchor for candidate filtering before running full
/// pattern execution. We score each possible window and select the one with the
/// highest expected selectivity (ties prefer later windows for slightly better
/// locality with following atoms).
fn select_anchor(
    prefix: &[u8; PREFIX_BUF_LEN],
    prefix_len: usize,
) -> ([u8; ANCHOR_MAX_LEN], usize, u64) {
    let mut anchor = [0u8; ANCHOR_MAX_LEN];
    if prefix_len == 0 {
        return (anchor, 0, 0);
    }

    let anchor_len = prefix_len.min(ANCHOR_MAX_LEN);
    let mut best_start = 0usize;
    let mut best_score = 0u32;
    for start in 0..=prefix_len - anchor_len {
        let score = anchor_window_score(&prefix[start..start + anchor_len]);
        if score > best_score || (score == best_score && start > best_start) {
            best_score = score;
            best_start = start;
        }
    }

    for (index, byte) in prefix[best_start..best_start + anchor_len]
        .iter()
        .copied()
        .enumerate()
    {
        anchor[index] = byte;
    }
    (anchor, anchor_len, best_start as u64)
}

/// Scores an anchor window by estimated filtering strength.
///
/// Higher scores prefer windows with more distinct and less common bytes, and a
/// stronger terminal byte because quick search probes the window tail first.
fn anchor_window_score(window: &[u8]) -> u32 {
    let mut seen = [false; 256];
    let mut distinct = 0u32;
    let mut byte_score = 0u32;
    for byte in window.iter().copied() {
        let idx = usize::from(byte);
        if !seen[idx] {
            seen[idx] = true;
            distinct += 1;
        }
        byte_score += anchor_byte_weight(byte);
    }

    let duplicate_count = window.len() as u32 - distinct;
    let last_weight = window.last().copied().map(anchor_byte_weight).unwrap_or(0);
    (distinct * 8) + byte_score + (last_weight * 2) - (duplicate_count * 3)
}

/// Heuristic byte rarity weight used by [`anchor_window_score`].
///
/// Common x86 opcode bytes/prefixes get lower weights so mixed or rarer windows
/// are chosen as anchors more often.
fn anchor_byte_weight(byte: u8) -> u32 {
    match byte {
        0x00 | 0x48 | 0x8b | 0x89 | 0x90 | 0xcc | 0xe8 | 0xe9 | 0xff => 1,
        0x40..=0x4f | 0x50..=0x5f | 0x70..=0x7f => 2,
        0x66 | 0x67 => 2,
        _ => 4,
    }
}

fn is_linear_pattern(pat: &[Atom]) -> bool {
    !pat.iter().any(|atom| {
        matches!(
            atom,
            Atom::SkipRange(_, _) | Atom::Push(_) | Atom::Pop | Atom::Case(_) | Atom::Break(_)
        )
    })
}

#[cfg(test)]
fn is_tiny_literal_jump_pattern(pat: &[Atom]) -> bool {
    let mut has_jump1 = false;
    for atom in pat {
        match atom {
            Atom::Byte(_) | Atom::Save(_) | Atom::Skip(_) | Atom::Nop => {}
            Atom::Jump1 => has_jump1 = true,
            Atom::Jump4 => return false,
            _ => return false,
        }
    }
    has_jump1
}

fn span_index_for_offset(spans: &[CodeSpan], offset: Offset) -> Option<usize> {
    let mut low = 0usize;
    let mut high = spans.len();
    while low < high {
        let mid = low + (high - low) / 2;
        let span = &spans[mid];
        if span.mapped.end <= offset {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    spans.get(low).and_then(|span| {
        if span.mapped.contains(&offset) {
            Some(low)
        } else {
            None
        }
    })
}

fn mapped_to_file_offset(span: &CodeSpan, mapped: Offset) -> Option<usize> {
    let delta = mapped.checked_sub(span.mapped.start)?;
    if mapped >= span.mapped.end {
        return None;
    }
    let delta_usize = usize::try_from(delta).ok()?;
    span.file.start.checked_add(delta_usize)
}

fn prefix_matches_mapped<B: BinaryView>(view: &B, cursor: Offset, prefix: &[u8]) -> bool {
    for (index, expected) in prefix.iter().enumerate() {
        let Some(offset) = cursor.checked_add(index as u64) else {
            return false;
        };
        if view.read_u8(offset) != Some(*expected) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{
        BinaryView, CodeSpan, Offset, PreparedPattern, Scanner, build_prefix, is_linear_pattern,
        is_tiny_literal_jump_pattern, select_anchor, span_index_for_offset,
    };
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
    fn prepared_pattern_exposes_required_slots() {
        let pat = vec![
            Atom::Save(0),
            Atom::Byte(0xaa),
            Atom::Save(2),
            Atom::Byte(0xbb),
        ];
        let prepared = PreparedPattern::from_atoms(pat);
        assert_eq!(prepared.required_slots(), 3);
    }

    #[test]
    fn matches_prepared_matches_runtime_behavior() {
        let view = TestView::new(&[0x00, 0xaa, 0xbb]);
        let scanner = Scanner::new(&view);
        let pat = [Atom::Save(0), Atom::Byte(0xaa), Atom::Byte(0xbb)];
        let prepared = scanner.prepare_pattern(&pat);

        let mut save_runtime = [0u64; 1];
        let mut save_prepared = [0u64; 1];
        assert!(scanner.matches_code(&pat).next(&mut save_runtime));
        assert!(scanner.matches_prepared(&prepared).next(&mut save_prepared));
        assert_eq!(save_runtime, save_prepared);
    }

    #[test]
    fn prepare_pattern_str_parses_runtime_text() {
        let view = TestView::new(&[0x00, 0xaa, 0xbb]);
        let scanner = Scanner::new(&view);
        let prepared = scanner
            .prepare_pattern_str("AA BB")
            .expect("runtime pattern text should parse");

        let mut save = vec![0u64; prepared.required_slots()];
        assert!(scanner.matches_prepared(&prepared).next(&mut save));
    }

    #[test]
    fn prepare_pattern_str_reports_parse_errors() {
        let view = TestView::new(&[]);
        let scanner = Scanner::new(&view);
        assert!(scanner.prepare_pattern_str("A?").is_err());
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

    #[test]
    fn anchor_selection_prefers_stronger_window_over_common_suffix() {
        let mut prefix = [0u8; super::PREFIX_BUF_LEN];
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x48, 0x8b, 0x05, 0x48];
        for (index, byte) in bytes.iter().copied().enumerate() {
            prefix[index] = byte;
        }

        let (anchor, len, offset) = select_anchor(&prefix, bytes.len());
        assert_eq!(len, 4);
        assert_eq!(offset, 0);
        assert_eq!(&anchor[..len], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn code_ranges_yield_mapped_ranges_in_order() {
        let view = TestView {
            bytes: vec![0u8; 16],
            spans: vec![
                CodeSpan {
                    mapped: 10..13,
                    file: 0..3,
                },
                CodeSpan {
                    mapped: 30..35,
                    file: 8..13,
                },
            ],
        };

        let ranges = view.code_ranges().cloned().collect::<Vec<_>>();
        assert_eq!(ranges, vec![10..13, 30..35]);
    }

    #[test]
    fn is_in_code_detects_hits_and_gaps() {
        let view = TestView {
            bytes: vec![0u8; 16],
            spans: vec![
                CodeSpan {
                    mapped: 5..8,
                    file: 0..3,
                },
                CodeSpan {
                    mapped: 12..15,
                    file: 8..11,
                },
            ],
        };

        assert!(view.is_in_code(5));
        assert!(view.is_in_code(7));
        assert!(!view.is_in_code(8));
        assert!(!view.is_in_code(11));
        assert!(view.is_in_code(14));
        assert!(!view.is_in_code(15));
    }

    #[test]
    fn linear_exec_selector_rejects_backtracking_atoms() {
        assert!(is_linear_pattern(&[
            Atom::Save(0),
            Atom::Byte(0x48),
            Atom::Skip(3)
        ]));
        assert!(!is_linear_pattern(&[Atom::Save(0), Atom::SkipRange(1, 3)]));
        assert!(!is_linear_pattern(&[Atom::Push(1), Atom::Pop]));
        assert!(!is_linear_pattern(&[Atom::Case(1), Atom::Break(0)]));
    }

    #[test]
    fn tiny_literal_jump_selector_is_strict() {
        assert!(is_tiny_literal_jump_pattern(&[
            Atom::Save(0),
            Atom::Byte(0x74),
            Atom::Jump1,
            Atom::Nop,
        ]));
        assert!(!is_tiny_literal_jump_pattern(&[
            Atom::Save(0),
            Atom::Byte(0xe8),
            Atom::Jump4,
            Atom::Nop,
        ]));
        assert!(!is_tiny_literal_jump_pattern(&[
            Atom::Byte(0xe8),
            Atom::Save(0)
        ]));
        assert!(!is_tiny_literal_jump_pattern(&[
            Atom::Save(0),
            Atom::Byte(0xe8),
            Atom::SkipRange(1, 2),
            Atom::Jump4,
        ]));
        assert!(!is_tiny_literal_jump_pattern(&[
            Atom::Save(0),
            Atom::Byte(0xe8),
            Atom::ReadU32(1),
            Atom::Jump4,
        ]));
    }

    #[test]
    fn span_index_binary_search_locates_offsets() {
        let spans = vec![
            CodeSpan {
                mapped: 5..8,
                file: 0..3,
            },
            CodeSpan {
                mapped: 12..15,
                file: 8..11,
            },
            CodeSpan {
                mapped: 30..35,
                file: 20..25,
            },
        ];

        assert_eq!(span_index_for_offset(&spans, 5), Some(0));
        assert_eq!(span_index_for_offset(&spans, 14), Some(1));
        assert_eq!(span_index_for_offset(&spans, 34), Some(2));
        assert_eq!(span_index_for_offset(&spans, 8), None);
        assert_eq!(span_index_for_offset(&spans, 100), None);
    }
}
