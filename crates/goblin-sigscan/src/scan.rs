use std::ops::Range;

use crate::pattern::{Atom, ParsePatError, save_len};
use memchr::memchr_iter;

pub type Offset = u64;
const MAX_BACKTRACK_STATES: usize = 1_000_000;
const ANCHOR_MAX_LEN: usize = 4;
/// How far into the fixed-offset prefix the anchor search looks (bounds work on big skips).
const ANCHOR_MAP_CAP: usize = 256;

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
    /// Index of the span currently being scanned, used to seed `ExecReader` so it
    /// skips the per-candidate `find_span` binary search for in-span reads.
    current_span: Option<usize>,
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

/// Reusable scratch for uniqueness scans ([`Scanner::finds_prepared_with`]).
///
/// Holding one across repeated `finds` calls avoids re-allocating the executor scratch
/// and the second-match probe buffer on every call (e.g. scanning many patterns).
#[derive(Clone, Debug, Default)]
pub struct FindScratch {
    exec: ExecScratch,
    probe: Vec<Offset>,
}

impl FindScratch {
    /// Creates empty scratch.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Copy, Clone, Debug)]
struct PatternPlan {
    required_slots: usize,
    linear_exec: bool,
    anchor: [u8; ANCHOR_MAX_LEN],
    anchor_len: usize,
    anchor_offset: u64,
    anchor_jumps: [u8; 256],
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
    anchor_jumps: [u8; 256],
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
            anchor_jumps: plan.anchor_jumps,
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
    fn pointer_size_bytes(&self) -> u8 {
        8
    }

    #[inline]
    fn follow_pointer_target(&self, raw: Offset) -> Option<Offset> {
        self.mapped_to_file_offset(raw).map(|_| raw)
    }

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
    fn read_pointer_raw(&self, offset: Offset) -> Option<Offset> {
        match self.pointer_size_bytes() {
            4 => self.read_u32(offset).map(Offset::from),
            8 => Some(u64::from_le_bytes(self.read_array::<8>(offset)?)),
            _ => None,
        }
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
    fn new(view: &'a B, start: Offset, span_hint: Option<usize>) -> Self {
        // Seed with the caller's span; `find_span` checks the seeded index first, so a
        // correct hint avoids the binary search. A stale/None hint self-corrects.
        let mut reader = Self {
            view,
            span_index: span_hint,
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

    #[inline]
    fn read_pointer_raw(&mut self, offset: Offset, width: u8) -> Option<Offset> {
        match width {
            4 => self.read_u32(offset).map(Offset::from),
            8 => Some(u64::from_le_bytes(self.read_array::<8>(offset)?)),
            _ => None,
        }
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
        self.finds_unique(
            pat,
            plan.linear_exec,
            plan.required_slots,
            plan.anchor,
            plan.anchor_len,
            plan.anchor_offset,
            &plan.anchor_jumps,
            save,
            &mut FindScratch::new(),
        )
    }

    /// Returns the minimum required save-slot buffer length for `pat`.
    ///
    /// Allocate at least this many elements before calling [`Self::finds_code`]
    /// or [`Self::matches_code`]/[`Matches::next`].
    ///
    /// Patterns produced by `pattern::parse` and `pattern!` always require at
    /// least one slot because they include an implicit `Save(0)` base capture.
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
        self.finds_prepared_with(pat, save, &mut FindScratch::new())
    }

    /// Like [`Self::finds_prepared`] but reuses caller-provided [`FindScratch`], avoiding
    /// per-call scratch allocation across repeated uniqueness scans.
    pub fn finds_prepared_with(
        &self,
        pat: &PreparedPattern,
        save: &mut [Offset],
        scratch: &mut FindScratch,
    ) -> bool {
        debug_assert!(
            save.len() >= pat.required_slots,
            "caller-provided save buffer must cover all slots referenced by the prepared pattern"
        );
        self.finds_unique(
            &pat.atoms,
            pat.linear_exec,
            pat.required_slots,
            pat.anchor,
            pat.anchor_len,
            pat.anchor_offset,
            &pat.anchor_jumps,
            save,
            scratch,
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
            anchor_jumps: pat.anchor_jumps,
            scratch: ExecScratch::default(),
        }
    }

    /// Returns an iterator-like matcher for all code-range matches.
    ///
    /// `save` buffers passed to [`Matches::next`] must be at least
    /// `self.required_slots(pat)` elements long.
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
            anchor_jumps: plan.anchor_jumps,
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

    #[allow(clippy::too_many_arguments)]
    fn finds_unique(
        &self,
        pat: &[Atom],
        linear_exec: bool,
        required_slots: usize,
        anchor: [u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        anchor_jumps: &[u8; 256],
        save: &mut [Offset],
        scratch: &mut FindScratch,
    ) -> bool {
        // Probe buffer holds captures of the second-and-later candidate matches so the
        // first match stays in `save`. `exec` and `probe` are disjoint fields, so both can
        // be borrowed at once below.
        scratch.probe.clear();
        scratch.probe.resize(required_slots, 0);
        let mut found_once = false;

        for (span_index, span) in self.view.code_spans().iter().enumerate() {
            let mut cursor = span.mapped.start;
            loop {
                let save_buf: &mut [Offset] = if found_once {
                    &mut scratch.probe
                } else {
                    &mut save[..required_slots]
                };
                let matched = self.find_next_in_span(
                    span,
                    span_index,
                    cursor,
                    pat,
                    save_buf,
                    linear_exec,
                    &anchor,
                    anchor_len,
                    anchor_offset,
                    anchor_jumps,
                    &mut scratch.exec,
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

    #[allow(clippy::too_many_arguments)]
    fn find_next_in_span(
        &self,
        span: &CodeSpan,
        span_index: usize,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        anchor_jumps: &[u8; 256],
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        if start >= span.mapped.end {
            return None;
        }

        // Seed exec's ExecReader with this span so in-span reads skip the find_span
        // binary search.
        scratch.current_span = Some(span_index);

        if anchor_len == 0 {
            return self.scan_range_linear(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                scratch,
            );
        }
        if anchor_len < 4 {
            return self.scan_span_first_byte(
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
        self.scan_span_quick(
            span,
            start,
            pat,
            save,
            linear_exec,
            anchor,
            anchor_len,
            anchor_offset,
            anchor_jumps,
            scratch,
        )
    }

    fn scan_range_linear(
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

    #[allow(clippy::too_many_arguments)]
    fn scan_span_first_byte(
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
            return self.scan_range_first_byte(
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
            return self.scan_range_first_byte(
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
            return self.scan_range_first_byte(
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
            return self.scan_range_first_byte(
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
                && haystack
                    .get(delta..delta + anchor_len)
                    .is_none_or(|window| window != anchor_window)
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

    #[allow(clippy::too_many_arguments)]
    fn scan_range_first_byte(
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

    #[allow(clippy::too_many_arguments)]
    fn scan_span_quick(
        &self,
        span: &CodeSpan,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        anchor_jumps: &[u8; 256],
        scratch: &mut ExecScratch,
    ) -> Option<Offset> {
        let Some(bytes) = self.view.image().get(span.file.clone()) else {
            return self.scan_range_quick(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                anchor_jumps,
                scratch,
            );
        };
        let anchor_start = start.checked_add(anchor_offset)?;
        let Some(start_file) = mapped_to_file_offset(span, anchor_start) else {
            return self.scan_range_quick(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                anchor_jumps,
                scratch,
            );
        };
        let Some(start_index) = start_file.checked_sub(span.file.start) else {
            return self.scan_range_quick(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                anchor_jumps,
                scratch,
            );
        };
        let prefix = &anchor[..anchor_len];
        let Some(haystack) = bytes.get(start_index..) else {
            return self.scan_range_quick(
                span.mapped.clone(),
                start,
                pat,
                save,
                linear_exec,
                anchor,
                anchor_len,
                anchor_offset,
                anchor_jumps,
                scratch,
            );
        };
        if haystack.len() < anchor_len {
            return None;
        }

        let last = prefix[anchor_len - 1];
        let mut index = 0usize;
        let max_index = haystack.len() - anchor_len;
        while index <= max_index {
            let probe = haystack[index + anchor_len - 1];
            let jump = usize::from(anchor_jumps[usize::from(probe)].max(1));
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

    #[allow(clippy::too_many_arguments)]
    fn scan_range_quick(
        &self,
        range: Range<Offset>,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        linear_exec: bool,
        anchor: &[u8; ANCHOR_MAX_LEN],
        anchor_len: usize,
        anchor_offset: u64,
        anchor_jumps: &[u8; 256],
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

            let jump = u64::from(anchor_jumps[usize::from(probe)].max(1));
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
        let span_hint = scratch.current_span;
        scratch.reset_from_save(save);
        let work_save = &mut scratch.work_save;
        let mut cursor = start;
        let mut pc = 0usize;
        let mut fuzzy = None;
        let mut reader = ExecReader::new(self.view, cursor, span_hint);

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
                    let skip = if n == 0 {
                        u64::from(self.view.pointer_size_bytes())
                    } else {
                        u64::from(n)
                    };
                    cursor = match cursor.checked_add(skip) {
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
                Atom::Ptr => {
                    let Some(raw) = reader.read_pointer_raw(cursor, self.view.pointer_size_bytes())
                    else {
                        return false;
                    };
                    let Some(next) = self.view.follow_pointer_target(raw) else {
                        return false;
                    };
                    cursor = next;
                    pc += 1;
                }
                Atom::Pir(slot) => {
                    let Some(disp) = reader.read_i32(cursor) else {
                        return false;
                    };
                    let base = work_save.get(usize::from(slot)).copied().unwrap_or(cursor);
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

    fn exec_backtracking(
        &self,
        start: Offset,
        pat: &[Atom],
        save: &mut [Offset],
        scratch: &mut ExecScratch,
    ) -> bool {
        let span_hint = scratch.current_span;
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

        // Reuse one reader across all backtrack states; its span cache persists (and
        // self-corrects), so popped states don't each re-run find_span.
        let mut reader = ExecReader::new(self.view, start, span_hint);
        while let Some(state) = scratch.stack.pop() {
            scratch.calls.truncate(state.calls_len);
            rollback(work_save, &mut scratch.save_log, state.save_log_len);

            let mut cursor = state.cursor;
            let mut pc = state.pc;
            let mut fuzzy = state.fuzzy;
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
                        let skip = if n == 0 {
                            u64::from(self.view.pointer_size_bytes())
                        } else {
                            u64::from(n)
                        };
                        let Some(next) = cursor.checked_add(skip) else {
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
                        let skip = if skip == 0 {
                            u64::from(self.view.pointer_size_bytes())
                        } else {
                            u64::from(skip)
                        };
                        let Some(resume_cursor) = cursor.checked_add(skip) else {
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
                    Atom::Ptr => {
                        let Some(raw) =
                            reader.read_pointer_raw(cursor, self.view.pointer_size_bytes())
                        else {
                            break;
                        };
                        let Some(next) = self.view.follow_pointer_target(raw) else {
                            break;
                        };
                        cursor = next;
                        pc += 1;
                    }
                    Atom::Pir(slot) => {
                        let Some(disp) = reader.read_i32(cursor) else {
                            break;
                        };
                        let base = work_save.get(usize::from(slot)).copied().unwrap_or(cursor);
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
    anchor_jumps: [u8; 256],
    scratch: ExecScratch,
}

impl<'a, 'p, B: BinaryView> Matches<'a, 'p, B> {
    /// Advances to the next match and writes save-slot values into `save`.
    ///
    /// # Save buffer contract
    ///
    /// - `save.len()` must be at least the pattern's required slot count.
    /// - Only the required prefix is written; extra tail elements are untouched.
    /// - On `true`, `save` contains captures for the returned match.
    /// - On `false`, `save` is left unchanged.
    ///
    /// For parsed patterns (`pattern::parse` / `pattern!`), slot `0` is the
    /// match start and corresponds to the parser-inserted `Save(0)`.
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
            let matched_at = self.scanner.find_next_in_span(
                span,
                self.range_index,
                start,
                self.pat,
                save,
                self.linear_exec,
                &self.anchor,
                self.anchor_len,
                self.anchor_offset,
                &self.anchor_jumps,
                &mut self.scratch,
            );

            if let Some(cursor) = matched_at {
                self.cursor = cursor.checked_add(1);
                return true;
            }

            self.range_index += 1;
            self.cursor = None;
        }

        false
    }
}

/// Builds a map of known bytes at fixed offsets from the match start, spanning wildcards,
/// skips and reads up to the first atom that breaks fixed-offset reasoning (jumps, ranges,
/// groups, back-rewind, pointer-width skip). `None` marks a wildcard/unknown byte.
///
/// Unlike a leading-run-only prefix, this lets the anchor land on the most selective
/// literal run *anywhere* in the linear prefix. The anchor stays a pure necessary-condition
/// filter, so the full pattern execution still verifies every candidate.
fn build_offset_map(pat: &[Atom]) -> Vec<Option<u8>> {
    let mut map: Vec<Option<u8>> = Vec::new();
    let mut offset = 0usize;
    let mut masked = false;
    for atom in pat {
        if offset >= ANCHOR_MAP_CAP {
            break;
        }
        match *atom {
            Atom::Byte(byte) => {
                if map.len() <= offset {
                    map.resize(offset + 1, None);
                }
                if !masked {
                    map[offset] = Some(byte);
                }
                masked = false;
                offset += 1;
            }
            Atom::Fuzzy(_) => masked = true,
            // Skip(0) means pointer width (view-dependent), so stop the fixed map there.
            Atom::Skip(0) => break,
            Atom::Skip(n) => offset += usize::from(n),
            Atom::ReadI8(_) | Atom::ReadU8(_) => offset += 1,
            Atom::ReadI16(_) | Atom::ReadU16(_) => offset += 2,
            Atom::ReadI32(_) | Atom::ReadU32(_) => offset += 4,
            Atom::Save(_) | Atom::Aligned(_) | Atom::Nop | Atom::Zero(_) | Atom::Check(_) => {}
            _ => break,
        }
    }
    map
}

fn analyze_pattern(pat: &[Atom]) -> PatternPlan {
    let required_slots = save_len(pat);
    let linear_exec = is_linear_pattern(pat);
    let map = build_offset_map(pat);
    let (anchor, anchor_len, anchor_offset) = select_anchor_from_map(&map);
    let anchor_jumps = build_anchor_jumps(&anchor, anchor_len);
    PatternPlan {
        required_slots,
        linear_exec,
        anchor,
        anchor_len,
        anchor_offset,
        anchor_jumps,
    }
}

fn build_anchor_jumps(anchor: &[u8; ANCHOR_MAX_LEN], anchor_len: usize) -> [u8; 256] {
    let default_jump = anchor_len.max(1) as u8;
    let mut jumps = [default_jump; 256];
    for (index, byte) in anchor.iter().take(anchor_len.saturating_sub(1)).enumerate() {
        jumps[usize::from(*byte)] = (anchor_len - index - 1) as u8;
    }
    jumps
}

/// Selects the most selective fixed-size literal window from the offset map, preferring
/// longer windows (more selective for the quick search) then higher [`anchor_window_score`]
/// (ties prefer later windows). Returns the anchor bytes, its length, and its offset from
/// the match start.
fn select_anchor_from_map(map: &[Option<u8>]) -> ([u8; ANCHOR_MAX_LEN], usize, u64) {
    let mut anchor = [0u8; ANCHOR_MAX_LEN];
    for win in (1..=ANCHOR_MAX_LEN).rev() {
        if map.len() < win {
            continue;
        }
        let mut best: Option<(u32, usize)> = None;
        for start in 0..=map.len() - win {
            if !map[start..start + win].iter().all(|slot| slot.is_some()) {
                continue;
            }
            let mut buf = [0u8; ANCHOR_MAX_LEN];
            for (k, &slot) in map[start..start + win].iter().enumerate() {
                buf[k] = slot.expect("window verified to be all-some");
            }
            let score = anchor_window_score(&buf[..win]);
            match best {
                Some((best_score, _)) if score < best_score => {}
                _ => best = Some((score, start)),
            }
        }
        if let Some((_, start)) = best {
            for (k, &slot) in map[start..start + win].iter().enumerate() {
                anchor[k] = slot.expect("window verified to be all-some");
            }
            return (anchor, win, start as u64);
        }
    }
    (anchor, 0, 0)
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
    use proptest::prelude::*;

    use super::{
        BinaryView, CodeSpan, Offset, PreparedPattern, Scanner, build_offset_map,
        is_linear_pattern, select_anchor_from_map, span_index_for_offset,
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
    fn ptr_follows_mapped_target_and_captures_destination() {
        let mut bytes = vec![0x68];
        bytes.extend_from_slice(&12u64.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        let view = TestView::new(&bytes);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Byte(0x68),
            Atom::Ptr,
            Atom::Save(1),
            Atom::Byte(0x31),
            Atom::Byte(0xc0),
            Atom::Byte(0xc3),
        ];
        let mut save = [0u64; 2];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[0], 0);
        assert_eq!(save[1], 12);
    }

    #[test]
    fn ptr_fails_when_target_is_not_mapped() {
        let mut bytes = vec![0x68];
        bytes.extend_from_slice(&1024u64.to_le_bytes());
        let view = TestView::new(&bytes);
        let scanner = Scanner::new(&view);
        let pat = [Atom::Save(0), Atom::Byte(0x68), Atom::Ptr, Atom::Byte(0x90)];
        let mut save = [0u64; 1];

        assert!(!scanner.matches_code(&pat).next(&mut save));
    }

    #[test]
    fn push_zero_uses_pointer_width_for_resume_cursor() {
        let view = TestView::new(&[0xaa, 0, 0, 0, 0, 0, 0, 0, 0x55]);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Push(0),
            Atom::Byte(0xaa),
            Atom::Pop,
            Atom::Save(1),
            Atom::Byte(0x55),
        ];
        let mut save = [0u64; 2];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[1], 8);
    }

    #[test]
    fn pir_follows_saved_base_slot_with_signed_disp32() {
        let bytes = [0x90, 0x11, 0x22, 0x33, 0xfc, 0xff, 0xff, 0xff];
        let view = TestView::new(&bytes);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Skip(4),
            Atom::Save(1),
            Atom::Pir(1),
            Atom::Byte(0x90),
        ];
        let mut save = [0u64; 2];

        assert!(scanner.matches_code(&pat).next(&mut save));
        assert_eq!(save[0], 0);
        assert_eq!(save[1], 4);
    }

    #[test]
    fn pir_fails_when_disp32_cannot_be_read() {
        let bytes = [0x90, 0x01, 0x02, 0x03];
        let view = TestView::new(&bytes);
        let scanner = Scanner::new(&view);
        let pat = [
            Atom::Save(0),
            Atom::Byte(0x90),
            Atom::Pir(0),
            Atom::Byte(0x90),
        ];
        let mut save = [0u64; 1];

        assert!(!scanner.matches_code(&pat).next(&mut save));
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
    fn offset_map_spans_zero_width_atoms_and_records_byte_offsets() {
        // Save/Aligned/Nop/Check are zero-width, so the literal bytes keep their offsets.
        let map = build_offset_map(&[
            Atom::Save(0),
            Atom::Aligned(0),
            Atom::Nop,
            Atom::Byte(0xaa),
            Atom::Save(1),
            Atom::Byte(0xbb),
            Atom::Check(1),
            Atom::Byte(0xcc),
        ]);

        assert_eq!(map, vec![Some(0xaa), Some(0xbb), Some(0xcc)]);
    }

    #[test]
    fn anchor_selection_prefers_stronger_window_over_common_suffix() {
        let map: Vec<Option<u8>> = [0xde, 0xad, 0xbe, 0xef, 0x48, 0x8b, 0x05, 0x48]
            .into_iter()
            .map(Some)
            .collect();

        let (anchor, len, offset) = select_anchor_from_map(&map);
        assert_eq!(len, 4);
        assert_eq!(offset, 0);
        assert_eq!(&anchor[..len], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn anchor_selection_reaches_past_leading_wildcards() {
        // `? ? 48 8b 0d 15 7c`: the anchor must skip the leading wildcards and land on
        // the literal run (the SCAN-8 improvement over leading-run-only selection).
        let map = vec![
            None,
            None,
            Some(0x48),
            Some(0x8b),
            Some(0x0d),
            Some(0x15),
            Some(0x7c),
        ];

        let (_, len, offset) = select_anchor_from_map(&map);
        assert_eq!(len, 4);
        assert!(offset >= 2, "anchor must skip the leading wildcards");
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

    proptest! {
        #[test]
        fn parsed_single_byte_scan_matches_manual_search(
            haystack in prop::collection::vec(any::<u8>(), 0..128),
            needle in any::<u8>(),
        ) {
            let source = format!("{needle:02X}");
            let atoms = crate::pattern::parse(&source).expect("hex byte pattern should parse");
            let required_slots = crate::pattern::save_len(&atoms);

            let view = TestView::new(&haystack);
            let scanner = Scanner::new(&view);

            let expected_first = haystack
                .iter()
                .position(|byte| *byte == needle)
                .map(|index| index as u64);
            let expected_unique = haystack.iter().filter(|byte| **byte == needle).count() == 1;

            let mut iter_save = vec![0u64; required_slots];
            let mut matches = scanner.matches_code(&atoms);
            let found = matches.next(&mut iter_save);
            prop_assert_eq!(found, expected_first.is_some());
            if let Some(expected_start) = expected_first {
                prop_assert_eq!(iter_save[0], expected_start);
            }

            let mut unique_save = vec![0u64; required_slots];
            let unique = scanner.finds_code(&atoms, &mut unique_save);
            prop_assert_eq!(unique, expected_unique);
            if unique {
                prop_assert_eq!(Some(unique_save[0]), expected_first);
            }
        }
    }
}
