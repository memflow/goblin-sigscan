//! Shared virtual/file address mapping for the ELF and Mach-O wrappers.
//!
//! Both formats describe loadable regions as `[virt_start, virt_end)` ranges backed by
//! a file offset, and both resolve addresses identically. This module factors that out
//! and keeps a tiny single-entry lookup cache. The cache is an [`AtomicUsize`] (rather
//! than a `Cell`) so the wrappers stay `Sync` and a parsed image can be shared across
//! threads for parallel scanning.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::scan::Offset;

/// Sentinel for "no cached range yet"; real indices are always smaller.
const NO_CACHE: usize = usize::MAX;

/// A single loadable region: a mapped range backed by a file offset of equal length.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadRange {
    pub virt_start: Offset,
    pub virt_end: Offset,
    pub file_start: Offset,
}

/// An ordered set of [`LoadRange`]s with a relaxed single-entry resolution cache.
#[derive(Debug)]
pub(crate) struct LoadMap {
    ranges: Vec<LoadRange>,
    cache: AtomicUsize,
}

impl LoadMap {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            cache: AtomicUsize::new(NO_CACHE),
        }
    }

    pub fn push(&mut self, range: LoadRange) {
        self.ranges.push(range);
    }

    /// Maps a mapped offset (ELF vaddr / Mach vmaddr) to a file offset.
    pub fn offset_to_file_offset(&self, offset: Offset) -> Option<usize> {
        let cached = self.cache.load(Ordering::Relaxed);
        if cached != NO_CACHE
            && let Some(mapped) = self.lookup(cached, offset)
        {
            return usize::try_from(mapped).ok();
        }

        for index in 0..self.ranges.len() {
            if let Some(mapped) = self.lookup(index, offset) {
                self.cache.store(index, Ordering::Relaxed);
                return usize::try_from(mapped).ok();
            }
        }

        None
    }

    fn lookup(&self, index: usize, offset: Offset) -> Option<Offset> {
        let range = self.ranges.get(index)?;
        let delta = offset.checked_sub(range.virt_start)?;
        if offset >= range.virt_end {
            return None;
        }
        range.file_start.checked_add(delta)
    }

    /// Maps a file offset back to a mapped offset (ELF vaddr / Mach vmaddr).
    pub fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
        self.ranges.iter().find_map(|range| {
            let file_start = usize::try_from(range.file_start).ok()?;
            let file_size = usize::try_from(range.virt_end.checked_sub(range.virt_start)?).ok()?;
            let file_end = file_start.checked_add(file_size)?;
            if !(file_start..file_end).contains(&file_offset) {
                return None;
            }
            let delta = file_offset.checked_sub(file_start)?;
            range.virt_start.checked_add(Offset::try_from(delta).ok()?)
        })
    }
}
