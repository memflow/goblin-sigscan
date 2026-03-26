use std::{ffi::CStr, ops::Range};

use goblin::elf::{
    Elf,
    program_header::{PF_X, PT_LOAD},
};
use thiserror::Error;

use crate::scan::{BinaryView, Offset, Scanner};

/// Error type returned by ELF wrapper APIs.
#[derive(Debug, Error)]
pub enum ElfError {
    #[error("failed to parse ELF: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("ELF load segment range overflows virtual address space")]
    InvalidLoadRange { vaddr: Offset, filesz: Offset },
}

/// Result alias for ELF wrapper APIs.
pub type Result<T> = std::result::Result<T, ElfError>;

/// Minimal ELF wrapper exposing pelite-like scanner behavior.
#[derive(Debug)]
pub struct ElfFile<'a> {
    bytes: &'a [u8],
    _elf: Elf<'a>,
    code_ranges: Vec<Range<Offset>>,
    load_ranges: Vec<LoadRange>,
}

#[derive(Debug, Clone, Copy)]
struct LoadRange {
    virt_start: Offset,
    virt_end: Offset,
    file_start: Offset,
}

impl<'a> ElfFile<'a> {
    /// Parses an ELF image from bytes.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
    /// let mut matches = file.scanner().matches_code(pattern);
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(bytes)?;

        let mut code_ranges = Vec::new();
        let mut load_ranges = Vec::new();

        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }

            let virt_start = ph.p_vaddr;
            let virt_end =
                virt_start
                    .checked_add(ph.p_filesz)
                    .ok_or(ElfError::InvalidLoadRange {
                        vaddr: virt_start,
                        filesz: ph.p_filesz,
                    })?;
            load_ranges.push(LoadRange {
                virt_start,
                virt_end,
                file_start: ph.p_offset,
            });

            if (ph.p_flags & PF_X) != 0 {
                code_ranges.push(virt_start..virt_end);
            }
        }

        Ok(Self {
            bytes,
            _elf: elf,
            code_ranges,
            load_ranges,
        })
    }

    /// Returns scanner access.
    pub fn scanner(&'a self) -> Scanner<'a, Self> {
        Scanner::new(self)
    }

    #[deprecated(
        note = "used only by parity-client-smoke; this helper may be removed in a future release"
    )]
    pub fn derva_c_str(&self, offset: Offset) -> Option<&'a CStr> {
        let start = self.offset_to_file_offset(offset)?;
        let tail = self.bytes.get(start..)?;
        let nul_pos = tail.iter().position(|b| *b == 0)?;
        CStr::from_bytes_with_nul(tail.get(..=nul_pos)?).ok()
    }

    fn offset_to_file_offset(&self, offset: Offset) -> Option<usize> {
        let mapped = self.load_ranges.iter().find_map(|range| {
            let delta = offset.checked_sub(range.virt_start)?;
            if offset >= range.virt_end {
                return None;
            }
            range.file_start.checked_add(delta)
        })?;
        usize::try_from(mapped).ok()
    }
}

impl BinaryView for ElfFile<'_> {
    fn code_ranges(&self) -> &[Range<Offset>] {
        &self.code_ranges
    }

    fn read_u8(&self, offset: Offset) -> Option<u8> {
        let file_offset = self.offset_to_file_offset(offset)?;
        self.bytes.get(file_offset).copied()
    }

    fn read_i32(&self, offset: Offset) -> Option<i32> {
        let file_offset = self.offset_to_file_offset(offset)?;
        let bytes = self.bytes.get(file_offset..file_offset.checked_add(4)?)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Some(i32::from_le_bytes(raw))
    }

    fn read_u32(&self, offset: Offset) -> Option<u32> {
        let file_offset = self.offset_to_file_offset(offset)?;
        let bytes = self.bytes.get(file_offset..file_offset.checked_add(4)?)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Some(u32::from_le_bytes(raw))
    }
}
