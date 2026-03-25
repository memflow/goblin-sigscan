use std::{ffi::CStr, ops::Range};

use goblin::pe::{
    PE,
    section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE},
};
use thiserror::Error;

use crate::scan::{BinaryView, Offset, Scanner};

/// Error type returned by PE wrapper APIs.
#[derive(Debug, Error)]
pub enum PeError {
    #[error("failed to parse PE: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("only 64-bit PE images are supported in this module")]
    NotPe64,
}

/// Result alias for PE wrapper APIs.
pub type Result<T> = std::result::Result<T, PeError>;

/// Minimal PE64 wrapper exposing pelite-like scanner behavior.
#[derive(Debug)]
pub struct PeFile<'a> {
    bytes: &'a [u8],
    pe: PE<'a>,
    code_ranges: Vec<Range<Offset>>,
}

impl<'a> PeFile<'a> {
    /// Parses a PE64 image from bytes.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let pe = PE::parse(bytes)?;
        if !pe.is_64 {
            return Err(PeError::NotPe64);
        }
        let code_ranges = pe
            .sections
            .iter()
            .filter_map(|section| {
                let is_code = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                    || (section.characteristics & IMAGE_SCN_CNT_CODE) != 0;
                if !is_code {
                    return None;
                }
                let start = u64::from(section.virtual_address);
                let end = start.checked_add(u64::from(section.size_of_raw_data))?;
                Some(start..end)
            })
            .collect();
        Ok(Self {
            bytes,
            pe,
            code_ranges,
        })
    }

    /// Returns scanner access.
    pub fn scanner(&'a self) -> Scanner<'a, Self> {
        Scanner::new(self)
    }

    /// Reads a NUL-terminated C string at a module-relative offset.
    #[deprecated(
        note = "used only by parity-client-smoke; this helper may be removed in a future release"
    )]
    pub fn derva_c_str(&self, offset: Offset) -> Option<&'a CStr> {
        let start = self.rva_to_file_offset(offset)?;
        let tail = self.bytes.get(start..)?;
        let nul_pos = tail.iter().position(|b| *b == 0)?;
        CStr::from_bytes_with_nul(tail.get(..=nul_pos)?).ok()
    }

    fn rva_to_file_offset(&self, rva: Offset) -> Option<usize> {
        let headers_end = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|oh| u64::from(oh.windows_fields.size_of_headers))
            .unwrap_or(0);
        if rva < headers_end {
            return usize::try_from(rva).ok();
        }

        self.pe.sections.iter().find_map(|section| {
            let section_rva = u64::from(section.virtual_address);
            let delta = rva.checked_sub(section_rva)?;
            if delta >= u64::from(section.size_of_raw_data) {
                return None;
            }
            let raw_start = usize::try_from(section.pointer_to_raw_data).ok()?;
            let delta_usize = usize::try_from(delta).ok()?;
            raw_start.checked_add(delta_usize)
        })
    }
}

impl BinaryView for PeFile<'_> {
    fn code_ranges(&self) -> &[Range<Offset>] {
        &self.code_ranges
    }

    fn read_u8(&self, offset: Offset) -> Option<u8> {
        let file_offset = self.rva_to_file_offset(offset)?;
        self.bytes.get(file_offset).copied()
    }

    fn read_i32(&self, offset: Offset) -> Option<i32> {
        let file_offset = self.rva_to_file_offset(offset)?;
        let bytes = self.bytes.get(file_offset..file_offset.checked_add(4)?)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Some(i32::from_le_bytes(raw))
    }

    fn read_u32(&self, offset: Offset) -> Option<u32> {
        let file_offset = self.rva_to_file_offset(offset)?;
        let bytes = self.bytes.get(file_offset..file_offset.checked_add(4)?)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Some(u32::from_le_bytes(raw))
    }
}
