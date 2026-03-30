use std::{ffi::CStr, ops::Range};

use goblin::pe::{
    PE,
    section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE},
};
use thiserror::Error;

use crate::{
    address::{FromLeBytes, MappedAddressView},
    scan::{BinaryView, Offset, Scanner},
};

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

    /// Returns the original image bytes.
    pub fn image(&self) -> &'a [u8] {
        self.bytes
    }

    /// Reads a copied little-endian value from an RVA.
    pub fn read_rva<T: FromLeBytes>(&self, rva: Offset) -> Option<T> {
        self.read_le(rva)
    }

    /// Converts an RVA into a virtual address.
    pub fn rva_to_va(&self, rva: Offset) -> Option<Offset> {
        let image_base = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|header| header.windows_fields.image_base)?;
        image_base.checked_add(rva)
    }

    /// Converts a virtual address into an RVA.
    pub fn va_to_rva(&self, va: Offset) -> Option<Offset> {
        let image_base = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|header| header.windows_fields.image_base)?;
        let rva = va.checked_sub(image_base)?;
        self.rva_to_file_offset(rva).map(|_| rva)
    }

    /// Reads a NUL-terminated C string at a module-relative offset.
    /// Reads a NUL-terminated C string at an RVA.
    pub fn derva_c_str(&self, rva: Offset) -> Option<&CStr> {
        self.mapped_c_str(rva)
    }

    /// Converts an RVA into a file offset.
    pub fn rva_to_file_offset(&self, rva: Offset) -> Option<usize> {
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

    /// Converts a file offset into an RVA.
    pub fn file_offset_to_rva(&self, file_offset: usize) -> Option<Offset> {
        let headers_end = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|header| usize::try_from(header.windows_fields.size_of_headers).ok())
            .flatten()
            .unwrap_or(0);
        if file_offset < headers_end {
            return Offset::try_from(file_offset).ok();
        }

        self.pe.sections.iter().find_map(|section| {
            let raw_start = usize::try_from(section.pointer_to_raw_data).ok()?;
            let raw_size = usize::try_from(section.size_of_raw_data).ok()?;
            let raw_end = raw_start.checked_add(raw_size)?;
            if !(raw_start..raw_end).contains(&file_offset) {
                return None;
            }
            let delta = file_offset.checked_sub(raw_start)?;
            let section_rva = Offset::from(section.virtual_address);
            section_rva.checked_add(Offset::try_from(delta).ok()?)
        })
    }
}

impl MappedAddressView for PeFile<'_> {
    fn image(&self) -> &[u8] {
        self.bytes
    }

    fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize> {
        self.rva_to_file_offset(mapped_offset)
    }

    fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
        self.file_offset_to_rva(file_offset)
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
        self.read_rva(offset)
    }

    fn read_u32(&self, offset: Offset) -> Option<u32> {
        self.read_rva(offset)
    }
}
