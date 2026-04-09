use std::{cell::Cell, ffi::CStr};

use goblin::pe::{
    PE,
    section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE},
};
use thiserror::Error;

use crate::{
    Pod, Ptr, TypedView,
    address::MappedAddressView,
    scan::{BinaryView, CodeSpan, Offset, Scanner},
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
    code_spans: Vec<CodeSpan>,
    section_lookup_cache: Cell<Option<usize>>,
}

impl<'a> PeFile<'a> {
    /// Parses a PE64 image from bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let pattern = goblin_lite::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let pe = PE::parse(bytes)?;
        if !pe.is_64 {
            return Err(PeError::NotPe64);
        }
        let code_spans = pe
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
                let file_start = usize::try_from(section.pointer_to_raw_data).ok()?;
                let file_size = usize::try_from(section.size_of_raw_data).ok()?;
                let file_end = file_start.checked_add(file_size)?;
                Some(CodeSpan {
                    mapped: start..end,
                    file: file_start..file_end,
                })
            })
            .collect();
        Ok(Self {
            bytes,
            pe,
            code_spans,
            section_lookup_cache: Cell::new(None),
        })
    }

    /// Returns scanner access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let pattern = goblin_lite::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
    /// ```
    pub fn scanner(&'a self) -> Scanner<'a, Self> {
        Scanner::new(self)
    }

    /// Returns the parsed underlying goblin PE object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let _sections = file.pe().sections.len();
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn pe(&self) -> &PE<'a> {
        &self.pe
    }

    /// Returns the original image bytes.
    #[inline]
    pub fn image(&self) -> &'a [u8] {
        self.bytes
    }

    /// Reads a borrowed POD reference from an RVA.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let Some(rva) = file.file_offset_to_rva(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _value = file.deref_rva::<u32>(rva);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn deref_rva<T: Pod>(&self, rva: u64) -> Option<&T> {
        self.deref(self.ptr_from_rva(rva))
    }

    /// Reads a copied POD value from an RVA.
    #[inline]
    pub fn deref_copy_rva<T: Pod>(&self, rva: u64) -> Option<T> {
        self.deref_copy(self.ptr_from_rva(rva))
    }

    /// Reads a NUL-terminated C string at an RVA.
    #[inline]
    pub fn deref_c_str_rva(&self, rva: u64) -> Option<&CStr> {
        self.deref_c_str(self.ptr_from_rva::<u8>(rva).cast())
    }

    /// Reads a borrowed POD reference from a virtual address.
    #[inline]
    pub fn deref_va<T: Pod>(&self, va: u64) -> Option<&T> {
        self.deref_rva(self.va_to_rva(va)?)
    }

    /// Reads a copied POD value from a virtual address.
    #[inline]
    pub fn deref_copy_va<T: Pod>(&self, va: u64) -> Option<T> {
        self.deref_copy_rva(self.va_to_rva(va)?)
    }

    /// Reads a NUL-terminated C string at a virtual address.
    #[inline]
    pub fn deref_c_str_va(&self, va: u64) -> Option<&CStr> {
        self.deref_c_str_rva(self.va_to_rva(va)?)
    }

    /// Builds a typed pointer from an RVA.
    #[inline]
    pub fn ptr_from_rva<T: ?Sized>(&self, rva: u64) -> Ptr<T> {
        Ptr::from_mapped(rva)
    }

    /// Builds a typed pointer from a virtual address.
    #[inline]
    pub fn ptr_from_va<T: ?Sized>(&self, va: u64) -> Option<Ptr<T>> {
        self.va_to_rva(va).map(Ptr::from_mapped)
    }

    /// Converts an RVA into a virtual address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let _va = file.rva_to_va(0x1000);
    ///     Ok(())
    /// }
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let Some(base) = file.rva_to_va(0) else {
    ///         return Ok(());
    ///     };
    ///     let _rva = file.va_to_rva(base + 0x1000);
    ///     Ok(())
    /// }
    /// ```
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

    /// Converts an RVA into a file offset.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let _file_offset = file.rva_to_file_offset(0x1000);
    ///     Ok(())
    /// }
    /// ```
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

        if let Some(index) = self.section_lookup_cache.get()
            && let Some(file_offset) = self.section_file_offset(index, rva)
        {
            return Some(file_offset);
        }

        for (index, _) in self.pe.sections.iter().enumerate() {
            if let Some(file_offset) = self.section_file_offset(index, rva) {
                self.section_lookup_cache.set(Some(index));
                return Some(file_offset);
            }
        }

        None
    }

    /// Converts a file offset into an RVA.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::pe64::PeFile::from_bytes(bytes)?;
    ///     let _rva = file.file_offset_to_rva(0x1000);
    ///     Ok(())
    /// }
    /// ```
    pub fn file_offset_to_rva(&self, file_offset: usize) -> Option<Offset> {
        let headers_end = self
            .pe
            .header
            .optional_header
            .as_ref()
            .and_then(|header| usize::try_from(header.windows_fields.size_of_headers).ok())
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

    fn section_file_offset(&self, index: usize, rva: Offset) -> Option<usize> {
        let section = self.pe.sections.get(index)?;
        let section_rva = u64::from(section.virtual_address);
        let delta = rva.checked_sub(section_rva)?;
        if delta >= u64::from(section.size_of_raw_data) {
            return None;
        }
        let raw_start = usize::try_from(section.pointer_to_raw_data).ok()?;
        let delta_usize = usize::try_from(delta).ok()?;
        raw_start.checked_add(delta_usize)
    }
}

impl MappedAddressView for PeFile<'_> {
    #[inline]
    fn image(&self) -> &[u8] {
        self.bytes
    }

    #[inline]
    fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize> {
        self.rva_to_file_offset(mapped_offset)
    }

    #[inline]
    fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
        self.file_offset_to_rva(file_offset)
    }
}

impl BinaryView for PeFile<'_> {
    fn image(&self) -> &[u8] {
        self.bytes
    }

    fn code_spans(&self) -> &[CodeSpan] {
        &self.code_spans
    }

    fn mapped_to_file_offset(&self, offset: Offset) -> Option<usize> {
        self.rva_to_file_offset(offset)
    }

    #[inline]
    fn follow_pointer_target(&self, raw: Offset) -> Option<Offset> {
        let rva = self.va_to_rva(raw)?;
        self.rva_to_file_offset(rva).map(|_| rva)
    }
}
