//! ELF binary wrapper and scanner entry points.
//!
//! This module provides [`ElfFile`], a minimal ELF view that exposes executable
//! segment scanning via [`ElfFile::scanner`] and mapped-address helpers through
//! [`crate::MappedAddressView`]. Mapped offsets in this module are ELF virtual
//! addresses.

use std::ffi::CStr;

use goblin::elf::{
    Elf,
    program_header::{PF_X, PT_LOAD},
};
use thiserror::Error;

use crate::{
    Pod, Ptr, TypedView,
    address::MappedAddressView,
    loadmap::{LoadMap, LoadRange},
    scan::{BinaryView, CodeSpan, Offset, Scanner},
};

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
    elf: Elf<'a>,
    code_spans: Vec<CodeSpan>,
    load_map: LoadMap,
}

impl<'a> ElfFile<'a> {
    /// Parses an ELF image from bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let pattern = goblin_sigscan::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(bytes)?;

        let mut code_spans = Vec::new();
        let mut load_map = LoadMap::new();

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
            load_map.push(LoadRange {
                virt_start,
                virt_end,
                file_start: ph.p_offset,
            });

            if (ph.p_flags & PF_X) != 0 {
                let file_start = usize::try_from(ph.p_offset).ok();
                let file_size = usize::try_from(ph.p_filesz).ok();
                if let (Some(file_start), Some(file_size)) = (file_start, file_size)
                    && let Some(file_end) = file_start.checked_add(file_size)
                {
                    code_spans.push(CodeSpan {
                        mapped: virt_start..virt_end,
                        file: file_start..file_end,
                    });
                }
            }
        }

        // Sort by mapped start: the scanner's span lookups assume ascending spans.
        code_spans.sort_by_key(|span| span.mapped.start);

        Ok(Self {
            bytes,
            elf,
            code_spans,
            load_map,
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
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let pattern = goblin_sigscan::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
    /// ```
    pub fn scanner(&'a self) -> Scanner<'a, Self> {
        Scanner::new(self)
    }

    /// Returns the parsed underlying goblin ELF object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let _segments = file.elf().program_headers.len();
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn elf(&self) -> &Elf<'a> {
        &self.elf
    }

    /// Returns the original image bytes.
    #[inline]
    pub fn image(&self) -> &'a [u8] {
        self.bytes
    }

    /// Converts a virtual address into a file offset.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let Some(vaddr) = file.file_offset_to_vaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _file_offset = file.vaddr_to_file_offset(vaddr);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn vaddr_to_file_offset(&self, vaddr: Offset) -> Option<usize> {
        self.offset_to_file_offset(vaddr)
    }

    /// Converts a file offset into a virtual address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let _vaddr = file.file_offset_to_vaddr(0x1000);
    ///     Ok(())
    /// }
    /// ```
    pub fn file_offset_to_vaddr(&self, file_offset: usize) -> Option<Offset> {
        self.load_map.file_offset_to_mapped(file_offset)
    }

    /// Reads a borrowed POD reference from a virtual address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let Some(vaddr) = file.file_offset_to_vaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _value = file.deref_vaddr::<u32>(vaddr);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn deref_vaddr<T: Pod>(&self, vaddr: u64) -> Option<&T> {
        self.deref(self.ptr_from_vaddr(vaddr))
    }

    /// Reads a copied POD value from a virtual address.
    #[inline]
    pub fn deref_copy_vaddr<T: Pod>(&self, vaddr: u64) -> Option<T> {
        self.deref_copy(self.ptr_from_vaddr(vaddr))
    }

    /// Builds a typed pointer from a virtual address.
    #[inline]
    pub fn ptr_from_vaddr<T: ?Sized>(&self, vaddr: u64) -> Ptr<T> {
        Ptr::from_mapped(vaddr)
    }

    /// Reads a NUL-terminated C string at a virtual address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_sigscan::elf::ElfFile::from_bytes(bytes)?;
    ///     let Some(vaddr) = file.file_offset_to_vaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _name = file
    ///         .deref_c_str_vaddr(vaddr)
    ///         .and_then(|value| value.to_str().ok());
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn deref_c_str_vaddr(&self, vaddr: u64) -> Option<&CStr> {
        self.deref_c_str(self.ptr_from_vaddr::<u8>(vaddr).cast())
    }

    fn offset_to_file_offset(&self, offset: Offset) -> Option<usize> {
        self.load_map.offset_to_file_offset(offset)
    }
}

impl MappedAddressView for ElfFile<'_> {
    #[inline]
    fn image(&self) -> &[u8] {
        self.bytes
    }

    #[inline]
    fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize> {
        self.vaddr_to_file_offset(mapped_offset)
    }

    #[inline]
    fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
        self.file_offset_to_vaddr(file_offset)
    }
}

impl BinaryView for ElfFile<'_> {
    fn image(&self) -> &[u8] {
        self.bytes
    }

    fn code_spans(&self) -> &[CodeSpan] {
        &self.code_spans
    }

    fn mapped_to_file_offset(&self, offset: Offset) -> Option<usize> {
        self.offset_to_file_offset(offset)
    }

    fn pointer_size_bytes(&self) -> u8 {
        // 32-bit ELFs are accepted here, so report the true pointer width instead of
        // the 8-byte default; `*` (`Ptr`), `Skip(0)`, and `Push(0)` depend on it.
        if self.elf.is_64 { 8 } else { 4 }
    }
}
