use std::{ffi::CStr, ops::Range};

use goblin::elf::{
    Elf,
    program_header::{PF_X, PT_LOAD},
};
use thiserror::Error;

use crate::{
    Pod, Ptr, TypedView,
    address::MappedAddressView,
    scan::{BinaryView, Offset, Scanner},
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
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
    ///     let pattern = goblin_lite::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
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
            elf,
            code_ranges,
            load_ranges,
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
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

    /// Returns the parsed underlying goblin ELF object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
    ///     let _vaddr = file.file_offset_to_vaddr(0x1000);
    ///     Ok(())
    /// }
    /// ```
    pub fn file_offset_to_vaddr(&self, file_offset: usize) -> Option<Offset> {
        self.load_ranges.iter().find_map(|range| {
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

    /// Reads a borrowed POD reference from a virtual address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_coredump.x86_64.so"
    ///     ));
    ///     let file = goblin_lite::elf::ElfFile::from_bytes(bytes)?;
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
    fn code_ranges(&self) -> &[Range<Offset>] {
        &self.code_ranges
    }

    fn read_u8(&self, offset: Offset) -> Option<u8> {
        let file_offset = self.offset_to_file_offset(offset)?;
        self.bytes.get(file_offset).copied()
    }

    fn read_i32(&self, offset: Offset) -> Option<i32> {
        self.read_le(offset)
    }

    fn read_u32(&self, offset: Offset) -> Option<u32> {
        self.read_le(offset)
    }
}
