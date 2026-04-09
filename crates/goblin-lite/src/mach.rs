use std::{cell::Cell, ffi::CStr};

use goblin::mach::{Mach, SingleArch, constants::VM_PROT_EXECUTE};
use thiserror::Error;

use crate::{
    Pod, Ptr, TypedView,
    address::MappedAddressView,
    scan::{BinaryView, CodeSpan, Offset, Scanner},
};

/// Error type returned by Mach-O wrapper APIs.
#[derive(Debug, Error)]
pub enum MachError {
    #[error("failed to parse Mach-O: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("fat Mach-O had no parseable binary architecture")]
    NoBinaryArch,
    #[error("Mach-O segment range overflows virtual address space")]
    InvalidLoadRange { vmaddr: Offset, filesize: Offset },
}

/// Result alias for Mach-O wrapper APIs.
pub type Result<T> = std::result::Result<T, MachError>;

/// Minimal Mach-O wrapper exposing pelite-like scanner behavior.
#[derive(Debug)]
pub struct MachFile<'a> {
    bytes: &'a [u8],
    mach: Mach<'a>,
    code_spans: Vec<CodeSpan>,
    load_ranges: Vec<LoadRange>,
    load_lookup_cache: Cell<Option<usize>>,
}

#[derive(Debug, Clone, Copy)]
struct LoadRange {
    virt_start: Offset,
    virt_end: Offset,
    file_start: Offset,
}

impl<'a> MachFile<'a> {
    /// Parses a Mach-O image from bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let pattern = goblin_lite::pattern::parse("90")?;
    ///     let mut matches = file.scanner().matches_code(&pattern);
    ///     let mut save = [0u64; 4];
    ///     let _ = matches.next(&mut save);
    ///     Ok(())
    /// }
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let mach = Mach::parse(bytes)?;

        let mut code_spans = Vec::new();
        let mut load_ranges = Vec::new();

        match &mach {
            Mach::Binary(binary) => {
                collect_ranges(binary.segments.iter(), &mut code_spans, &mut load_ranges)?;
            }
            Mach::Fat(fat) => {
                let mut found = false;
                for index in 0..fat.narches {
                    let arch = fat.get(index)?;
                    if let SingleArch::MachO(binary) = arch {
                        collect_ranges(binary.segments.iter(), &mut code_spans, &mut load_ranges)?;
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(MachError::NoBinaryArch);
                }
            }
        }

        Ok(Self {
            bytes,
            mach,
            code_spans,
            load_ranges,
            load_lookup_cache: Cell::new(None),
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
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
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

    /// Returns the parsed underlying goblin Mach object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let _is_fat = matches!(file.mach(), goblin::mach::Mach::Fat(_));
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn mach(&self) -> &Mach<'a> {
        &self.mach
    }

    /// Returns the original image bytes.
    #[inline]
    pub fn image(&self) -> &'a [u8] {
        self.bytes
    }

    /// Converts a VM address into a file offset.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let Some(vmaddr) = file.file_offset_to_vmaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _file_offset = file.vmaddr_to_file_offset(vmaddr);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn vmaddr_to_file_offset(&self, vmaddr: Offset) -> Option<usize> {
        self.offset_to_file_offset(vmaddr)
    }

    /// Converts a file offset into a VM address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let _vmaddr = file.file_offset_to_vmaddr(0x1000);
    ///     Ok(())
    /// }
    /// ```
    pub fn file_offset_to_vmaddr(&self, file_offset: usize) -> Option<Offset> {
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

    /// Reads a borrowed POD reference from a VM address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let Some(vmaddr) = file.file_offset_to_vmaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _value = file.deref_vmaddr::<u32>(vmaddr);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn deref_vmaddr<T: Pod>(&self, vmaddr: u64) -> Option<&T> {
        self.deref(self.ptr_from_vmaddr(vmaddr))
    }

    /// Reads a copied POD value from a VM address.
    #[inline]
    pub fn deref_copy_vmaddr<T: Pod>(&self, vmaddr: u64) -> Option<T> {
        self.deref_copy(self.ptr_from_vmaddr(vmaddr))
    }

    /// Builds a typed pointer from a VM address.
    #[inline]
    pub fn ptr_from_vmaddr<T: ?Sized>(&self, vmaddr: u64) -> Ptr<T> {
        Ptr::from_mapped(vmaddr)
    }

    /// Reads a NUL-terminated C string at a VM address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // Use real module bytes in production code.
    ///     let bytes: &[u8] = &[];
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let Some(vmaddr) = file.file_offset_to_vmaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _name = file
    ///         .deref_c_str_vmaddr(vmaddr)
    ///         .and_then(|value| value.to_str().ok());
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn deref_c_str_vmaddr(&self, vmaddr: u64) -> Option<&CStr> {
        self.deref_c_str(self.ptr_from_vmaddr::<u8>(vmaddr).cast())
    }

    fn offset_to_file_offset(&self, offset: Offset) -> Option<usize> {
        if let Some(index) = self.load_lookup_cache.get()
            && let Some(mapped) = self.lookup_mapped_file_offset(index, offset)
        {
            return usize::try_from(mapped).ok();
        }

        let mut mapped = None;
        for (index, _) in self.load_ranges.iter().enumerate() {
            if let Some(value) = self.lookup_mapped_file_offset(index, offset) {
                self.load_lookup_cache.set(Some(index));
                mapped = Some(value);
                break;
            }
        }

        let mapped = mapped?;
        usize::try_from(mapped).ok()
    }

    fn lookup_mapped_file_offset(&self, index: usize, offset: Offset) -> Option<Offset> {
        let range = self.load_ranges.get(index)?;
        let delta = offset.checked_sub(range.virt_start)?;
        if offset >= range.virt_end {
            return None;
        }
        range.file_start.checked_add(delta)
    }
}

impl MappedAddressView for MachFile<'_> {
    #[inline]
    fn image(&self) -> &[u8] {
        self.bytes
    }

    #[inline]
    fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize> {
        self.vmaddr_to_file_offset(mapped_offset)
    }

    #[inline]
    fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
        self.file_offset_to_vmaddr(file_offset)
    }
}

impl BinaryView for MachFile<'_> {
    fn image(&self) -> &[u8] {
        self.bytes
    }

    fn code_spans(&self) -> &[CodeSpan] {
        &self.code_spans
    }

    fn mapped_to_file_offset(&self, offset: Offset) -> Option<usize> {
        self.offset_to_file_offset(offset)
    }
}

fn collect_ranges<'a, I>(
    segments: I,
    code_spans: &mut Vec<CodeSpan>,
    load_ranges: &mut Vec<LoadRange>,
) -> Result<()>
where
    I: Iterator<Item = &'a goblin::mach::segment::Segment<'a>>,
{
    for segment in segments {
        let virt_start = segment.vmaddr;
        let virt_end =
            virt_start
                .checked_add(segment.filesize)
                .ok_or(MachError::InvalidLoadRange {
                    vmaddr: virt_start,
                    filesize: segment.filesize,
                })?;
        load_ranges.push(LoadRange {
            virt_start,
            virt_end,
            file_start: segment.fileoff,
        });

        if (segment.initprot & VM_PROT_EXECUTE) != 0 {
            let file_start = usize::try_from(segment.fileoff).ok();
            let file_size = usize::try_from(segment.filesize).ok();
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

    Ok(())
}
