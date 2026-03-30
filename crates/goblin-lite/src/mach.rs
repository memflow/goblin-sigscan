use std::{ffi::CStr, ops::Range};

use goblin::mach::{constants::VM_PROT_EXECUTE, Mach, SingleArch};
use thiserror::Error;

use crate::{
    address::{FromLeBytes, MappedAddressView},
    scan::{BinaryView, Offset, Scanner},
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
    code_ranges: Vec<Range<Offset>>,
    load_ranges: Vec<LoadRange>,
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
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

        let mut code_ranges = Vec::new();
        let mut load_ranges = Vec::new();

        match &mach {
            Mach::Binary(binary) => {
                collect_ranges(binary.segments.iter(), &mut code_ranges, &mut load_ranges)?;
            }
            Mach::Fat(fat) => {
                let mut found = false;
                for index in 0..fat.narches {
                    let arch = fat.get(index)?;
                    if let SingleArch::MachO(binary) = arch {
                        collect_ranges(binary.segments.iter(), &mut code_ranges, &mut load_ranges)?;
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
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
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
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
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

    /// Reads a copied little-endian value from a VM address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let Some(vmaddr) = file.file_offset_to_vmaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _value = file.read_vmaddr::<u32>(vmaddr);
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn read_vmaddr<T: FromLeBytes>(&self, vmaddr: Offset) -> Option<T> {
        self.read_le(vmaddr)
    }

    /// Reads a NUL-terminated C string at a VM address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::error::Error;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     let bytes = include_bytes!(concat!(
    ///         env!("CARGO_MANIFEST_DIR"),
    ///         "/fixtures/libmemflow_native.aarch64.dylib"
    ///     ));
    ///     let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    ///     let Some(vmaddr) = file.file_offset_to_vmaddr(0x1000) else {
    ///         return Ok(());
    ///     };
    ///     let _name = file.dvmaddr_c_str(vmaddr).and_then(|value| value.to_str().ok());
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn dvmaddr_c_str(&self, vmaddr: Offset) -> Option<&CStr> {
        self.mapped_c_str(vmaddr)
    }

    /// Backward-compatible alias for existing call sites.
    #[inline]
    pub fn derva_c_str(&self, offset: Offset) -> Option<&CStr> {
        self.dvmaddr_c_str(offset)
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
    fn code_ranges(&self) -> &[Range<Offset>] {
        &self.code_ranges
    }

    fn read_u8(&self, offset: Offset) -> Option<u8> {
        let file_offset = self.offset_to_file_offset(offset)?;
        self.bytes.get(file_offset).copied()
    }

    fn read_i32(&self, offset: Offset) -> Option<i32> {
        self.read_vmaddr(offset)
    }

    fn read_u32(&self, offset: Offset) -> Option<u32> {
        self.read_vmaddr(offset)
    }
}

fn collect_ranges<'a, I>(
    segments: I,
    code_ranges: &mut Vec<Range<Offset>>,
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
            code_ranges.push(virt_start..virt_end);
        }
    }

    Ok(())
}
