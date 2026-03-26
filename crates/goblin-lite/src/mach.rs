use std::{ffi::CStr, ops::Range};

use goblin::mach::{Mach, SingleArch, constants::VM_PROT_EXECUTE};
use thiserror::Error;

use crate::scan::{BinaryView, Offset, Scanner};

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
    /// ```ignore
    /// let file = goblin_lite::mach::MachFile::from_bytes(bytes)?;
    /// let mut matches = file.scanner().matches_code(pattern);
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let mach = Mach::parse(bytes)?;

        let mut code_ranges = Vec::new();
        let mut load_ranges = Vec::new();

        match mach {
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

impl BinaryView for MachFile<'_> {
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
