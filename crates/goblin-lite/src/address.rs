use std::ffi::CStr;

use crate::scan::Offset;

/// Primitive type that can be decoded from little-endian bytes.
///
/// # Examples
///
/// ```
/// use goblin_lite::FromLeBytes;
///
/// let value = u32::from_le_slice(&[0x78, 0x56, 0x34, 0x12]);
/// assert_eq!(value, 0x1234_5678);
/// ```
pub trait FromLeBytes: Sized {
    const SIZE: usize;

    fn from_le_slice(bytes: &[u8]) -> Self;
}

macro_rules! impl_from_le_bytes {
    ($ty:ty, $size:expr) => {
        impl FromLeBytes for $ty {
            const SIZE: usize = $size;

            fn from_le_slice(bytes: &[u8]) -> Self {
                debug_assert_eq!(
                    bytes.len(),
                    Self::SIZE,
                    "read helper always slices exactly SIZE bytes"
                );
                let mut raw = [0u8; $size];
                raw.copy_from_slice(bytes);
                <$ty>::from_le_bytes(raw)
            }
        }
    };
}

impl_from_le_bytes!(u8, 1);
impl_from_le_bytes!(i8, 1);
impl_from_le_bytes!(u16, 2);
impl_from_le_bytes!(i16, 2);
impl_from_le_bytes!(u32, 4);
impl_from_le_bytes!(i32, 4);
impl_from_le_bytes!(u64, 8);
impl_from_le_bytes!(i64, 8);

/// Shared mapped-address helpers used by PE/ELF/Mach wrappers.
///
/// This trait operates on module-relative mapped offsets (RVA/virtual address/VM address,
/// depending on the concrete format wrapper).
///
/// # Examples
///
/// ```no_run
/// use std::error::Error;
///
/// use goblin_lite::{MappedAddressView, pe64::PeFile};
///
/// fn main() -> Result<(), Box<dyn Error>> {
///     let bytes = include_bytes!(concat!(
///         env!("CARGO_MANIFEST_DIR"),
///         "/fixtures/memflow_coredump.x86_64.dll"
///     ));
///     let file = PeFile::from_bytes(bytes)?;
///     let Some(rva) = file.file_offset_to_mapped(0x1000) else {
///         return Ok(());
///     };
///     let _value = file.read_le::<u32>(rva);
///     let _name = file.mapped_c_str(rva).and_then(|value| value.to_str().ok());
///     Ok(())
/// }
/// ```
pub trait MappedAddressView {
    /// Returns the underlying binary image bytes.
    fn image(&self) -> &[u8];

    /// Converts a mapped/module-relative offset into a file offset.
    fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize>;

    /// Converts a file offset into a mapped/module-relative offset.
    fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset>;

    /// Reads a mapped byte range.
    fn mapped_slice(&self, mapped_offset: Offset, size: usize) -> Option<&[u8]> {
        let file_offset = self.mapped_to_file_offset(mapped_offset)?;
        let end = file_offset.checked_add(size)?;
        self.image().get(file_offset..end)
    }

    /// Reads a copied primitive value at a mapped offset.
    fn read_le<T: FromLeBytes>(&self, mapped_offset: Offset) -> Option<T> {
        let bytes = self.mapped_slice(mapped_offset, T::SIZE)?;
        Some(T::from_le_slice(bytes))
    }

    /// Reads a NUL-terminated C string at a mapped offset.
    fn mapped_c_str(&self, mapped_offset: Offset) -> Option<&CStr> {
        let file_offset = self.mapped_to_file_offset(mapped_offset)?;
        let tail = self.image().get(file_offset..)?;
        let nul_pos = tail.iter().position(|byte| *byte == 0)?;
        CStr::from_bytes_with_nul(tail.get(..=nul_pos)?).ok()
    }
}
