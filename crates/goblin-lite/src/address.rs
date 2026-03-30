use std::ffi::CStr;

use crate::scan::Offset;

/// Primitive type that can be decoded from little-endian bytes.
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
