use std::{ffi::CStr, marker::PhantomData, mem};

use bytemuck::pod_read_unaligned;

use crate::{MappedAddressView, Offset};

/// Virtual address compatibility alias.
pub type Va = u64;

/// Marker trait for plain-old-data values that can be read from bytes.
pub trait Pod: bytemuck::Pod {}

impl<T: bytemuck::Pod> Pod for T {}

/// Typed mapped pointer into a parsed binary image.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ptr<T: ?Sized> {
    mapped: Offset,
    _marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> Copy for Ptr<T> {}

impl<T: ?Sized> Clone for Ptr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Ptr<T> {
    /// Creates a null pointer.
    #[inline]
    pub const fn null() -> Self {
        Self {
            mapped: 0,
            _marker: PhantomData,
        }
    }

    /// Creates a pointer from a mapped address.
    #[inline]
    pub const fn from_mapped(mapped: Offset) -> Self {
        Self {
            mapped,
            _marker: PhantomData,
        }
    }

    /// Returns `true` when this pointer is null.
    #[inline]
    pub const fn is_null(self) -> bool {
        self.mapped == 0
    }

    /// Returns the mapped address carried by this pointer.
    #[inline]
    pub const fn addr(self) -> Offset {
        self.mapped
    }

    /// Reinterprets this pointer as another pointee type.
    #[inline]
    pub const fn cast<U: ?Sized>(self) -> Ptr<U> {
        Ptr::from_mapped(self.mapped)
    }

    /// Adds a byte offset and returns a pointer to another type.
    #[inline]
    pub fn offset<U: ?Sized>(self, bytes: Offset) -> Option<Ptr<U>> {
        self.mapped.checked_add(bytes).map(Ptr::from_mapped)
    }
}

/// Typed read helpers for any mapped-address view.
pub trait TypedView: MappedAddressView {
    /// Reads a copied POD value from mapped offset, allowing unaligned data.
    fn read_pod_copy<T: Pod>(&self, mapped: Offset) -> Option<T> {
        let bytes = self.mapped_slice_strict(mapped, mem::size_of::<T>())?;
        Some(pod_read_unaligned(bytes))
    }

    /// Reads a copied POD value from a typed pointer, allowing unaligned data.
    #[inline]
    fn deref_copy<T: Pod>(&self, ptr: Ptr<T>) -> Option<T> {
        self.read_pod_copy(ptr.addr())
    }

    /// Reads a borrowed POD reference from a typed pointer.
    ///
    /// Returns `None` when bytes are out-of-bounds, non-contiguous in mapped space,
    /// or not aligned for `T`.
    fn deref<T: Pod>(&self, ptr: Ptr<T>) -> Option<&T> {
        let bytes = self.mapped_slice_strict(ptr.addr(), mem::size_of::<T>())?;
        bytemuck::try_from_bytes::<T>(bytes).ok()
    }

    /// Reads a NUL-terminated C string from a typed pointer.
    #[inline]
    fn deref_c_str(&self, ptr: Ptr<CStr>) -> Option<&CStr> {
        if ptr.is_null() {
            return None;
        }
        self.mapped_c_str(ptr.addr())
    }

    fn mapped_slice_strict(&self, mapped: Offset, size: usize) -> Option<&[u8]> {
        let file_start = self.mapped_to_file_offset(mapped)?;
        if size == 0 {
            return self.image().get(file_start..file_start);
        }

        let width_minus_one = size.checked_sub(1)?;
        let mapped_span = Offset::try_from(width_minus_one).ok()?;
        let mapped_end = mapped.checked_add(mapped_span)?;
        let file_end = self.mapped_to_file_offset(mapped_end)?;
        let expected_end = file_start.checked_add(width_minus_one)?;
        if file_end != expected_end {
            return None;
        }

        let file_end_exclusive = file_start.checked_add(size)?;
        self.image().get(file_start..file_end_exclusive)
    }
}

impl<T: MappedAddressView + ?Sized> TypedView for T {}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::{Ptr, TypedView};
    use crate::{MappedAddressView, Offset};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    struct Pair {
        a: u16,
        b: u16,
    }

    #[derive(Debug)]
    struct TestView {
        bytes: Vec<u8>,
    }

    impl MappedAddressView for TestView {
        fn image(&self) -> &[u8] {
            &self.bytes
        }

        fn mapped_to_file_offset(&self, mapped_offset: Offset) -> Option<usize> {
            if mapped_offset >= 100 && mapped_offset < 108 {
                return usize::try_from(mapped_offset - 100).ok();
            }
            if mapped_offset >= 200 && mapped_offset < 204 {
                return usize::try_from(mapped_offset - 192).ok();
            }
            None
        }

        fn file_offset_to_mapped(&self, file_offset: usize) -> Option<Offset> {
            if file_offset < 8 {
                return Offset::try_from(file_offset).ok().map(|value| value + 100);
            }
            if (8..12).contains(&file_offset) {
                return Offset::try_from(file_offset).ok().map(|value| value + 192);
            }
            None
        }
    }

    #[test]
    fn ptr_helpers_behave_as_expected() {
        let ptr = Ptr::<u32>::from_mapped(0x1000);
        assert!(!ptr.is_null());
        assert_eq!(ptr.addr(), 0x1000);
        assert_eq!(Ptr::<u32>::null().addr(), 0);
        assert!(Ptr::<u32>::null().is_null());

        let cast = ptr.cast::<u8>();
        assert_eq!(cast.addr(), 0x1000);

        let next = ptr.offset::<u32>(8).expect("offset should not overflow");
        assert_eq!(next.addr(), 0x1008);
        assert!(ptr.offset::<u32>(u64::MAX).is_none());
    }

    #[test]
    fn read_pod_copy_accepts_unaligned_data() {
        let view = TestView {
            bytes: vec![0xFF, 0x22, 0x11, 0x44, 0x33, 0, 0, 0, 0, 0, 0, 0],
        };
        let value = view
            .read_pod_copy::<Pair>(101)
            .expect("unaligned POD reads should use copy path");
        assert_eq!(
            value,
            Pair {
                a: 0x1122,
                b: 0x3344
            }
        );
    }

    #[test]
    fn deref_requires_alignment() {
        let view = TestView {
            bytes: vec![0, 0x22, 0x11, 0x44, 0x33, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(view.deref::<Pair>(Ptr::from_mapped(101)).is_none());
        assert!(view.deref::<Pair>(Ptr::from_mapped(100)).is_some());
    }

    #[test]
    fn strict_slice_rejects_mapped_holes() {
        let view = TestView {
            bytes: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0],
        };
        assert!(view.read_pod_copy::<u32>(106).is_none());
    }

    #[test]
    fn deref_c_str_works_for_non_null_ptrs() {
        let view = TestView {
            bytes: vec![0, 0, 0, 0, 0, 0, 0, 0, b'f', b'o', b'o', 0],
        };
        let ptr = Ptr::<u8>::from_mapped(200).cast::<CStr>();
        let value = view
            .deref_c_str(ptr)
            .expect("valid mapped C string should decode");
        assert_eq!(value.to_str().expect("ASCII fixture"), "foo");

        assert!(view.deref_c_str(Ptr::<CStr>::null()).is_none());
    }
}
