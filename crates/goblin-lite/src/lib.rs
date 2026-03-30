//! Goblin-powered multi-format pattern scanning with pelite-style signatures.

pub use goblin_lite_macros::pattern;

mod address;
pub mod elf;
pub mod mach;
pub mod pattern;
pub mod pe64;
mod scan;
pub use address::{FromLeBytes, MappedAddressView};
pub use scan::{BinaryView, Offset};
