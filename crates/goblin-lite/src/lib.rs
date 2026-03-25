//! Goblin-powered multi-format pattern scanning with pelite-style signatures.

pub use goblin_lite_macros::pattern;

pub mod elf;
pub mod mach;
pub mod pattern;
pub mod pe64;
mod scan;
