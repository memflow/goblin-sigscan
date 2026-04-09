//! Goblin-powered multi-format pattern scanning with pelite-style signatures.
//!
//! `goblin-lite` combines:
//!
//! - pelite-inspired pattern syntax and semantics,
//! - scanner APIs over PE/ELF/Mach binaries,
//! - compile-time (`pattern!`) and runtime (`pattern::parse`) pattern parsing.
//!
//! This crate's design and pattern language are heavily inspired by pelite.
//! See the original project by casualx:
//! <https://github.com/CasualX/pelite> and
//! <https://docs.rs/pelite/latest/pelite/pattern/>.
//!
//! # Docs map
//!
//! - Syntax overview and parser API: [`mod@crate::pattern`]
//! - Parser internals/reference crate: [`goblin_lite_pattern`]
//! - Scanner entry points: [`Scanner`], [`Matches`], [`PreparedPattern`]
//! - Binary wrappers: [`pe64`], [`elf`], [`mach`]
//!
//! # Pattern Scanner Tutorial
//!
//! ## 1) Parse a pattern
//!
//! Runtime parse:
//!
//! ```
//! use goblin_lite::pattern;
//!
//! let atoms = pattern::parse("48 8B ? ? ? ? 48 89")?;
//! assert!(atoms.len() >= 3);
//! # Ok::<(), pattern::ParsePatError>(())
//! ```
//!
//! Compile-time parse via macro:
//!
//! ```no_run
//! let atoms = goblin_lite::pattern!("48 8B ? ? ? ? 48 89");
//! assert!(!atoms.is_empty());
//! ```
//!
//! ## 2) Size your save buffer correctly
//!
//! Save-slot length and semantics are the easiest API to misuse.
//!
//! - Use [`pattern::save_len`] for parsed atom slices.
//! - For prepared patterns, use [`PreparedPattern::required_slots`].
//! - Parsed patterns always include an implicit `Save(0)`, so slot `0` is
//!   always the match start cursor (RVA/VA/mapped offset based on wrapper).
//! - Extra tail elements in larger `save` buffers are left untouched.
//!
//! ```
//! use goblin_lite::pattern;
//!
//! let atoms = pattern::parse("e8 ${'}")?;
//! let mut save = vec![0u64; pattern::save_len(&atoms)];
//! assert!(save.len() >= 2);
//! # Ok::<(), pattern::ParsePatError>(())
//! ```
//!
//! ## 3) Scan binary code ranges
//!
//! ```no_run
//! use std::error::Error;
//!
//! use goblin_lite::{pattern, pe64::PeFile};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Provide real module bytes from your target binary in production code.
//!     let bytes: &[u8] = &[];
//!     let file = PeFile::from_bytes(bytes)?;
//!     let atoms = pattern::parse("48 8B ? ? ? ? 48 89")?;
//!     let mut save = vec![0u64; pattern::save_len(&atoms)];
//!     let mut matches = file.scanner().matches_code(&atoms);
//!     if matches.next(&mut save) {
//!         let match_start = save[0];
//!         let _ = match_start;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## 4) Reuse prepared patterns for repeated scans
//!
//! ```no_run
//! use std::error::Error;
//!
//! use goblin_lite::{pattern, pe64::PeFile};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Provide real module bytes from your target binary in production code.
//!     let bytes: &[u8] = &[];
//!     let file = PeFile::from_bytes(bytes)?;
//!     let atoms = pattern::parse("e8 ${'}")?;
//!     let prepared = file.scanner().prepare_pattern(&atoms);
//!     let mut save = vec![0u64; prepared.required_slots()];
//!     let _is_unique = file.scanner().finds_prepared(&prepared, &mut save);
//!     Ok(())
//! }
//! ```
//!
//! ## 5) Syntax tutorial
//!
//! For full syntax semantics and examples, use the canonical parser tutorial:
//! [`goblin_lite_pattern::parse`].
//!
//! The `goblin_lite::pattern` module is a re-export convenience surface:
//! [`mod@crate::pattern`].
//!
//! ## Common pitfalls
//!
//! - Allocating `save` too short for the parsed pattern.
//! - Assuming slot `0` is optional (it is always present for parsed patterns).
//! - Forgetting that `[a-b]` uses an exclusive upper parse convention (`b - 1`
//!   is the maximum encoded skip).
//! - Comparing benchmark runs with mismatched sample settings.
//!
//! For benchmark methodology guidance, see `scripts/README.md` in the repo.

extern crate self as goblin_lite;

pub use goblin_lite_macros::pattern;

mod address;
pub mod elf;
pub mod mach;
pub mod pattern;
pub mod pe64;
mod scan;
mod typed;
pub use address::{FromLeBytes, MappedAddressView};
pub use scan::{BinaryView, CodeSpan, Matches, Offset, PreparedPattern, Scanner};
pub use typed::{Pod, Ptr, TypedView, Va};
